"""Local passive packet/flow observer for NetScope basic topology mode.

No AEGIS, Kafka or third-party packet parser is required. The collector uses
Linux AF_PACKET in inventory-discovery (network_mode=host, CAP_NET_RAW), keeps
bounded in-memory aggregates and periodically persists only compact evidence.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import subprocess
import threading
import time
import redis
from collections import OrderedDict
from datetime import datetime, timedelta

from services.network_utils import parse_network_spec
from services.netscope_discovery import get_default_iface
from services.netscope_topology_evidence import (
    normalize_mac,
    observe_identity,
    record_evidence,
    record_flow,
)

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


def _mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def _unicast_mac(mac):
    try:
        first = int(str(mac).split(":")[0], 16)
        return bool(mac) and not (first & 1)
    except (ValueError, IndexError):
        return False


def _network_for(ip, networks):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in networks:
        if addr in net:
            return net
    return None


def parse_frame(frame):
    """Parse only fields required by topology analytics.

    Returns None for unsupported/truncated frames. IPv6 extension headers are
    deliberately not guessed; those packets remain countable as IPv6 without
    L4 ports.
    """
    if len(frame) < 14:
        return None
    dst_mac = _mac(frame[0:6])
    src_mac = _mac(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    vlan = ""
    if ethertype in (ETH_P_8021Q, ETH_P_8021AD):
        if len(frame) < 18:
            return None
        tci, ethertype = struct.unpack("!HH", frame[14:18])
        vlan = str(tci & 0x0FFF)
        offset = 18

    base = {
        "src_mac": normalize_mac(src_mac),
        "dst_mac": normalize_mac(dst_mac),
        "vlan": vlan,
        "bytes": len(frame),
        "src_ip": "", "dst_ip": "",
        "src_port": 0, "dst_port": 0, "protocol": "",
    }

    if ethertype == ETH_P_ARP:
        if len(frame) < offset + 28:
            return None
        arp = frame[offset:offset + 28]
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", arp[:8])
        if htype != 1 or ptype != ETH_P_IP or hlen != 6 or plen != 4:
            return None
        return {
            **base, "protocol": "ARP", "arp_op": int(op),
            "arp_sender_mac": _mac(arp[8:14]),
            "arp_sender_ip": socket.inet_ntoa(arp[14:18]),
            "arp_target_mac": _mac(arp[18:24]),
            "arp_target_ip": socket.inet_ntoa(arp[24:28]),
        }

    if ethertype == ETH_P_IP:
        if len(frame) < offset + 20:
            return None
        vihl = frame[offset]
        ihl = (vihl & 0x0F) * 4
        if (vihl >> 4) != 4 or ihl < 20 or len(frame) < offset + ihl:
            return None
        proto = frame[offset + 9]
        src_ip = socket.inet_ntoa(frame[offset + 12:offset + 16])
        dst_ip = socket.inet_ntoa(frame[offset + 16:offset + 20])
        l4 = offset + ihl
        src_port = dst_port = 0
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP-{proto}")
        if proto in (6, 17) and len(frame) >= l4 + 4:
            src_port, dst_port = struct.unpack("!HH", frame[l4:l4 + 4])
        packet = {
            **base, "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol, "l4_offset": l4,
        }
        if proto == 17 and {src_port, dst_port} == {67, 68}:
            packet["dhcp"] = _parse_dhcp(frame[l4 + 8:])
        return packet

    if ethertype == ETH_P_IPV6:
        if len(frame) < offset + 40:
            return None
        src_ip = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        proto = frame[offset + 6]
        l4 = offset + 40
        src_port = dst_port = 0
        protocol = {6: "TCP", 17: "UDP", 58: "ICMPV6"}.get(proto, f"IP6-{proto}")
        if proto in (6, 17) and len(frame) >= l4 + 4:
            src_port, dst_port = struct.unpack("!HH", frame[l4:l4 + 4])
        return {
            **base, "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol,
        }
    return None


def _parse_dhcp(payload):
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    yiaddr = socket.inet_ntoa(payload[16:20])
    ciaddr = socket.inet_ntoa(payload[12:16])
    hlen = min(int(payload[2]), 16)
    client_mac = _mac(payload[28:28 + hlen]) if hlen == 6 else ""
    msg_type = None
    lease = None
    hostname = ""
    i = 240
    while i < len(payload):
        code = payload[i]
        i += 1
        if code == 255:
            break
        if code == 0:
            continue
        if i >= len(payload):
            break
        size = payload[i]
        i += 1
        value = payload[i:i + size]
        i += size
        if code == 53 and value:
            msg_type = int(value[0])
        elif code == 51 and len(value) == 4:
            lease = struct.unpack("!I", value)[0]
        elif code == 12:
            hostname = value.decode("utf-8", "ignore")[:255]
    ip = yiaddr if yiaddr != "0.0.0.0" else ciaddr
    return {
        "message_type": msg_type, "ip": ip, "client_mac": client_mac,
        "lease_seconds": lease, "hostname": hostname,
    }


class PassiveTopologyCollector:
    def __init__(self, app):
        self.app = app
        self.stop_event = threading.Event()
        self.thread = None
        self.sock = None
        self.interface = ""
        self.sensor_id = ""
        self._flows = OrderedDict()
        self._identities = OrderedDict()
        self._evidence = OrderedDict()
        self._lock = threading.Lock()
        self.stats = {
            "running": False, "packets": 0, "parsed": 0, "dropped": 0,
            "flushes": 0, "last_error": "", "last_flush": None,
        }

    def _publish_status(self):
        try:
            client=redis.Redis.from_url(
                os.getenv("REDIS_URL","redis://127.0.0.1:6379/0"),
                decode_responses=True,socket_connect_timeout=1,socket_timeout=1)
            payload={**self.stats,"interface":self.interface,
                     "sensor_id":self.sensor_id,
                     "updated_at":datetime.utcnow().isoformat()}
            client.set("inventory:netscope:passive:status",
                       json.dumps(payload),ex=120)
        except Exception:
            pass

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run, name="netscope-passive", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        if self.thread:
            self.thread.join(timeout=3)

    def _settings(self):
        from services.netscope_core import load_config
        with self.app.app_context():
            cfg = load_config()
        topo = cfg.get("topology") or {}
        mode = str(topo.get("mode") or "basic").lower()
        enabled = bool(topo.get("passive_enabled", True))
        iface = str(topo.get("passive_interface") or
                    os.getenv("NETSCOPE_PASSIVE_INTERFACE") or
                    get_default_iface() or "")
        networks = []
        for raw in cfg.get("networks") or []:
            try:
                networks.append(parse_network_spec(
                    raw.get("cidr") or raw.get("subnet")))
            except (ValueError, TypeError):
                pass
        local_networks = []
        for raw in topo.get("passive_local_networks") or []:
            try:
                local_networks.append(parse_network_spec(raw))
            except (ValueError, TypeError):
                pass
        if not local_networks and iface:
            try:
                p = subprocess.run(
                    ["ip", "-j", "addr", "show", "dev", iface],
                    capture_output=True, text=True, timeout=3)
                if p.returncode == 0:
                    for item in json.loads(p.stdout or "[]"):
                        for ai in item.get("addr_info") or []:
                            local = ai.get("local")
                            prefix = ai.get("prefixlen")
                            if local and prefix is not None:
                                local_networks.append(
                                    ipaddress.ip_network(
                                        f"{local}/{prefix}", strict=False))
            except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
                pass
        return cfg, topo, mode, enabled, iface, networks, local_networks

    def _open(self, iface, promiscuous=False):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETH_P_ALL))
        sock.settimeout(1.0)
        if iface:
            sock.bind((iface, 0))
        if promiscuous and iface:
            ifindex = socket.if_nametoindex(iface)
            mreq = struct.pack("IHH8s", ifindex, PACKET_MR_PROMISC, 0, b"")
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        return sock

    def _run(self):
        last_flush = time.monotonic()
        last_settings = 0.0
        last_status = 0.0
        settings = None
        while not self.stop_event.is_set():
            try:
                now_mono = time.monotonic()
                if settings is None or now_mono - last_settings >= 5.0:
                    settings = self._settings()
                    last_settings = now_mono
                cfg, topo, _mode, enabled, iface, networks, local_networks = settings
                if not enabled or not iface:
                    self.stats["running"] = False
                    self._publish_status()
                    self.stop_event.wait(5)
                    continue
                if self.sock is None or self.interface != iface:
                    if self.sock:
                        self.sock.close()
                    self.sock = self._open(
                        iface, bool(topo.get("promiscuous", False)))
                    self.interface = iface
                    self.sensor_id = str(
                        topo.get("sensor_id") or
                        f"{socket.gethostname()}:{iface}")[:128]
                self.stats["running"] = True
                if now_mono - last_status >= 5.0:
                    self._publish_status()
                    last_status = now_mono
                try:
                    frame = self.sock.recv(65535)
                except socket.timeout:
                    frame = None
                if frame:
                    self.stats["packets"] += 1
                    parsed = parse_frame(frame)
                    if parsed:
                        self.stats["parsed"] += 1
                        self._observe(parsed, cfg, topo, networks, local_networks)
                flush_s = max(5, int(topo.get("flush_seconds", 15)))
                if time.monotonic() - last_flush >= flush_s:
                    self.flush(topo)
                    last_flush = time.monotonic()
            except Exception as exc:
                self.stats["last_error"] = str(exc)[:300]
                self.stats["running"] = False
                self._publish_status()
                try:
                    if self.sock:
                        self.sock.close()
                except OSError:
                    pass
                self.sock = None
                self.stop_event.wait(3)
        try:
            self.flush({})
        except Exception:
            pass

    def _bounded_put(self, mapping, key, value, cap):
        if key in mapping:
            mapping.move_to_end(key)
            mapping[key] = value
            return
        if len(mapping) >= cap:
            mapping.popitem(last=False)
            self.stats["dropped"] += 1
        mapping[key] = value

    def _observe(self, packet, cfg, topo, networks, local_networks):
        if packet["protocol"] == "ARP":
            ip = packet.get("arp_sender_ip") or ""
            mac = normalize_mac(packet.get("arp_sender_mac"))
            if ip and mac and _network_for(ip, local_networks):
                self._identity(ip, mac, "arp", 0.97, {})
                self._topology_evidence(
                    "arp", "arp-presence", subject_ip=ip,
                    details={"mac": mac, "operation": packet.get("arp_op")},
                    confidence=0.92)
            return

        src_ip = packet.get("src_ip") or ""
        dst_ip = packet.get("dst_ip") or ""
        src_mac = normalize_mac(packet.get("src_mac"))
        dst_mac = normalize_mac(packet.get("dst_mac"))
        src_net = _network_for(src_ip, networks)
        dst_net = _network_for(dst_ip, networks)
        src_local = _network_for(src_ip, local_networks)
        dst_local = _network_for(dst_ip, local_networks)

        if src_local and src_mac:
            self._identity(src_ip, src_mac, "ethernet", 0.92,
                           {"interface": self.interface,
                            "vlan": packet.get("vlan") or ""})
        if dst_local and dst_mac and _unicast_mac(dst_mac):
            self._identity(dst_ip, dst_mac, "ethernet", 0.88,
                           {"interface": self.interface,
                            "vlan": packet.get("vlan") or ""})

        dhcp = packet.get("dhcp")
        if (dhcp and dhcp.get("message_type") == 5 and
                dhcp.get("ip") and dhcp.get("ip") != "0.0.0.0" and
                dhcp.get("client_mac")):
            valid_to = None
            if dhcp.get("lease_seconds"):
                valid_to = datetime.utcnow() + timedelta(
                    seconds=int(dhcp["lease_seconds"]))
            self._identity(
                dhcp["ip"], dhcp["client_mac"], "dhcp", 0.98,
                {"hostname": dhcp.get("hostname") or "",
                 "valid_to": valid_to.isoformat() if valid_to else None,
                 "message_type": dhcp.get("message_type")},
                hostname=dhcp.get("hostname") or "", valid_to=valid_to)

        if not src_ip or not dst_ip:
            return
        fkey = (
            src_ip, dst_ip, int(packet.get("src_port") or 0),
            int(packet.get("dst_port") or 0), packet.get("protocol") or "IP",
            packet.get("vlan") or "", src_mac, dst_mac,
        )
        with self._lock:
            current = self._flows.get(fkey)
            now = datetime.utcnow()
            if current:
                current["packets"] += 1
                current["bytes"] += int(packet.get("bytes") or 0)
                current["last_seen"] = now
                self._flows.move_to_end(fkey)
            else:
                self._bounded_put(self._flows, fkey, {
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "src_mac": src_mac, "dst_mac": dst_mac,
                    "src_port": int(packet.get("src_port") or 0),
                    "dst_port": int(packet.get("dst_port") or 0),
                    "protocol": packet.get("protocol") or "IP",
                    "vlan": packet.get("vlan") or "",
                    "packets": 1, "bytes": int(packet.get("bytes") or 0),
                    "first_seen": now, "last_seen": now,
                }, max(256, int(topo.get("max_flow_keys", 5000))))

        # L2 direct peer on a configured subnet. It is a communication/link
        # observation, not proof of cable or switch port.
        if src_local and dst_local and src_local == dst_local and src_mac and dst_mac:
            self._topology_evidence(
                "passive", "l2-peer-observed",
                subject_ip=src_ip, peer_ip=dst_ip,
                details={"src_mac": src_mac, "dst_mac": dst_mac,
                         "interface": self.interface},
                confidence=0.82, vlan=packet.get("vlan") or "")

        # When an internal endpoint sends outside its local subnet, the
        # Ethernet destination is the observed next hop (normally gateway).
        if src_local and (not dst_local or dst_local != src_local) and _unicast_mac(dst_mac):
            self._topology_evidence(
                "passive", "l2-next-hop",
                subject_ip=src_ip,
                details={"peer_mac": dst_mac, "remote_ip": dst_ip,
                         "direction": "egress",
                         "interface": self.interface},
                confidence=0.90, vlan=packet.get("vlan") or "")
        elif dst_local and (not src_local or src_local != dst_local) and _unicast_mac(src_mac):
            self._topology_evidence(
                "passive", "l2-next-hop",
                subject_ip=dst_ip,
                details={"peer_mac": src_mac, "remote_ip": src_ip,
                         "direction": "ingress",
                         "interface": self.interface},
                confidence=0.88, vlan=packet.get("vlan") or "")

    def _identity(self, ip, mac, source, confidence, details,
                  hostname="", valid_to=None):
        key = (ip, mac, source, hostname)
        with self._lock:
            self._bounded_put(self._identities, key, {
                "ip": ip, "mac": mac, "source": source,
                "confidence": confidence, "details": details,
                "hostname": hostname, "valid_to": valid_to,
            }, 4096)

    def _topology_evidence(self, source, relation, *, subject_ip="",
                           peer_ip="", confidence=0.5, details=None, vlan=""):
        peer_mac = normalize_mac((details or {}).get("peer_mac"))
        key = (source, relation, subject_ip, peer_ip, peer_mac, vlan)
        with self._lock:
            existing = self._evidence.get(key)
            value = {
                "source": source, "relation": relation,
                "subject_ip": subject_ip, "peer_ip": peer_ip,
                "confidence": confidence, "details": details or {},
                "vlan": vlan,
            }
            if existing:
                merged = dict(existing.get("details") or {})
                merged.update(value["details"])
                value["details"] = merged
            self._bounded_put(self._evidence, key, value, 4096)

    def flush(self, topo):
        with self._lock:
            flows = list(self._flows.values())
            identities = list(self._identities.values())
            evidences = list(self._evidence.values())
            self._flows.clear()
            self._identities.clear()
            self._evidence.clear()
        if not (flows or identities or evidences):
            return
        with self.app.app_context():
            from models import db
            from services.netscope_core import store, dev_key, load_config
            from services.netscope_topology_evidence import reconcile_device_identities
            cfg = load_config()
            ttl = int(topo.get("evidence_ttl_seconds", 1800) or 1800)
            window = int(topo.get("flow_window_seconds", 300) or 300)
            for item in identities:
                observe_identity(
                    item["ip"], item["mac"], hostname=item.get("hostname", ""),
                    source=item["source"], sensor_id=self.sensor_id,
                    confidence=item["confidence"],
                    valid_to=item.get("valid_to"),
                    details=item.get("details"), commit=False)
            for item in flows:
                record_flow(
                    sensor_id=self.sensor_id, interface=self.interface,
                    src_ip=item["src_ip"], dst_ip=item["dst_ip"],
                    src_mac=item["src_mac"], dst_mac=item["dst_mac"],
                    src_port=item["src_port"], dst_port=item["dst_port"],
                    protocol=item["protocol"], vlan=item["vlan"],
                    packets=item["packets"], bytes_count=item["bytes"],
                    flow_count=1, seen_at=item["last_seen"],
                    window_seconds=window, commit=False)
            for item in evidences:
                subject = store.find_by_ip(item.get("subject_ip"),
                                           include_deleted=False)
                peer = store.find_by_ip(item.get("peer_ip"),
                                        include_deleted=False)
                details = dict(item.get("details") or {})
                peer_mac = normalize_mac(details.get("peer_mac"))
                if peer is None and peer_mac:
                    peer = store.find(peer_mac, include_deleted=False)
                if peer is None and item.get("relation") == "l2-next-hop":
                    try:
                        subject_addr = ipaddress.ip_address(item.get("subject_ip") or "")
                    except ValueError:
                        subject_addr = None
                    if subject_addr is not None:
                        for net_cfg in cfg.get("networks") or []:
                            try:
                                network = parse_network_spec(
                                    net_cfg.get("cidr") or net_cfg.get("subnet"))
                            except (ValueError, TypeError):
                                continue
                            if subject_addr in network:
                                gateway_ip = str(net_cfg.get("gateway") or "")
                                peer = store.find_by_ip(gateway_ip, include_deleted=False)
                                if peer_mac and gateway_ip:
                                    observe_identity(
                                        gateway_ip, peer_mac, source="next-hop",
                                        sensor_id=self.sensor_id, confidence=0.91,
                                        details={"derived_from": item.get("subject_ip"),
                                                 "interface": self.interface},
                                        commit=False)
                                break
                record_evidence(
                    source=item["source"], relation=item["relation"],
                    observer=self.sensor_id,
                    subject_key=dev_key(subject) if subject else "",
                    peer_key=dev_key(peer) if peer else "",
                    subject_ip=item.get("subject_ip", ""),
                    peer_ip=item.get("peer_ip", ""),
                    vlan=item.get("vlan", ""),
                    confidence=item["confidence"], ttl_seconds=ttl,
                    details=details, commit=False)
            db.session.commit()
            identity_result = reconcile_device_identities(store)
            self.stats["identity_updates"] = identity_result.get("changed", 0)
            self.stats["identity_conflicts"] = identity_result.get("conflicts", 0)
            self.stats["flushes"] += 1
            self.stats["last_flush"] = datetime.utcnow().isoformat()
            self._publish_status()


_collector = None


def start_passive_collector(app):
    global _collector
    if _collector is None:
        _collector = PassiveTopologyCollector(app)
        _collector.start()
    return _collector


def passive_status():
    if _collector:
        return {**_collector.stats,"interface":_collector.interface,
                "sensor_id":_collector.sensor_id}
    try:
        client=redis.Redis.from_url(
            os.getenv("REDIS_URL","redis://127.0.0.1:6379/0"),
            decode_responses=True,socket_connect_timeout=1,socket_timeout=1)
        raw=client.get("inventory:netscope:passive:status")
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return {
        "running": False, "packets": 0, "parsed": 0, "dropped": 0,
        "flushes": 0, "last_error": "", "last_flush": None,
    }
