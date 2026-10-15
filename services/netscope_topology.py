"""Evidence-driven NetScope topology inference.

Basic mode:
  manual/configured ports + local passive Ethernet/ARP/flow evidence +
  configured L3 gateways.

Advanced mode:
  everything in basic mode + LLDP/CDP/FDB evidence produced by SNMP.

FDB by itself is never treated as proof of a physical cable.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict

from services.network_utils import parse_network_spec


def key_of(device):
    return str(device.get("uid") or device.get("mac") or "").strip().lower()


def _network_pairs(cfg):
    pairs = []
    for raw in cfg.get("networks") or []:
        if not isinstance(raw, dict):
            continue
        try:
            network = parse_network_spec(raw.get("cidr") or raw.get("subnet"))
            gateway = str(ipaddress.ip_address(raw.get("gateway") or ""))
            if ipaddress.ip_address(gateway) not in network:
                continue
            pairs.append((network, gateway))
        except (TypeError, ValueError):
            continue
    return sorted(pairs, key=lambda row: row[0].prefixlen, reverse=True)


def _cycle(child, parent, parents):
    seen = {child}
    node = parent
    while node:
        if node in seen:
            return True
        seen.add(node)
        node = parents.get(node)
    return False


def _add_candidate(candidates, child, parent, *, priority, confidence,
                   relation, evidence):
    child = str(child or "").lower()
    parent = str(parent or "").lower()
    if not child or not parent or child == parent:
        return
    candidates[child].append({
        "parent_id": parent,
        "parent_inferred": True,
        "parent_confidence": int(round(float(confidence) * 100)),
        "parent_relation": relation,
        "parent_evidence": evidence,
        "_priority": int(priority),
    })


def infer_topology(devices, config, evidence=None):
    active = [
        d for d in devices
        if isinstance(d, dict) and not d.get("deleted") and key_of(d)
    ]
    by_key = {key_of(d): d for d in active}
    by_ip = defaultdict(list)
    for device in active:
        try:
            by_ip[str(ipaddress.ip_address(device.get("ip") or ""))].append(device)
        except ValueError:
            pass

    topology = config.get("topology") or {}
    mode = str(topology.get("mode") or "basic").lower()
    if mode not in ("basic", "advanced"):
        mode = "basic"

    manual = {}
    for device in active:
        identifier = key_of(device)
        if device.get("parent_id") and not device.get("parent_inferred"):
            manual[identifier] = str(device["parent_id"]).lower()

    assigned = set(manual)
    parents = dict(manual)
    plan = {}
    candidates = defaultdict(list)
    conflicts = 0
    skipped_cycles = 0

    # Explicit operator-configured switch ports are strong declared evidence.
    for switch_id, switch_cfg in (config.get("switches") or {}).items():
        switch_key = str(switch_id).lower()
        sw = by_key.get(switch_key)
        if not sw or sw.get("type") != "switch" or not isinstance(switch_cfg, dict):
            continue
        for port, port_data in (switch_cfg.get("ports") or {}).items():
            if not isinstance(port_data, dict):
                continue
            child_id = str(port_data.get("device_mac") or "").lower()
            if child_id and child_id in by_key:
                _add_candidate(
                    candidates, child_id, switch_key, priority=100,
                    confidence=0.90, relation="physical-configured",
                    evidence=f"switch-port:{port}")

    # Persisted observations. Basic mode accepts only passive evidence.
    for ev in evidence or []:
        source = str(getattr(ev, "source", "") or "")
        relation = str(getattr(ev, "relation", "") or "")
        child = str(getattr(ev, "subject_key", "") or "").lower()
        peer = str(getattr(ev, "peer_key", "") or "").lower()
        confidence = float(getattr(ev, "confidence", 0.0) or 0.0)
        local_port = str(getattr(ev, "local_port", "") or "")
        remote_port = str(getattr(ev, "remote_port", "") or "")
        if child not in by_key or peer not in by_key:
            continue

        if relation == "l2-next-hop" and source in ("passive", "ethernet"):
            _add_candidate(
                candidates, child, peer, priority=90,
                confidence=max(0.70, min(0.94, confidence)),
                relation="passive-next-hop",
                evidence=f"passive-next-hop:{source}")

        if mode != "advanced":
            continue

        if relation == "fdb-access-candidate" and source == "snmp-fdb":
            _add_candidate(
                candidates, child, peer, priority=96,
                confidence=max(0.70, min(0.90, confidence)),
                relation="physical-fdb-candidate",
                evidence=f"fdb-access-port:{local_port}")

        if relation == "physical-neighbor" and source in ("lldp", "cdp"):
            child_type = str(by_key[child].get("type") or "")
            peer_type = str(by_key[peer].get("type") or "")
            # Parent semantics are safe when the neighbor is a router/firewall
            # and the local subject is downstream network equipment.
            if peer_type in ("router", "firewall", "loadbalancer") and                     child_type in ("switch", "ap"):
                _add_candidate(
                    candidates, child, peer, priority=115,
                    confidence=max(0.90, min(0.995, confidence)),
                    relation=f"physical-{source}",
                    evidence=f"{source}:{local_port}->{remote_port}")

    # Configured L3 gateway remains a logical fallback, never physical proof.
    for network, gateway in _network_pairs(config):
        matches = by_ip.get(gateway) or []
        if len(matches) != 1:
            continue
        gateway_id = key_of(matches[0])
        for device in active:
            child_id = key_of(device)
            if child_id == gateway_id or child_id in assigned:
                continue
            try:
                host_ip = ipaddress.ip_address(device.get("ip") or "")
            except ValueError:
                continue
            if host_ip in network:
                _add_candidate(
                    candidates, child_id, gateway_id, priority=55,
                    confidence=0.55, relation="logical-gateway",
                    evidence=f"configured-gateway:{gateway}")

    # Select one unambiguous strongest parent for the tree projection.
    for child_id, options in candidates.items():
        if child_id in assigned:
            continue
        best_priority = max(o["_priority"] for o in options)
        best = [o for o in options if o["_priority"] == best_priority]
        peers = {o["parent_id"] for o in best}
        configured_ports = {
            o["parent_evidence"] for o in best
            if o["parent_relation"] == "physical-configured"
        }
        if len(peers) != 1 or len(configured_ports) > 1:
            conflicts += 1
            continue
        proposal = sorted(
            best, key=lambda o: (-o["parent_confidence"],
                                 o["parent_evidence"]))[0]
        if _cycle(child_id, proposal["parent_id"], parents):
            skipped_cycles += 1
            continue
        proposal = {k: v for k, v in proposal.items()
                    if not k.startswith("_")}
        plan[child_id] = proposal
        parents[child_id] = proposal["parent_id"]
        assigned.add(child_id)

    summary = {
        "mode": mode,
        "physical_configured": sum(
            p["parent_relation"] == "physical-configured"
            for p in plan.values()),
        "passive_next_hop": sum(
            p["parent_relation"] == "passive-next-hop"
            for p in plan.values()),
        "physical_advanced": sum(
            p["parent_relation"].startswith("physical-") and
            p["parent_relation"] != "physical-configured"
            for p in plan.values()),
        "logical_gateway": sum(
            p["parent_relation"] == "logical-gateway"
            for p in plan.values()),
        "manual_preserved": len(manual),
        "unresolved": len(active) - len(assigned),
        "conflicts": conflicts,
        "cycles_prevented": skipped_cycles,
    }
    return plan, summary
