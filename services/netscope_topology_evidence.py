"""Persistent topology evidence and passive communication analytics.

This module is intentionally independent from AEGIS/Kafka. NetScope writes its
own bounded flow aggregates, identity observations and evidence to PostgreSQL.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
from collections import defaultdict
from datetime import datetime, timedelta

from models import (
    db,
    NetscopeFlowAggregate,
    NetscopeIdentityObservation,
    NetscopeTopologyEvidence,
)


def _now():
    return datetime.utcnow()


def _hash(*parts):
    return hashlib.sha256("|".join(str(p or "") for p in parts).encode()).hexdigest()[:48]


def normalize_mac(value):
    raw = str(value or "").strip().lower().replace("-", ":")
    parts = raw.split(":")
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        return ""
    try:
        if any(int(p, 16) < 0 for p in parts):
            return ""
    except ValueError:
        return ""
    if raw in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return ""
    return raw


def record_evidence(*, source, relation, observer="", subject_key="", peer_key="",
                    subject_ip="", peer_ip="", local_port="", remote_port="",
                    vlan="", confidence=0.5, ttl_seconds=1800, details=None,
                    commit=True):
    now = _now()
    key = _hash(source, relation, observer, subject_key, peer_key,
                subject_ip, peer_ip, local_port, remote_port, vlan)
    row = NetscopeTopologyEvidence.query.filter_by(evidence_key=key).first()
    if row is None:
        row = NetscopeTopologyEvidence(
            evidence_key=key, source=str(source), relation=str(relation),
            observer=str(observer or ""), subject_key=str(subject_key or ""),
            peer_key=str(peer_key or ""), subject_ip=str(subject_ip or ""),
            peer_ip=str(peer_ip or ""), local_port=str(local_port or ""),
            remote_port=str(remote_port or ""), vlan=str(vlan or ""),
            confidence=max(0.0, min(1.0, float(confidence))),
            first_seen=now, last_seen=now, active=True,
            details=details or {},
        )
        db.session.add(row)
    else:
        row.last_seen = now
        row.active = True
        row.confidence = max(row.confidence or 0.0,
                             max(0.0, min(1.0, float(confidence))))
        if details:
            merged = dict(row.details or {})
            merged.update(details)
            row.details = merged
    row.expires_at = now + timedelta(seconds=max(30, int(ttl_seconds)))
    if commit:
        db.session.commit()
    return row


def observe_identity(ip, mac="", *, hostname="", source="ethernet",
                     sensor_id="netscope-local", confidence=0.8,
                     valid_to=None, details=None, commit=True):
    try:
        ip = str(ipaddress.ip_address(str(ip)))
    except ValueError:
        return None
    mac = normalize_mac(mac)
    if not mac and not hostname:
        return None
    key = _hash(ip, mac, str(hostname).lower(), source, sensor_id)
    now = _now()
    row = NetscopeIdentityObservation.query.filter_by(
        observation_key=key).first()
    if row is None:
        row = NetscopeIdentityObservation(
            observation_key=key, ip=ip, mac=mac,
            hostname=str(hostname or "")[:255], source=str(source),
            sensor_id=str(sensor_id), confidence=float(confidence),
            first_seen=now, last_seen=now, valid_to=valid_to,
            details=details or {},
        )
        db.session.add(row)
    else:
        row.last_seen = now
        row.confidence = max(row.confidence or 0.0, float(confidence))
        if valid_to and (row.valid_to is None or valid_to > row.valid_to):
            row.valid_to = valid_to
        if details:
            merged = dict(row.details or {})
            merged.update(details)
            row.details = merged
    if commit:
        db.session.commit()
    return row


def record_flow(*, sensor_id, interface, src_ip, dst_ip, src_mac="", dst_mac="",
                src_port=0, dst_port=0, protocol="IP", vlan="",
                packets=1, bytes_count=0, flow_count=1, seen_at=None,
                window_seconds=300, commit=True):
    try:
        src_ip = str(ipaddress.ip_address(str(src_ip)))
        dst_ip = str(ipaddress.ip_address(str(dst_ip)))
    except ValueError:
        return None
    when = seen_at or _now()
    bucket = int(when.timestamp()) // max(30, int(window_seconds))
    key = _hash(sensor_id, bucket, src_ip, dst_ip, int(src_port or 0),
                int(dst_port or 0), str(protocol).upper(), vlan)
    row = NetscopeFlowAggregate.query.filter_by(flow_key=key).first()
    if row is None:
        row = NetscopeFlowAggregate(
            flow_key=key, sensor_id=str(sensor_id), interface=str(interface or ""),
            src_ip=src_ip, dst_ip=dst_ip,
            src_mac=normalize_mac(src_mac), dst_mac=normalize_mac(dst_mac),
            src_port=int(src_port or 0), dst_port=int(dst_port or 0),
            protocol=str(protocol or "IP").upper()[:12], vlan=str(vlan or ""),
            packets=int(packets or 0), bytes=int(bytes_count or 0),
            flow_count=int(flow_count or 0), first_seen=when, last_seen=when,
        )
        db.session.add(row)
    else:
        row.packets += int(packets or 0)
        row.bytes += int(bytes_count or 0)
        row.flow_count += int(flow_count or 0)
        row.last_seen = max(row.last_seen or when, when)
        if not row.src_mac:
            row.src_mac = normalize_mac(src_mac)
        if not row.dst_mac:
            row.dst_mac = normalize_mac(dst_mac)
    if commit:
        db.session.commit()
    return row



def recent_identity_candidates(window_minutes=60, min_confidence=0.90):
    cutoff = _now() - timedelta(minutes=max(1, int(window_minutes)))
    rows = NetscopeIdentityObservation.query.filter(
        NetscopeIdentityObservation.last_seen >= cutoff,
        NetscopeIdentityObservation.confidence >= float(min_confidence),
        NetscopeIdentityObservation.mac != '',
    ).order_by(NetscopeIdentityObservation.last_seen.desc()).all()
    grouped = defaultdict(dict)
    for row in rows:
        current = grouped[row.ip].get(row.mac)
        if current is None or row.confidence > current["confidence"]:
            grouped[row.ip][row.mac] = {
                "mac": row.mac, "source": row.source,
                "confidence": float(row.confidence or 0.0),
                "last_seen": row.last_seen,
            }
    return {
        ip: next(iter(macs.values()))
        for ip, macs in grouped.items() if len(macs) == 1
    }


def reconcile_device_identities(store, window_minutes=60):
    """Fill only missing MACs from a unique recent high-confidence observation.

    Existing MACs are never overwritten and ambiguous observations are ignored.
    """
    candidates = recent_identity_candidates(window_minutes)
    changed = 0
    conflicts = 0
    with store._lock:
        store._cache_loaded_at = 0.0
        store._load()
        for ip, observed in candidates.items():
            device = store.find_by_ip(ip, include_deleted=False)
            if not device or device.get("mac"):
                continue
            existing = store.find(observed["mac"], include_deleted=False)
            if existing and existing is not device:
                conflicts += 1
                continue
            device["mac"] = observed["mac"]
            device["identity_evidence"] = {
                "source": observed["source"],
                "confidence": observed["confidence"],
                "last_seen": observed["last_seen"].isoformat()
                if observed["last_seen"] else None,
            }
            changed += 1
        if changed:
            store._flush()
    return {"changed": changed, "conflicts": conflicts}

def expire_stale(*, evidence_grace_seconds=0, flow_retention_hours=24,
                 identity_retention_days=30):
    now = _now()
    cutoff = now + timedelta(seconds=int(evidence_grace_seconds))
    NetscopeTopologyEvidence.query.filter(
        NetscopeTopologyEvidence.active.is_(True),
        NetscopeTopologyEvidence.expires_at.isnot(None),
        NetscopeTopologyEvidence.expires_at < cutoff,
    ).update({"active": False}, synchronize_session=False)
    NetscopeFlowAggregate.query.filter(
        NetscopeFlowAggregate.last_seen <
        now - timedelta(hours=max(1, int(flow_retention_hours)))
    ).delete(synchronize_session=False)
    NetscopeIdentityObservation.query.filter(
        NetscopeIdentityObservation.last_seen <
        now - timedelta(days=max(1, int(identity_retention_days)))
    ).delete(synchronize_session=False)
    db.session.commit()


def active_evidence(*, sources=None, relations=None):
    now = _now()
    query = NetscopeTopologyEvidence.query.filter(
        NetscopeTopologyEvidence.active.is_(True),
        (NetscopeTopologyEvidence.expires_at.is_(None) |
         (NetscopeTopologyEvidence.expires_at >= now)),
    )
    if sources:
        query = query.filter(NetscopeTopologyEvidence.source.in_(list(sources)))
    if relations:
        query = query.filter(
            NetscopeTopologyEvidence.relation.in_(list(relations)))
    return query.all()


def _pagerank(edges, nodes, iterations=25, damping=0.85):
    if not nodes:
        return {}
    nodes = set(nodes)
    rank = {n: 1.0 / len(nodes) for n in nodes}
    outgoing = defaultdict(dict)
    for (src, dst), weight in edges.items():
        if src != dst and weight > 0:
            outgoing[src][dst] = outgoing[src].get(dst, 0.0) + float(weight)
    for _ in range(iterations):
        base = (1.0 - damping) / len(nodes)
        nxt = {n: base for n in nodes}
        dangling = sum(rank[n] for n in nodes if not outgoing.get(n))
        share = damping * dangling / len(nodes)
        for n in nodes:
            nxt[n] += share
        for src, targets in outgoing.items():
            total = sum(targets.values()) or 1.0
            for dst, weight in targets.items():
                if dst in nxt:
                    nxt[dst] += damping * rank.get(src, 0.0) * weight / total
        rank = nxt
    return rank


def communication_metrics(window_minutes=30):
    cutoff = _now() - timedelta(minutes=max(1, int(window_minutes)))
    rows = NetscopeFlowAggregate.query.filter(
        NetscopeFlowAggregate.last_seen >= cutoff).all()
    peers = defaultdict(set)
    in_peers = defaultdict(set)
    out_peers = defaultdict(set)
    bytes_total = defaultdict(int)
    packets_total = defaultdict(int)
    flows_total = defaultdict(int)
    incoming_ports = defaultdict(lambda: defaultdict(set))
    edge_weights = defaultdict(float)
    nodes = set()
    for row in rows:
        a, b = row.src_ip, row.dst_ip
        nodes.update((a, b))
        peers[a].add(b); peers[b].add(a)
        out_peers[a].add(b); in_peers[b].add(a)
        amount = max(1, int(row.flow_count or 0))
        edge_weights[(a, b)] += amount
        for ip in (a, b):
            bytes_total[ip] += int(row.bytes or 0)
            packets_total[ip] += int(row.packets or 0)
            flows_total[ip] += amount
        if row.dst_port:
            incoming_ports[b][int(row.dst_port)].add(a)
    rank = _pagerank(edge_weights, nodes)
    return {
        ip: {
            "peers": len(peers[ip]),
            "in_peers": len(in_peers[ip]),
            "out_peers": len(out_peers[ip]),
            "bytes": bytes_total[ip],
            "packets": packets_total[ip],
            "flows": flows_total[ip],
            "pagerank": rank.get(ip, 0.0),
            "incoming_ports": {
                str(port): len(clients)
                for port, clients in incoming_ports[ip].items()
            },
        } for ip in nodes
    }


def infer_roles(devices, window_minutes=30):
    metrics = communication_metrics(window_minutes)
    by_ip = {str(d.get("ip") or ""): d for d in devices if d.get("ip")}
    next_hop_count = defaultdict(set)
    for ev in active_evidence(relations=("l2-next-hop",)):
        if ev.peer_key:
            next_hop_count[ev.peer_key].add(ev.subject_key or ev.subject_ip)
    ranks = sorted((m["pagerank"] for m in metrics.values()), reverse=True)
    rank_cut = ranks[max(0, math.ceil(len(ranks) * 0.20) - 1)] if ranks else 1.0
    out = {}
    for ip, device in by_ip.items():
        key = str(device.get("uid") or device.get("mac") or "").lower()
        m = metrics.get(ip, {})
        roles = []
        pr = float(m.get("pagerank", 0.0))
        peers = int(m.get("peers", 0))
        ports = m.get("incoming_ports", {})
        hop_users = len(next_hop_count.get(key, set()))
        if hop_users >= 2:
            roles.append({
                "role": "network-transit-candidate",
                "score": min(0.98, 0.70 + 0.05 * hop_users),
                "evidence": f"next-hop observado para {hop_users} ativos",
            })
        if peers >= 3 and pr >= rank_cut:
            roles.append({
                "role": "communication-centralizer",
                "score": min(0.95, 0.55 + min(0.35, peers * 0.03)),
                "evidence": f"{peers} peers; pagerank={pr:.4f}",
            })
        if int(ports.get("53", 0)) >= 2:
            roles.append({
                "role": "dns-service",
                "score": min(0.95, 0.65 + int(ports["53"]) * 0.04),
                "evidence": f"DNS recebido de {ports['53']} peers",
            })
        if int(ports.get("67", 0)) >= 2:
            roles.append({
                "role": "dhcp-service",
                "score": 0.85,
                "evidence": f"DHCP observado de {ports['67']} peers",
            })
        if roles:
            out[key] = {"ip": ip, "roles": roles, "metrics": m}
    return out


def evidence_summary():
    now = _now()
    rows = NetscopeTopologyEvidence.query.filter(
        NetscopeTopologyEvidence.active.is_(True),
        (NetscopeTopologyEvidence.expires_at.is_(None) |
         (NetscopeTopologyEvidence.expires_at >= now)),
    ).all()
    by_source = defaultdict(int)
    by_relation = defaultdict(int)
    for row in rows:
        by_source[row.source] += 1
        by_relation[row.relation] += 1
    return {
        "active": len(rows),
        "by_source": dict(sorted(by_source.items())),
        "by_relation": dict(sorted(by_relation.items())),
        "flow_aggregates": NetscopeFlowAggregate.query.count(),
        "identity_observations": NetscopeIdentityObservation.query.count(),
    }
