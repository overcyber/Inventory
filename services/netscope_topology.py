"""Conservative, evidence-labelled topology inference for NetScope.

Physical edges come from configured switch ports. Gateway edges represent
logical L3 associations, never physical L2 cabling. No .1/first-IP guesses.
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
    # Longest prefix first (avoid a broad range shadowing a more specific one).
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


def infer_topology(devices, config):
    """Plan inferred parent relationships; do not mutate input devices.

    Returns (plan, summary). Plan is keyed by device UID and includes relation,
    evidence and confidence. Only devices with unique identifiers can be linked.
    """
    active = [
        d for d in devices
        if isinstance(d, dict) and not d.get("deleted") and key_of(d)
    ]
    by_key = {key_of(d): d for d in active}
    by_ip = defaultdict(list)
    for device in active:
        try:
            ip = str(ipaddress.ip_address(device.get("ip") or ""))
            by_ip[ip].append(device)
        except ValueError:
            pass

    manual = {}
    for device in active:
        identifier = key_of(device)
        if device.get("parent_id") and not device.get("parent_inferred"):
            manual[identifier] = str(device["parent_id"]).lower()

    # Preserve every manual relationship, including links to unavailable nodes.
    assigned = set(manual)
    parents = dict(manual)
    plan = {}
    conflicts = 0
    skipped_cycles = 0
    port_candidates = defaultdict(set)

    # Explicitly configured port-to-device assignment.
    for switch_id, switch_cfg in (config.get("switches") or {}).items():
        switch_key = str(switch_id).lower()
        sw = by_key.get(switch_key)
        if not sw or sw.get("type") != "switch" or not isinstance(switch_cfg, dict):
            continue
        for port, port_data in (switch_cfg.get("ports") or {}).items():
            if not isinstance(port_data, dict):
                continue
            child_id = str(port_data.get("device_mac") or "").lower()
            if child_id and child_id in by_key and child_id != switch_key:
                port_candidates[child_id].add((switch_key, str(port)))

    # Device-local switch_port references are an equivalent configured source.
    for device in active:
        reference = device.get("switch_port")
        if not isinstance(reference, dict):
            continue
        switch_key = str(reference.get("switch_mac") or "").lower()
        sw = by_key.get(switch_key)
        port = reference.get("port")
        if sw and sw.get("type") == "switch" and port and switch_key != key_of(device):
            port_candidates[key_of(device)].add((switch_key, str(port)))

    for child_id in sorted(port_candidates):
        if child_id in assigned:
            continue
        candidates = port_candidates[child_id]
        # Multiple configured switch ports for one host are ambiguous,
        # even when those ports belong to the same switch.
        if len(candidates) != 1:
            conflicts += 1
            continue
        parent, selected_port = next(iter(candidates))
        if _cycle(child_id, parent, parents):
            skipped_cycles += 1
            continue
        plan[child_id] = {
            "parent_id": parent, "parent_inferred": True,
            "parent_confidence": 90,
            "parent_relation": "physical-configured",
            "parent_evidence": "switch-port:" + selected_port,
        }
        parents[child_id] = parent
        assigned.add(child_id)

    for network, gateway in _network_pairs(config):
        matches = by_ip.get(gateway) or []
        # Ambiguous IPs are not trustworthy anchors for topology.
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
            if host_ip not in network:
                continue
            if _cycle(child_id, gateway_id, parents):
                skipped_cycles += 1
                continue
            plan[child_id] = {
                "parent_id": gateway_id, "parent_inferred": True,
                "parent_confidence": 55,
                "parent_relation": "logical-gateway",
                "parent_evidence": "configured-gateway:" + gateway,
            }
            parents[child_id] = gateway_id
            assigned.add(child_id)

    summary = {
        "physical_configured": sum(
            p["parent_relation"] == "physical-configured" for p in plan.values()),
        "logical_gateway": sum(
            p["parent_relation"] == "logical-gateway" for p in plan.values()),
        "manual_preserved": len(manual),
        "unresolved": len(active) - len(assigned),
        "conflicts": conflicts,
        "cycles_prevented": skipped_cycles,
    }
    return plan, summary
