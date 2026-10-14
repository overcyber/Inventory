"""Bounded TCP liveness checks for hosts which do not answer ICMP/ARP.

TCP connect success is positive evidence. Timeout/refused/filtered is not
negative evidence: a reachable machine can close or filter every tested port.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORTS = (22, 80, 443, 445, 3389, 5985, 8080, 8443, 53)


def configured_ports() -> tuple[int, ...]:
    raw = os.getenv("NETSCOPE_TCP_LIVENESS_PORTS", "")
    if not raw.strip():
        return DEFAULT_PORTS
    ports = []
    for part in raw.split(","):
        try:
            port = int(part.strip())
            if 1 <= port <= 65535 and port not in ports:
                ports.append(port)
        except ValueError:
            continue
    return tuple(ports[:16])


def probe_tcp(ip: str, ports=None, timeout: float | None = None) -> int | None:
    """Return an open TCP port, or None when availability is unconfirmed."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback:
        return None
    ports = configured_ports() if ports is None else tuple(ports)
    if timeout is None:
        try:
            timeout = float(os.getenv("NETSCOPE_TCP_LIVENESS_TIMEOUT", "0.4"))
        except ValueError:
            timeout = 0.4
    timeout = max(0.1, min(2.0, float(timeout)))
    for port in ports:
        try:
            with socket.create_connection((str(addr), port), timeout=timeout):
                return int(port)
        except (OSError, ValueError):
            continue
    return None


def probe_many(ips, max_workers=32) -> dict[str, int]:
    unique = list(dict.fromkeys(str(ip) for ip in ips if ip))
    if not unique:
        return {}
    max_workers = max(1, min(int(max_workers), 32))
    found: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_tcp, ip): ip for ip in unique}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                port = future.result()
                if port is not None:
                    found[ip] = port
            except Exception:
                pass
    return found
