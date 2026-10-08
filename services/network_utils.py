from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator


def parse_network_spec(spec: str):
    """Accept CIDR, full IPv4, or legacy three-octet NetScope prefixes."""
    raw = str(spec or '').strip()
    if not raw:
        raise ValueError('rede vazia')
    if '/' in raw:
        return ipaddress.ip_network(raw, strict=False)
    if raw.count('.') == 2:
        return ipaddress.ip_network(raw + '.0/24', strict=False)
    if raw.count('.') == 3:
        return ipaddress.ip_network(raw + '/24', strict=False)
    if ':' in raw:
        return ipaddress.ip_network(raw + '/64', strict=False)
    raise ValueError(f'rede inválida: {raw}')


def network_label(spec: str) -> str:
    return str(parse_network_spec(spec))


def ip_in_network(ip: str, spec: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip)) in parse_network_spec(spec)
    except ValueError:
        return False


def iter_network_hosts(spec: str, max_hosts: int | None = None) -> Iterator[str]:
    network = parse_network_spec(spec)
    emitted = 0
    for host in network.hosts():
        if max_hosts is not None and emitted >= max_hosts:
            break
        emitted += 1
        yield str(host)


def chunked(items: Iterable[str], size: int = 1024) -> Iterator[list[str]]:
    size = max(1, int(size))
    chunk: list[str] = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk
