from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from models import (
    Asset, AssetAddress, AssetChange, AssetHardware, AssetIdentifier,
    AssetInterface, AssetObservation, AssetPort, AssetProcess, AssetService,
    AssetSnapshot, AssetSoftware, InventorySourceState, db,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _text(value: Any) -> str:
    return str(value or '').strip()


def normalize_hostname(value: Any) -> str:
    return _text(value).rstrip('.').upper()


def normalize_mac(value: Any) -> str:
    raw = re.sub(r'[^0-9A-Fa-f]', '', _text(value))
    if len(raw) != 12:
        return ''
    return ':'.join(raw[i:i + 2] for i in range(0, 12, 2)).lower()


def _json_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _first(seq, default=None):
    try:
        return seq[0]
    except (TypeError, IndexError):
        return default


def wazuh_payload_to_state(hostname: str, payload: dict, external_id: str = '') -> dict:
    agent = copy.deepcopy(payload.get('agent_info') or {})
    inv = copy.deepcopy(payload.get('inventory') or {})
    os_item = _first(inv.get('os') or [], {}) or {}
    hw = _first(inv.get('hardware') or [], {}) or {}
    host = normalize_hostname(os_item.get('hostname') or agent.get('name') or hostname)
    macs = []
    for iface in inv.get('netiface') or []:
        mac = normalize_mac(iface.get('mac'))
        if mac and mac not in macs:
            macs.append(mac)
    ips = []
    aip = _text(agent.get('ip'))
    if aip and aip not in ('127.0.0.1', 'localhost', 'unknown', 'N/A'):
        ips.append(aip)
    for addr in inv.get('netaddr') or []:
        ip = _text(addr.get('address'))
        if ip and ip not in ips and ip not in ('127.0.0.1', '::1'):
            ips.append(ip)
    raw_status = _text(agent.get('status')).lower() or 'unknown'
    network_status = 'reachable' if raw_status == 'active' else 'unknown'
    device_status = 'Ativo' if raw_status == 'active' else 'Inativo'
    serial = _text(hw.get('board_serial'))
    if serial.lower() in {'', 'unknown', 'n/a', 'none', 'to be filled by o.e.m.'}:
        serial = ''
    return {
        'hostname': host or normalize_hostname(hostname),
        'ip_address': ips[0] if ips else '',
        'ips': ips,
        'macs': macs,
        'serial': serial,
        'wazuh_agent_id': _text(external_id or agent.get('id')),
        'agent_status': raw_status,
        'agent_status_raw': raw_status,
        'network_status': network_status,
        'device_status': device_status,
        'last_seen': agent.get('lastKeepAlive') or payload.get('last_update'),
        'groups': payload.get('groups') or agent.get('group') or [],
        'source': ['wazuh'],
        'confidence': 0.98,
        'inventory': inv,
        'raw_agent_info': agent,
    }


def netscope_device_to_state(device: dict) -> dict:
    mac = normalize_mac(device.get('mac') or device.get('uid'))
    ip = _text(device.get('ip'))
    host = normalize_hostname(device.get('hostname') or device.get('dns_name'))
    online = _text(device.get('status')).lower() == 'online'
    ports = []
    pscan = device.get('port_scan') or {}
    for item in pscan.get('tcp') or []:
        ports.append({'local': {'port': item.get('port'), 'ip': ip},
                      'process': item.get('name') or '', 'pid': '',
                      'state': 'listening', 'protocol': 'tcp'})
    for item in pscan.get('udp_open') or []:
        ports.append({'local': {'port': item.get('port'), 'ip': ip},
                      'process': item.get('name') or '', 'pid': '',
                      'state': item.get('state') or 'open', 'protocol': 'udp'})
    return {
        'hostname': host,
        'ip_address': ip,
        'ips': [ip] if ip else [],
        'macs': [mac] if mac else [],
        'network_status': 'reachable' if online else 'unreachable',
        'device_status': 'Ativo' if online else 'Inativo',
        'last_seen': device.get('last_seen'),
        'source': ['netscope'],
        'confidence': 0.80 if mac else 0.60,
        'vendor': device.get('vendor') or '',
        'device_type': device.get('type') or '',
        'switch_port': device.get('switch_port') or '',
        'subnet': device.get('subnet') or '',
        'ports': ports,
        'inventory': {
            'ports': ports,
            'netiface': ([{'name': '', 'mac': mac, 'state': 'up' if online else 'down',
                           'mtu': '', 'type': ''}] if mac else []),
            'netaddr': ([{'iface': '', 'address': ip, 'netmask': '',
                          'proto': 'ipv4', 'broadcast': ''}] if ip else []),
        },
    }


def generic_payload_to_state(payload: dict, source: str, external_id: str = '') -> dict:
    p = copy.deepcopy(payload or {})
    host = normalize_hostname(p.get('hostname') or p.get('name'))
    macs = [normalize_mac(x) for x in (p.get('macs') or [])]
    macs = [x for x in macs if x]
    ips = [str(x).strip() for x in (p.get('ips') or []) if str(x).strip()]
    if p.get('ip') and p.get('ip') not in ips:
        ips.insert(0, str(p.get('ip')).strip())
    state = {
        'hostname': host,
        'ip_address': ips[0] if ips else '',
        'ips': ips,
        'macs': macs,
        'serial': _text(p.get('serial')),
        'machine_id': _text(p.get('machine_id')),
        'cloud_instance_id': _text(p.get('cloud_instance_id')),
        'device_status': p.get('device_status') or 'Desconhecido',
        'network_status': p.get('network_status') or 'unknown',
        'last_seen': p.get('last_seen') or utcnow().isoformat(),
        'groups': p.get('groups') or [],
        'source': [source],
        'confidence': float(p.get('confidence', 0.70)),
        'inventory': p.get('inventory') or {},
    }
    for key in ('vendor', 'device_type', 'switch_port', 'subnet', 'os_name',
                'os_version', 'cpu_name', 'ram_gb', 'packages', 'processes',
                'ports', 'services', 'users', 'hotfixes', 'browser_extensions'):
        if key in p:
            state[key] = copy.deepcopy(p[key])
    if external_id:
        state[f'{source}_id'] = str(external_id)
    return state


def identity_candidates(state: dict, source: str, external_id: str = ''):
    out = []
    def add(kind, value, confidence):
        v = _text(value)
        if v and not any(kind == a and v == b for a, b, _ in out):
            out.append((kind, v, confidence))
    add('serial', state.get('serial'), 1.0)
    add('machine_id', state.get('machine_id'), 1.0)
    add('cloud_instance_id', state.get('cloud_instance_id'), 1.0)
    if source == 'wazuh' or state.get('wazuh_agent_id'):
        add('wazuh_agent_id', state.get('wazuh_agent_id') or external_id, 0.99)
    for mac in state.get('macs') or []:
        add('mac', normalize_mac(mac), 0.97)
    add('hostname', normalize_hostname(state.get('hostname')), 0.70)
    if external_id:
        add(f'{source}_external_id', external_id, 0.90)
    return out


def deep_diff(old: Any, new: Any, path: str = '', limit: int = 128):
    changes = []
    def walk(a, b, p):
        if len(changes) >= limit:
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for key in sorted(set(a) | set(b)):
                np = f'{p}.{key}' if p else str(key)
                if key not in a:
                    changes.append((np, None, b[key]))
                elif key not in b:
                    changes.append((np, a[key], None))
                else:
                    walk(a[key], b[key], np)
            return
        if a != b:
            changes.append((p or '$', a, b))
    walk(old, new, path)
    return changes


def _merge_state(current: dict, incoming: dict, source: str) -> dict:
    out = copy.deepcopy(current or {})
    source_list = list(out.get('source') or [])
    if source not in source_list:
        source_list.append(source)
    out['source'] = source_list

    incoming_conf = float(incoming.get('confidence') or 0.5)
    provenance = copy.deepcopy(out.get('_provenance') or {})
    volatile = {'device_status', 'network_status', 'last_seen', 'agent_status',
                'agent_status_raw', 'ip_address', 'ips', 'ports'}

    def may_replace(field):
        if field in volatile:
            return True
        prev = provenance.get(field) or {}
        return incoming_conf >= float(prev.get('confidence') or 0)

    for key, value in incoming.items():
        if key in ('source', '_provenance'):
            continue
        empty = value in (None, '', [], {})
        if empty and key not in volatile:
            continue
        if key == 'inventory':
            inv = copy.deepcopy(out.get('inventory') or {})
            inv_prov = copy.deepcopy(provenance.get('inventory') or {})
            for ik, iv in (value or {}).items():
                if iv in (None, '', [], {}):
                    continue
                prev = inv_prov.get(ik) or {}
                if incoming_conf >= float(prev.get('confidence') or 0):
                    inv[ik] = copy.deepcopy(iv)
                    inv_prov[ik] = {'source': source, 'confidence': incoming_conf}
            out['inventory'] = inv
            provenance['inventory'] = inv_prov
        elif value not in (None, '') and may_replace(key):
            out[key] = copy.deepcopy(value)
            provenance[key] = {'source': source, 'confidence': incoming_conf}
    out['_provenance'] = provenance
    return out


def _resolve_asset(state: dict, source: str, external_id: str = ''):
    for kind, value, _confidence in identity_candidates(state, source, external_id):
        ident = AssetIdentifier.query.filter_by(kind=kind, value=value).first()
        if ident and ident.asset:
            return ident.asset
    asset = Asset(
        asset_uuid=str(uuid.uuid4()),
        canonical_name=state.get('hostname') or state.get('ip_address') or external_id or 'UNKNOWN',
        status=state.get('device_status') or 'Desconhecido',
        agent_status=state.get('agent_status') or 'unknown',
        network_status=state.get('network_status') or 'unknown',
        confidence=float(state.get('confidence') or 0.5),
        first_seen=utcnow(), last_seen=utcnow(), last_observed_at=utcnow(),
        current_state={}, active=True,
    )
    db.session.add(asset)
    db.session.flush()
    return asset


def _upsert_identifiers(asset, state: dict, source: str, external_id: str = ''):
    now = utcnow()
    for kind, value, confidence in identity_candidates(state, source, external_id):
        row = AssetIdentifier.query.filter_by(kind=kind, value=value).first()
        if row:
            row.last_seen = now
            row.confidence = max(float(row.confidence or 0), confidence)
            continue
        db.session.add(AssetIdentifier(
            asset_id=asset.id, kind=kind, value=value, source=source,
            confidence=confidence, first_seen=now, last_seen=now,
        ))



def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _project_source_tables(asset, state: dict, source: str) -> None:
    """Materialize the latest normalized view for one source.

    Raw observations/snapshots keep temporal truth; these tables optimize
    CMDB queries for the current source view.
    """
    inv = state.get('inventory') or {}
    now = utcnow()
    models = (AssetAddress, AssetInterface, AssetHardware, AssetSoftware,
              AssetProcess, AssetService, AssetPort)
    for model in models:
        model.query.filter_by(asset_id=asset.id, source=source).delete(
            synchronize_session=False)

    seen_addr = set()
    address_rows = list(inv.get('netaddr') or [])
    for ip in state.get('ips') or []:
        address_rows.append({'address': ip})
    for row in address_rows:
        if not isinstance(row, dict):
            row = {'address': row}
        address = _text(row.get('address') or row.get('ip'))
        if not address or address in seen_addr:
            continue
        seen_addr.add(address)
        family = _text(row.get('proto') or row.get('family'))
        if not family:
            family = 'ipv6' if ':' in address else 'ipv4'
        db.session.add(AssetAddress(
            asset_id=asset.id, address=address, family=family,
            interface_name=_text(row.get('iface') or row.get('interface')),
            source=source, first_seen=now, last_seen=now))

    interfaces = list(inv.get('netiface') or [])
    if not interfaces:
        interfaces = [{'mac': mac} for mac in state.get('macs') or []]
    for row in interfaces:
        if not isinstance(row, dict):
            continue
        db.session.add(AssetInterface(
            asset_id=asset.id, name=_text(row.get('name')),
            mac=normalize_mac(row.get('mac')), state=_text(row.get('state')),
            mtu=_text(row.get('mtu')),
            interface_type=_text(row.get('type')), source=source,
            data=row))

    hardware_rows = _as_list(inv.get('hardware'))
    if not hardware_rows and any(state.get(k) for k in ('serial', 'cpu_name', 'ram_gb')):
        hardware_rows = [state]
    for row in hardware_rows:
        if not isinstance(row, dict):
            continue
        cpu = row.get('cpu') or {}
        ram = row.get('ram') or {}
        ram_total = ram.get('total')
        if ram_total is None and state.get('ram_gb'):
            try:
                ram_total = int(float(state['ram_gb']) * 1024 * 1024)
            except (TypeError, ValueError):
                ram_total = None
        db.session.add(AssetHardware(
            asset_id=asset.id, source=source,
            serial=_text(row.get('board_serial') or row.get('serial') or state.get('serial')),
            cpu_name=_text(cpu.get('name') or row.get('cpu_name') or state.get('cpu_name')),
            cpu_cores=_text(cpu.get('cores') or row.get('cpu_cores')),
            ram_total=ram_total if isinstance(ram_total, int) else None,
            data=row))

    for row in _as_list(inv.get('packages') or state.get('packages')):
        if not isinstance(row, dict):
            continue
        name = _text(row.get('name'))
        if not name:
            continue
        db.session.add(AssetSoftware(
            asset_id=asset.id, source=source, name=name,
            version=_text(row.get('version')),
            architecture=_text(row.get('architecture') or row.get('arch')),
            package_format=_text(row.get('format') or row.get('type')),
            first_seen=now, last_seen=now))

    for row in _as_list(inv.get('processes') or state.get('processes')):
        if not isinstance(row, dict):
            continue
        db.session.add(AssetProcess(
            asset_id=asset.id, source=source, pid=_text(row.get('pid')),
            name=_text(row.get('name')), user_name=_text(row.get('euser') or row.get('user') or row.get('uid')),
            command=_text(row.get('cmd') or row.get('cmdline') or row.get('path')),
            state=_text(row.get('state'))))

    for row in _as_list(inv.get('services') or state.get('services')):
        if not isinstance(row, dict):
            continue
        db.session.add(AssetService(
            asset_id=asset.id, source=source, name=_text(row.get('name')),
            state=_text(row.get('state') or row.get('status')),
            start_type=_text(row.get('start_type') or row.get('start')),
            data=row))

    for row in _as_list(inv.get('ports') or state.get('ports')):
        if not isinstance(row, dict):
            continue
        local = row.get('local') if isinstance(row.get('local'), dict) else {}
        p = local.get('port', row.get('port'))
        try:
            p = int(p) if p not in (None, '') else None
        except (TypeError, ValueError):
            p = None
        db.session.add(AssetPort(
            asset_id=asset.id, source=source,
            protocol=_text(row.get('protocol') or row.get('proto')).lower(),
            address=_text(local.get('ip') or row.get('address')),
            port=p, state=_text(row.get('state')),
            process_name=_text(row.get('process') or row.get('name')),
            pid=_text(row.get('pid'))))


def ingest_observation(source: str, external_id: str, raw_data: dict,
                       normalized: dict | None = None,
                       observed_at: datetime | None = None):
    observed_at = observed_at or utcnow()
    source = _text(source).lower() or 'unknown'
    external_id = _text(external_id)
    if normalized is None:
        normalized = generic_payload_to_state(raw_data, source, external_id)
    normalized = copy.deepcopy(normalized or {})
    digest = _json_hash({'source': source, 'external_id': external_id,
                         'normalized': normalized})
    existing = (AssetObservation.query
                .filter_by(source=source, external_id=external_id,
                           content_hash=digest)
                .order_by(AssetObservation.id.desc()).first())
    if existing and existing.asset:
        return existing.asset
    asset = _resolve_asset(normalized, source, external_id)
    old = copy.deepcopy(asset.current_state or {})
    merged = _merge_state(old, normalized, source)
    changes = deep_diff(old, merged)
    asset.current_state = merged
    asset.canonical_name = merged.get('hostname') or merged.get('ip_address') or asset.canonical_name
    asset.status = merged.get('device_status') or asset.status
    asset.agent_status = merged.get('agent_status') or asset.agent_status
    asset.network_status = merged.get('network_status') or asset.network_status
    asset.confidence = max(float(asset.confidence or 0), float(merged.get('confidence') or 0))
    asset.last_observed_at = observed_at
    asset.last_seen = observed_at
    asset.active = True
    _upsert_identifiers(asset, normalized, source, external_id)
    _project_source_tables(asset, normalized, source)
    db.session.add(AssetObservation(
        asset_id=asset.id, source=source, external_id=external_id,
        observed_at=observed_at, raw_data=raw_data or {},
        normalized_data=normalized, content_hash=digest,
    ))
    if changes:
        for path, old_value, new_value in changes:
            db.session.add(AssetChange(
                asset_id=asset.id, observed_at=observed_at, source=source,
                path=path, old_value={'value': old_value},
                new_value={'value': new_value},
            ))
        db.session.add(AssetSnapshot(
            asset_id=asset.id, snapshot_uuid=str(uuid.uuid4()),
            observed_at=observed_at, source=source, state=merged,
        ))
    db.session.commit()
    try:
        from services.integrations import publish_asset_event
        publish_asset_event(asset, changes)
    except Exception:
        pass
    return asset


def ingest_wazuh_payload(hostname: str, payload: dict, agent_id: str = ''):
    state = wazuh_payload_to_state(hostname, payload, agent_id)
    return ingest_observation('wazuh',
                              agent_id or state.get('wazuh_agent_id') or hostname,
                              payload, state)


def ingest_netscope_device(device: dict):
    state = netscope_device_to_state(device)
    external_id = _text(device.get('uid') or device.get('mac') or device.get('ip'))
    return ingest_observation('netscope', external_id, device, state)


def sync_netscope_assets() -> dict:
    from services.netscope_core import store
    observed = 0
    errors = 0
    for dev in store.active():
        try:
            ingest_netscope_device(dev)
            observed += 1
        except Exception:
            db.session.rollback()
            errors += 1
    return {'observed': observed, 'errors': errors}


def record_source_state(source: str, *, enabled: bool = True, status: str = 'ok',
                        error: str = '', metadata: dict | None = None,
                        success: bool = True) -> None:
    row = InventorySourceState.query.filter_by(source=source).first()
    if not row:
        row = InventorySourceState(source=source)
        db.session.add(row)
    now = utcnow()
    row.enabled = enabled
    row.last_run = now
    if success:
        row.last_success = now
    row.status = status
    row.last_error = error[:4000]
    row.metadata_json = metadata or {}
    db.session.commit()


def asset_to_machine(asset) -> dict:
    s = copy.deepcopy(asset.current_state or {})
    inv = s.get('inventory') or {}
    machine = {
        'asset_uuid': asset.asset_uuid,
        'hostname': s.get('hostname') or asset.canonical_name or 'N/A',
        'ip_address': s.get('ip_address') or _first(s.get('ips') or [], 'N/A'),
        'device_status': s.get('device_status') or asset.status or 'Desconhecido',
        'agent_status_raw': s.get('agent_status_raw') or s.get('agent_status') or asset.agent_status or 'unknown',
        'network_status': s.get('network_status') or asset.network_status or 'unknown',
        'last_seen': s.get('last_seen') or (asset.last_seen.isoformat() if asset.last_seen else 'N/A'),
        'id': s.get('wazuh_agent_id') or s.get('machine_id') or asset.asset_uuid,
        'groups': s.get('groups') or [],
        'source': s.get('source') or [],
        'confidence': asset.confidence,
        'board_serial': s.get('serial') or 'N/A',
        'netiface': inv.get('netiface') or [],
        'netaddr': inv.get('netaddr') or [],
        'ports': inv.get('ports') or s.get('ports') or [],
        'packages': inv.get('packages') or s.get('packages') or [],
        'processes': inv.get('processes') or s.get('processes') or [],
    }
    hw = _first(inv.get('hardware') or [], {}) or {}
    cpu = hw.get('cpu') or {}
    ram = hw.get('ram') or {}
    machine['cpu_name'] = s.get('cpu_name') or cpu.get('name') or 'Unknown'
    machine['cpu_cores'] = cpu.get('cores') or 'N/A'
    ram_total = ram.get('total') or 0
    machine['ram_gb'] = s.get('ram_gb') or (round(ram_total / (1024 * 1024)) if ram_total else 0)
    machine['ram_usage'] = ram.get('usage', 'N/A')
    osi = _first(inv.get('os') or [], {}) or {}
    osd = osi.get('os') or {}
    machine['os_name'] = s.get('os_name') or osd.get('name') or 'Unknown'
    machine['os_version'] = s.get('os_version') or osd.get('version') or 'N/A'
    machine['os_platform'] = osd.get('platform') or 'N/A'
    machine['os_architecture'] = osi.get('architecture') or 'N/A'
    machine['os_kernel'] = osi.get('release') or osi.get('os_release') or 'N/A'
    machine['os_codename'] = osd.get('codename') or ''
    machine['os_full'] = f"{machine['os_name']} {machine['os_version']}".strip()
    return machine


def list_machine_views(active_only: bool = True):
    q = Asset.query
    if active_only:
        q = q.filter_by(active=True)
    return [asset_to_machine(a)
            for a in q.order_by(Asset.canonical_name.asc()).all()]


def find_machine_view(name: str):
    target = normalize_hostname(name)
    if not target:
        return None
    asset = Asset.query.filter(Asset.canonical_name.ilike(target)).first()
    if not asset:
        ident = AssetIdentifier.query.filter_by(kind='hostname', value=target).first()
        asset = ident.asset if ident else None
    return asset_to_machine(asset) if asset else None


def source_states():
    return [{
        'source': r.source, 'enabled': r.enabled, 'status': r.status,
        'last_run': r.last_run.isoformat() if r.last_run else None,
        'last_success': r.last_success.isoformat() if r.last_success else None,
        'last_error': r.last_error, 'metadata': r.metadata_json or {},
    } for r in InventorySourceState.query.order_by(InventorySourceState.source).all()]
