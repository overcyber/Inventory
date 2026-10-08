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
    AssetIdentityConflict, AssetInterface, AssetObservation, AssetPort,
    AssetProcess, AssetService, AssetSnapshot, AssetSoftware, AssetSourceState,
    InventorySourceState, db,
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
        'agent_status': p.get('agent_status') or 'unknown',
        'agent_status_raw': p.get('agent_status_raw') or p.get('agent_status') or 'unknown',
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
    # Hostnames are mutable aliases, never globally unique identifiers.
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


def _record_identity_conflict(kind: str, value: str, source: str, assets) -> None:
    ids=sorted({a.id for a in assets if a is not None})
    if len(ids) < 2:
        return
    row=(AssetIdentityConflict.query.filter_by(kind=kind,value=value,source=source,
                                               resolved=False)
         .order_by(AssetIdentityConflict.id.desc()).first())
    if row:
        row.candidate_asset_ids=ids
        row.observed_at=utcnow()
    else:
        db.session.add(AssetIdentityConflict(kind=kind,value=value,source=source,
                                            candidate_asset_ids=ids,
                                            observed_at=utcnow(),resolved=False))


def _resolve_asset(state: dict, source: str, external_id: str = ''):
    candidates=identity_candidates(state,source,external_id)
    # 1) same-source stable external identifier
    ext_kind=f'{source}_external_id'
    for kind,value,_ in candidates:
        if kind != ext_kind:
            continue
        rows=AssetIdentifier.query.filter_by(kind=kind,value=value,source=source).all()
        assets=list({r.asset for r in rows if r.asset})
        if len(assets)==1:
            return assets[0]
        if len(assets)>1:
            _record_identity_conflict(kind,value,source,assets)

    # 2) strong hardware/agent identifiers
    for kind in ('serial','machine_id','cloud_instance_id','wazuh_agent_id'):
        for ck,value,_ in candidates:
            if ck != kind:
                continue
            rows=AssetIdentifier.query.filter_by(kind=kind,value=value).all()
            assets=list({r.asset for r in rows if r.asset})
            if len(assets)==1:
                return assets[0]
            if len(assets)>1:
                _record_identity_conflict(kind,value,source,assets)

    # 3) MAC only when globally unambiguous. Hostname/IP never auto-merge.
    for kind,value,_ in candidates:
        if kind!='mac' or not value:
            continue
        rows=AssetIdentifier.query.filter_by(kind='mac',value=value).all()
        assets=list({r.asset for r in rows if r.asset})
        if len(assets)==1:
            return assets[0]
        if len(assets)>1:
            _record_identity_conflict(kind,value,source,assets)

    now=utcnow()
    asset=Asset(asset_uuid=str(uuid.uuid4()),
                canonical_name=state.get('hostname') or state.get('ip_address')
                               or external_id or 'UNKNOWN',
                status=state.get('device_status') or 'Desconhecido',
                agent_status=state.get('agent_status') or 'unknown',
                network_status=state.get('network_status') or 'unknown',
                confidence=float(state.get('confidence') or 0.5),
                first_seen=now,last_seen=now,last_observed_at=now,
                current_state={},active=True)
    db.session.add(asset)
    db.session.flush()
    return asset


def _upsert_identifiers(asset, state: dict, source: str, external_id: str = ''):
    now=utcnow()
    for kind,value,confidence in identity_candidates(state,source,external_id):
        row=(AssetIdentifier.query.filter_by(asset_id=asset.id,kind=kind,
                                             value=value,source=source).first())
        if row:
            row.last_seen=now
            row.confidence=max(float(row.confidence or 0),confidence)
        else:
            db.session.add(AssetIdentifier(asset_id=asset.id,kind=kind,value=value,
                                           source=source,confidence=confidence,
                                           first_seen=now,last_seen=now))


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value,list) else [value]


def _entity_key(*parts) -> str:
    raw='|'.join(_text(p).lower() for p in parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:40]


def _touch_entity(model, asset_id, source, key, values, now):
    row=model.query.filter_by(asset_id=asset_id,source=source,entity_key=key).first()
    if row is None:
        row=model(asset_id=asset_id,source=source,entity_key=key,
                  first_seen=now,last_seen=now,active=True)
        db.session.add(row)
    else:
        row.active=True
        row.last_seen=now
        row.valid_to=None
    for k,v in values.items():
        if hasattr(row,k):
            setattr(row,k,v)
    return row


def _project_source_tables(asset, state: dict, source: str, observed_at=None) -> None:
    """Temporal materialization of current source facts.

    Rows that disappear are retained with active=false and valid_to, making
    software/port/interface appearance and disappearance queryable.
    """
    inv=state.get('inventory') or {}
    now=observed_at or utcnow()
    models=(AssetAddress,AssetInterface,AssetHardware,AssetSoftware,
            AssetProcess,AssetService,AssetPort)
    for model in models:
        for row in model.query.filter_by(asset_id=asset.id,source=source,
                                         active=True).all():
            row.active=False
            row.valid_to=now

    address_rows=list(inv.get('netaddr') or [])
    address_rows.extend({'address':ip} for ip in (state.get('ips') or []))
    seen=set()
    for row in address_rows:
        if not isinstance(row,dict):
            row={'address':row}
        address=_text(row.get('address') or row.get('ip'))
        iface=_text(row.get('iface') or row.get('interface'))
        if not address:
            continue
        key=_entity_key(address,iface)
        if key in seen: continue
        seen.add(key)
        family=_text(row.get('proto') or row.get('family')) or ('ipv6' if ':' in address else 'ipv4')
        _touch_entity(AssetAddress,asset.id,source,key,{
            'address':address,'family':family,'interface_name':iface},now)

    interfaces=list(inv.get('netiface') or [])
    if not interfaces:
        interfaces=[{'mac':m} for m in state.get('macs') or []]
    for row in interfaces:
        if not isinstance(row,dict): continue
        name=_text(row.get('name')); mac=normalize_mac(row.get('mac'))
        key=_entity_key(name,mac)
        _touch_entity(AssetInterface,asset.id,source,key,{
            'name':name,'mac':mac,'state':_text(row.get('state')),
            'mtu':_text(row.get('mtu')),'interface_type':_text(row.get('type')),
            'data':row},now)

    hardware=_as_list(inv.get('hardware'))
    if not hardware and any(state.get(k) for k in ('serial','cpu_name','ram_gb')):
        hardware=[state]
    for row in hardware:
        if not isinstance(row,dict): continue
        cpu=row.get('cpu') or {}; ram=row.get('ram') or {}
        serial=_text(row.get('board_serial') or row.get('serial') or state.get('serial'))
        cpu_name=_text(cpu.get('name') or row.get('cpu_name') or state.get('cpu_name'))
        ram_total=ram.get('total')
        if ram_total is None and state.get('ram_gb'):
            try: ram_total=int(float(state['ram_gb'])*1024*1024)
            except (TypeError,ValueError): ram_total=None
        key=_entity_key(serial or cpu_name or 'hardware')
        _touch_entity(AssetHardware,asset.id,source,key,{
            'serial':serial,'cpu_name':cpu_name,
            'cpu_cores':_text(cpu.get('cores') or row.get('cpu_cores')),
            'ram_total':ram_total if isinstance(ram_total,int) else None,'data':row},now)

    for row in _as_list(inv.get('packages') or state.get('packages')):
        if not isinstance(row,dict): continue
        name=_text(row.get('name')); version=_text(row.get('version'))
        arch=_text(row.get('architecture') or row.get('arch'))
        if not name: continue
        key=_entity_key(name,version,arch)
        _touch_entity(AssetSoftware,asset.id,source,key,{
            'name':name,'version':version,'architecture':arch,
            'package_format':_text(row.get('format') or row.get('type'))},now)

    for row in _as_list(inv.get('processes') or state.get('processes')):
        if not isinstance(row,dict): continue
        pid=_text(row.get('pid')); name=_text(row.get('name'))
        cmd=_text(row.get('cmd') or row.get('cmdline') or row.get('path'))
        key=_entity_key(pid,name,cmd)
        _touch_entity(AssetProcess,asset.id,source,key,{
            'pid':pid,'name':name,
            'user_name':_text(row.get('euser') or row.get('user') or row.get('uid')),
            'command':cmd,'state':_text(row.get('state'))},now)

    for row in _as_list(inv.get('services') or state.get('services')):
        if not isinstance(row,dict): continue
        name=_text(row.get('name'))
        if not name: continue
        key=_entity_key(name)
        _touch_entity(AssetService,asset.id,source,key,{
            'name':name,'state':_text(row.get('state') or row.get('status')),
            'start_type':_text(row.get('start_type') or row.get('start')),'data':row},now)

    for row in _as_list(inv.get('ports') or state.get('ports')):
        if not isinstance(row,dict): continue
        local=row.get('local') if isinstance(row.get('local'),dict) else {}
        p=local.get('port',row.get('port'))
        try: p=int(p) if p not in (None,'') else None
        except (TypeError,ValueError): p=None
        proto=_text(row.get('protocol') or row.get('proto')).lower()
        address=_text(local.get('ip') or row.get('address'))
        proc=_text(row.get('process') or row.get('name'))
        key=_entity_key(proto,address,p,proc)
        _touch_entity(AssetPort,asset.id,source,key,{
            'protocol':proto,'address':address,'port':p,
            'state':_text(row.get('state')),'process_name':proc,
            'pid':_text(row.get('pid'))},now)


def _canonical_from_sources(asset_id: int) -> dict:
    rows=(AssetSourceState.query.filter_by(asset_id=asset_id)
          .order_by(AssetSourceState.confidence.asc(),
                    AssetSourceState.observed_at.asc()).all())
    out={}
    for row in rows:
        out=_merge_state(out,row.state or {},row.source)
    # Union network identifiers across active source states.
    ips=[]; macs=[]; sources=[]
    for row in rows:
        if row.source not in sources: sources.append(row.source)
        for ip in (row.state or {}).get('ips') or []:
            if ip and ip not in ips: ips.append(ip)
        for mac in (row.state or {}).get('macs') or []:
            mac=normalize_mac(mac)
            if mac and mac not in macs: macs.append(mac)
    out['ips']=ips; out['macs']=macs; out['source']=sources
    if ips and not out.get('ip_address'): out['ip_address']=ips[0]
    return out


def ingest_observation(source: str, external_id: str, raw_data: dict,
                       normalized: dict | None = None,
                       observed_at: datetime | None = None):
    observed_at=observed_at or utcnow()
    source=_text(source).lower() or 'unknown'
    external_id=_text(external_id)
    if normalized is None:
        normalized=generic_payload_to_state(raw_data,source,external_id)
    normalized=copy.deepcopy(normalized or {})
    digest=_json_hash({'source':source,'external_id':external_id,'normalized':normalized})

    asset=_resolve_asset(normalized,source,external_id)
    source_row=AssetSourceState.query.filter_by(asset_id=asset.id,source=source,
                                                external_id=external_id).first()
    old_source=copy.deepcopy(source_row.state or {}) if source_row else {}
    source_changes=deep_diff(old_source,normalized,limit=512)
    if source_row is None:
        source_row=AssetSourceState(asset_id=asset.id,source=source,
                                    external_id=external_id,
                                    confidence=float(normalized.get('confidence') or 0.5),
                                    first_seen=observed_at,last_seen=observed_at,
                                    observed_at=observed_at,state=normalized)
        db.session.add(source_row)
    else:
        source_row.state=normalized
        source_row.confidence=float(normalized.get('confidence') or source_row.confidence or 0.5)
        source_row.last_seen=max(source_row.last_seen or observed_at,observed_at)
        source_row.observed_at=observed_at

    _upsert_identifiers(asset,normalized,source,external_id)
    _project_source_tables(asset,normalized,source,observed_at)
    db.session.flush()

    old_canonical=copy.deepcopy(asset.current_state or {})
    canonical=_canonical_from_sources(asset.id)
    canonical_changes=deep_diff(old_canonical,canonical,limit=512)
    asset.current_state=canonical
    asset.canonical_name=canonical.get('hostname') or canonical.get('ip_address') or asset.canonical_name
    asset.status=canonical.get('device_status') or asset.status
    asset.agent_status=canonical.get('agent_status') or asset.agent_status
    asset.network_status=canonical.get('network_status') or asset.network_status
    asset.confidence=max([float(r.confidence or 0) for r in
                          AssetSourceState.query.filter_by(asset_id=asset.id).all()] or [0.5])
    asset.last_observed_at=max(asset.last_observed_at or observed_at,observed_at)
    asset.last_seen=max(asset.last_seen or observed_at,observed_at)
    asset.inventory_freshness_seconds=0
    asset.active=True

    db.session.add(AssetObservation(asset_id=asset.id,source=source,
                   external_id=external_id,observed_at=observed_at,
                   raw_data=raw_data or {},normalized_data=normalized,
                   content_hash=digest))
    for path,old_value,new_value in source_changes:
        db.session.add(AssetChange(asset_id=asset.id,observed_at=observed_at,
                       source=source,path=f'source.{source}.{path}',
                       old_value={'value':old_value},new_value={'value':new_value}))
    for path,old_value,new_value in canonical_changes:
        db.session.add(AssetChange(asset_id=asset.id,observed_at=observed_at,
                       source='canonical',path=path,
                       old_value={'value':old_value},new_value={'value':new_value}))
    db.session.add(AssetSnapshot(asset_id=asset.id,snapshot_uuid=str(uuid.uuid4()),
                   observed_at=observed_at,source=source,
                   state={'source_state':normalized,'canonical':canonical}))

    from services.integrations import enqueue_asset_event
    enqueue_asset_event(asset,canonical_changes)
    db.session.commit()
    return asset


def refresh_asset_liveness(now=None):
    import os
    now=now or utcnow()
    ttl=max(300,int(os.getenv('ASSET_ACTIVE_TTL_SECONDS','2592000')))
    for asset in Asset.query.all():
        latest=(AssetSourceState.query.filter_by(asset_id=asset.id)
                .order_by(AssetSourceState.last_seen.desc()).first())
        if latest and latest.last_seen:
            age=max(0,int((now-latest.last_seen).total_seconds()))
            asset.inventory_freshness_seconds=age
            asset.active=age <= ttl
    db.session.commit()

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
        'has_agent': any(x in ('wazuh','wazuh_indexer','osquery','inventory_agent','ssh','winrm')
                         for x in (s.get('source') or [])),
        'vendor': s.get('vendor') or '',
        'device_type': s.get('device_type') or '',
        'switch_port': s.get('switch_port') or '',
        'subnet': s.get('subnet') or '',
        'confidence': asset.confidence,
        'inventory_freshness_seconds': (max(0,int((utcnow()-asset.last_observed_at).total_seconds()))
                                        if asset.last_observed_at else None),
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



def backfill_legacy_host_inventory(logger=None):
    """One-time migration of pre-v0.19 current Wazuh rows into Asset Core."""
    import os
    if os.getenv('ASSET_BACKFILL_LEGACY','true').strip().lower() not in ('1','true','yes','on','sim'):
        return {'skipped':True}
    from models import HostInventory, SystemSetting
    key='asset_core_backfill_v1'
    if SystemSetting.query.filter_by(key=key).first():
        return {'skipped':True,'reason':'already_done'}
    migrated=errors=0
    for host in HostInventory.query.filter_by(is_legacy=False).all():
        try:
            data=host.data or {}
            aid=str((data.get('agent_info') or {}).get('id') or host.hostname)
            ingest_wazuh_payload(host.hostname,data,aid)
            migrated+=1
        except Exception as exc:
            db.session.rollback(); errors+=1
            if logger: logger.warning('[AssetCore] backfill %s: %s',host.hostname,exc)
    db.session.add(SystemSetting(key=key,value={'migrated':migrated,'errors':errors,
                                                'completed_at':utcnow().isoformat()}))
    db.session.commit()
    return {'migrated':migrated,'errors':errors}


def source_states():
    return [{
        'source': r.source, 'enabled': r.enabled, 'status': r.status,
        'last_run': r.last_run.isoformat() if r.last_run else None,
        'last_success': r.last_success.isoformat() if r.last_success else None,
        'last_error': r.last_error, 'metadata': r.metadata_json or {},
    } for r in InventorySourceState.query.order_by(InventorySourceState.source).all()]
