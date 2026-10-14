from __future__ import annotations

import json
import os

from models import SystemSetting, db

SETTING_KEY = 'source_schedules'
MIN_INTERVAL_SECONDS = 300
MAX_INTERVAL_SECONDS = 86400
DEFAULT_INTERVAL_SECONDS = 3600

SOURCE_CATALOG = (
    {
        'name': 'wazuh',
        'label': 'Wazuh Manager',
        'icon': 'fa-shield-halved',
        'hint': 'API do Wazuh Manager / Syscollector.',
    },
    {
        'name': 'wazuh_indexer',
        'label': 'Wazuh Indexer',
        'icon': 'fa-database',
        'hint': 'Índices wazuh-states-inventory-* do Wazuh Indexer.',
    },
    {
        'name': 'netscope',
        'label': 'NetScope → Asset Core',
        'icon': 'fa-diagram-project',
        'hint': 'Projeta os dispositivos descobertos pelo NetScope no inventário canônico.',
    },
    {
        'name': 'osquery',
        'label': 'osquery (local)',
        'icon': 'fa-terminal',
        'hint': 'Executa osqueryi localmente no host/container do coletor; não é gerenciamento remoto.',
    },
    {
        'name': 'snmp',
        'label': 'SNMP',
        'icon': 'fa-network-wired',
        'hint': 'Coleta switches, roteadores e topologia dos alvos SNMP configurados.',
    },
    {
        'name': 'ssh',
        'label': 'SSH',
        'icon': 'fa-server',
        'hint': 'Inventário remoto Linux/Unix dos alvos SSH configurados.',
    },
    {
        'name': 'winrm',
        'label': 'WinRM',
        'icon': 'fa-desktop',
        'hint': 'Inventário remoto Windows dos alvos WinRM configurados.',
    },
)

SOURCE_NAMES = tuple(item['name'] for item in SOURCE_CATALOG)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on', 'sim'}


def _clamp_interval(value) -> int:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        seconds = DEFAULT_INTERVAL_SECONDS
    return max(MIN_INTERVAL_SECONDS, min(MAX_INTERVAL_SECONDS, seconds))


def _default_enabled(name: str) -> bool:
    if name == 'wazuh':
        host = (os.getenv('WAZUH_HOST') or '').strip()
        inferred = bool(host and host.upper() not in {'IP_WAZUH', 'CHANGEME'})
        return _env_bool('WAZUH_ENABLED', inferred)
    if name == 'wazuh_indexer':
        return _env_bool('WAZUH_INDEXER_ENABLED', False)
    if name == 'netscope':
        return _env_bool('NETSCOPE_SOURCE_ENABLED', True)
    if name == 'osquery':
        return _env_bool('OSQUERY_ENABLED', False)
    if name == 'snmp':
        return _env_bool('SNMP_ENABLED', False)
    if name == 'ssh':
        return _env_bool('SSH_SOURCE_ENABLED', False)
    if name == 'winrm':
        return _env_bool('WINRM_SOURCE_ENABLED', False)
    return False


def _legacy_wazuh_interval() -> int:
    try:
        row = SystemSetting.query.filter_by(key='sync_interval').first()
        if row and isinstance(row.value, dict):
            return _clamp_interval(row.value.get('seconds'))
    except Exception:
        pass
    return _clamp_interval(os.getenv('SOURCE_SYNC_INTERVAL', DEFAULT_INTERVAL_SECONDS))


def default_source_schedules() -> dict:
    base_interval = _clamp_interval(
        os.getenv('SOURCE_SYNC_INTERVAL', DEFAULT_INTERVAL_SECONDS))
    result = {}
    for name in SOURCE_NAMES:
        env_key = f'{name.upper()}_INTERVAL_SECONDS'
        interval = _clamp_interval(os.getenv(env_key, base_interval))
        if name == 'wazuh':
            interval = _legacy_wazuh_interval()
        result[name] = {
            'enabled': _default_enabled(name),
            'interval_seconds': interval,
        }
    return result


def _sanitize_schedule(name: str, value, fallback: dict) -> dict:
    value = value if isinstance(value, dict) else {}
    return {
        'enabled': bool(value.get('enabled', fallback['enabled'])),
        'interval_seconds': _clamp_interval(
            value.get('interval_seconds', fallback['interval_seconds'])),
    }


def get_source_schedules(*, persist: bool = False) -> dict:
    defaults = default_source_schedules()
    row = SystemSetting.query.filter_by(key=SETTING_KEY).first()
    stored = row.value if row and isinstance(row.value, dict) else {}

    merged = {
        name: _sanitize_schedule(name, stored.get(name), defaults[name])
        for name in SOURCE_NAMES
    }

    if persist and (row is None or stored != merged):
        if row is None:
            row = SystemSetting(key=SETTING_KEY, value=merged)
            db.session.add(row)
        else:
            row.value = json.loads(json.dumps(merged))
        db.session.commit()

    return merged


def save_source_schedules(updates: dict) -> dict:
    if not isinstance(updates, dict):
        raise ValueError('sources deve ser um objeto')

    current = get_source_schedules(persist=True)
    for name, value in updates.items():
        if name not in SOURCE_NAMES:
            continue
        if not isinstance(value, dict):
            raise ValueError(f'configuração inválida para {name}')
        next_value = dict(current[name])
        if 'enabled' in value:
            next_value['enabled'] = bool(value['enabled'])
        if 'interval_seconds' in value:
            next_value['interval_seconds'] = _clamp_interval(
                value['interval_seconds'])
        current[name] = next_value

    row = SystemSetting.query.filter_by(key=SETTING_KEY).first()
    if row is None:
        row = SystemSetting(key=SETTING_KEY, value=current)
        db.session.add(row)
    else:
        row.value = json.loads(json.dumps(current))
    db.session.commit()

    # Keep legacy Wazuh interval readable by old code/clients.
    wazuh_seconds = current['wazuh']['interval_seconds']
    legacy = SystemSetting.query.filter_by(key='sync_interval').first()
    if legacy is None:
        db.session.add(SystemSetting(
            key='sync_interval', value={'seconds': wazuh_seconds}))
    else:
        legacy.value = {'seconds': wazuh_seconds}
    db.session.commit()
    return current


def enabled_overrides(schedules: dict | None = None) -> dict[str, bool]:
    schedules = schedules or get_source_schedules()
    return {
        name: bool((schedules.get(name) or {}).get('enabled'))
        for name in SOURCE_NAMES
    }


def schedule_signature(schedules: dict) -> str:
    return json.dumps(schedules, sort_keys=True, separators=(',', ':'))
