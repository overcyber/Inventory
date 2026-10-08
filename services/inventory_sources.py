from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from services.asset_core import (
    generic_payload_to_state, ingest_observation, record_source_state,
    sync_netscope_assets,
)

log = logging.getLogger('inventory.sources')


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on', 'sim'}


@dataclass
class SourceResult:
    source: str
    observed: int = 0
    errors: int = 0
    skipped: bool = False
    detail: dict[str, Any] | None = None


class InventorySource(ABC):
    name = 'base'
    def enabled(self) -> bool:
        return True
    @abstractmethod
    def collect(self, app) -> SourceResult:
        raise NotImplementedError


class WazuhSource(InventorySource):
    name = 'wazuh'
    def enabled(self) -> bool:
        host = (os.getenv('WAZUH_HOST') or '').strip()
        default = bool(host and host.upper() not in {'IP_WAZUH', 'CHANGEME'})
        return env_bool('WAZUH_ENABLED', default)
    def collect(self, app) -> SourceResult:
        from utils.collector import _sync_wazuh_only
        result = _sync_wazuh_only(app) or {}
        return SourceResult(self.name, observed=int(result.get('processed', 0)),
                            errors=int(result.get('errors', 0)), detail=result)


class NetScopeSource(InventorySource):
    name = 'netscope'
    def enabled(self) -> bool:
        return env_bool('NETSCOPE_SOURCE_ENABLED', True)
    def collect(self, app) -> SourceResult:
        result = sync_netscope_assets()
        return SourceResult(self.name, observed=result['observed'],
                            errors=result['errors'], detail=result)


class OsquerySource(InventorySource):
    name = 'osquery'
    QUERIES = {
        'system_info': 'select * from system_info;',
        'os_version': 'select * from os_version;',
        'interfaces': 'select * from interface_addresses;',
        'listening_ports': 'select * from listening_ports;',
        'processes': 'select pid,name,path,cmdline,uid from processes;',
    }
    def enabled(self) -> bool:
        return env_bool('OSQUERY_ENABLED', False)
    @staticmethod
    def _query(sql: str):
        binary = os.getenv('OSQUERY_BINARY', 'osqueryi')
        if not shutil.which(binary):
            raise RuntimeError(f'{binary} não encontrado')
        proc = subprocess.run([binary, '--json', sql], capture_output=True,
                              text=True, timeout=30, check=True)
        return json.loads(proc.stdout or '[]')
    def collect(self, app) -> SourceResult:
        raw = {name: self._query(sql) for name, sql in self.QUERIES.items()}
        system = (raw.get('system_info') or [{}])[0]
        osv = (raw.get('os_version') or [{}])[0]
        interfaces = raw.get('interfaces') or []
        host = system.get('hostname') or system.get('computer_name') or ''
        ips, macs = [], []
        for row in interfaces:
            addr = row.get('address')
            if addr and addr not in ips and addr not in ('127.0.0.1', '::1'):
                ips.append(addr)
            mac = row.get('mac')
            if mac and mac not in macs:
                macs.append(mac)
        machine_id = system.get('uuid') or system.get('hardware_serial') or host
        payload = {
            'hostname': host, 'ips': ips, 'macs': macs,
            'serial': system.get('hardware_serial') or '',
            'machine_id': machine_id,
            'os_name': osv.get('name') or osv.get('platform') or '',
            'os_version': osv.get('version') or '',
            'cpu_name': system.get('cpu_brand') or '',
            'network_status': 'reachable', 'device_status': 'Ativo',
            'processes': raw.get('processes') or [],
            'ports': raw.get('listening_ports') or [],
            'confidence': 0.95,
            'inventory': {'processes': raw.get('processes') or [],
                          'netaddr': interfaces,
                          'ports': raw.get('listening_ports') or []},
        }
        state = generic_payload_to_state(payload, self.name, machine_id)
        ingest_observation(self.name, str(machine_id), raw, state)
        return SourceResult(self.name, observed=1, detail={'host': host})


class SNMPSource(InventorySource):
    name = 'snmp'
    def enabled(self) -> bool:
        return env_bool('SNMP_ENABLED', False)
    def collect(self, app) -> SourceResult:
        targets = json.loads(os.getenv('SNMP_TARGETS_JSON', '[]') or '[]')
        binary = os.getenv('SNMPGET_BINARY', 'snmpget')
        if not shutil.which(binary):
            raise RuntimeError('snmpget não encontrado; instale net-snmp')
        observed, errors = 0, 0
        oids = {'hostname': '1.3.6.1.2.1.1.5.0',
                'description': '1.3.6.1.2.1.1.1.0',
                'location': '1.3.6.1.2.1.1.6.0'}
        for target in targets:
            host = str(target.get('host') or '').strip()
            community = str(target.get('community') or 'public')
            if not host:
                continue
            data = {'ip': host, 'hostname': '', 'network_status': 'reachable',
                    'device_status': 'Ativo', 'confidence': 0.75}
            try:
                for key, oid in oids.items():
                    p = subprocess.run([binary, '-v2c', '-c', community, '-Oqv',
                                        host, oid], capture_output=True,
                                       text=True, timeout=8)
                    if p.returncode == 0:
                        data[key] = p.stdout.strip().strip('"')
                state = generic_payload_to_state(data, self.name, host)
                ingest_observation(self.name, host, data, state)
                observed += 1
            except Exception:
                errors += 1
        return SourceResult(self.name, observed=observed, errors=errors)


class SSHSource(InventorySource):
    name = 'ssh'
    def enabled(self) -> bool:
        return env_bool('SSH_SOURCE_ENABLED', False)
    def collect(self, app) -> SourceResult:
        import paramiko
        targets = json.loads(os.getenv('SSH_TARGETS_JSON', '[]') or '[]')
        observed, errors = 0, 0
        for target in targets:
            host = str(target.get('host') or '').strip()
            if not host:
                continue
            client = paramiko.SSHClient()
            strict_host_key = env_bool('SSH_STRICT_HOST_KEY', True)
            if strict_host_key:
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(hostname=host, port=int(target.get('port', 22)),
                               username=target.get('username'),
                               password=target.get('password'),
                               key_filename=target.get('key_filename'),
                               timeout=8, banner_timeout=8, auth_timeout=8)
                commands = {
                    'hostname': 'hostname',
                    'machine_id': 'cat /etc/machine-id 2>/dev/null || true',
                    'os_release': 'cat /etc/os-release 2>/dev/null || uname -a',
                    'addresses': 'ip -j addr 2>/dev/null || true',
                    'ports': 'ss -lntup 2>/dev/null || true',
                }
                raw = {}
                for key, cmd in commands.items():
                    _stdin, stdout, _stderr = client.exec_command(cmd, timeout=10)
                    raw[key] = stdout.read().decode('utf-8', 'replace').strip()
                payload = {'hostname': raw.get('hostname'), 'ip': host,
                           'machine_id': raw.get('machine_id'),
                           'network_status': 'reachable',
                           'device_status': 'Ativo', 'confidence': 0.90,
                           'inventory': {'ssh': raw}}
                state = generic_payload_to_state(payload, self.name,
                                                 raw.get('machine_id') or host)
                ingest_observation(self.name, raw.get('machine_id') or host,
                                   raw, state)
                observed += 1
            except Exception:
                errors += 1
            finally:
                client.close()
        return SourceResult(self.name, observed=observed, errors=errors)


class WinRMSource(InventorySource):
    name = 'winrm'
    def enabled(self) -> bool:
        return env_bool('WINRM_SOURCE_ENABLED', False)
    def collect(self, app) -> SourceResult:
        import winrm
        targets = json.loads(os.getenv('WINRM_TARGETS_JSON', '[]') or '[]')
        observed, errors = 0, 0
        script = "$cs=Get-CimInstance Win32_ComputerSystem;$os=Get-CimInstance Win32_OperatingSystem;$bios=Get-CimInstance Win32_BIOS;$n=Get-NetIPAddress -AddressFamily IPv4 | ? {$_.IPAddress -ne '127.0.0.1'};[pscustomobject]@{hostname=$env:COMPUTERNAME;serial=$bios.SerialNumber;os_name=$os.Caption;os_version=$os.Version;ram=[int64]$cs.TotalPhysicalMemory;ips=@($n.IPAddress)}|ConvertTo-Json -Compress"
        for target in targets:
            host = str(target.get('host') or '').strip()
            if not host:
                continue
            try:
                session = winrm.Session(
                    host, auth=(target.get('username'), target.get('password')),
                    transport=target.get('transport', 'ntlm'),
                    server_cert_validation=target.get('server_cert_validation', 'validate'))
                result = session.run_ps(script)
                if result.status_code != 0:
                    raise RuntimeError(result.std_err.decode('utf-8', 'replace'))
                raw = json.loads(result.std_out.decode('utf-8', 'replace'))
                raw.update({'ip': host, 'network_status': 'reachable',
                            'device_status': 'Ativo', 'confidence': 0.92})
                state = generic_payload_to_state(raw, self.name,
                                                 raw.get('serial') or host)
                ingest_observation(self.name, raw.get('serial') or host,
                                   raw, state)
                observed += 1
            except Exception:
                errors += 1
        return SourceResult(self.name, observed=observed, errors=errors)


class WazuhIndexerSource(InventorySource):
    name = 'wazuh_indexer'
    def enabled(self) -> bool:
        return env_bool('WAZUH_INDEXER_ENABLED', False)
    def collect(self, app) -> SourceResult:
        import requests
        base = (os.getenv('WAZUH_INDEXER_URL') or '').rstrip('/')
        if not base:
            raise RuntimeError('WAZUH_INDEXER_URL não configurada')
        user = os.getenv('WAZUH_INDEXER_USER') or ''
        password = os.getenv('WAZUH_INDEXER_PASSWORD') or ''
        verify_raw = os.getenv('WAZUH_INDEXER_TLS_VERIFY', 'true').lower()
        verify = verify_raw not in {'0', 'false', 'no'}
        ca = (os.getenv('WAZUH_INDEXER_CA_BUNDLE') or '').strip()
        if verify and ca:
            verify = ca
        size = int(os.getenv('WAZUH_INDEXER_PAGE_SIZE', '1000'))
        response = requests.post(
            base + '/wazuh-states-inventory-*/_search',
            auth=(user, password), verify=verify,
            json={'size': min(max(size, 1), 5000), 'sort': ['_doc']},
            timeout=30)
        response.raise_for_status()
        hits = response.json().get('hits', {}).get('hits', [])
        grouped = {}
        for hit in hits:
            src = hit.get('_source') or {}
            agent = src.get('agent') or {}
            aid = str(agent.get('id') or src.get('agent_id') or '')
            if not aid:
                continue
            bucket = grouped.setdefault(aid, {'agent': agent, 'documents': []})
            bucket['documents'].append(src)
        for aid, raw in grouped.items():
            payload = {'hostname': (raw.get('agent') or {}).get('name') or '',
                       'wazuh_agent_id': aid, 'confidence': 0.98,
                       'inventory': {'indexer_documents': raw['documents']}}
            state = generic_payload_to_state(payload, self.name, aid)
            state['wazuh_agent_id'] = aid
            ingest_observation(self.name, aid, raw, state)
        return SourceResult(self.name, observed=len(grouped),
                            detail={'hits': len(hits)})


SOURCES = [WazuhSource, NetScopeSource, OsquerySource, SNMPSource,
           SSHSource, WinRMSource, WazuhIndexerSource]


def sync_configured_sources(app) -> dict:
    summary = {}
    for cls in SOURCES:
        src = cls()
        enabled = False
        try:
            enabled = src.enabled()
            if not enabled:
                record_source_state(src.name, enabled=False,
                                    status='disabled', success=False)
                summary[src.name] = {'skipped': True}
                continue
            result = src.collect(app)
            payload = {'observed': result.observed, 'errors': result.errors,
                       'skipped': result.skipped, 'detail': result.detail or {}}
            summary[src.name] = payload
            record_source_state(src.name, enabled=True,
                                status='ok' if not result.errors else 'partial',
                                metadata=payload, success=True)
        except Exception as exc:
            try:
                record_source_state(src.name, enabled=enabled, status='error',
                                    error=str(exc), success=False)
            except Exception:
                pass
            app.logger.error('[Source:%s] %s', src.name, exc)
            summary[src.name] = {'error': str(exc)}
    return summary
