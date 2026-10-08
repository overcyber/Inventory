from concurrent.futures import ThreadPoolExecutor, as_completed
from models import db, HostInventory, Group
from datetime import datetime, timedelta
import requests
import urllib3
import logging
import random
import threading
import time
import os

from utils import cache as shared_cache

MIN_REQUEST_INTERVAL = 0.2
MAX_RETRIES = 3
RETRY_DELAY_BASE = 1.0
ENDPOINTS = [
    'hardware', 'os', 'packages', 'ports', 'processes', 'netaddr', 'netiface',
    'netproto', 'services', 'users', 'groups', 'browser_extensions', 'hotfixes',
]

def _env_bool(name, default=True):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on', 'sim')

class WazuhCollector:

    AGENTS_SELECT = ('id,name,ip,lastKeepAlive,status,'
                     'os.platform,os.name,os.version,group')
    PAGE_SIZE = 500

    def __init__(self, protocol, host, port, user, password, logger):
        self.base_url = f"{protocol}://{host}:{port}"
        self._user = user
        self._password = password
        self._local = threading.local()
        self._rate_lock = threading.Lock()
        self._last_req = 0.0
        self.token = None
        self.logger = logger
        verify = _env_bool('WAZUH_TLS_VERIFY', True)
        ca_bundle = (os.getenv('WAZUH_CA_BUNDLE') or '').strip()
        self.verify = ca_bundle if verify and ca_bundle else verify

    def _get_session(self):

        s = getattr(self._local, 'session', None)
        if s is None:
            s = requests.Session()
            s.verify = self.verify
            if self.token:
                s.headers.update({'Authorization': f'Bearer {self.token}'})
            else:
                s.auth = (self._user, self._password)
            self._local.session = s
        return s

    def authenticate(self) -> bool:

        url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            resp = self._request('GET', url, timeout=10)
            self.token = resp.text.strip()
            self._local.session = None
            self.logger.info("[Coletor] Autenticação bem-sucedida.")
            return True
        except Exception as e:
            self.logger.error(f'[Coletor] Falha na autenticação Wazuh ({self.base_url}): {e}')
            return False

    def _request(self, method, url, **kwargs):

        session = self._get_session()
        for attempt in range(MAX_RETRIES + 1):
            with self._rate_lock:
                now = time.time()
                wait = MIN_REQUEST_INTERVAL - (now - self._last_req)
                self._last_req = max(now, self._last_req + MIN_REQUEST_INTERVAL)
            if wait > 0:
                time.sleep(wait)

            try:
                resp = session.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp
            except requests.RequestException as e:
                if attempt < MAX_RETRIES:
                    delay = RETRY_DELAY_BASE * (2 ** attempt) + random.random() * 0.1
                    self.logger.warning(f"[Coletor] Falha na requisição (Tentativa {attempt+1}): {e}. Retentando em {delay:.2f}s...")
                    time.sleep(delay)
                else:
                    self.logger.error(f"[Coletor] Erro crítico após {MAX_RETRIES} tentativas em {url}: {e}")
                    raise

    def get_json(self, endpoint, optional=False):

        url = f"{self.base_url}/{endpoint}"
        try:
            resp = self._request('GET', url, timeout=30)
            return resp.json()
        except Exception as e:
            if optional:
                self.logger.debug(f'[Coletor] Endpoint opcional indisponível {url}: {e}')
            else:
                self.logger.error(f'[Coletor] Falha ao obter JSON de {url}: {e}')
            return {}

    @staticmethod
    def _clean_data(obj):

        if isinstance(obj, dict):
            return {
                k: WazuhCollector._clean_data(v)
                for k, v in obj.items()
                if k not in ('agent_id', 'scan_id', 'scan_time')
            }
        if isinstance(obj, list):
            return [WazuhCollector._clean_data(i) for i in obj]
        return obj

    @staticmethod
    def _determine_status(last_seen: str) -> str:

        if not last_seen or last_seen == 'unknown':
            return 'Desligado'
        try:
            ts = last_seen.rstrip('Z') + '+00:00' if last_seen.endswith('Z') else last_seen
            dt = datetime.fromisoformat(ts)
            now = datetime.now(dt.tzinfo)
            delta = now - dt
            grace = max(60, int(os.getenv('WAZUH_ACTIVE_GRACE_SECONDS', '300')))
            return 'Ligado' if delta <= timedelta(seconds=grace) else 'Desligado'
        except Exception:
            return 'Desligado'

    def _fetch_agent_inventory(self, agent_id):

        inv = {}
        mandatory = {'hardware', 'os', 'packages', 'ports', 'processes',
                     'netaddr', 'netiface', 'netproto'}
        for ep in ENDPOINTS:
            data = self.get_json(f"syscollector/{agent_id}/{ep}",
                                 optional=ep not in mandatory)
            items = data.get('data', {}).get('affected_items', [])
            inv[ep] = [self._clean_data(it) for it in items]
        return inv

    def fetch_all_agents(self, select=None, page_size=None):

        select = select or self.AGENTS_SELECT
        page_size = page_size or self.PAGE_SIZE
        agents = []
        offset = 0
        total = None
        while True:
            url = f"agents?select={select}&limit={page_size}&offset={offset}"
            data = self.get_json(url).get('data', {}) or {}
            items = data.get('affected_items', []) or []
            agents.extend(items)
            if total is None:
                total = data.get('total_affected_items')
            offset += len(items)
            if total is None:
                if len(items) < page_size:
                    break
            elif offset >= total or not items:
                break
            if offset > 200000:
                self.logger.warning(
                    "[Coletor] Paginação de agentes interrompida "
                    f"(offset {offset} excedeu o teto de segurança).")
                break
        return agents

def _sync_wazuh_only(app):

    with app.app_context():
        logger = app.logger
        host = (os.getenv('WAZUH_HOST') or '').strip()
        default_enabled = bool(host and host.upper() not in {'IP_WAZUH', 'CHANGEME'})
        if not _env_bool('WAZUH_ENABLED', default_enabled):
            logger.info("[Coletor] Wazuh desabilitado; ciclo pulado.")
            return {'processed': 0, 'errors': 0, 'skipped': True}
        if not host or host.upper() in {'IP_WAZUH', 'CHANGEME'}:
            logger.info("[Coletor] Wazuh não configurado; ciclo pulado.")
            return {'processed': 0, 'errors': 0, 'skipped': True}
        logger.info("[Coletor] Iniciando ciclo de sincronização Wazuh...")

        found_groups = []
        found_agent_ids = []

        collector = WazuhCollector(
            protocol=os.getenv('WAZUH_PROTOCOL', 'https'),
            host=os.getenv('WAZUH_HOST', ''),
            port=os.getenv('WAZUH_PORT', '55000'),
            user=os.getenv('WAZUH_USER', ''),
            password=os.getenv('WAZUH_PASSWORD', ''),
            logger=logger
        )

        if not collector.authenticate():
            return

        groups_data = collector.get_json('groups?pretty=true')
        groups_api = groups_data.get('data', {}).get('affected_items', [])

        group_counts = {g.get('name'): 0 for g in groups_api}
        if 'default' not in group_counts: group_counts['default'] = 0

        agents = collector.fetch_all_agents()

        logger.info(f"[Coletor] API retornou {len(agents)} agentes (paginado, "
                    f"{collector.PAGE_SIZE}/página).")

        if not agents:
            logger.warning("[Coletor] Nenhum agente encontrado para sincronizar.")

        for agent in agents:
            a_groups = agent.get('group', ['default'])
            if isinstance(a_groups, str): a_groups = [a_groups]
            for gn in a_groups:
                if gn in group_counts:
                    group_counts[gn] += 1
                else:
                    group_counts[gn] = 1

        for gname, count in group_counts.items():
            found_groups.append(gname)
            group_payload = {
                "grupo": gname,
                "quantidade_agentes": count,
                "agentes": []
            }
            db_group = Group.query.filter_by(name=gname).first()
            if db_group:
                db_group.data = group_payload
                db_group.is_legacy = False
            else:
                db.session.add(Group(name=gname, data=group_payload, is_legacy=False))

        def process_agent(agent):
            agent_id = agent.get('id')
            agent['calculated_status'] = collector._determine_status(agent.get('lastKeepAlive', 'unknown'))

            inventory = collector._fetch_agent_inventory(agent_id)

            hostname_inv = inventory.get('os', [{}])[0].get('hostname')
            hostname = (hostname_inv or agent.get('name', 'unknown')).upper().strip()

            agent_groups = agent.get('group', ['default'])
            if isinstance(agent_groups, str): agent_groups = [agent_groups]

            payload = {
                'agent_info': agent,
                'inventory': inventory,
                'groups': agent_groups,
                'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            return hostname, payload, agent_id

        processed_count = 0
        error_count = 0
        found_agent_ids = []
        found_hostnames = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(process_agent, a) for a in agents]
            for future in as_completed(futures):
                try:
                    hostname, payload, agent_id = future.result()
                    found_agent_ids.append(agent_id)
                    found_hostnames.append(hostname)

                    from services.asset_core import ingest_wazuh_payload
                    ingest_wazuh_payload(hostname, payload, str(agent_id or ''))
                    if _env_bool('LEGACY_HOST_MIRROR', False):
                        registro = HostInventory.query.filter_by(hostname=hostname).first()
                        if registro:
                            registro.data = payload
                            registro.is_legacy = False
                            registro.last_updated = datetime.utcnow()
                        else:
                            db.session.add(HostInventory(hostname=hostname, data=payload, is_legacy=False))
                        db.session.commit()
                    processed_count += 1
                except Exception as e:
                    error_count += 1
                    logger.error(f"[Coletor] Erro ao processar detalhe de agente: {e}")

        try:
            unseen_hosts = []
            if _env_bool('LEGACY_HOST_MIRROR', False):
                unseen_hosts = HostInventory.query.filter(~HostInventory.hostname.in_(found_hostnames), HostInventory.is_legacy == False).all()
                for h in unseen_hosts:
                    h.is_legacy = True

            unseen_groups = Group.query.filter(~Group.name.in_(found_groups), Group.is_legacy == False).all()
            for g in unseen_groups:
                g.is_legacy = True

            db.session.commit()
            logger.info(f"[Coletor] Ciclo finalizado. {processed_count} sincronizados. {len(unseen_hosts)} movidos para legado.")

            if hasattr(app, 'MACHINES_CACHE'): app.MACHINES_CACHE['data'] = None
            if hasattr(app, 'STATS_CACHE'): app.STATS_CACHE['data'] = None
            shared_cache.invalidate('machines', 'stats')
            logger.info("[Coletor] Cache do Dashboard invalidado (memória + Redis) para atualização imediata.")

        except Exception as e:
            db.session.rollback()
            error_count += 1
            logger.error(f"[Coletor] Falha ao persistir ou expirar dados: {e}")

        return {'processed': processed_count, 'errors': error_count}


def sync_wazuh_data(app):
    """Backward-compatible entry point. It now runs all enabled InventorySource adapters."""
    with app.app_context():
        from services.inventory_sources import sync_configured_sources
        return sync_configured_sources(app)
