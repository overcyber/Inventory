# Inventory v0.20 — implementação completa do Asset Intelligence multifuente

## Escopo

Esta versão implementa o planejamento arquitetural originalmente proposto para tornar o Inventory independente do Wazuh, preservando duas exceções explícitas do mantenedor:

- **não remover** `ssl/key.pem` do Git;
- **não remover** os logs já versionados em `logs/`.

Essas exceções permanecem riscos conhecidos e não representam recomendação de segurança.

## Arquitetura final

```text
                    FONTES
 Wazuh API ───────────┐
 Wazuh Indexer ───────┤
 NetScope ────────────┤
 osquery ─────────────┤
 SNMP v2c/v3 ─────────┤
 SSH ─────────────────┤
 WinRM ───────────────┤
 Inventory Agent ─────┤
 API batch/manual ────┘
          │
          ▼
     InventorySource
          │
          ▼
      Asset Core
  identity resolution
  state per source
  canonical merge
  provenance/confidence
  temporal entities
  snapshots / changes
          │
  ┌───────┼───────────────┐
  ▼       ▼               ▼
PostgreSQL Dashboard/API  Transactional Outbox
                           │
                     Kafka / Webhooks
                     CTI / NDR / SOAR
```

## Independência do Wazuh

```env
WAZUH_ENABLED=false
NETSCOPE_SOURCE_ENABLED=true
```

Com Wazuh desligado:

1. aplicação inicia;
2. PostgreSQL/Redis funcionam;
3. NetScope descobre ativos;
4. osquery/SNMP/SSH/WinRM/Inventory Agent podem enriquecer ativos;
5. dashboard, busca, detalhes, relatórios e notificações usam Asset Core;
6. Kafka/webhooks recebem eventos do Asset Core.

`HostInventory` permanece apenas para compatibilidade/backfill e espelho opcional:

```env
ASSET_BACKFILL_LEGACY=true
LEGACY_HOST_MIRROR=false
```

## Modelo canônico

### Assets

- `assets`: identidade interna UUID;
- `asset_identifiers`: identificadores observados por fonte;
- `asset_source_states`: estado mais recente de cada fonte;
- `asset_observations`: eventos raw + normalizados;
- `asset_snapshots`: snapshots temporais;
- `asset_changes`: diffs por fonte e canônicos;
- `asset_identity_conflicts`: conflitos que não podem ser resolvidos automaticamente.

### Entidades temporais

- `asset_addresses`;
- `asset_interfaces`;
- `asset_hardware`;
- `asset_software`;
- `asset_processes`;
- `asset_services`;
- `asset_ports`.

Cada entidade mantém:

```text
entity_key
first_seen
last_seen
active
valid_to
source
```

Quando software/porta/processo/interface desaparece, a linha não é apagada: fica `active=false` e recebe `valid_to`.

## Resolução de identidade

Ordem de associação automática:

1. external-id estável da mesma fonte;
2. serial;
3. machine-id;
4. cloud instance id;
5. Wazuh agent id;
6. MAC apenas quando não ambíguo.

Hostname e IP **não** são identidade canônica suficiente.

Quando um identificador forte aponta para múltiplos ativos, o sistema grava `asset_identity_conflicts` em vez de fazer merge silencioso.

## Merge multifuente

Cada fonte mantém seu próprio estado em `asset_source_states`.

O canônico é recomposto a partir de todos os source states, levando em conta:

- confidence;
- origem por campo;
- informações de rede agregadas;
- freshness;
- estado de agente separado do estado de rede.

Campos relevantes:

```text
agent_status
network_status
device_status
inventory_freshness_seconds
confidence
_provenance
```

## Wazuh

### API

TLS validado por padrão:

```env
WAZUH_TLS_VERIFY=true
WAZUH_CA_BUNDLE=/etc/inventory/ca/wazuh-ca.pem
```

Categorias coletadas:

- hardware;
- os;
- packages;
- ports;
- processes;
- netaddr;
- netiface;
- netproto;
- services;
- users;
- groups;
- browser_extensions;
- hotfixes.

### Indexer

`WazuhIndexerSource` usa scroll paginado para consumir `wazuh-states-inventory-*` além da primeira página.

Configuração:

```env
WAZUH_INDEXER_ENABLED=true
WAZUH_INDEXER_URL=https://indexer:9200
WAZUH_INDEXER_PAGE_SIZE=1000
WAZUH_INDEXER_MAX_DOCS=500000
WAZUH_INDEXER_TLS_VERIFY=true
WAZUH_INDEXER_CA_BUNDLE=/path/ca.pem
```

## NetScope

Implementado:

- CIDR IPv4;
- CIDR IPv6;
- prefixo legado `192.168.1`;
- limites por rede;
- chunking;
- múltiplas redes;
- interface por rede;
- active ARP discovery em IPv4;
- ping IPv4/IPv6;
- persistência de hosts sem MAC por identidade IP;
- DNS;
- bounded port scanning;
- perfis quick/standard/full/custom;
- dedup por identificadores fortes.

Exemplo:

```json
{
  "cidr": "10.20.0.0/16",
  "interface": "eth1",
  "gateway": "10.20.0.1"
}
```

Para IPv6 não é usado ARP; descoberta usa ping/NDP do kernel e os hosts alcançáveis são mantidos por IP quando MAC não é observável.

## osquery

O adapter tenta coletar:

- system_info;
- os_version;
- interface_addresses;
- interface_details;
- listening_ports;
- processes;
- users;
- services;
- deb/rpm/homebrew/programs;
- patches;
- Chrome extensions;
- Firefox addons.

Tabelas indisponíveis são registradas como erros parciais sem abortar toda a fonte.

## SNMP

Suporte:

- SNMP v2c;
- SNMP v3 authPriv/authNoPriv;
- sysName/sysDescr/sysLocation;
- IF-MIB;
- MAC de interfaces;
- estado de interfaces;
- VLAN PVID;
- FDB bridge.

Credenciais devem ficar no ambiente/secret store e não no código.

## SSH

Inventário Linux/Unix:

- hostname;
- machine-id;
- interfaces/endereço;
- serial DMI;
- packages;
- processes;
- services;
- users;
- listening ports;
- status de patch/reboot quando disponível.

Host-key checking é estrito por padrão.

## WinRM

Inventário Windows:

- computer system;
- BIOS/serial;
- OS;
- CPU/RAM;
- interfaces;
- registry installed software;
- processes;
- services;
- local users;
- hotfixes;
- TCP listening ports.

## Inventory Agent

`agent/inventory_agent.py` é um collector opcional para endpoints.

Preferência:

1. usa osquery quando instalado;
2. aplica fallback nativo básico;
3. envia HTTPS para `/api/v1/assets/observations`;
4. suporta CA privada;
5. suporta certificado cliente para mTLS;
6. usa token com escopo `ingest`.

Linux systemd unit:

```text
agent/inventory-agent.service
```

## API

Rotas principais:

```text
GET    /api/v1/assets
GET    /api/v1/assets/{uuid}
GET    /api/v1/assets/{uuid}/changes
GET    /api/v1/assets/{uuid}/snapshots
GET    /api/v1/sources

POST   /api/v1/assets/observations
POST   /api/v1/assets/observations/batch
POST   /api/v1/sources/sync

GET    /api/v1/tokens
POST   /api/v1/tokens
DELETE /api/v1/tokens/{id}

GET    /api/v1/outbox
GET    /api/v1/dead-letters
POST   /api/v1/dead-letters/{id}/retry
```

## Autenticação API

Collectors podem usar:

```http
Authorization: Bearer inv_...
```

Tokens são armazenados apenas como SHA-256 e possuem:

- scopes;
- validade;
- revogação;
- last_used_at.

Também é mantido `INVENTORY_INGEST_TOKEN` como compatibilidade.

## CSRF e RBAC

Sessões de navegador usam synchronizer token:

- cookie `inventory_csrf`;
- header `X-CSRF-Token`;
- hidden input em forms;
- Origin/Referer também é validado quando presente.

API máquina-a-máquina usa bearer token e não depende de CSRF.

`login_required` e `admin_required` retornam JSON 401/403 para rotas API.

## Kafka / CTI / NDR / SOAR

O evento não é mais publicado diretamente na transação HTTP.

Fluxo:

```text
Asset transaction
    │
    ├── update asset
    ├── observation
    ├── snapshot/diff
    └── asset_outbox
          │ COMMIT
          ▼
      outbox worker
          │
          ├── Kafka asset.snapshot.v1
          ├── generic webhooks
          ├── CTI_WEBHOOK_URL
          ├── NDR_WEBHOOK_URL
          └── SOAR_WEBHOOK_URL
```

A outbox usa:

- `FOR UPDATE SKIP LOCKED`;
- processing lease;
- retry exponencial;
- máximo de tentativas;
- dead-letter persistente;
- replay administrativo.

## Docker/microservices

Serviços:

- `inventory-web`;
- `inventory-scheduler`;
- `inventory-worker` (outbox);
- `inventory-discovery`;
- PostgreSQL;
- Redis;
- Caddy;
- Kafka opcional;
- Caddy mTLS opcional.

Somente `inventory-discovery` recebe `NET_RAW`.

### Normal

```bash
docker compose up -d --build
```

### Kafka

```bash
docker compose --profile events up -d
```

### mTLS collector endpoint

Coloque CA dos clientes em:

```text
mtls/ca.pem
```

e execute:

```bash
docker compose --profile mtls up -d
```

Endpoint: `https://host:9443/api/v1/assets/observations`.

## Systemd

O instalador cria serviços separados:

- `inventory.service` — Gunicorn;
- `inventory-scheduler.service`;
- `inventory-outbox.service`;
- `inventory-discovery.service`.

Somente discovery recebe `CAP_NET_RAW`.

## Migrations

`db.create_all()` foi removido do boot normal.

Alembic é a autoridade do schema:

```bash
alembic upgrade head
```

A migration `0002_complete_platform` também cria as tabelas legadas quando ausentes para permitir upgrade de instalações pré-Alembic.

## Health/readiness

```text
GET /health
GET /ready
```

Verificam:

- PostgreSQL;
- Redis;
- backlog da outbox;
- versão.

Readiness retorna 503 se PostgreSQL não estiver funcional.

## Testes

CI sobe:

- PostgreSQL 16 real;
- Redis 7 real.

Executa:

1. instalação de dependências;
2. `compileall`;
3. `alembic upgrade head`;
4. segundo `alembic upgrade head` para idempotência;
5. `docker compose config`;
6. pytest.

Casos novos incluem:

- Wazuh completamente ausente;
- identidade multifuente;
- hostname reutilizado;
- software desaparecendo;
- outbox;
- token de collector;
- CSRF/RBAC;
- IPv6 bounded enumeration.

## Compatibilidade

`HostInventory` continua no schema porque:

- instalações existentes já possuem dados;
- existe backfill automático;
- área administrativa legado pode precisar acessar registros antigos.

Ele não é mais a fonte canônica de dashboard/Asset Core e o Wazuh não o alimenta por padrão.

## Matriz requisito original → implementação

| Requisito original | Implementação |
|---|---|
| Wazuh opcional | `WAZUH_ENABLED`, source adapters |
| Asset independente | `Asset`, UUID, source states |
| InventorySource | ABC + 7 sources |
| WazuhAdapter | API + Indexer |
| NetScopeAdapter | sync para Asset Core |
| Dashboard Asset Core | `services/stats.py` |
| Temporal CMDB | observations/snapshots/changes + valid_to |
| Alembic | migrations 0001/0002 |
| TLS Wazuh | verify/CA bundle |
| Senhas padrão | geração instalador |
| Gunicorn/proxy | Docker/systemd + Caddy |
| Docker completo | web/scheduler/outbox/discovery/db/cache |
| CIDR | network_utils + engine |
| IPv6 | parser + ping6/IP identity |
| bounded scanner | port scan profiles/window |
| dedup escalável | indexed strong identifiers |
| Wazuh novas categorias | collector + Indexer |
| osquery | OsquerySource |
| SNMP | v2c/v3 + IF/VLAN/FDB |
| SSH/WinRM | inventário profundo |
| agente próprio | agent/inventory_agent.py |
| histórico real | temporal entity rows |
| agent/network/freshness | campos separados |
| Kafka | transactional outbox |
| CTI/NDR/SOAR | webhook adapters |
| testes | unit + PostgreSQL/Redis integration |
| API segura | hashed scoped tokens + CSRF/RBAC |
