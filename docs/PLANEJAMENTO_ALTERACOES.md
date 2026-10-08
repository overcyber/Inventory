# Inventory — Planejamento de alterações para Asset Intelligence multifuente

## Objetivo

Evoluir o Inventory de um painel cujo inventário detalhado depende estruturalmente do Wazuh/SysCollector para uma plataforma de **Asset Intelligence / CMDB técnica multifuente**, preservando compatibilidade com a integração Wazuh existente.

Arquitetura-alvo:

```text
Wazuh ───────────────┐
NetScope ────────────┤
osquery ─────────────┤
SNMP ────────────────┤
SSH/WinRM ───────────┤
API externa ─────────┘
          │
          ▼
   InventorySource
          │
          ▼
      Asset Core
 identity + merge + history
          │
          ├── PostgreSQL
          ├── Dashboard/API
          ├── Kafka asset.snapshot.v1
          └── Webhooks CTI/NDR/SOAR
```

`WAZUH_ENABLED=false` passa a ser um modo suportado, e não apenas uma instalação parcialmente funcional.

## Exceções determinadas

Por decisão explícita do mantenedor, **não fazem parte deste commit**:

1. remoção de `ssl/key.pem` do Git;
2. remoção dos logs já versionados em `logs/`.

Esses arquivos permanecem intocados.

## P0 — Fundação

### Asset Core

Novo modelo canônico:

- `assets`;
- `asset_identifiers`;
- `asset_observations`;
- `asset_snapshots`;
- `asset_changes`;
- `inventory_source_states`.

`HostInventory` permanece como compatibilidade durante a transição.

### Identidade

A identidade deixa de usar hostname como chave conceitual. O resolver usa, em ordem aproximada de confiança:

1. serial;
2. machine-id;
3. cloud instance id;
4. Wazuh agent id;
5. MAC;
6. hostname;
7. external id da fonte.

### InventorySource

Foi introduzida uma interface comum com adaptadores para:

- Wazuh API;
- NetScope;
- osquery;
- SNMP;
- SSH;
- WinRM;
- Wazuh Indexer;
- API genérica de ingestão.

### Wazuh opcional

```env
WAZUH_ENABLED=false
```

Quando desabilitado, o ciclo Wazuh é ignorado sem bloquear NetScope ou outras fontes.

### TLS Wazuh

```env
WAZUH_TLS_VERIFY=true
WAZUH_CA_BUNDLE=/caminho/ca.pem
```

A validação passa a ser o padrão.

### Credenciais

`.env.example` deixa `DB_PASS` e `ADMIN_PASSWORD` vazios. O instalador gera segredos fortes quando necessário e mantém `ADMIN_MUST_CHANGE_PASSWORD=true`.

## P1 — Histórico e operação

Cada observação segue:

```text
source observation
      ↓
identity resolution
      ↓
merge state
      ↓
deep diff
      ├── AssetObservation
      ├── AssetChange
      └── AssetSnapshot
```

O sistema passa a manter histórico de alterações de IP, hostname, software, portas, hardware e demais campos observados.

Estados são separados em:

- `agent_status`;
- `network_status`;
- `device_status`;
- `inventory_freshness_seconds`.

O dashboard passa a preferir Asset Core, com fallback para `HostInventory` enquanto a base nova estiver vazia.

## Alembic

Foi adicionada infraestrutura Alembic com migration inicial do Asset Core. Novas alterações estruturais devem ser versionadas por migrations.

## NetScope

### CIDR

A descoberta passa a aceitar o formato legado e CIDR real:

```text
192.168.1
192.168.1.0/24
10.10.0.0/20
10.20.0.0/16
```

A enumeração é processada em chunks para limitar Futures e RAM.

### ARP

O mecanismo que envia ARP/UDP é documentado e tratado como **active discovery**.

### Port scan

Perfis:

- `quick`;
- `standard`;
- `full`;
- `custom`.

O executor passa a usar uma janela limitada de Futures, evitando a criação de 65.535 tarefas simultâneas.

### Deduplicação

A deduplicação deve usar índices por IP, MAC/prefixo e hostname, reduzindo o comportamento quadrático no caso comum.

## Wazuh

O coletor passa a tentar também:

- `services`;
- `users`;
- `groups`;
- `browser_extensions`;
- `hotfixes`.

Endpoints opcionais não devem derrubar o ciclo completo.

Também foi incluído `WazuhIndexerSource` para leitura em lote dos índices `wazuh-states-inventory-*`.

## Fontes alternativas

### osquery

`OSQUERY_ENABLED=true` ativa consultas locais via `osqueryi --json`.

### SNMP

`SNMP_ENABLED=true` usa `snmpget` para equipamentos de rede.

### SSH

`SSH_SOURCE_ENABLED=true` usa Paramiko para inventário básico Unix/Linux.

### WinRM

`WINRM_SOURCE_ENABLED=true` usa pywinrm + PowerShell/CIM para Windows.

## API Asset Core

```text
GET  /api/v1/assets
GET  /api/v1/assets/<asset_uuid>
GET  /api/v1/sources
POST /api/v1/assets/observations
POST /api/v1/sources/sync
```

A ingestão máquina-a-máquina pode usar `X-Inventory-Token`.

## Kafka e integrações

Contrato externo:

```text
asset.snapshot.v1
```

Kafka é ativado por `KAFKA_BOOTSTRAP_SERVERS`.

Webhooks em `ASSET_WEBHOOK_URLS` permitem integração com CTI, NDR, SIEM, SOAR e pipelines próprios.

## Docker / microserviços

A implantação passa a contemplar:

- `inventory-web` — Flask/Gunicorn sem `NET_RAW`;
- `inventory-worker` — sincronização multifuente;
- `inventory-discovery` — NetScope, com `NET_RAW`;
- PostgreSQL;
- Redis;
- Caddy;
- Kafka opcional pelo profile `events`.

A separação reduz privilégios da interface web.

## Servidor de produção

O container usa Gunicorn e Caddy. `app.run()` permanece apenas como caminho de desenvolvimento/compatibilidade.

## Testes e CI

A suíte cobre:

- normalização Wazuh;
- normalização NetScope;
- diff;
- CIDR;
- perfis de port scan;
- TLS do Wazuh;
- modo standalone.

O workflow executa `compileall` e `pytest`.

## Sequência de migração

1. atualizar código;
2. revisar `.env`;
3. definir/gerar segredos;
4. executar migration;
5. iniciar aplicação;
6. sincronizar Wazuh/NetScope;
7. validar `assets`;
8. validar dashboard;
9. opcionalmente ativar osquery/SNMP/SSH/WinRM;
10. opcionalmente ativar Kafka/webhooks;
11. desabilitar Wazuh apenas depois, se desejado.

## Critérios de aceite

- app inicia com `WAZUH_ENABLED=false`;
- NetScope continua operacional;
- ativos NetScope entram no Asset Core sem Wazuh;
- Wazuh continua preenchendo legado + Asset Core;
- observações idênticas são deduplicadas por hash;
- mudanças geram histórico;
- TLS Wazuh é validado por padrão;
- não há senhas fixas como defaults;
- port scan é bounded;
- CIDR real é aceito;
- web não requer `NET_RAW`;
- eventos podem sair por Kafka/webhook.

## Resultado

Antes:

```text
Wazuh -> Inventory -> NetScope
```

Depois:

```text
Wazuh -----\
NetScope ----\
osquery ------- > Asset Core -> PostgreSQL/API/Dashboard/Kafka/Webhooks
SNMP ---------/
SSH/WinRM ---/
```

O Wazuh continua sendo uma fonte importante de inventário profundo, mas deixa de ser dependência estrutural.


## Atualização de execução — v0.20

O plano acima foi implementado na v0.20. A rastreabilidade final, componentes e critérios de validação estão documentados em [IMPLEMENTACAO_COMPLETA_020.md](IMPLEMENTACAO_COMPLETA_020.md). As duas exceções explícitas continuam válidas: `ssl/key.pem` e logs versionados não foram removidos.
