# Revisão de implementação Inventory v0.19 — auditoria corretiva

Data: 2026-10-08. Base auditada: commit `3ff67168d752d29c497dafd577802ffb945cd0a5`.

## Escopo e regra de preservação

A análise compara o planejamento original de independência do Wazuh com o código realmente versionado. A instrução explícita de preservar `ssl/key.pem` e os logs já presentes no Git **continua vigente**: nenhum arquivo dessas duas áreas foi modificado.

## Veredito

A implementação anterior tinha funcionalidades parcialmente conectadas que foram indevidamente declaradas concluídas. A existência de um adaptador, modelo, endpoint ou Docker service não é evidência suficiente de operação de produção.

## Matriz de rastreabilidade

| Requisito | Estado após revisão | Evidência / lacuna |
|---|---|---|
| P0 TLS Wazuh | Implementado parcialmente | `requests.Session.verify` segue opção de CA; ausência de teste de certificado real e rotação |
| P0 Senhas padrão | Parcial | instalador gera DB/admin; instalação Docker manual continua exigindo configuração, não automatiza segredos |
| P0 Asset Core | Parcial | tabelas, identidade UUID e ingestão existem; identidade/conflitos ainda precisam de testes de integração |
| P0 Interface InventorySource | Parcial | ABC e adaptadores disponíveis, falta contrato formal de paginação/cancelamento/retries |
| P1 WazuhAdapter | Parcial | Wazuh API integrada; fluxo legado ainda convive com o núcleo |
| P1 NetScopeAdapter | Parcial | ingestão para Asset Core; ponte legado/Wazuh persiste |
| P1 Dashboard Asset Core | Parcial | `services/stats.py` prefere Asset; buscas, relatórios e notificações não migrados integralmente |
| P1 snapshots/diff | Parcial | modelos e deep_diff; ainda sem políticas de retenção/consistência por fonte |
| P1 Alembic | Parcial | baseline inicial corrigido para tolerar tabelas criadas pelo bootstrap; falta remover `create_all` e backfill controlado |
| P1 Testes | Incompleto | 4 módulos de testes unitários; falta PostgreSQL real, concorrência, rollback, migrations, MFA/CSRF/RBAC |
| P1 osquery | Parcial | consulta local `osqueryi` de um host; não existe `osqueryd` distribuído nem agente próprio |
| P2 SNMP/SSH/WinRM | Parcial | adaptadores básicos; SNMP usa v2c, sem coleta completa de interfaces/VLANs/switchport e sem SNMPv3 |
| P2 Kafka | Parcial | produtor síncrono `asset.snapshot.v1`; sem outbox, DLQ, retry persistente ou consumer |
| P2 Docker | Parcial | web/worker/discovery/cache/db/caddy/kafka; sem isolamento robusto de credenciais, migração coordenada e teste de compose |
| P2 CTI/NDR/SOAR | Parcial | webhook genérico, não contratos nativos nem adaptadores de integração |
| CIDR/IPv6 | Parcial | CIDR IPv4 implementado; IPv6 e multi-interface/VLAN não operacionais ponta a ponta |
| Deduplicação | Parcial | índices NetScope substituíram comparação de pares, mas regras de conflito e MAC compartilhado exigem validação |
| Port scanning bounded | Parcial | janela limitada de Futures TCP/UDP; falta cancelamento e teste de consumo real |

## Correções efetivamente realizadas nesta revisão

1. **Idempotência temporal:** observação cujo conteúdo normalizado não mudou atualiza `last_seen` e `last_observed_at` do ativo, além dos identificadores da fonte.
2. **Identity safety:** não resolver identidades por hostname apenas, porque hostnames podem ser reutilizados; `external_id` da mesma fonte tem prioridade de lookup.
3. **Alembic baseline:** criação de tabelas e índices no baseline agora usa introspecção para não tentar recriar objetos existentes pelo bootstrap legado. Isso é uma correção de compatibilidade, **não substitui** a migração formal do legado.
4. **Docker web:** certificado TLS disponibilizado em volume de leitura para comportamento compatível com a configuração preexistente.

## Falhas arquiteturais abertas (priorizadas)

### P0 — segurança/consistência

- Remover `db.create_all()` do caminho normal após migração controlada e versionar schema legado no Alembic. Sem isso, há desvio potencial entre metadata SQLAlchemy e versionamento DDL.
- Implantar testes integrados com PostgreSQL, Redis, migrações de base vazia e base legada e inicialização de todos os containers.
- Formalizar resolução de identidade com conflito explícito, aliases, evidências por atributo, escopo de MAC/IP por rede e regra de merge/split reversível.
- Endurecer API de ingestão: escopo e rotação de tokens, rate limiting, auditoria de credenciais, validação de payloads, limites por coleção; testar CSRF/RBAC.
- Persistência de eventos via outbox transacional; publicação após commit em job separado, com idempotência e DLQ.

### P1 — domínio funcional

- Migrar buscas, relatórios, notificações e todos os consumidores de `HostInventory` para Asset Core, com testes de equivalência.
- Substituir ponte Wazuh → NetScope por correlação de identidades usando Asset Core sem dependência do legado.
- Normalizar fatos temporais em `first_seen`, `last_seen`, `observed_at`, `valid_from`/`valid_to` e por fonte, preservando histórico quando software/porta desaparece.
- Implementar reconciliação de observações atrasadas, concorrência multi-worker e resolução de conflitos com precedência/recência por atributo.
- Indexer Wazuh: paginação completa `search_after`/PIT ou scroll apropriado, validação da estrutura dos índices e testes em Wazuh suportado.
- Implementar osquery distribuído, import batch, agente próprio opcional (Windows/Linux/macOS) com HTTPS/mTLS, enrollment e rotação.
- Discovery IPv6 (NDP/ping6/DNS AAAA), interfaces selecionáveis, CIDR por VLAN, prevenção de varredura fora da rede autorizada.

### P2 — robustez/operacionalização

- SNMPv3, SSH bastion/keys, WinRM HTTPS/Kerberos, políticas de segredos externos.
- Scheduler singleton distribuído/queue, workers separados por tipo e graceful shutdown.
- Compose testado, healthchecks dependentes, usuário não-root em todos os componentes quando viável, limites de CPU/RAM e volumes.
- Métricas Prometheus/OpenTelemetry, retentores/compaction de observações, snapshots periódicos, índices e benchmarks de 10k/100k ativos.
- API schema OpenAPI v1, export CSV/JSON por ativo e contratos CTI/NDR/SOAR específicos.

## Critérios para declarar conclusão real

- Instalação vazia e upgrade de base legado completos em PostgreSQL sem intervenção manual indevida.
- Integração ponta a ponta com Wazuh desligado: descoberta → Asset Core → dashboard → busca → relatório → notificação.
- Duas fontes com identidade conflitante não geram fusão indevida; atributos têm proveniência e regras de freshness verificadas.
- 10k ativos sem explosão de memória/latência, import incremental e diffs corretos.
- Testes de segurança de API (autenticação, MFA, RBAC, CSRF, TLS, limites).
- Publicação Kafka reconcilia eventos com committed state sem perda e suporta repetição.
- CI + teste Docker Compose + teste PostgreSQL reais aprovados.

## Observação sobre segurança

Por ordem do mantenedor, `ssl/key.pem` e logs permaneceram versionados. Isso mantém o risco de exposição de material sensível. Preservação solicitada **não equivale a avaliação de segurança positiva**.
