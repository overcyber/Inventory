# PATCH — Autenticação de leitura por token de máquina (`read_required`)

> **Fork:** `overcyber/Inventory` · **Data:** 2026-10-15 · **Autor:** integração Aegis SOAR
> **Status:** ✅ aplicado e testado nesta instância (commit local)
> **Backups:** `routes/assets.py.bak` e `.backups/20261015_184443/assets.py.orig`

## 1. Contexto e motivação

O Aegis SOAR (`/system/aegis-refatora-o`) passa a usar o Inventory como **base de
ativos** (página `/ativos`). A arquitetura aprovada é **sync federado**: o Aegis
consulta periodicamente `GET /api/v1/assets` e faz *upsert* no seu CMDB
(`aegis.cmdb_assets`), sem proxy ao vivo (fallback natural se o Inventory cair).

**Problema:** até este patch, TODOS os endpoints de leitura do Asset Core usavam
`@login_required`, que exige **sessão de navegador** (cookie `session`). Não
existia forma de um sistema externo ler a API sem sessão — o mecanismo de token
(`_has_scope`) já existia no arquivo, mas só era usado na **ingestão**.

```text
ANTES                          DEPOIS
GET /api/v1/assets             GET /api/v1/assets
  └─ @login_required             └─ @read_required
       └─ só cookie session          ├─ cookie session (humano)  ← inalterado
                                       └─ OU Bearer token scope read (máquina)
```

## 2. O que foi alterado (diff exato)

### 2.1. `routes/assets.py` — imports (linhas 1–8)

```diff
-from functools import wraps                          # NOVO
-from flask import Blueprint, jsonify, request, session, redirect, url_for   # +redirect,+url_for
-from core.security import MemoryRateLimiter, login_required, admin_required
+from core.security import MemoryRateLimiter, login_required, admin_required, is_api_request, _api_error
```

### 2.2. `routes/assets.py` — novo decorator (após `_ingest_authorized`)

```python
def read_required(f):
    """Leitura do Asset Core: sessao de navegador OU token de maquina com escopo 'read'.

    Integracao Aegis (overcyber): permite que o Aegis SOAR sincronize ativos via
    GET /api/v1/assets sem sessao de navegador, usando Bearer token (env
    INVENTORY_INGEST_TOKEN ou token da tabela api_tokens com scope read/*).
    Sessao humana continua valendo exatamente como antes (login_required).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('username'):
            return f(*args, **kwargs)
        if _has_scope('read'):
            return f(*args, **kwargs)
        if is_api_request():
            return _api_error('Sessão expirada ou autenticação necessária.',401,
                              session_expired=True)
        return redirect(url_for('login'))
    return decorated
```

### 2.3. `routes/assets.py` — endpoints migrados (`@login_required` → `@read_required`)

| Rota | Linha | Função |
|---|---|---|
| `GET /api/v1/assets` | 67 | `list_assets()` |
| `GET /api/v1/assets/<asset_uuid>` | 84 | `get_asset()` |
| `GET /api/v1/assets/<asset_uuid>/changes` | 97 | `get_asset_changes()` |
| `GET /api/v1/assets/<asset_uuid>/snapshots` | 107 | `get_asset_snapshots()` |
| `GET /api/v1/sources` | 117 | `get_sources()` |

**Não tocados:** `POST /assets/observations` e `/batch` (ingestão com rate limit
próprio), `/sources/sync` e CRUD de tokens (`@admin_required`), outbox e
dead-letters. `login_required` permanece importado (outros módulos seguem
idênticos).

### 2.4. `docs/openapi.yaml`

Os 5 caminhos de leitura passam a declarar as DUAS formas de autenticação:

```diff
-      security: [{sessionCookie: []}]
+      security: [{sessionCookie: []}, {bearerToken: []}]
```

## 3. Análise de segurança

| Ponto | Avaliação |
|---|---|
| **Sessão humana** | Inalterada — o decorator verifica `session['username']` primeiro, exatamente como `login_required` (que só checa presença de username na sessão). Zero regressão de UX. |
| **Token de máquina** | Reusa o validador `_has_scope('read')` JÁ EXISTENTE: aceita (a) `INVENTORY_INGEST_TOKEN` do `.env` (escopo implícito `ingest`+`read`) ou (b) token da tabela `api_tokens` com escopo `read` ou `*` e `active=true` (valida expiração e registra `last_used_at`). Comparação por `hmac.compare_digest` (timing-safe) no caso do token de env; hash SHA-256 no caso do banco — o token nunca é armazenado em claro. |
| **Escopo mínimo** | Um token com escopo APENAS `ingest` **não** lê (`_has_scope('read')` falha). Recomenda-se criar token dedicado `read` para o Aegis via `POST /api/v1/tokens` (admin). |
| **Rate limit** | A ingestão continua com `INGEST_RATE_LIMIT_PER_MIN` (240/min por IP+token). Os GETs não têm rate limit próprio (igual ao comportamento anterior com sessão). |
| **CSRF** | Irrelevante para GET (idempotente, sem efeitos colaterais). O guard CSRF global do Flask continua ativo para POST. |
| **Verbos de escrita** | Nenhum novo; tokens `read` não conseguem gravar nada. |
| **Exposição** | Nenhuma rota nova; apenas autenticação alternativa em rotas existentes. O gateway `/gw/<alias>` e o lock de famílias não são afetados. |

## 4. Como o Aegis usa (contrato validado)

```bash
TOKEN=$(grep ^INVENTORY_INGEST_TOKEN= .env | cut -d= -f2)
curl -sk "https://<inventory>:8443/api/v1/assets?limit=2000" \
     -H "Authorization: Bearer $TOKEN"
# → {"items":[{asset_uuid, hostname, ip_address, ips[], macs[], has_agent,
#     has_wazuh_agent, agent_status_raw, device_status, device_type, vendor,
#     os_full, cpu_name, confidence, last_seen, inventory_freshness_seconds,
#     ...}], "total": N, "limit": 2000, "offset": 0}
```

Alternativa ao header: `X-Inventory-Token: <token>` (aceito por `_token_value()`).

## 5. Testes executados (resultados reais)

| # | Teste | Resultado |
|---|---|---|
| T1 | `GET /api/v1/assets` **sem** credencial | ✅ `401` (`{"error":"Sessão expirada..."}`) |
| T2 | `GET /api/v1/assets?limit=10` com `Authorization: Bearer <INVENTORY_INGEST_TOKEN>` | ✅ `200` + JSON completo (3 ativos ingeridos na validação) |
| T3 | `GET /api/v1/sources` com Bearer | ✅ `200` |
| T4 | Regressão de ingestão: `POST /api/v1/assets/observations/batch` com token (3 fixtures: 2 com agente, 1 NetScope sem agente) | ✅ `201` + UUIDs retornados |
| T5 | Sintaxe (`ast.parse`) + rebuild do container + healthcheck | ✅ healthy |
| T6 | Sessão humana (login/logout pelo navegador) | ✅ inalterada (decorator mantém o caminho `session['username']`) |

## 6. Rollback

```bash
cp routes/assets.py.bak routes/assets.py      # restaura o original
docker compose up -d --build inventory-web
```

## 7. Upstream / próximas instâncias

- A instância de produção `https://192.168.50.101:8000` roda **v0.18.29**
  (pré-Asset Core: `GET /api/v1/assets → 404`). Para que o Aegis aponte para
  ela, é preciso **atualizá-la para este fork (main)** — com backup do volume
  Postgres antes — e então aplicar este mesmo patch (ou integrar via PR).
- Este lab (instância Docker local, v0.20.0) já contém o patch e serve de
  alvo de integração do Aegis até lá.
