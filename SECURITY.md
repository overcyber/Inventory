# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.19.x | ✅ |
| 0.18.x | Security fixes only |
| < 0.18 | ❌ |

## Deployment requirements

- Wazuh TLS certificate validation is enabled by default. Use `WAZUH_CA_BUNDLE` for private CAs.
- Do not configure fixed/default database or administrator passwords. The installer generates secrets when values are absent.
- Keep `INVENTORY_INGEST_TOKEN`, Wazuh credentials, SSH/WinRM credentials and webhook tokens outside source code.
- In the microservice deployment, only `inventory-discovery` requires raw-network capability; `inventory-web` must run without `NET_RAW`.
- Prefer Caddy/reverse-proxy TLS + Gunicorn for production.

## Reporting a vulnerability

Report security issues privately to the repository maintainer. Include affected version, reproduction conditions, impact and any proposed mitigation. Do not include production credentials or sensitive inventory exports in public issues.
