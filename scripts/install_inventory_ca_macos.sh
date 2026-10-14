#!/bin/sh
set -eu

CA_FILE="${1:-}"
if [ -z "$CA_FILE" ] || [ ! -f "$CA_FILE" ]; then
    echo "Uso: $0 /caminho/para/ca.pem" >&2
    exit 2
fi

openssl x509 -in "$CA_FILE" -noout >/dev/null 2>&1 || {
    echo "ERRO: arquivo não é um certificado X.509 PEM válido." >&2
    exit 1
}

echo "[TLS] adicionando Inventory Local CA ao System Keychain..."
sudo security add-trusted-cert -d -r trustRoot     -k /Library/Keychains/System.keychain "$CA_FILE"

echo "[TLS] concluído. Feche completamente e reabra o navegador."
openssl x509 -in "$CA_FILE" -noout -subject -fingerprint -sha256
