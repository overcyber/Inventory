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
openssl x509 -in "$CA_FILE" -text -noout | grep -q "CA:TRUE" || {
    echo "ERRO: certificado informado não é uma CA." >&2
    exit 1
}

run_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "ERRO: privilégios administrativos necessários." >&2
        exit 1
    fi
}

echo "[TLS] instalando Inventory Local CA no trust store do sistema..."
run_root install -m 0644 "$CA_FILE" /usr/local/share/ca-certificates/inventory-local-ca.crt

if command -v update-ca-certificates >/dev/null 2>&1; then
    run_root update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1; then
    run_root update-ca-trust
else
    echo "ERRO: update-ca-certificates/update-ca-trust não encontrado." >&2
    exit 1
fi

# Chromium/Chrome em algumas distribuições Linux também consultam o NSS DB
# do usuário. Quando certutil estiver disponível, registramos a mesma CA ali.
if command -v certutil >/dev/null 2>&1; then
    NSS_DIR="$HOME/.pki/nssdb"
    mkdir -p "$NSS_DIR"
    if [ ! -f "$NSS_DIR/cert9.db" ]; then
        certutil -N --empty-password -d "sql:$NSS_DIR" >/dev/null 2>&1 || true
    fi
    certutil -D -d "sql:$NSS_DIR" -n "Inventory Local CA" >/dev/null 2>&1 || true
    certutil -A -d "sql:$NSS_DIR" -n "Inventory Local CA" -t "C,," -i "$CA_FILE"
    echo "[TLS] CA adicionada também ao NSS DB do usuário."
fi

echo "[TLS] concluído. Feche completamente e reabra o navegador."
openssl x509 -in "$CA_FILE" -noout -subject -fingerprint -sha256
