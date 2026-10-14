#!/bin/sh
set -eu

SSL_DIR="${SSL_DIR:-/app/ssl}"
CERT_FILE="${SSL_DIR}/cert.pem"
KEY_FILE="${SSL_DIR}/key.pem"
CA_CERT_FILE="${SSL_DIR}/ca.pem"
CA_KEY_FILE="${SSL_DIR}/ca-key.pem"

TLS_HOST="${INVENTORY_TLS_HOST:-localhost}"
TLS_ALT_NAMES="${INVENTORY_TLS_ALT_NAMES:-}"
CERT_DAYS="${TLS_CERT_DAYS:-365}"
CA_DAYS="${TLS_CA_DAYS:-3650}"
RENEW_BEFORE_DAYS="${TLS_RENEW_BEFORE_DAYS:-30}"
RENEW_BEFORE_SECONDS="$((RENEW_BEFORE_DAYS * 86400))"

umask 077
mkdir -p "$SSL_DIR"

timestamp() {
    date -u +%Y%m%dT%H%M%SZ
}

backup_if_exists() {
    path="$1"
    reason="$2"
    if [ -e "$path" ]; then
        backup="${path}.${reason}.$(timestamp)"
        cp -p "$path" "$backup"
        echo "[TLS] backup preservado: $backup"
    fi
}

pubkey_hash_from_key() {
    openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
}

pubkey_hash_from_cert() {
    openssl x509 -in "$1" -pubkey -noout 2>/dev/null |
        openssl pkey -pubin -outform DER 2>/dev/null |
        sha256sum | awk '{print $1}'
}

is_ip_literal() {
    value="$1"
    case "$value" in
        *:*) return 0 ;;
        *[!0-9.]*) return 1 ;;
        *.*.*.*) return 0 ;;
        *) return 1 ;;
    esac
}

cert_has_name() {
    cert="$1"
    name="$2"
    san="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null || true)"
    if is_ip_literal "$name"; then
        printf '%s\n' "$san" | grep -Fq "IP Address:$name"
    else
        printf '%s\n' "$san" | grep -Fq "DNS:$name"
    fi
}

key_matches_cert() {
    [ -s "$1" ] && [ -s "$2" ] || return 1
    key_hash="$(pubkey_hash_from_key "$1" || true)"
    cert_hash="$(pubkey_hash_from_cert "$2" || true)"
    [ -n "$key_hash" ] && [ "$key_hash" = "$cert_hash" ]
}

ca_is_valid() {
    [ -s "$CA_CERT_FILE" ] && [ -s "$CA_KEY_FILE" ] || return 1
    openssl x509 -in "$CA_CERT_FILE" -noout >/dev/null 2>&1 || return 1
    openssl pkey -in "$CA_KEY_FILE" -noout >/dev/null 2>&1 || return 1
    key_matches_cert "$CA_KEY_FILE" "$CA_CERT_FILE" || return 1
    openssl x509 -checkend "$RENEW_BEFORE_SECONDS" -noout         -in "$CA_CERT_FILE" >/dev/null 2>&1 || return 1
    return 0
}

server_cert_is_valid() {
    [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ] || return 1
    openssl x509 -in "$CERT_FILE" -noout >/dev/null 2>&1 || return 1
    openssl pkey -in "$KEY_FILE" -noout >/dev/null 2>&1 || return 1
    key_matches_cert "$KEY_FILE" "$CERT_FILE" || return 1
    openssl x509 -checkend "$RENEW_BEFORE_SECONDS" -noout         -in "$CERT_FILE" >/dev/null 2>&1 || return 1
    cert_has_name "$CERT_FILE" "$TLS_HOST" || return 1
    cert_has_name "$CERT_FILE" "localhost" || return 1
    cert_has_name "$CERT_FILE" "127.0.0.1" || return 1
    openssl verify -CAfile "$CA_CERT_FILE" "$CERT_FILE" >/dev/null 2>&1 || return 1

    old_ifs="$IFS"
    IFS=','
    for extra in $TLS_ALT_NAMES; do
        extra="$(printf '%s' "$extra" | xargs)"
        [ -z "$extra" ] && continue
        cert_has_name "$CERT_FILE" "$extra" || {
            IFS="$old_ifs"
            return 1
        }
    done
    IFS="$old_ifs"
    return 0
}

generate_ca() {
    tmpdir="$1"
    echo "[TLS] gerando CA local do Inventory..."
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes         -days "$CA_DAYS"         -subj "/CN=Inventory Local CA"         -addext "basicConstraints=critical,CA:TRUE"         -addext "keyUsage=critical,keyCertSign,cRLSign"         -keyout "$tmpdir/ca-key.pem"         -out "$tmpdir/ca.pem" >/dev/null 2>&1

    openssl x509 -in "$tmpdir/ca.pem" -noout >/dev/null
    openssl pkey -in "$tmpdir/ca-key.pem" -noout >/dev/null

    backup_if_exists "$CA_CERT_FILE" invalid
    backup_if_exists "$CA_KEY_FILE" invalid

    install -m 0600 "$tmpdir/ca-key.pem" "$CA_KEY_FILE"
    install -m 0644 "$tmpdir/ca.pem" "$CA_CERT_FILE"
}

build_san_config() {
    outfile="$1"
    {
        echo "[server_ext]"
        echo "basicConstraints=critical,CA:FALSE"
        echo "keyUsage=critical,digitalSignature,keyEncipherment"
        echo "extendedKeyUsage=serverAuth"
        echo "subjectAltName=@alt_names"
        echo
        echo "[alt_names]"
    } > "$outfile"

    names_file="$outfile.names"
    {
        echo "$TLS_HOST"
        echo "localhost"
        echo "127.0.0.1"
        old_ifs="$IFS"
        IFS=','
        for extra in $TLS_ALT_NAMES; do
            extra="$(printf '%s' "$extra" | xargs)"
            [ -n "$extra" ] && echo "$extra"
        done
        IFS="$old_ifs"
    } | awk 'NF && !seen[$0]++' > "$names_file"

    dns_i=0
    ip_i=0
    while IFS= read -r name; do
        if is_ip_literal "$name"; then
            ip_i=$((ip_i + 1))
            echo "IP.$ip_i=$name" >> "$outfile"
        else
            dns_i=$((dns_i + 1))
            echo "DNS.$dns_i=$name" >> "$outfile"
        fi
    done < "$names_file"
    rm -f "$names_file"
}

generate_server_cert() {
    tmpdir="$1"
    extfile="$tmpdir/server-ext.cnf"
    build_san_config "$extfile"

    key_reused=0
    if [ -s "$KEY_FILE" ] && openssl pkey -in "$KEY_FILE" -noout >/dev/null 2>&1; then
        cp "$KEY_FILE" "$tmpdir/key.pem"
        chmod 0600 "$tmpdir/key.pem"
        key_reused=1
        echo "[TLS] reutilizando ssl/key.pem existente."
    else
        echo "[TLS] chave privada ausente/inválida; gerando nova chave."
        openssl genpkey -algorithm RSA             -pkeyopt rsa_keygen_bits:3072             -out "$tmpdir/key.pem" >/dev/null 2>&1
    fi

    echo "[TLS] emitindo certificado para $TLS_HOST..."
    openssl req -new -sha256         -subj "/CN=$TLS_HOST"         -key "$tmpdir/key.pem"         -out "$tmpdir/server.csr" >/dev/null 2>&1

    serial="0x$(openssl rand -hex 16)"
    openssl x509 -req         -in "$tmpdir/server.csr"         -CA "$CA_CERT_FILE"         -CAkey "$CA_KEY_FILE"         -set_serial "$serial"         -days "$CERT_DAYS"         -sha256         -extfile "$extfile"         -extensions server_ext         -out "$tmpdir/cert.pem" >/dev/null 2>&1

    openssl verify -CAfile "$CA_CERT_FILE" "$tmpdir/cert.pem" >/dev/null
    key_matches_cert "$tmpdir/key.pem" "$tmpdir/cert.pem"
    cert_has_name "$tmpdir/cert.pem" "$TLS_HOST"
    cert_has_name "$tmpdir/cert.pem" "localhost"
    cert_has_name "$tmpdir/cert.pem" "127.0.0.1"

    backup_if_exists "$CERT_FILE" invalid
    install -m 0644 "$tmpdir/cert.pem" "$CERT_FILE"

    if [ "$key_reused" -eq 1 ]; then
        chmod 0600 "$KEY_FILE"
    else
        backup_if_exists "$KEY_FILE" invalid
        install -m 0600 "$tmpdir/key.pem" "$KEY_FILE"
    fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

ca_recreated=0
if ca_is_valid; then
    echo "[TLS] CA local válida."
else
    generate_ca "$tmpdir"
    ca_recreated=1
fi

if [ "$ca_recreated" -eq 0 ] && server_cert_is_valid; then
    echo "[TLS] certificado válido para $TLS_HOST; nenhuma alteração necessária."
else
    generate_server_cert "$tmpdir"
fi

if ! server_cert_is_valid; then
    echo "[TLS] ERRO: certificado final falhou na validação." >&2
    exit 1
fi

echo "[TLS] certificado pronto:"
openssl x509 -in "$CERT_FILE" -noout -subject -issuer -dates -ext subjectAltName
echo "[TLS] CA para confiar nos clientes: $CA_CERT_FILE"
