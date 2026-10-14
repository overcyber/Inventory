# TLS local do Inventory

O Inventory usa uma CA privada local para permitir HTTPS em endereços de rede
interna, como `192.168.1.100`.

## Arquivos

- `ssl/ca.pem`: certificado público da CA. É o arquivo que deve ser instalado
  como confiável nos computadores clientes.
- `ssl/ca-key.pem`: chave privada da CA. Nunca deve sair do servidor.
- `ssl/cert.pem`: certificado TLS do servidor.
- `ssl/key.pem`: chave privada TLS do servidor.

O serviço `cert-init` valida e repara automaticamente o certificado antes do
Caddy iniciar. Ele verifica validade, SAN, correspondência da chave e cadeia.

## Verificação

```bash
openssl verify -CAfile ssl/ca.pem ssl/cert.pem
openssl x509 -in ssl/cert.pem -noout -checkip 192.168.1.100
openssl x509 -in ssl/cert.pem -noout -subject -issuer -dates -ext subjectAltName
```

## Linux

Copie apenas `ssl/ca.pem` para a estação cliente e execute:

```bash
./scripts/install_inventory_ca_linux.sh ./ca.pem
```

## Windows

Copie apenas `ssl/ca.pem` para a estação cliente:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_inventory_ca_windows.ps1 -CaFile .\ca.pem
```

Por padrão a CA é instalada em `CurrentUser\Root`. Para toda a máquina,
abra PowerShell como Administrador e use `-Scope LocalMachine`.

## macOS

```bash
./scripts/install_inventory_ca_macos.sh ./ca.pem
```

Depois da instalação, encerre completamente e reabra o navegador.

Nunca copie `ca-key.pem` ou `key.pem` para as estações clientes.
