# Diagnóstico de disponibilidade NetScope

O sistema não presume que toda máquina que ignora ICMP esteja offline.
O estado `online` exige evidência positiva: resposta ICMP, ARP local ativo,
TCP com conexão concluída ou status ativo de agente Wazuh.

O estado `unverified` indica que o coletor não conseguiu comprovar a
disponibilidade. Não é uma afirmação de desligamento.

## Redes e containers

- `inventory-web` usa bridge, e **não executa varredura ARP**.
- O botão **Scan** e o comando **Sincronizar Agora** enfileiram scans via Redis.
- `inventory-discovery` recebe o trabalho e executa em rede host.
- Para ARP, a interface é determinada via `ip -j -4 route get`. Um alvo
  roteado não possui MAC recuperável via ARP local; use switches SNMP,
  LLDP/CDP ou agente no segmento remoto.

## Verificação do coletor

```bash
docker exec inventory_discovery ip -j -4 route get 192.168.10.14
docker exec inventory_discovery ping -c 2 -W 1 192.168.10.14
docker exec inventory_discovery python -c "from services.netscope_reachability import probe_tcp; print('porta TCP:', probe_tcp('192.168.10.14'))"
docker logs --tail=100 inventory_discovery
```

Substitua o IP por um host que você tenha comprovado estar ativo. Uma conexão
TCP bem-sucedida retorna a porta aberta; `None` significa resultado
inconclusivo, não que o host está desligado.

## Portas TCP

Por padrão, são testadas as portas 22, 80, 443, 445, 3389, 5985, 8080,
8443 e 53. Personalize no arquivo `.env`:

```dotenv
NETSCOPE_TCP_LIVENESS_PORTS=22,80,443,445,3389,5985,8080,8443,53
NETSCOPE_TCP_LIVENESS_TIMEOUT=0.4
```

A sondagem é limitada aos IPs **já cadastrados** e que não foram confirmados
por ICMP/ARP. Não é uma varredura TCP completa dos 65 mil endereços.

## Conferir resultado do último scan

Na interface, clique em **Scan**. O retorno agora distingue
`ping_found`, `tcp_found`, `tcp_probed`, `arp_found` e `warnings`.

Para consultar estados persistidos:

```bash
docker exec inventory_postgres psql -U inventorydb -d inventory_db -c \
"SELECT data->>'status' AS status, COUNT(*) FROM netscope_devices WHERE NOT deleted GROUP BY 1"
```

Não edite manualmente o estado de dispositivos para `online` sem evidência
de disponibilidade. Não delete volumes ou dados do PostgreSQL para forçar
redescoberta.
