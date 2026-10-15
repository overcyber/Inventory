# NetScope — Topologia Básica e Avançada

O NetScope mantém dois modos independentes do AEGIS. Nenhum evento do AEGIS
é consumido e Kafka não é requisito para descoberta ou inferência.

## Modo Básico

Funciona sem switch gerenciável.

Fontes:

- ICMP, ARP e TCP da descoberta ativa;
- observação passiva local via Linux AF_PACKET no `inventory-discovery`;
- cabeçalhos Ethernet (MAC de origem/destino), IPv4/IPv6 e VLAN 802.1Q;
- DHCPACK observado passivamente para identidade IP ↔ MAC;
- agregados locais de fluxos IP/protocolo/porta;
- gateway configurado de cada rede.

O coletor passivo é limitado e não grava pacotes. Mantém agregados em memória,
com limites, e persiste somente metadados compactos em PostgreSQL.

### Inferências básicas

- próximo salto Ethernet observado;
- centralizador de comunicações;
- candidato a equipamento de trânsito;
- serviço DNS/DHCP compartilhado;
- associação lógica a gateway;
- identidade IP/MAC com validade e origem da evidência.

Centralidade de comunicação não é tratada como prova de cabeamento físico.

## Modo Avançado

Inclui tudo do modo Básico e acrescenta evidências SNMP:

- LLDP;
- CDP;
- BRIDGE-MIB FDB;
- Q-BRIDGE-MIB FDB/VLAN;
- IF-MIB e mapeamento bridge-port → ifIndex.

A FDB **não escreve diretamente** em `switch_port`. Cada observação vai para
`netscope_topology_evidence`. Uma MAC em FDB pode estar atrás de uplink, AP,
telefone IP ou outro bridge.

Uma FDB é promovida a `fdb-access-candidate` somente quando:

1. existe apenas uma MAC aprendida na porta na janela;
2. a porta não foi identificada como vizinhança LLDP/CDP;
3. a MAC pertence a um dispositivo conhecido no NetScope.

Mesmo nesse caso a confiança é inferior a LLDP/CDP.

## Prioridade do Inferir

1. vínculo manual;
2. LLDP/CDP compatível com hierarquia de equipamento (Avançado);
3. porta explicitamente configurada pelo operador;
4. candidato FDB de porta de acesso (Avançado);
5. próximo salto Ethernet observado (Básico/Avançado);
6. gateway L3 configurado.

Conflitos no mesmo nível não são resolvidos arbitrariamente.

## Captura passiva

O container `inventory-discovery` já utiliza `network_mode: host` e
`CAP_NET_RAW`.

A interface pode ser definida em `.env`:

```dotenv
NETSCOPE_PASSIVE_INTERFACE=enp3s0
```

ou deixada vazia para usar a interface da rota padrão.

O modo promíscuo fica desabilitado por padrão. Pode ser habilitado no objeto
`topology` da configuração quando a interface estiver conectada a TAP/SPAN.

### Segmento L2 confiável

MAC Ethernet somente é associado diretamente a um IP quando o IP pertence a
uma rede diretamente configurada na interface de captura. Isso evita mapear o
MAC do roteador para um host de outra sub-rede.

Em uma interface TAP sem endereço IP, configure explicitamente
`topology.passive_local_networks`, por exemplo:

```json
{
  "topology": {
    "passive_local_networks": ["192.168.1.0/24"],
    "promiscuous": true
  }
}
```

## Persistência

### netscope_topology_evidence

Histórico e estado das evidências de topologia:

- origem: passive, arp, lldp, cdp, snmp-fdb;
- relação;
- observador;
- dispositivo e peer;
- portas;
- VLAN;
- confiança;
- first_seen / last_seen / expires_at;
- detalhes da observação.

### netscope_flow_aggregates

Agregados temporais, não PCAP:

- src/dst IP e MAC;
- portas e protocolo;
- VLAN;
- pacotes/bytes;
- interface/sensor;
- first_seen / last_seen.

### netscope_identity_observations

Identidade temporal:

- IP;
- MAC;
- hostname;
- origem (ARP, DHCPACK, Ethernet, next-hop);
- confiança;
- validade.

Um MAC já existente no dispositivo nunca é sobrescrito automaticamente.
MAC ausente só é preenchido quando há uma única observação recente de alta
confiança. Observações contraditórias permanecem sem reconciliação automática.

## SNMP

O modo Avançado não ativa credenciais automaticamente. Configure somente
leitura, preferencialmente SNMPv3:

```dotenv
SNMP_ENABLED=true
SNMP_TARGETS_JSON=[{"host":"192.168.1.2","version":"3","username":"inventory",...}]
```

MIBs LLDP/CDP/FDB são opcionais. Um switch que não implemente CDP ou LLDP não
faz mais a coleta SNMP inteira falhar.

## Interface

O seletor **Modo de topologia** oferece:

- **Básico — ativo + passivo local**
- **Avançado — + SNMP/LLDP/CDP/FDB**

O status mostra se o observador passivo está executando e quantas evidências
existem por fonte.

O botão **Inferir** continua com prévia. A prévia diferencia:

- links configurados;
- próximos saltos passivos;
- relações avançadas;
- gateways lógicos;
- atualizações de papéis/centralidade;
- links antigos a remover.

LLDP/CDP também são desenhados como arestas de evidência física mesmo quando a
relação entre dois switches não pode ser encaixada com segurança em um único
`parent_id`.

## Limites de observabilidade

Sem TAP/SPAN, uma interface Ethernet comum enxerga principalmente tráfego
destinado ao próprio host, broadcast/multicast e tráfego originado por ele.
Logo, a análise passiva pode ser parcial.

Sem switch gerenciável, o modo Básico consegue identificar relações de
comunicação, próximo salto e equipamentos de trânsito, mas não consegue provar
a porta física de um switch Ethernet invisível.

## Critérios de segurança

- nenhum PCAP é persistido;
- sem AEGIS;
- sem dependência de Kafka;
- buffers passivos têm limite;
- FDB não sobrescreve vínculo manual;
- inferência não sobrescreve MAC existente;
- vínculos manuais têm prioridade máxima;
- ciclos e candidatos ambíguos são rejeitados.
