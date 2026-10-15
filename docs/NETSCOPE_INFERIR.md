# NetScope — Inferir baseado em evidências

> Este documento substitui a versão anterior que registrava LLDP/CDP/FDB como limitação futura. Essas fontes já estão implementadas no modo Avançado.

## Modos

- **Básico:** descoberta ativa + análise passiva local + fluxos + gateway.
- **Avançado:** tudo do Básico + SNMP/LLDP/CDP/FDB/VLAN.

## Prioridade

1. vínculo manual;
2. LLDP/CDP;
3. porta configurada;
4. candidato FDB;
5. próximo salto passivo;
6. gateway lógico.

## Segurança

- vínculos manuais são preservados;
- ciclos são rejeitados;
- ambiguidades não são resolvidas arbitrariamente;
- FDB não prova cabeamento;
- gateway duplicado não vira pai;
- preview é calculado antes da gravação.

## Relações

| relation | interpretação |
| --- | --- |
| physical-configured | porta declarada pelo operador |
| physical-lldp | vizinho físico LLDP |
| physical-cdp | vizinho físico CDP |
| physical-fdb-candidate | provável acesso baseado em FDB |
| passive-next-hop | próximo salto Ethernet observado |
| logical-gateway | agrupamento lógico L3 |

## Fluxos

A centralidade de comunicação é usada para inferir papéis funcionais, não cabeamento:

- network-transit-candidate;
- communication-centralizer;
- dns-service;
- dhcp-service.

## Documentação completa

Consulte:

- [NETSCOPE_TOPOLOGY_INFERENCE.md](NETSCOPE_TOPOLOGY_INFERENCE.md)
- [NETSCOPE_DISCOVERY_IDENTITY.md](NETSCOPE_DISCOVERY_IDENTITY.md)
- [NETSCOPE_DATA_MODEL.md](NETSCOPE_DATA_MODEL.md)
