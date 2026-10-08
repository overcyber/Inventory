# Asset Core

O Asset Core é a camada canônica de identidade, normalização e histórico do Inventory.

## Contrato

Cada fonte produz uma observação com:

- `source`;
- `external_id`;
- `raw_data`;
- `normalized`.

O núcleo resolve a identidade, mescla o estado atual, calcula diferenças e persiste histórico.

## Identidade

Ordem de preferência: serial/machine-id/cloud-id > agent-id > MAC > hostname > external-id.

## Compatibilidade

`HostInventory` permanece disponível para componentes legados. Novos componentes devem consumir `Asset`.

## Eventos

`asset.snapshot.v1` é o contrato externo para Kafka e webhooks.
