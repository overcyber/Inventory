# NetScope — Inferir topologia (versão baseada em evidências)

## O que foi corrigido

A versão anterior do botão **Inferir** apenas removia conexões inferidas,
sem reconstruir nenhuma ligação. Isso produzia um grafo fragmentado.
O algoritmo foi substituído, preservando links manuais.

## Hierarquia de evidências

1. **Manual** — conexão definida pelo operador: preservada, não reescrita.
2. **Porta de switch configurada** — dados do cadastro de Switches
   (ou `switch_port` cadastrado no dispositivo). É uma associação
   **física declarada/configurada**, não uma observação LLDP ou CDP.
3. **Gateway da rede** — associa dispositivos ao equipamento que tem
   exatamente o endereço de gateway cadastrado, se esse equipamento
   aparece uma única vez no inventário. É relação **lógica L3**,
   não cabeamento físico. Representada por ligação pontilhada.
4. **Sem evidências** — o dispositivo permanece sem vínculo inferido.
   Não se escolhe arbitrariamente `.1` ou o primeiro IP do segmento.

## Restrições de segurança e consistência

- Não altera ligações manuais.
- Não cria ciclos.
- Se houver dois dispositivos usando o IP de gateway, não o usa como pai.
- Se um dispositivo estiver configurado em múltiplas portas de switch,
  a atribuição é considerada ambígua.
- Revisita inferências antigas e remove as que não têm evidência atual.
- Oferece **prévia de alterações e confirmação** antes de gravar.
- Execuções repetidas sem alteração na configuração são idempotentes.

## Cenário conhecido

Para `192.168.10.0/24`, quando `192.168.10.1` estiver inventariado
e configurado como gateway, os dispositivos sem ligação manual/portas
podem ser agrupados logicamente ao gateway.

Para `192.168.1.0/24`, caso o gateway configurado não apareça no
inventário, os dispositivos permanecem sem pai inferido; inventariar
o gateway real e mapear portas de switches permite aprimorar o diagrama.

## Limitação atual

O projeto contém configuração de portas de switches, mas **não possui
um pipeline comprovado de descoberta automática LLDP/CDP ou FDB** usado
por este inferidor. A versão não deve afirmar que as conexões lógicas
são cabos físicos reais. Para topologia física automática, é preciso
implantar e validar coleta SNMP LLDP/CDP/FDB e relacionar interfaces/portas
aos respectivos ativos, com timestamp e procedência por aresta.

## Testar

```bash
pytest -q tests/test_netscope_topology.py
```

Na interface, clique **Inferir**, revise a contagem de conexões configuradas,
lógicas e manuais e confirme a aplicação. O campo **Evidência** no popover
do dispositivo distingue a natureza de cada ligação.
