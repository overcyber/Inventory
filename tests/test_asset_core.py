from services.asset_core import deep_diff, netscope_device_to_state, wazuh_payload_to_state

def test_deep_diff_reports_nested_change():
    assert deep_diff({'a': {'b': 1}}, {'a': {'b': 2}}) == [('a.b', 1, 2)]

def test_wazuh_normalization_separates_agent_and_network_state():
    payload = {
        'agent_info': {'id': '007', 'name': 'host-a', 'ip': '10.0.0.7',
                       'status': 'active', 'lastKeepAlive': '2026-10-08T12:00:00Z'},
        'inventory': {
            'os': [{'hostname': 'host-a', 'os': {'name': 'Linux', 'version': '1'}}],
            'hardware': [{'board_serial': 'ABC123'}],
            'netiface': [{'mac': 'AA-BB-CC-DD-EE-FF'}],
            'netaddr': [{'address': '10.0.0.7'}],
        },
        'groups': ['default'],
    }
    state = wazuh_payload_to_state('host-a', payload, '007')
    assert state['hostname'] == 'HOST-A'
    assert state['wazuh_agent_id'] == '007'
    assert state['agent_status'] == 'active'
    assert state['network_status'] == 'reachable'
    assert state['macs'] == ['aa:bb:cc:dd:ee:ff']

def test_netscope_is_valid_without_wazuh():
    state = netscope_device_to_state({
        'uid': 'aa:bb:cc:dd:ee:ff', 'mac': 'aa:bb:cc:dd:ee:ff',
        'ip': '192.168.1.10', 'hostname': 'printer-01', 'status': 'online',
        'vendor': 'Example', 'type': 'printer',
    })
    assert state['hostname'] == 'PRINTER-01'
    assert state['device_status'] == 'Ativo'
    assert state['source'] == ['netscope']
