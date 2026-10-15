from services.netscope_core import Store
from services.stats import build_chart_response, get_machine_stats


def _device(uid, status='online', has_agent=False, agent_status=''):
    return {
        'uid': uid, 'mac': uid if ':' in uid else '',
        'ip': '192.168.1.' + str(abs(hash(uid)) % 200 + 10),
        'deleted': False, 'status': status,
        'type': 'desktop', 'user': '',
        'has_agent': has_agent, 'agent_status': agent_status,
        'agent_exempt': False,
    }


def test_netscope_stats_separate_agent_status_from_network_status(monkeypatch):
    store = Store()
    devices = [
        _device('00:11:22:33:44:01', 'online', True, 'active'),
        _device('00:11:22:33:44:02', 'online', True, 'disconnected'),
        _device('00:11:22:33:44:03', 'unverified', True, 'unknown'),
        _device('00:11:22:33:44:04', 'unverified', False, ''),
    ]
    monkeypatch.setattr(store, 'active', lambda: devices)

    stats = store.stats()
    assert stats['total'] == 4
    assert stats['online'] == 2
    assert stats['offline'] == 0
    assert stats['unverified'] == 2
    assert stats['agent_online'] == 1
    assert stats['agent_offline'] == 1
    assert stats['agent_unknown'] == 1


def test_dashboard_wazuh_kpis_do_not_count_generic_active_assets(app, monkeypatch):
    fake_ns = [
        _device('00:11:22:33:44:11', 'online', True, 'active'),
        _device('00:11:22:33:44:12', 'online', True, 'disconnected'),
        _device('00:11:22:33:44:13', 'online', False, ''),
    ]

    import services.netscope_core as core
    monkeypatch.setattr(core.store, 'active', lambda: fake_ns)

    # These machine rows deliberately look "Ativo"; they must NOT become
    # Wazuh-agent counters merely because Asset Core considers them active.
    machines = [
        {'hostname': f'host-{i}', 'device_status': 'Ativo',
         'agent_status_raw': 'active', 'last_seen': 'N/A',
         'os_name': 'Linux', 'cpu_name': 'x', 'ram_gb': 4,
         'ports': [], 'processes': [], 'packages': []}
        for i in range(10)
    ]

    with app.test_request_context('/'):
        generic = get_machine_stats(machines)
        result = build_chart_response(generic, machines)

    assert generic['status']['Ativo'] == 10
    assert result['active_count'] == 1
    assert result['inactive_count'] == 1
    assert result['ns_total'] == 3
    assert result['ns_with_agent'] == 2
