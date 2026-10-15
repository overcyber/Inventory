from services.netscope_core import Store, device_ips, device_macs
from services.netscope_wazuh_bridge import _merge_pair
from services.stats import get_netscope_wazuh_stats


def test_find_by_secondary_ip_resolves_same_device(monkeypatch):
    dev = {
        'uid': 'host-a',
        'mac': '00:11:22:33:44:55',
        'macs': ['00:11:22:33:44:55', '00:11:22:33:44:66'],
        'ip': '192.168.10.100',
        'ips': ['192.168.10.100', '192.168.1.100'],
        'deleted': False,
        'has_agent': True,
    }
    store = Store()
    store._cache = {'devices': [dev]}
    monkeypatch.setattr(store, '_load', lambda: store._cache)

    assert store.find_by_ip('192.168.10.100') is dev
    assert store.find_by_ip('192.168.1.100') is dev
    assert store.find('00:11:22:33:44:66') is dev
    assert store.ip_conflicts() == []


def test_merge_same_host_preserves_multiple_interfaces():
    keep = {
        'uid': '00:11:22:33:44:55',
        'mac': '00:11:22:33:44:55',
        'macs': ['00:11:22:33:44:55'],
        'ip': '192.168.10.100',
        'ips': ['192.168.10.100'],
        'deleted': False,
        'has_agent': True,
        'agent_id': '007',
        'first_seen': '2026-10-15T10:00:00',
        'last_seen': '2026-10-15T10:00:00',
    }
    dup = {
        'uid': '00:11:22:33:44:66',
        'mac': '00:11:22:33:44:66',
        'macs': ['00:11:22:33:44:66'],
        'ip': '192.168.1.100',
        'ips': ['192.168.1.100'],
        'deleted': False,
        'has_agent': True,
        'agent_id': '007',
        'first_seen': '2026-10-15T10:01:00',
        'last_seen': '2026-10-15T10:01:00',
    }

    _merge_pair(keep, dup, 'agent-id')

    assert set(device_ips(keep)) == {'192.168.10.100', '192.168.1.100'}
    assert set(device_macs(keep)) == {
        '00:11:22:33:44:55', '00:11:22:33:44:66'
    }
    assert dup['deleted'] is True
    assert dup['merged_into'] == '00:11:22:33:44:55'


def test_dashboard_wazuh_counts_are_subset_of_netscope(monkeypatch):
    devices = [
        {'uid': 'a', 'deleted': False, 'has_agent': True,
         'agent_status': 'active'},
        {'uid': 'b', 'deleted': False, 'has_agent': True,
         'agent_status': 'disconnected'},
        {'uid': 'c', 'deleted': False, 'has_agent': False},
        {'uid': 'd', 'deleted': False, 'has_agent': False,
         'agent_exempt': True},
    ]
    import services.netscope_core as core
    monkeypatch.setattr(core.store, 'active', lambda: devices)

    stats = get_netscope_wazuh_stats()

    assert stats['total'] == 4
    assert stats['with_agent'] == 2
    assert stats['agent_online'] == 1
    assert stats['agent_offline'] == 1
    assert stats['without_agent'] == 1
    assert stats['agent_exempt'] == 1
    assert stats['agent_online'] + stats['agent_offline'] + stats['agent_unknown'] <= stats['total']
