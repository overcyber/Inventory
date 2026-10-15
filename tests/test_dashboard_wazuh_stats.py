from services.stats import get_canonical_wazuh_stats


def test_canonical_wazuh_stats_never_exceed_asset_total():
    machines = [
        {
            'asset_uuid': 'a1',
            'source': ['wazuh'],
            'has_wazuh_agent': True,
            'agent_status_raw': 'active',
            'agent_exempt': False,
        },
        {
            'asset_uuid': 'a2',
            'source': ['ssh'],
            'has_wazuh_agent': False,
            'agent_status_raw': 'unknown',
            'agent_exempt': False,
        },
        {
            'asset_uuid': 'a3',
            'source': ['wazuh_indexer'],
            'has_wazuh_agent': True,
            'agent_status_raw': 'disconnected',
            'agent_exempt': False,
        },
        {
            'asset_uuid': 'a4',
            'source': ['snmp'],
            'has_wazuh_agent': False,
            'agent_status_raw': 'unknown',
            'agent_exempt': True,
        },
    ]
    stats = get_canonical_wazuh_stats(machines)
    assert stats['total'] == 4
    assert stats['with_agent'] == 2
    assert stats['without_agent'] == 1
    assert stats['agent_exempt'] == 1
    assert stats['agent_online'] == 1
    assert stats['agent_offline'] == 1
    assert stats['agent_unknown'] == 0


def test_non_wazuh_sources_do_not_count_as_wazuh_agent():
    machines = [
        {
            'asset_uuid': 'a1',
            'source': ['osquery'],
            'has_wazuh_agent': False,
            'agent_status_raw': 'active',
            'agent_exempt': False,
        },
        {
            'asset_uuid': 'a2',
            'source': ['inventory_agent', 'ssh', 'winrm'],
            'has_wazuh_agent': False,
            'agent_status_raw': 'active',
            'agent_exempt': False,
        },
    ]
    stats = get_canonical_wazuh_stats(machines)
    assert stats['total'] == 2
    assert stats['with_agent'] == 0
    assert stats['agent_online'] == 0
    assert stats['without_agent'] == 2
