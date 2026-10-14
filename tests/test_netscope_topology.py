"""Regression tests for evidence-driven NetScope Inferir."""
from services.netscope_topology import infer_topology


def device(uid, ip, kind='desktop', **extra):
    return {'uid': uid, 'ip': ip, 'type': kind, 'parent_id': None,
            'parent_inferred': False, **extra}


def test_gateway_only_when_configured_and_present():
    devices = [
        device('gw', '192.168.10.1', 'router'),
        device('a', '192.168.10.14'),
        device('b', '192.168.10.23'),
    ]
    cfg = {'networks': [
        {'subnet': '192.168.10', 'gateway': '192.168.10.1'}]}
    plan, summary = infer_topology(devices, cfg)
    assert plan['a']['parent_id'] == 'gw'
    assert plan['a']['parent_relation'] == 'logical-gateway'
    assert plan['b']['parent_id'] == 'gw'
    assert summary['logical_gateway'] == 2
    assert summary['physical_configured'] == 0


def test_absent_gateway_does_not_use_arbitrary_first_ip():
    devices = [
        device('a', '192.168.1.100'),
        device('b', '192.168.1.174'),
    ]
    cfg = {'networks': [
        {'subnet': '192.168.1', 'gateway': '192.168.1.1'}]}
    plan, summary = infer_topology(devices, cfg)
    assert plan == {}
    assert summary['unresolved'] == 2


def test_switch_port_precedes_gateway_and_respects_manual():
    devices = [
        device('gateway', '192.168.10.1', 'router'),
        device('switch', '192.168.10.2', 'switch'),
        device('pc', '192.168.10.10'),
        device('printer', '192.168.10.20',
               parent_id='gateway', parent_inferred=False),
    ]
    cfg = {
        'networks': [{'subnet': '192.168.10',
                      'gateway': '192.168.10.1'}],
        'switches': {'switch': {
            'port_count': 8,
            'ports': {'3': {'device_mac': 'pc'}}}},
    }
    plan, summary = infer_topology(devices, cfg)
    assert plan['pc']['parent_id'] == 'switch'
    assert plan['pc']['parent_relation'] == 'physical-configured'
    assert plan['pc']['parent_evidence'] == 'switch-port:3'
    assert 'printer' not in plan
    assert summary['manual_preserved'] == 1
    assert summary['logical_gateway'] == 1  # switch -> gateway


def test_conflicting_switch_port_assignments_are_rejected():
    devices = [
        device('sw', '10.1.1.2', 'switch'),
        device('pc', '10.1.1.50'),
    ]
    cfg = {'networks': [], 'switches': {'sw': {
        'ports': {'1': {'device_mac': 'pc'},
                  '2': {'device_mac': 'pc'}}}}}
    plan, summary = infer_topology(devices, cfg)
    assert plan == {}
    assert summary['conflicts'] == 1


def test_cycle_with_manual_parent_is_not_created():
    devices = [
        device('gw', '10.20.0.1', 'router',
               parent_id='pc', parent_inferred=False),
        device('pc', '10.20.0.5'),
    ]
    cfg = {'networks': [
        {'cidr': '10.20.0.0/24', 'gateway': '10.20.0.1'}]}
    plan, summary = infer_topology(devices, cfg)
    assert 'pc' not in plan
    assert summary['cycles_prevented'] >= 1


def test_duplicate_gateway_ip_does_not_create_edges():
    devices = [
        device('gw1', '10.0.0.1', 'router'),
        device('gw2', '10.0.0.1', 'router'),
        device('pc', '10.0.0.10'),
    ]
    cfg = {'networks': [
        {'cidr': '10.0.0.0/24', 'gateway': '10.0.0.1'}]}
    plan, _ = infer_topology(devices, cfg)
    assert plan == {}


def test_device_local_switch_port_is_accepted():
    devices = [
        device('sw', '10.0.0.2', 'switch'),
        device('host', '10.0.0.8',
               switch_port={'switch_mac': 'sw', 'port': 7}),
    ]
    plan, summary = infer_topology(devices, {'networks': []})
    assert plan['host']['parent_id'] == 'sw'
    assert summary['physical_configured'] == 1


def test_store_infer_preview_does_not_mutate(monkeypatch):
    from services.netscope_core import Store

    sw = device('gateway', '192.168.10.1', 'router')
    host = device('host', '192.168.10.14')
    st = Store()
    st._cache = {'devices': [sw, host]}
    monkeypatch.setattr(st, '_load', lambda: st._cache)
    flushed = []
    monkeypatch.setattr(st, '_flush', lambda: flushed.append(True))
    cfg = {'networks': [
        {'cidr': '192.168.10.0/24', 'gateway': '192.168.10.1'}]}

    preview = st.infer_links(cfg, details=True, dry_run=True)
    assert preview['preview'] is True
    assert preview['changed'] == 1
    assert host['parent_id'] is None
    assert flushed == []

    applied = st.infer_links(cfg, details=True)
    assert applied['changed'] == 1
    assert host['parent_id'] == 'gateway'
    assert host['parent_relation'] == 'logical-gateway'
    assert flushed == [True]

    again = st.infer_links(cfg, details=True)
    assert again['changed'] == 0


def test_store_infer_replaces_legacy_guesses_preserves_manual(monkeypatch):
    from services.netscope_core import Store

    original = device('first-ip', '10.0.0.10')
    stale = device('stale', '10.0.0.20',
                   parent_id='first-ip', parent_inferred=True,
                   parent_confidence=75)
    manual = device('manual', '10.0.0.30',
                    parent_id='first-ip', parent_inferred=False)
    st = Store()
    st._cache = {'devices': [original, stale, manual]}
    monkeypatch.setattr(st, '_load', lambda: st._cache)
    monkeypatch.setattr(st, '_flush', lambda: None)

    outcome = st.infer_links({'networks': []}, details=True)
    assert stale['parent_id'] is None
    assert manual['parent_id'] == 'first-ip'
    assert outcome['cleared'] == 1
    assert outcome['manual_preserved'] == 1
