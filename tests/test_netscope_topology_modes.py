from types import SimpleNamespace

from services.netscope_topology import infer_topology


def dev(uid, ip, kind='desktop', **extra):
    return {
        'uid': uid, 'ip': ip, 'type': kind,
        'parent_id': None, 'parent_inferred': False, **extra,
    }


def ev(source, relation, subject, peer, confidence=.9, local_port=''):
    return SimpleNamespace(
        source=source, relation=relation, subject_key=subject, peer_key=peer,
        confidence=confidence, local_port=local_port, remote_port='',
    )


def test_basic_passive_next_hop_beats_logical_gateway():
    devices = [
        dev('gw', '192.168.1.1', 'router'),
        dev('host', '192.168.1.20'),
    ]
    cfg = {
        'networks': [{'subnet': '192.168.1', 'gateway': '192.168.1.1'}],
        'topology': {'mode': 'basic'},
        'switches': {},
    }
    plan, summary = infer_topology(
        devices, cfg, [ev('passive', 'l2-next-hop', 'host', 'gw', .91)])
    assert plan['host']['parent_id'] == 'gw'
    assert plan['host']['parent_relation'] == 'passive-next-hop'
    assert summary['passive_next_hop'] == 1


def test_basic_ignores_snmp_fdb_candidate():
    devices = [
        dev('sw', '10.0.0.2', 'switch'),
        dev('host', '10.0.0.20'),
    ]
    cfg = {'networks': [], 'topology': {'mode': 'basic'}, 'switches': {}}
    plan, summary = infer_topology(
        devices, cfg,
        [ev('snmp-fdb', 'fdb-access-candidate', 'host', 'sw', .82, 'Gi1/0/2')])
    assert 'host' not in plan
    assert summary['physical_advanced'] == 0


def test_advanced_accepts_single_mac_access_candidate():
    devices = [
        dev('sw', '10.0.0.2', 'switch'),
        dev('host', '10.0.0.20'),
    ]
    cfg = {'networks': [], 'topology': {'mode': 'advanced'}, 'switches': {}}
    plan, summary = infer_topology(
        devices, cfg,
        [ev('snmp-fdb', 'fdb-access-candidate', 'host', 'sw', .82, 'Gi1/0/2')])
    assert plan['host']['parent_id'] == 'sw'
    assert plan['host']['parent_relation'] == 'physical-fdb-candidate'
    assert summary['physical_advanced'] == 1


def test_advanced_lldp_switch_to_router_is_physical():
    devices = [
        dev('router', '10.0.0.1', 'router'),
        dev('sw', '10.0.0.2', 'switch'),
    ]
    cfg = {'networks': [], 'topology': {'mode': 'advanced'}, 'switches': {}}
    plan, _ = infer_topology(
        devices, cfg,
        [ev('lldp', 'physical-neighbor', 'sw', 'router', .99, 'Gi1/0/48')])
    assert plan['sw']['parent_id'] == 'router'
    assert plan['sw']['parent_relation'] == 'physical-lldp'


def test_manual_link_remains_authoritative():
    devices = [
        dev('router', '10.0.0.1', 'router'),
        dev('sw', '10.0.0.2', 'switch'),
        dev('host', '10.0.0.20',
            parent_id='router', parent_inferred=False),
    ]
    cfg = {'networks': [], 'topology': {'mode': 'advanced'}, 'switches': {}}
    plan, summary = infer_topology(
        devices, cfg,
        [ev('snmp-fdb', 'fdb-access-candidate', 'host', 'sw', .82)])
    assert 'host' not in plan
    assert summary['manual_preserved'] == 1
