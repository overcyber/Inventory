from services.network_utils import ip_in_network, iter_network_hosts, parse_network_spec

def test_legacy_prefix_becomes_24():
    assert str(parse_network_spec('192.168.50')) == '192.168.50.0/24'

def test_cidr_hosts():
    assert list(iter_network_hosts('10.0.0.0/30')) == ['10.0.0.1', '10.0.0.2']

def test_membership():
    assert ip_in_network('10.20.7.3', '10.20.0.0/16')
    assert not ip_in_network('10.21.0.1', '10.20.0.0/16')
