from services.inventory_sources import SNMPSource

def test_snmp_mac_value_normalization():
    assert SNMPSource._mac_value('Hex-STRING: AA BB CC DD EE FF') == 'aa:bb:cc:dd:ee:ff'
    assert SNMPSource._mac_value('AA:BB:CC:DD:EE:01') == 'aa:bb:cc:dd:ee:01'
    assert SNMPSource._mac_value('invalid') == ''


def test_qbridge_fdb_mac_from_oid_suffix():
    base = SNMPSource.OIDS['dot1q_fdb_port']
    mac, vlan = SNMPSource._mac_from_oid_suffix(
        base + '.37.0.17.34.51.68.85', base)
    assert mac == '00:11:22:33:44:55'
    assert vlan == '37'
