from services.inventory_sources import SNMPSource

def test_snmp_mac_value_normalization():
    assert SNMPSource._mac_value('Hex-STRING: AA BB CC DD EE FF') == 'aa:bb:cc:dd:ee:ff'
    assert SNMPSource._mac_value('AA:BB:CC:DD:EE:01') == 'aa:bb:cc:dd:ee:01'
    assert SNMPSource._mac_value('invalid') == ''
