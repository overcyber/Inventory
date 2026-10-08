from services.netscope_portscan import ports_for_profile

def test_quick_is_bounded():
    ports = ports_for_profile('quick')
    assert 22 in ports and 443 in ports
    assert len(ports) < 200

def test_standard_is_not_full_range():
    ports = ports_for_profile('standard')
    assert len(ports) < 5000
    assert 3389 in ports
