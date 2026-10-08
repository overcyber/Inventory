from services.asset_core import identity_candidates, normalize_hostname

def test_hostname_is_not_a_canonical_identifier():
    keys = identity_candidates({'hostname': 'shared-host'}, 'api', 'source-42')
    assert ('hostname', 'SHARED-HOST', 0.70) not in keys
    assert any(k == 'api_external_id' and v == 'source-42' for k, v, _ in keys)

def test_same_source_external_id_is_stable():
    before = identity_candidates({'hostname': 'HOST-A'}, 'api', 'machine-7')
    after = identity_candidates({'hostname': 'HOST-B'}, 'api', 'machine-7')
    assert any(k == 'api_external_id' and v == 'machine-7' for k, v, _ in before)
    assert any(k == 'api_external_id' and v == 'machine-7' for k, v, _ in after)
