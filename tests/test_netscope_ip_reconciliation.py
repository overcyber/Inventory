from services.netscope_core import Store


def _dev(uid, ip, mac='', source='scan', **extra):
    return {
        'uid': uid, 'ip': ip, 'mac': mac, 'deleted': False,
        'source': source, 'status': 'online', 'hostname': '',
        'dns_name': '', 'vendor': '', 'type': 'desktop',
        'first_seen': '2026-10-15T10:00:00',
        'last_seen': '2026-10-15T10:00:00',
        **extra,
    }


def _prepare(monkeypatch, devices):
    import services.netscope_core as core
    store = Store()
    store._cache = {'devices': devices}
    store._cache_loaded_at = 10**12
    monkeypatch.setattr(store, '_load', lambda: store._cache)
    monkeypatch.setattr(store, '_flush', lambda: None)
    monkeypatch.setattr(core, 'load_config', lambda: {'switches': {}})
    monkeypatch.setattr(core, 'save_config', lambda cfg: None)
    return store


def test_known_mac_moving_to_provisional_ip_merges_placeholder(monkeypatch):
    strong = _dev('aa:bb:cc:dd:ee:01', '192.168.1.10',
                  'aa:bb:cc:dd:ee:01')
    weak = _dev('dev-provisional', '192.168.1.20', '',
                notes='observado antes do ARP')
    store = _prepare(monkeypatch, [strong, weak])

    created = store.upsert_scan_result(
        'aa:bb:cc:dd:ee:01',
        {'ip': '192.168.1.20', 'vendor': '', 'subnet': '192.168.1',
         'gateway': '192.168.1.1', 'ttl': 64, 'discovery': 'arp-active',
         'dns_name': ''},
        flush=False,
    )

    assert created is False
    assert strong['ip'] == '192.168.1.20'
    assert strong['notes'] == 'observado antes do ARP'
    assert weak['deleted'] is True
    assert weak['merged_into'] == 'aa:bb:cc:dd:ee:01'
    active = [d for d in store._cache['devices'] if not d.get('deleted')]
    assert [d['ip'] for d in active].count('192.168.1.20') == 1


def test_reconcile_existing_strong_plus_weak_duplicate(monkeypatch):
    strong = _dev('aa:bb:cc:dd:ee:01', '192.168.1.20',
                  'aa:bb:cc:dd:ee:01')
    weak = _dev('dev-provisional', '192.168.1.20', '')
    store = _prepare(monkeypatch, [strong, weak])

    assert store.reconcile_weak_ip_duplicates(flush=False) == 1
    assert weak['deleted'] is True
    assert weak['merged_into'] == 'aa:bb:cc:dd:ee:01'


def test_real_two_mac_ip_conflict_is_not_merged(monkeypatch):
    one = _dev('aa:bb:cc:dd:ee:01', '192.168.1.20',
               'aa:bb:cc:dd:ee:01')
    two = _dev('aa:bb:cc:dd:ee:02', '192.168.1.20',
               'aa:bb:cc:dd:ee:02')
    store = _prepare(monkeypatch, [one, two])

    assert store.reconcile_weak_ip_duplicates(flush=False) == 0
    assert not one['deleted']
    assert not two['deleted']
    conflicts = store.ip_conflicts()
    assert len(conflicts) == 1
    assert conflicts[0]['ip'] == '192.168.1.20'


def test_manual_create_rejects_existing_active_ip(monkeypatch):
    existing = _dev('aa:bb:cc:dd:ee:01', '192.168.1.20',
                    'aa:bb:cc:dd:ee:01')
    store = _prepare(monkeypatch, [existing])

    dev, status, error = store.create_device(
        {'ip': '192.168.1.20', 'mac': '', 'hostname': 'duplicate'},
        {'networks': []},
    )
    assert dev is None
    assert status == 409
    assert 'Já existe' in error


def test_manual_ip_edit_rejects_other_active_device(monkeypatch):
    one = _dev('aa:bb:cc:dd:ee:01', '192.168.1.20',
               'aa:bb:cc:dd:ee:01')
    two = _dev('aa:bb:cc:dd:ee:02', '192.168.1.30',
               'aa:bb:cc:dd:ee:02')
    store = _prepare(monkeypatch, [one, two])

    dev, status, error = store.update_device(
        'aa:bb:cc:dd:ee:02', {'ip': '192.168.1.20'})
    assert dev is None
    assert status == 409
    assert 'duplicidade' in error
