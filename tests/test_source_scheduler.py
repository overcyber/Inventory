from services.source_scheduler import (
    SOURCE_NAMES,
    get_source_schedules,
    save_source_schedules,
)


def test_source_schedule_persistence(app):
    with app.app_context():
        saved = save_source_schedules({
            'snmp': {'enabled': True, 'interval_seconds': 900},
            'ssh': {'enabled': True, 'interval_seconds': 1800},
            'winrm': {'enabled': False, 'interval_seconds': 7200},
        })
        assert saved['snmp'] == {
            'enabled': True,
            'interval_seconds': 900,
        }
        assert saved['ssh']['interval_seconds'] == 1800
        assert saved['winrm']['enabled'] is False

        loaded = get_source_schedules()
        assert set(loaded) == set(SOURCE_NAMES)
        assert loaded['snmp']['enabled'] is True
        assert loaded['snmp']['interval_seconds'] == 900


def test_source_schedule_interval_clamped(app):
    with app.app_context():
        saved = save_source_schedules({
            'osquery': {'enabled': True, 'interval_seconds': 1},
            'netscope': {'enabled': True, 'interval_seconds': 9999999},
        })
        assert saved['osquery']['interval_seconds'] == 300
        assert saved['netscope']['interval_seconds'] == 86400
