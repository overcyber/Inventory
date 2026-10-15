from models import db, NetscopeDevice
from services.netscope_core import Store


def row(ip, mac, uid, **data):
    doc = {
        'uid': uid, 'ip': ip, 'mac': mac or '',
        'deleted': False, 'status': 'online',
        'hostname': '', 'type': 'desktop',
        **data,
    }
    return NetscopeDevice(
        mac=mac or None, ip=ip, hostname=doc.get('hostname') or '',
        deleted=False, data=doc,
    )


def test_db_reconcile_strong_plus_weak(app):
    with app.app_context():
        strong = row('192.168.10.21', 'aa:bb:cc:dd:ee:21',
                     'aa:bb:cc:dd:ee:21')
        weak = row('192.168.10.21', None, 'provisional-21',
                   notes='preservar')
        db.session.add_all([strong, weak])
        db.session.commit()

        store = Store()
        assert store.reconcile_weak_ip_duplicates_db() == 1

        db.session.expire_all()
        active = NetscopeDevice.query.filter_by(
            ip='192.168.10.21', deleted=False).all()
        assert len(active) == 1
        assert active[0].mac == 'aa:bb:cc:dd:ee:21'
        assert active[0].data['notes'] == 'preservar'

        merged = NetscopeDevice.query.filter_by(
            ip='192.168.10.21', deleted=True).one()
        assert merged.data['merged_into'] == 'aa:bb:cc:dd:ee:21'
        assert merged.data['status'] == 'merged'


def test_db_reconcile_preserves_two_real_macs(app):
    with app.app_context():
        db.session.add_all([
            row('192.168.10.40', 'aa:bb:cc:dd:ee:40',
                'aa:bb:cc:dd:ee:40'),
            row('192.168.10.40', 'aa:bb:cc:dd:ee:41',
                'aa:bb:cc:dd:ee:41'),
        ])
        db.session.commit()

        store = Store()
        assert store.reconcile_weak_ip_duplicates_db() == 0

        active = NetscopeDevice.query.filter_by(
            ip='192.168.10.40', deleted=False).all()
        assert len(active) == 2
