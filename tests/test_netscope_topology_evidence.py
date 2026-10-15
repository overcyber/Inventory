from models import db
from services.netscope_topology_evidence import (
    infer_roles,
    observe_identity,
    recent_identity_candidates,
    record_evidence,
    record_flow,
)


def test_identity_candidate_requires_unique_recent_mac(app):
    with app.app_context():
        observe_identity('192.168.1.20', '00:11:22:33:44:55',
                         source='arp', confidence=.97)
        c = recent_identity_candidates()
        assert c['192.168.1.20']['mac'] == '00:11:22:33:44:55'

        observe_identity('192.168.1.20', '00:11:22:33:44:66',
                         source='dhcp', confidence=.98)
        c = recent_identity_candidates()
        assert '192.168.1.20' not in c


def test_passive_roles_detect_transit_and_dns_centralizer(app):
    with app.app_context():
        for i in range(10, 14):
            record_flow(
                sensor_id='tap:test', interface='eth0',
                src_ip=f'192.168.1.{i}', dst_ip='192.168.1.1',
                src_port=40000 + i, dst_port=53, protocol='UDP',
                packets=4, bytes_count=500, commit=False)
        record_evidence(
            source='passive', relation='l2-next-hop',
            subject_key='h10', peer_key='gw',
            subject_ip='192.168.1.10', peer_ip='192.168.1.1',
            confidence=.9, commit=False)
        record_evidence(
            source='passive', relation='l2-next-hop',
            subject_key='h11', peer_key='gw',
            subject_ip='192.168.1.11', peer_ip='192.168.1.1',
            confidence=.9, commit=False)
        db.session.commit()

        devices = [
            {'uid': 'gw', 'ip': '192.168.1.1'},
            {'uid': 'h10', 'ip': '192.168.1.10'},
            {'uid': 'h11', 'ip': '192.168.1.11'},
            {'uid': 'h12', 'ip': '192.168.1.12'},
            {'uid': 'h13', 'ip': '192.168.1.13'},
        ]
        roles = infer_roles(devices, window_minutes=30)
        names = {x['role'] for x in roles['gw']['roles']}
        assert 'network-transit-candidate' in names
        assert 'communication-centralizer' in names
        assert 'dns-service' in names
