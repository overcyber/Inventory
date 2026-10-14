from types import SimpleNamespace
import ipaddress
import json
import socket

from services import netscope_reachability as live
from services import netscope_discovery as discovery
from services import netscope_scan_control as control


def test_tcp_probe_requires_successful_connect(monkeypatch):
    attempts = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def connect(address, timeout):
        attempts.append(address[1])
        if address[1] == 443:
            return Connection()
        raise ConnectionRefusedError()

    monkeypatch.setattr(socket, 'create_connection', connect)
    assert live.probe_tcp('192.168.1.23', ports=[22, 443], timeout=0.1) == 443
    assert attempts == [22, 443]
    assert live.probe_tcp('invalid', ports=[443]) is None


def test_tcp_probe_failure_is_inconclusive(monkeypatch):
    def fail(address, timeout):
        raise socket.timeout('filtered')

    monkeypatch.setattr(socket, 'create_connection', fail)
    assert live.probe_tcp('192.168.1.23', ports=[22, 443], timeout=0.1) is None


def test_arp_interface_uses_actual_route_not_default(monkeypatch):
    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps([{
            'dev': 'enp3s0', 'prefsrc': '192.168.10.100'
        }]))

    monkeypatch.setattr(discovery.subprocess, 'run', fake_run)
    assert discovery.routed_direct_interface(
        ipaddress.ip_network('192.168.10.0/24')) == ('enp3s0', '192.168.10.100')


def test_no_remote_mac_from_routed_arp(monkeypatch):
    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps([{
            'dev': 'enp3s0', 'prefsrc': '192.168.1.100',
            'gateway': '192.168.1.1'
        }]))

    monkeypatch.setattr(discovery.subprocess, 'run', fake_run)
    assert discovery.routed_direct_interface(
        ipaddress.ip_network('192.168.10.0/24')) == (None, None)


def test_manual_scan_queued_for_host_worker(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.values = {}
            self.queues = {}

        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.values:
                return False
            self.values[key] = value
            return True

        def get(self, key):
            return self.values.get(key)

        def delete(self, key):
            self.values.pop(key, None)

        def lpush(self, key, value):
            self.queues.setdefault(key, []).insert(0, value)

        def rpop(self, key):
            q = self.queues.get(key, [])
            return q.pop() if q else None

    client = FakeRedis()
    monkeypatch.setattr(control, '_client', lambda: client)
    ok, result, code = control.submit_scan(subnet_count=2)
    assert ok and code == 200
    assert result['subnets'] == 2
    assert control.scan_state()['status'] == 'scanning'
    job = control.claim_scan()
    control.begin_scan(job)
    control.finish_scan(job, {'total': 12, 'ping_found': 8, 'tcp_found': 4})
    assert control.scan_state()['status'] == 'complete'
    assert control.scan_state()['total'] == 12
    assert client.get(control._LOCK) is None
