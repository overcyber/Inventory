import logging
from utils.collector import WazuhCollector

def test_wazuh_tls_verification_defaults_true(monkeypatch):
    monkeypatch.delenv('WAZUH_TLS_VERIFY', raising=False)
    monkeypatch.delenv('WAZUH_CA_BUNDLE', raising=False)
    c = WazuhCollector('https', '127.0.0.1', '55000', 'u', 'p', logging.getLogger('t'))
    assert c.verify is True

def test_wazuh_ca_bundle(monkeypatch):
    monkeypatch.setenv('WAZUH_TLS_VERIFY', 'true')
    monkeypatch.setenv('WAZUH_CA_BUNDLE', '/tmp/ca.pem')
    c = WazuhCollector('https', '127.0.0.1', '55000', 'u', 'p', logging.getLogger('t'))
    assert c.verify == '/tmp/ca.pem'
