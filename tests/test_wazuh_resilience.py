import logging
import requests
import utils.collector as collector_mod
from utils.collector import WazuhCollector

class FakeResponse:
    def __init__(self, fail=False, payload=None):
        self.fail=fail
        self._payload=payload or {}
        self.text='token'
    def raise_for_status(self):
        if self.fail:
            raise requests.HTTPError('429/timeout simulation')
    def json(self):
        return self._payload

class SequenceSession:
    def __init__(self, responses):
        self.responses=list(responses)
        self.calls=0
    def request(self, *args, **kwargs):
        self.calls += 1
        item=self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

def build():
    return WazuhCollector('https','wazuh.local','55000','u','p',logging.getLogger('test'))

def test_wazuh_request_retries_transient_failure(monkeypatch):
    c=build()
    session=SequenceSession([FakeResponse(True),FakeResponse(True),FakeResponse(False)])
    monkeypatch.setattr(c,'_get_session',lambda:session)
    monkeypatch.setattr(collector_mod.time,'sleep',lambda *_:None)
    monkeypatch.setattr(collector_mod.random,'random',lambda:0)
    monkeypatch.setattr(collector_mod,'MIN_REQUEST_INTERVAL',0)
    response=c._request('GET','https://wazuh.local/test')
    assert response is not None
    assert session.calls==3

def test_wazuh_request_raises_after_retry_budget(monkeypatch):
    c=build()
    session=SequenceSession([requests.Timeout('timeout') for _ in range(4)])
    monkeypatch.setattr(c,'_get_session',lambda:session)
    monkeypatch.setattr(collector_mod.time,'sleep',lambda *_:None)
    monkeypatch.setattr(collector_mod.random,'random',lambda:0)
    monkeypatch.setattr(collector_mod,'MIN_REQUEST_INTERVAL',0)
    try:
        c._request('GET','https://wazuh.local/test')
        assert False, 'expected RequestException'
    except requests.RequestException:
        pass
    assert session.calls==4

def test_optional_syscollector_category_does_not_break_agent(monkeypatch):
    c=build()
    def fake(endpoint, optional=False):
        if endpoint.endswith('/services'):
            return {}
        return {'data':{'affected_items':[]}}
    monkeypatch.setattr(c,'get_json',fake)
    result=c._fetch_agent_inventory('001')
    assert 'services' in result
    assert result['services']==[]
    assert 'hardware' in result
