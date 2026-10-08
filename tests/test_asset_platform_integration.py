import hashlib
from datetime import datetime
from models import ApiToken, Asset, AssetOutbox, AssetSoftware, AssetSourceState, db
from services.asset_core import generic_payload_to_state, ingest_observation
from services.integrations import flush_outbox
from services.inventory_sources import sync_configured_sources

def ingest(source, external, payload):
    return ingest_observation(source, external, payload,
                              generic_payload_to_state(payload, source, external))

def test_standalone_without_wazuh(app):
    with app.app_context():
        result=sync_configured_sources(app)
        assert result['wazuh']['skipped'] is True
        assert 'netscope' in result

def test_multisource_identity_and_hostname_safety(app):
    with app.app_context():
        a=ingest('netscope','dev-1',{'hostname':'same-name','ips':['10.0.0.10'],
             'macs':['aa:bb:cc:dd:ee:01'],'network_status':'reachable','device_status':'Ativo','confidence':0.8})
        b=ingest('osquery','host-1',{'hostname':'renamed','ips':['10.0.0.10'],
             'macs':['aa:bb:cc:dd:ee:01'],'machine_id':'host-1','confidence':0.96})
        assert a.id==b.id
        assert AssetSourceState.query.filter_by(asset_id=a.id).count()==2
        c=ingest('api','other-1',{'hostname':'same-name','ips':['10.0.0.20'],
             'macs':['aa:bb:cc:dd:ee:02'],'confidence':0.7})
        assert c.id!=a.id
        assert Asset.query.count()==2

def test_temporal_software_disappearance(app):
    with app.app_context():
        a=ingest('api','machine-7',{'hostname':'h7','machine_id':'machine-7','confidence':0.9,
             'inventory':{'packages':[{'name':'openssl','version':'3.0'}]}})
        row=AssetSoftware.query.filter_by(asset_id=a.id,name='openssl').first()
        assert row and row.active is True
        ingest('api','machine-7',{'hostname':'h7','machine_id':'machine-7','confidence':0.9,
             'inventory':{'packages':[]}})
        db.session.expire_all()
        row=AssetSoftware.query.filter_by(asset_id=a.id,name='openssl').first()
        assert row.active is False
        assert row.valid_to is not None

def test_outbox_transaction_and_delivery_without_destinations(app):
    with app.app_context():
        ingest('api','machine-outbox',{'hostname':'outbox','machine_id':'machine-outbox','confidence':0.9})
        row=AssetOutbox.query.one()
        assert row.status=='pending'
        result=flush_outbox()
        db.session.expire_all()
        assert result['published']==1
        assert AssetOutbox.query.one().status=='published'

def test_machine_token_ingestion(app):
    token='unit-test-collector-token'
    with app.app_context():
        row=ApiToken(name='test-agent',token_hash=hashlib.sha256(token.encode()).hexdigest(),
                     scopes=['ingest'],active=True,created_at=datetime.utcnow())
        db.session.add(row); db.session.commit()
    client=app.test_client()
    response=client.post('/api/v1/assets/observations',
        headers={'Authorization':'Bearer '+token},
        json={'source':'inventory_agent','external_id':'agent-1',
              'data':{'hostname':'agent-host','machine_id':'agent-1'}})
    assert response.status_code==201
    with app.app_context():
        assert Asset.query.count()==1
