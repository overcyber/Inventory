from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from models import AssetDeadLetter, AssetOutbox, db

log=logging.getLogger('inventory.integrations')


def _event(asset, changes):
    return {
        'schema':'asset.snapshot.v1',
        'event_id':str(uuid.uuid4()),
        'event_time':datetime.now(timezone.utc).isoformat(),
        'asset_uuid':asset.asset_uuid,
        'canonical_name':asset.canonical_name,
        'status':asset.status,
        'network_status':asset.network_status,
        'agent_status':asset.agent_status,
        'confidence':asset.confidence,
        'inventory_freshness_seconds':asset.inventory_freshness_seconds,
        'state':asset.current_state or {},
        'changes':[{'path':p,'old':old,'new':new} for p,old,new in (changes or [])],
    }


def enqueue_asset_event(asset, changes=None):
    """Queue event in the SAME database transaction as the asset update."""
    event=_event(asset,changes or [])
    db.session.add(AssetOutbox(
        event_uuid=event['event_id'],
        topic=os.getenv('KAFKA_ASSET_TOPIC','asset.snapshot.v1'),
        event_key=asset.asset_uuid,
        payload=event,
        status='pending',
        attempts=0,
        created_at=datetime.utcnow(),
    ))
    return event['event_id']


def _kafka_servers():
    return [x.strip() for x in (os.getenv('KAFKA_BOOTSTRAP_SERVERS') or '').split(',')
            if x.strip()]


def _deliver_kafka(row):
    servers=_kafka_servers()
    if not servers:
        return
    from kafka import KafkaProducer
    producer=KafkaProducer(
        bootstrap_servers=servers,
        value_serializer=lambda v:json.dumps(v,default=str,separators=(',',':')).encode(),
        key_serializer=lambda v:v.encode() if isinstance(v,str) else v,
        acks='all',retries=5,enable_idempotence=True,max_in_flight_requests_per_connection=5,
    )
    try:
        future=producer.send(row.topic,key=row.event_key,value=row.payload)
        future.get(timeout=float(os.getenv('KAFKA_PUBLISH_TIMEOUT','10')))
        producer.flush(timeout=10)
    finally:
        producer.close(timeout=5)


def _webhook_targets():
    out=[]
    for url in (os.getenv('ASSET_WEBHOOK_URLS') or '').split(','):
        if url.strip(): out.append(('generic',url.strip()))
    for kind,env in (('cti','CTI_WEBHOOK_URL'),('ndr','NDR_WEBHOOK_URL'),
                     ('soar','SOAR_WEBHOOK_URL')):
        url=(os.getenv(env) or '').strip()
        if url: out.append((kind,url))
    return out


def _deliver_webhooks(row):
    targets=_webhook_targets()
    if not targets:
        return
    import requests
    token=(os.getenv('ASSET_WEBHOOK_TOKEN') or '').strip()
    for kind,url in targets:
        headers={'Content-Type':'application/json',
                 'X-Inventory-Schema':'asset.snapshot.v1',
                 'X-Inventory-Integration':kind,
                 'X-Inventory-Event-ID':row.event_uuid}
        if token:
            headers['Authorization']='Bearer '+token
        response=requests.post(url,json=row.payload,headers=headers,
                               timeout=float(os.getenv('ASSET_WEBHOOK_TIMEOUT','8')))
        response.raise_for_status()


def flush_outbox(limit=100):
    """Deliver due events with row locks, lease, retry/backoff and DLQ."""
    now=datetime.utcnow()
    lease=max(30,int(os.getenv('OUTBOX_LEASE_SECONDS','120')))
    q=(AssetOutbox.query
       .filter(AssetOutbox.status.in_(['pending','retry','processing']))
       .filter((AssetOutbox.next_attempt_at.is_(None)) |
               (AssetOutbox.next_attempt_at <= now))
       .order_by(AssetOutbox.id.asc())
       .with_for_update(skip_locked=True)
       .limit(max(1,min(int(limit),1000))))
    rows=q.all()
    ids=[]
    for row in rows:
        row.status='processing'
        row.next_attempt_at=now+timedelta(seconds=lease)
        ids.append(row.id)
    db.session.commit()

    published=failed=dead=0
    max_attempts=max(1,int(os.getenv('OUTBOX_MAX_ATTEMPTS','10')))
    for row_id in ids:
        row=AssetOutbox.query.get(row_id)
        if not row: continue
        try:
            _deliver_kafka(row); _deliver_webhooks(row)
            row.status='published'; row.published_at=datetime.utcnow()
            row.next_attempt_at=None; row.last_error=''; published+=1
            db.session.commit()
        except Exception as exc:
            db.session.rollback(); row=AssetOutbox.query.get(row_id)
            row.attempts=int(row.attempts or 0)+1; row.last_error=str(exc)[:8000]
            if row.attempts>=max_attempts:
                row.status='dead'; row.next_attempt_at=None
                db.session.add(AssetDeadLetter(event_uuid=row.event_uuid,topic=row.topic,
                    event_key=row.event_key,payload=row.payload,attempts=row.attempts,
                    last_error=row.last_error,failed_at=datetime.utcnow())); dead+=1
            else:
                row.status='retry'
                delay=min(3600,2 ** min(row.attempts,11))
                row.next_attempt_at=datetime.utcnow()+timedelta(seconds=delay); failed+=1
            db.session.commit()
    return {'selected':len(ids),'published':published,'retry':failed,'dead':dead}


def publish_asset_event(asset, changes=None):
    return enqueue_asset_event(asset,changes)
