from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

log = logging.getLogger('inventory.integrations')
ASSET_TOPIC = os.getenv('KAFKA_ASSET_TOPIC', 'asset.snapshot.v1')


def _event(asset, changes):
    return {
        'schema': 'asset.snapshot.v1',
        'event_time': datetime.now(timezone.utc).isoformat(),
        'asset_uuid': asset.asset_uuid,
        'canonical_name': asset.canonical_name,
        'status': asset.status,
        'network_status': asset.network_status,
        'agent_status': asset.agent_status,
        'confidence': asset.confidence,
        'state': asset.current_state or {},
        'changes': [{'path': p, 'old': old, 'new': new}
                    for p, old, new in (changes or [])],
    }


def _publish_kafka(event: dict) -> None:
    servers = (os.getenv('KAFKA_BOOTSTRAP_SERVERS') or '').strip()
    if not servers:
        return
    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers=[x.strip() for x in servers.split(',') if x.strip()],
            value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
            acks='all', retries=3,
        )
        producer.send(ASSET_TOPIC, key=event['asset_uuid'].encode('utf-8'), value=event)
        producer.flush(timeout=5)
        producer.close(timeout=2)
    except Exception as exc:
        log.warning('Kafka asset event failed: %s', exc)


def _publish_webhooks(event: dict) -> None:
    urls = [u.strip() for u in (os.getenv('ASSET_WEBHOOK_URLS') or '').split(',') if u.strip()]
    if not urls:
        return
    import requests
    token = (os.getenv('ASSET_WEBHOOK_TOKEN') or '').strip()
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    for url in urls:
        try:
            requests.post(url, json=event, headers=headers, timeout=4).raise_for_status()
        except Exception as exc:
            log.warning('Asset webhook failed for %s: %s', url, exc)


def publish_asset_event(asset, changes=None) -> None:
    """Publish normalized Asset Core events to Kafka and CTI/NDR/SOAR webhooks."""
    event = _event(asset, changes or [])
    _publish_kafka(event)
    _publish_webhooks(event)
