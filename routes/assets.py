from __future__ import annotations

import hmac
import os
import threading

from flask import Blueprint, jsonify, request, session

from models import Asset, AssetChange, AssetObservation
from core.security import login_required
from services.asset_core import (
    asset_to_machine, generic_payload_to_state, ingest_observation, source_states,
)

asset_bp = Blueprint('assets_api', __name__, url_prefix='/api/v1')


def _ingest_authorized() -> bool:
    expected = (os.getenv('INVENTORY_INGEST_TOKEN') or '').strip()
    supplied = (request.headers.get('X-Inventory-Token') or '').strip()
    if expected and supplied and hmac.compare_digest(expected, supplied):
        return True
    return session.get('role') == 'admin'


@asset_bp.get('/assets')
@login_required
def list_assets():
    limit = max(1, min(request.args.get('limit', 200, type=int), 2000))
    q = Asset.query.filter_by(active=True).order_by(Asset.canonical_name.asc()).limit(limit)
    return jsonify({'items': [asset_to_machine(a) for a in q.all()]})


@asset_bp.get('/assets/<asset_uuid>')
@login_required
def get_asset(asset_uuid):
    asset = Asset.query.filter_by(asset_uuid=asset_uuid).first_or_404()
    return jsonify({
        'asset': asset_to_machine(asset),
        'state': asset.current_state or {},
        'changes': [{
            'observed_at': c.observed_at.isoformat() if c.observed_at else None,
            'source': c.source, 'path': c.path, 'old': c.old_value, 'new': c.new_value,
        } for c in (AssetChange.query.filter_by(asset_id=asset.id)
                    .order_by(AssetChange.id.desc()).limit(100).all())],
        'observations': [{
            'source': o.source, 'external_id': o.external_id,
            'observed_at': o.observed_at.isoformat() if o.observed_at else None,
        } for o in (AssetObservation.query.filter_by(asset_id=asset.id)
                    .order_by(AssetObservation.id.desc()).limit(100).all())],
    })


@asset_bp.get('/sources')
@login_required
def get_sources():
    return jsonify({'sources': source_states()})


@asset_bp.post('/assets/observations')
def ingest_asset_observation():
    if not _ingest_authorized():
        return jsonify({'error': 'unauthorized'}), 401
    body = request.get_json(silent=True) or {}
    source = str(body.get('source') or 'api').strip().lower()
    external_id = str(body.get('external_id') or '').strip()
    data = body.get('data')
    normalized = body.get('normalized')
    if not isinstance(data, dict):
        return jsonify({'error': 'data deve ser objeto JSON'}), 400
    if normalized is not None and not isinstance(normalized, dict):
        return jsonify({'error': 'normalized deve ser objeto JSON'}), 400
    if normalized is None:
        normalized = generic_payload_to_state(data, source, external_id)
    asset = ingest_observation(source, external_id, data, normalized)
    return jsonify({'asset_uuid': asset.asset_uuid,
                    'canonical_name': asset.canonical_name}), 201


@asset_bp.post('/sources/sync')
@login_required
def sync_sources():
    if session.get('role') != 'admin':
        return jsonify({'error': 'admin required'}), 403
    from flask import current_app
    app = current_app._get_current_object()

    def _run():
        with app.app_context():
            from services.inventory_sources import sync_configured_sources
            sync_configured_sources(app)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({'status': 'started'}), 202
