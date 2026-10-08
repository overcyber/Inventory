from __future__ import annotations
import hashlib, hmac, os, secrets, threading
from datetime import datetime
from flask import Blueprint, jsonify, request, session
from models import (ApiToken, Asset, AssetChange, AssetDeadLetter, AssetObservation,
                    AssetOutbox, AssetSnapshot, AssetSourceState, db)
from core.security import MemoryRateLimiter, login_required, admin_required
from services.asset_core import asset_to_machine, generic_payload_to_state, ingest_observation, source_states

asset_bp=Blueprint('assets_api',__name__,url_prefix='/api/v1')
_INGEST_LIMIT=MemoryRateLimiter(max_events=max(10,int(os.getenv('INGEST_RATE_LIMIT_PER_MIN','240'))),window_seconds=60)

def _token_value():
    auth=(request.headers.get('Authorization') or '').strip()
    if auth.lower().startswith('bearer '): return auth.split(None,1)[1].strip()
    return (request.headers.get('X-Inventory-Token') or '').strip()

def _token_hash(token): return hashlib.sha256(token.encode()).hexdigest()

def _has_scope(scope):
    token=_token_value()
    env_token=(os.getenv('INVENTORY_INGEST_TOKEN') or '').strip()
    if token and env_token and hmac.compare_digest(token,env_token):
        return scope in ('ingest','read') or scope=='*'
    if not token: return False
    row=ApiToken.query.filter_by(token_hash=_token_hash(token),active=True).first()
    if not row: return False
    if row.expires_at and row.expires_at <= datetime.utcnow(): return False
    scopes=row.scopes if isinstance(row.scopes,list) else []
    if '*' not in scopes and scope not in scopes: return False
    row.last_used_at=datetime.utcnow(); db.session.commit()
    return True

def _ingest_authorized():
    if session.get('role')=='admin': return True
    key=(request.remote_addr or '?')+':'+_token_hash(_token_value() or 'anonymous')[:16]
    return _INGEST_LIMIT.allow(key) and _has_scope('ingest')

def _serialize_token(row):
    return {'id':row.id,'name':row.name,'scopes':row.scopes or [],'active':row.active,
            'created_at':row.created_at.isoformat() if row.created_at else None,
            'expires_at':row.expires_at.isoformat() if row.expires_at else None,
            'last_used_at':row.last_used_at.isoformat() if row.last_used_at else None}

@asset_bp.get('/assets')
@login_required
def list_assets():
    limit=max(1,min(request.args.get('limit',200,type=int),2000))
    offset=max(0,request.args.get('offset',0,type=int))
    q=Asset.query
    if request.args.get('active','true').lower()!='all':
        q=q.filter_by(active=request.args.get('active','true').lower() in ('1','true','yes'))
    status=(request.args.get('status') or '').strip()
    if status: q=q.filter(Asset.status.ilike(status))
    source=(request.args.get('source') or '').strip()
    if source:
        q=q.join(AssetSourceState,AssetSourceState.asset_id==Asset.id).filter(AssetSourceState.source==source)
    total=q.count()
    rows=q.order_by(Asset.canonical_name.asc()).offset(offset).limit(limit).all()
    return jsonify({'items':[asset_to_machine(a) for a in rows],'total':total,'limit':limit,'offset':offset})

@asset_bp.get('/assets/<asset_uuid>')
@login_required
def get_asset(asset_uuid):
    asset=Asset.query.filter_by(asset_uuid=asset_uuid).first_or_404()
    sources=(AssetSourceState.query.filter_by(asset_id=asset.id)
             .order_by(AssetSourceState.source.asc()).all())
    return jsonify({'asset':asset_to_machine(asset),'state':asset.current_state or {},
      'sources':[{'source':x.source,'external_id':x.external_id,'confidence':x.confidence,
                  'first_seen':x.first_seen.isoformat() if x.first_seen else None,
                  'last_seen':x.last_seen.isoformat() if x.last_seen else None,
                  'observed_at':x.observed_at.isoformat() if x.observed_at else None,
                  'state':x.state or {}} for x in sources]})

@asset_bp.get('/assets/<asset_uuid>/changes')
@login_required
def get_asset_changes(asset_uuid):
    asset=Asset.query.filter_by(asset_uuid=asset_uuid).first_or_404()
    limit=max(1,min(request.args.get('limit',200,type=int),2000))
    rows=(AssetChange.query.filter_by(asset_id=asset.id)
          .order_by(AssetChange.id.desc()).limit(limit).all())
    return jsonify({'items':[{'observed_at':x.observed_at.isoformat() if x.observed_at else None,
       'source':x.source,'path':x.path,'old':x.old_value,'new':x.new_value} for x in rows]})

@asset_bp.get('/assets/<asset_uuid>/snapshots')
@login_required
def get_asset_snapshots(asset_uuid):
    asset=Asset.query.filter_by(asset_uuid=asset_uuid).first_or_404()
    limit=max(1,min(request.args.get('limit',100,type=int),500))
    rows=(AssetSnapshot.query.filter_by(asset_id=asset.id)
          .order_by(AssetSnapshot.id.desc()).limit(limit).all())
    return jsonify({'items':[{'snapshot_uuid':x.snapshot_uuid,'source':x.source,
      'observed_at':x.observed_at.isoformat() if x.observed_at else None,'state':x.state} for x in rows]})

@asset_bp.get('/sources')
@login_required
def get_sources(): return jsonify({'sources':source_states()})

def _one_observation(body):
    source=str(body.get('source') or 'api').strip().lower()[:64]
    external_id=str(body.get('external_id') or '').strip()[:512]
    data=body.get('data'); normalized=body.get('normalized')
    if not source.replace('_','').replace('-','').isalnum(): raise ValueError('source inválida')
    if not external_id: raise ValueError('external_id é obrigatório')
    if not isinstance(data,dict): raise ValueError('data deve ser objeto JSON')
    if normalized is not None and not isinstance(normalized,dict): raise ValueError('normalized deve ser objeto JSON')
    if normalized is None: normalized=generic_payload_to_state(data,source,external_id)
    asset=ingest_observation(source,external_id,data,normalized)
    return {'asset_uuid':asset.asset_uuid,'canonical_name':asset.canonical_name}

@asset_bp.post('/assets/observations')
def ingest_asset_observation():
    if not _ingest_authorized(): return jsonify({'error':'unauthorized_or_rate_limited'}),401
    try: return jsonify(_one_observation(request.get_json(silent=True) or {})),201
    except ValueError as exc: return jsonify({'error':str(exc)}),400

@asset_bp.post('/assets/observations/batch')
def ingest_asset_batch():
    if not _ingest_authorized(): return jsonify({'error':'unauthorized_or_rate_limited'}),401
    body=request.get_json(silent=True) or {}
    items=body.get('items') if isinstance(body,dict) else body
    if not isinstance(items,list): return jsonify({'error':'items deve ser lista'}),400
    if len(items)>max(1,int(os.getenv('INGEST_BATCH_MAX','500'))):
        return jsonify({'error':'batch_too_large'}),413
    out=[]; errors=[]
    for i,item in enumerate(items):
        try: out.append(_one_observation(item if isinstance(item,dict) else {}))
        except Exception as exc: db.session.rollback(); errors.append({'index':i,'error':str(exc)})
    return jsonify({'items':out,'errors':errors}),207 if errors else 201

@asset_bp.post('/sources/sync')
@admin_required
def sync_sources():
    from flask import current_app
    app=current_app._get_current_object()
    def _run():
        with app.app_context():
            from services.inventory_sources import sync_configured_sources
            sync_configured_sources(app)
    threading.Thread(target=_run,daemon=True).start()
    return jsonify({'status':'started'}),202

@asset_bp.get('/tokens')
@admin_required
def list_tokens(): return jsonify({'items':[_serialize_token(x) for x in ApiToken.query.order_by(ApiToken.id.desc()).all()]})

@asset_bp.post('/tokens')
@admin_required
def create_token():
    body=request.get_json(silent=True) or {}
    name=str(body.get('name') or '').strip()[:120]
    scopes=body.get('scopes') or ['ingest']
    if not name or not isinstance(scopes,list): return jsonify({'error':'name/scopes inválidos'}),400
    allowed={'ingest','read','admin','*'}
    scopes=sorted({str(x) for x in scopes if str(x) in allowed})
    if not scopes: return jsonify({'error':'scope inválido'}),400
    token='inv_'+secrets.token_urlsafe(32)
    expires=None
    if body.get('expires_at'):
        try: expires=datetime.fromisoformat(str(body['expires_at']).replace('Z','+00:00')).replace(tzinfo=None)
        except ValueError: return jsonify({'error':'expires_at inválido'}),400
    row=ApiToken(name=name,token_hash=_token_hash(token),scopes=scopes,active=True,
                 created_at=datetime.utcnow(),expires_at=expires)
    db.session.add(row); db.session.commit()
    return jsonify({'token':token,'record':_serialize_token(row)}),201

@asset_bp.delete('/tokens/<int:token_id>')
@admin_required
def revoke_token(token_id):
    row=ApiToken.query.get_or_404(token_id); row.active=False; db.session.commit()
    return jsonify({'revoked':True,'id':row.id})

@asset_bp.get('/outbox')
@admin_required
def outbox_status():
    pending=AssetOutbox.query.filter(AssetOutbox.status.in_(['pending','retry'])).count()
    dead=AssetDeadLetter.query.count()
    return jsonify({'pending':pending,'dead_letters':dead})


@asset_bp.get('/dead-letters')
@admin_required
def list_dead_letters():
    limit=max(1,min(request.args.get('limit',100,type=int),1000))
    rows=AssetDeadLetter.query.order_by(AssetDeadLetter.id.desc()).limit(limit).all()
    return jsonify({'items':[{'id':x.id,'event_uuid':x.event_uuid,'topic':x.topic,
      'event_key':x.event_key,'attempts':x.attempts,'last_error':x.last_error,
      'failed_at':x.failed_at.isoformat() if x.failed_at else None} for x in rows]})

@asset_bp.post('/dead-letters/<int:dead_id>/retry')
@admin_required
def retry_dead_letter(dead_id):
    row=AssetDeadLetter.query.get_or_404(dead_id)
    out=AssetOutbox.query.filter_by(event_uuid=row.event_uuid).first()
    if out:
        out.status='pending'; out.attempts=0; out.next_attempt_at=None; out.last_error=''
    db.session.delete(row); db.session.commit()
    return jsonify({'queued':True,'event_uuid':out.event_uuid if out else None})
