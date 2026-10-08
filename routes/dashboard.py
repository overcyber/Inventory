
from __future__ import annotations

from flask import current_app, jsonify, redirect, render_template, session, url_for

from core.config import APP_VERSION
from core.security import login_required
from services.stats import (
    get_cached_stats, get_cached_machines, build_chart_response,
)

ROUTES = [
    ('/', 'dashboard', 'dashboard', {}),
    ('/dashboard', 'dashboard', 'dashboard', {}),
    ('/get_chart_data', 'get_chart_data', 'get_chart_data', {}),
    ('/health', 'health', 'health', {}),
    ('/ready', 'ready', 'ready', {}),
]

def _app():

    return current_app._get_current_object()

@login_required
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    app = _app()
    stats = get_cached_stats()

    ns_total = ns_with_agent = ns_without_agent = ns_agent_exempt = 0
    try:
        from services.netscope_core import store
        ns_stats = store.stats()
        ns_total = ns_stats.get('total', 0)
        ns_with_agent = ns_stats.get('with_agent', 0)
        ns_without_agent = ns_stats.get('without_agent', 0)
        ns_agent_exempt = ns_stats.get('agent_exempt', 0)
    except Exception as e:
        app.logger.debug(f"[Dashboard] NetScope stats indisponíveis: {e}")

    db_layout = None
    try:
        from models import SystemSetting
        row = SystemSetting.query.filter_by(key='dashboard_layout').first()
        if row and isinstance(row.value, dict):
            saved = row.value.get(session.get('username', ''))
            if isinstance(saved, dict) and isinstance(saved.get('containers'), list):
                import json as _json
                db_layout = _json.dumps(saved)
    except Exception:
        db_layout = None

    return render_template('dashboard.html',
                           stats=stats,
                           active_count=stats['status']['Ativo'],
                           inactive_count=stats['status']['Inativo'],
                           ns_total=ns_total,
                           ns_with_agent=ns_with_agent,
                           ns_without_agent=ns_without_agent,
                           ns_agent_exempt=ns_agent_exempt,
                           db_layout=db_layout)

def get_chart_data():
    if 'username' not in session:
        return redirect(url_for('login'))

    app = _app()
    stats = get_cached_stats()
    machines = get_cached_machines()
    try:
        response_data = build_chart_response(stats, machines)
        return jsonify(response_data)
    except Exception as e:
        app.logger.error(f"Erro crítico em /get_chart_data: {e}")
        return jsonify({'error': str(e), 'os_labels': [], 'os_data': []}), 500

def _health_payload():
    from datetime import datetime
    from sqlalchemy import text
    from models import AssetOutbox, db
    from utils import cache as shared_cache
    db_ok=True; db_error=''
    try:
        db.session.execute(text('SELECT 1'))
    except Exception as exc:
        db.session.rollback(); db_ok=False; db_error=str(exc)
    try:
        pending=AssetOutbox.query.filter(AssetOutbox.status.in_(('pending','retry','processing'))).count() if db_ok else None
    except Exception:
        pending=None
    return {'status':'ok' if db_ok else 'degraded','app':'inventory',
            'version':APP_VERSION,'database':{'ok':db_ok,'error':db_error[:500]},
            'cache':shared_cache.ping(),'outbox_pending':pending,
            'time':datetime.now().isoformat(timespec='seconds')}

def health():
    payload=_health_payload()
    return jsonify(payload),200 if payload['database']['ok'] else 503

def ready():
    payload=_health_payload()
    return jsonify(payload),200 if payload['database']['ok'] else 503
