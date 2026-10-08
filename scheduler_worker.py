from __future__ import annotations
import os, signal, time
os.environ.setdefault('INVENTORY_SCHEDULER_ENABLED','false')
os.environ.setdefault('NETSCOPE_BACKGROUND_ENABLED','false')
from core.app import create_app
from services.inventory_sources import sync_configured_sources
from services.asset_core import refresh_asset_liveness

app=create_app()
stopping=False
def _stop(*_):
    global stopping; stopping=True
signal.signal(signal.SIGTERM,_stop); signal.signal(signal.SIGINT,_stop)
interval=max(60,int(os.getenv('SOURCE_SYNC_INTERVAL','3600')))
next_run=0.0
while not stopping:
    now=time.monotonic()
    if now >= next_run:
        with app.app_context():
            try:
                result=sync_configured_sources(app)
                refresh_asset_liveness()
                try:
                    from services.notifications import evaluate_all
                    evaluate_all(app,logger=app.logger)
                except Exception:
                    app.logger.exception('[Scheduler] notificações falharam')
                app.logger.info('[Scheduler] fontes: %s',result)
            except Exception:
                app.logger.exception('[Scheduler] ciclo falhou')
        next_run=time.monotonic()+interval
    time.sleep(min(5,max(1,next_run-time.monotonic())))
