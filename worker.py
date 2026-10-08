from __future__ import annotations
import os, signal, time
os.environ.setdefault('INVENTORY_SCHEDULER_ENABLED','false')
os.environ.setdefault('NETSCOPE_BACKGROUND_ENABLED','false')
from core.app import create_app
from services.integrations import flush_outbox

app=create_app()
stopping=False
def _stop(*_):
    global stopping; stopping=True
signal.signal(signal.SIGTERM,_stop); signal.signal(signal.SIGINT,_stop)
poll=max(1,float(os.getenv('OUTBOX_POLL_SECONDS','2')))
batch=max(1,int(os.getenv('OUTBOX_BATCH_SIZE','200')))
while not stopping:
    with app.app_context():
        try:
            result=flush_outbox(batch)
            if result.get('published') or result.get('retry') or result.get('dead'):
                app.logger.info('[Outbox] %s',result)
        except Exception:
            app.logger.exception('[Outbox] ciclo falhou')
    time.sleep(poll)
