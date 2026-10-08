from __future__ import annotations

import os
import time

os.environ.setdefault('INVENTORY_SCHEDULER_ENABLED', 'false')
os.environ.setdefault('NETSCOPE_BACKGROUND_ENABLED', 'false')

from core.app import create_app
from services.netscope_core import load_config
from services.netscope_engine import run_scan

app = create_app()
interval = max(300, int(os.getenv('NETSCOPE_DISCOVERY_INTERVAL', '900')))

while True:
    with app.app_context():
        try:
            cfg = load_config()
            networks = cfg.get('networks') or []
            if networks:
                run_scan(app, networks, cfg.get('scan') or {}, auto_snapshot=True)
        except Exception as exc:
            app.logger.exception('[Discovery] ciclo falhou: %s', exc)
    time.sleep(interval)
