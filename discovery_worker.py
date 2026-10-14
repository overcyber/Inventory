from __future__ import annotations

import os
import time

os.environ.setdefault('INVENTORY_SCHEDULER_ENABLED', 'false')
os.environ.setdefault('NETSCOPE_BACKGROUND_ENABLED', 'false')

from core.app import create_app
from services.netscope_core import load_config
from services.netscope_engine import run_scan, local_scan_result
from services.netscope_scan_control import claim_scan, begin_scan, finish_scan

app = create_app()
interval = max(300, int(os.getenv('NETSCOPE_DISCOVERY_INTERVAL', '900')))
next_automatic = time.monotonic()

while True:
    with app.app_context():
        try:
            job = claim_scan()
            if job:
                try:
                    begin_scan(job)
                    cfg = load_config()
                    networks = cfg.get('networks') or []
                    if not networks:
                        raise ValueError('Nenhuma rede configurada')
                    run_scan(app, networks, cfg.get('scan') or {},
                             auto_snapshot=bool(job.get('auto_snapshot')))
                    result = local_scan_result()
                    finish_scan(job, result=result)
                    app.logger.info('[Discovery] scan manual concluído: %s', result)
                except Exception as exc:
                    app.logger.exception('[Discovery] scan manual falhou: %s', exc)
                    finish_scan(job, error=str(exc))
            elif time.monotonic() >= next_automatic:
                try:
                    cfg = load_config()
                    networks = cfg.get('networks') or []
                    if networks:
                        run_scan(app, networks, cfg.get('scan') or {},
                                 auto_snapshot=True)
                        app.logger.info('[Discovery] scan periódico: %s',
                                        local_scan_result())
                finally:
                    next_automatic = time.monotonic() + interval
        except Exception as exc:
            app.logger.exception('[Discovery] ciclo falhou: %s', exc)
            next_automatic = time.monotonic() + 30
    time.sleep(2)
