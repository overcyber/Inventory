from __future__ import annotations

import os
import time

os.environ.setdefault('INVENTORY_SCHEDULER_ENABLED', 'false')
os.environ.setdefault('NETSCOPE_BACKGROUND_ENABLED', 'false')

from core.app import create_app
from services.inventory_sources import sync_configured_sources

app = create_app()
interval = max(60, int(os.getenv('SOURCE_SYNC_INTERVAL', '3600')))

while True:
    with app.app_context():
        try:
            app.logger.info('[Worker] iniciando sincronização multifuente')
            result = sync_configured_sources(app)
            app.logger.info('[Worker] sincronização concluída: %s', result)
        except Exception as exc:
            app.logger.exception('[Worker] ciclo falhou: %s', exc)
    time.sleep(interval)
