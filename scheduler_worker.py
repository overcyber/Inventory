from __future__ import annotations

import signal
import time

from core.app import create_app
from services.asset_core import refresh_asset_liveness
from services.inventory_sources import sync_configured_sources
from services.source_scheduler import (
    get_source_schedules,
    schedule_signature,
)

app = create_app()
stopping = False


def _stop(*_):
    global stopping
    stopping = True


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)

poll_seconds = 5.0
next_due: dict[str, float] = {}
last_signature = None

while not stopping:
    now = time.monotonic()
    with app.app_context():
        try:
            schedules = get_source_schedules(persist=True)
            signature = schedule_signature(schedules)

            if signature != last_signature:
                first_load = last_signature is None
                for name, cfg in schedules.items():
                    if not cfg['enabled']:
                        next_due.pop(name, None)
                        continue
                    # First boot preserves the old behaviour: collect now.
                    # A settings change restarts the countdown from Save.
                    next_due[name] = now if first_load else (
                        now + int(cfg['interval_seconds']))
                last_signature = signature
                app.logger.info(
                    '[Scheduler] agenda multifuente atualizada: %s',
                    schedules)

            due = [
                name for name, cfg in schedules.items()
                if cfg['enabled'] and now >= next_due.get(name, now)
            ]

            for name in due:
                cfg = schedules[name]
                app.logger.info(
                    '[Scheduler] executando fonte %s (intervalo=%ss)',
                    name, cfg['interval_seconds'])
                sync_configured_sources(
                    app,
                    only=[name],
                    enabled_overrides={name: True},
                )
                next_due[name] = (
                    time.monotonic() + int(cfg['interval_seconds']))

            if due:
                refresh_asset_liveness()
                try:
                    from services.notifications import evaluate_all
                    evaluate_all(app, logger=app.logger)
                except Exception:
                    app.logger.exception(
                        '[Scheduler] notificações falharam')
        except Exception:
            app.logger.exception('[Scheduler] ciclo falhou')

    time.sleep(poll_seconds)
