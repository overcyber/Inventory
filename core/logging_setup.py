from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler


def _stream_handler(level: int, formatter: logging.Formatter) -> logging.Handler:
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    handler._inventory_handler = True
    return handler


def _file_handler(path: str, level: int, formatter: logging.Formatter):
    handler = RotatingFileHandler(
        path, maxBytes=10 * 1024 * 1024, backupCount=5)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    handler._inventory_handler = True
    return handler


def _clear_inventory_handlers(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        if getattr(handler, '_inventory_handler', False):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass


def setup_logging(app, log_dir: str) -> None:
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    security_formatter = logging.Formatter(
        '%(asctime)s - SECURITY - %(message)s')
    audit_formatter = logging.Formatter('%(asctime)s - %(message)s')

    app.logger.setLevel(logging.DEBUG)
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False
    audit_logger = logging.getLogger('audit')
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

    _clear_inventory_handlers(app.logger)
    _clear_inventory_handlers(security_logger)
    _clear_inventory_handlers(audit_logger)

    try:
        os.makedirs(log_dir, exist_ok=True)
        # Verify write access before constructing five file handlers.
        probe = os.path.join(log_dir, '.inventory-write-test')
        with open(probe, 'a', encoding='utf-8'):
            pass
        try:
            os.unlink(probe)
        except OSError:
            pass

        for name, level in (
            ('info.log', logging.INFO),
            ('warning.log', logging.WARNING),
            ('error.log', logging.ERROR),
        ):
            app.logger.addHandler(_file_handler(
                os.path.join(log_dir, name), level, formatter))

        security_logger.addHandler(_file_handler(
            os.path.join(log_dir, 'security.log'),
            logging.INFO, security_formatter))
        audit_logger.addHandler(_file_handler(
            os.path.join(log_dir, 'audit.log'),
            logging.INFO, audit_formatter))
    except OSError as exc:
        # A bind-mounted ./logs may be owned by root while the app runs as
        # UID 10001. Logging must never prevent the application from booting.
        app.logger.addHandler(_stream_handler(logging.INFO, formatter))
        security_logger.addHandler(
            _stream_handler(logging.INFO, security_formatter))
        audit_logger.addHandler(
            _stream_handler(logging.INFO, audit_formatter))
        app.logger.warning(
            "[Logging] %s não é gravável (%s); usando stderr.",
            log_dir, exc)
