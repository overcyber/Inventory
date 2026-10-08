from __future__ import annotations

import os
from pathlib import Path

def upgrade_database(logger=None) -> None:
    """Apply Alembic migrations before ORM access.

    This replaces the historical db.create_all() bootstrap. It is safe to call
    repeatedly; Alembic serializes schema state through alembic_version.
    """
    if (os.getenv('INVENTORY_AUTO_MIGRATE','true').strip().lower()
            not in ('1','true','yes','on','sim')):
        return
    from alembic import command
    from alembic.config import Config
    root=Path(__file__).resolve().parents[1]
    cfg=Config(str(root/'alembic.ini'))
    cfg.set_main_option('script_location',str(root/'migrations'))
    command.upgrade(cfg,'head')
    if logger:
        logger.info('[DB] Alembic upgrade head concluído.')
