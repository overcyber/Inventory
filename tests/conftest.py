import os
os.environ.setdefault('DB_USER','inventory_test')
os.environ.setdefault('DB_PASS','inventory_test_password')
os.environ.setdefault('DB_HOST','127.0.0.1')
os.environ.setdefault('DB_PORT','5432')
os.environ.setdefault('DB_NAME','inventory_test')
os.environ.setdefault('REDIS_URL','redis://127.0.0.1:6379/15')
os.environ.setdefault('SECRET_KEY','test-secret-key-0123456789abcdef0123456789abcdef')
os.environ.setdefault('SESSION_SALT','test-session-salt-0123456789abcdef')
os.environ.setdefault('ADMIN_PASSWORD','TestAdmin-ChangeMe-9842')
os.environ.setdefault('ADMIN_MUST_CHANGE_PASSWORD','false')
os.environ.setdefault('USE_HTTPS','false')
os.environ.setdefault('WAZUH_ENABLED','false')
os.environ.setdefault('NETSCOPE_BACKGROUND_ENABLED','false')
os.environ.setdefault('INVENTORY_SCHEDULER_ENABLED','false')
os.environ.setdefault('ASSET_BACKFILL_LEGACY','false')
os.environ.setdefault('KAFKA_BOOTSTRAP_SERVERS','')
os.environ.setdefault('ASSET_WEBHOOK_URLS','')

import pytest
from sqlalchemy import text
from core.app import create_app
from models import db

@pytest.fixture(scope='session')
def app():
    app=create_app()
    app.config.update(TESTING=True)
    return app

@pytest.fixture(autouse=True)
def clean_asset_tables(app):
    with app.app_context():
        db.session.execute(text("""TRUNCATE TABLE asset_dead_letters,asset_outbox,asset_identity_conflicts,asset_changes,asset_snapshots,asset_observations,asset_source_states,asset_ports,asset_services,asset_processes,asset_software,asset_hardware,asset_interfaces,asset_addresses,asset_identifiers,assets RESTART IDENTITY CASCADE"""))
        db.session.commit()
    yield
