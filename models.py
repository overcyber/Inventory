from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)

class HostInventory(db.Model):
    __tablename__ = 'host_inventory'
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    data = db.Column(JSONB, nullable=False)
    is_legacy = db.Column(db.Boolean, default=True)

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    data = db.Column(JSONB, nullable=False)
    is_legacy = db.Column(db.Boolean, default=True)

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(JSONB, nullable=False)

class Notification(db.Model):

    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(160), nullable=False, index=True)
    kind = db.Column(db.String(40), nullable=False)
    params = db.Column(JSONB, nullable=False, default=dict)
    category = db.Column(db.String(20), nullable=False, default='system')
    severity = db.Column(db.String(10), nullable=False, default='info')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read = db.Column(db.Boolean, default=False, index=True)

class ChatMessage(db.Model):

    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    role = db.Column(db.String(10), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class NetscopeDevice(db.Model):

    __tablename__ = 'netscope_devices'
    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(20), unique=True, nullable=True, index=True)
    ip = db.Column(db.String(64), default='')
    hostname = db.Column(db.String(255), default='')
    deleted = db.Column(db.Boolean, default=False, index=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    data = db.Column(JSONB, nullable=False)

class NetscopeSetting(db.Model):

    __tablename__ = 'netscope_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(JSONB, nullable=False)

class NetscopeSnapshot(db.Model):

    __tablename__ = 'netscope_snapshots'
    snap_id = db.Column(db.String(64), primary_key=True)
    label = db.Column(db.String(255), default='')
    notes = db.Column(db.Text, default='')
    auto = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.String(40))
    device_count = db.Column(db.Integer, default=0)
    link_count = db.Column(db.Integer, default=0)
    data = db.Column(JSONB, nullable=False)

class NetscopeScanHistory(db.Model):

    __tablename__ = 'netscope_scan_history'
    id = db.Column(db.Integer, primary_key=True)
    device_uid = db.Column(db.String(40), nullable=False, index=True)
    hostname = db.Column(db.String(255), default='')
    ip = db.Column(db.String(64), default='')
    status = db.Column(db.String(10), default='done')
    started_at = db.Column(db.String(40))
    finished_at = db.Column(db.String(40))
    duration_s = db.Column(db.Float, default=0)
    tcp_count = db.Column(db.Integer, default=0)
    udp_count = db.Column(db.Integer, default=0)
    udp_closed = db.Column(db.Integer, default=0)
    error = db.Column(db.Text, default='')
    results = db.Column(JSONB, nullable=False)


# ---------------------------------------------------------------------------
# Asset Core v0.19 — canonical multi-source asset model.
# HostInventory remains for backward compatibility during migration.
# ---------------------------------------------------------------------------

class Asset(db.Model):
    __tablename__ = 'assets'
    id = db.Column(db.Integer, primary_key=True)
    asset_uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    canonical_name = db.Column(db.String(255), nullable=False, index=True)
    status = db.Column(db.String(32), nullable=False, default='Desconhecido', index=True)
    agent_status = db.Column(db.String(32), nullable=False, default='unknown', index=True)
    network_status = db.Column(db.String(32), nullable=False, default='unknown', index=True)
    inventory_freshness_seconds = db.Column(db.Integer, nullable=True)
    confidence = db.Column(db.Float, nullable=False, default=0.5)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_observed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    current_state = db.Column(JSONB, nullable=False, default=dict)

    identifiers = db.relationship('AssetIdentifier', back_populates='asset',
                                  cascade='all, delete-orphan')
    observations = db.relationship('AssetObservation', back_populates='asset',
                                   cascade='all, delete-orphan')


class AssetIdentifier(db.Model):
    __tablename__ = 'asset_identifiers'
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    kind = db.Column(db.String(64), nullable=False, index=True)
    value = db.Column(db.String(512), nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, default='unknown')
    confidence = db.Column(db.Float, nullable=False, default=0.5)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    asset = db.relationship('Asset', back_populates='identifiers')


class AssetObservation(db.Model):
    __tablename__ = 'asset_observations'
    id = db.Column(db.BigInteger, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    external_id = db.Column(db.String(512), nullable=False, default='', index=True)
    observed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False,
                            index=True)
    content_hash = db.Column(db.String(64), nullable=False, index=True)
    raw_data = db.Column(JSONB, nullable=False, default=dict)
    normalized_data = db.Column(JSONB, nullable=False, default=dict)
    asset = db.relationship('Asset', back_populates='observations')


class AssetSnapshot(db.Model):
    __tablename__ = 'asset_snapshots'
    id = db.Column(db.BigInteger, primary_key=True)
    snapshot_uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    observed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False,
                            index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    state = db.Column(JSONB, nullable=False, default=dict)


class AssetChange(db.Model):
    __tablename__ = 'asset_changes'
    id = db.Column(db.BigInteger, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    observed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False,
                            index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    path = db.Column(db.String(512), nullable=False, index=True)
    old_value = db.Column(JSONB, nullable=False, default=dict)
    new_value = db.Column(JSONB, nullable=False, default=dict)



class AssetAddress(db.Model):
    __tablename__ = 'asset_addresses'
    id = db.Column(db.BigInteger, primary_key=True)
    entity_key = db.Column(db.String(128), nullable=False, default='', index=True)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    valid_to = db.Column(db.DateTime, nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    address = db.Column(db.String(128), nullable=False, index=True)
    family = db.Column(db.String(16), nullable=False, default='')
    interface_name = db.Column(db.String(128), nullable=False, default='')
    source = db.Column(db.String(64), nullable=False, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AssetInterface(db.Model):
    __tablename__ = 'asset_interfaces'
    id = db.Column(db.BigInteger, primary_key=True)
    entity_key = db.Column(db.String(128), nullable=False, default='', index=True)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    name = db.Column(db.String(128), nullable=False, default='')
    mac = db.Column(db.String(32), nullable=False, default='', index=True)
    state = db.Column(db.String(32), nullable=False, default='')
    mtu = db.Column(db.String(32), nullable=False, default='')
    interface_type = db.Column(db.String(64), nullable=False, default='')
    source = db.Column(db.String(64), nullable=False, index=True)
    data = db.Column(JSONB, nullable=False, default=dict)


class AssetHardware(db.Model):
    __tablename__ = 'asset_hardware'
    id = db.Column(db.BigInteger, primary_key=True)
    entity_key = db.Column(db.String(128), nullable=False, default='', index=True)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    serial = db.Column(db.String(255), nullable=False, default='', index=True)
    cpu_name = db.Column(db.String(512), nullable=False, default='')
    cpu_cores = db.Column(db.String(32), nullable=False, default='')
    ram_total = db.Column(db.BigInteger, nullable=True)
    data = db.Column(JSONB, nullable=False, default=dict)


class AssetSoftware(db.Model):
    __tablename__ = 'asset_software'
    id = db.Column(db.BigInteger, primary_key=True)
    entity_key = db.Column(db.String(128), nullable=False, default='', index=True)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    valid_to = db.Column(db.DateTime, nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    name = db.Column(db.String(512), nullable=False, index=True)
    version = db.Column(db.String(255), nullable=False, default='')
    architecture = db.Column(db.String(128), nullable=False, default='')
    package_format = db.Column(db.String(64), nullable=False, default='')
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AssetProcess(db.Model):
    __tablename__ = 'asset_processes'
    id = db.Column(db.BigInteger, primary_key=True)
    entity_key = db.Column(db.String(128), nullable=False, default='', index=True)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    pid = db.Column(db.String(32), nullable=False, default='')
    name = db.Column(db.String(512), nullable=False, default='', index=True)
    user_name = db.Column(db.String(255), nullable=False, default='')
    command = db.Column(db.Text, nullable=False, default='')
    state = db.Column(db.String(64), nullable=False, default='')


class AssetService(db.Model):
    __tablename__ = 'asset_services'
    id = db.Column(db.BigInteger, primary_key=True)
    entity_key = db.Column(db.String(128), nullable=False, default='', index=True)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    name = db.Column(db.String(512), nullable=False, default='', index=True)
    state = db.Column(db.String(64), nullable=False, default='')
    start_type = db.Column(db.String(128), nullable=False, default='')
    data = db.Column(JSONB, nullable=False, default=dict)


class AssetPort(db.Model):
    __tablename__ = 'asset_ports'
    id = db.Column(db.BigInteger, primary_key=True)
    entity_key = db.Column(db.String(128), nullable=False, default='', index=True)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    protocol = db.Column(db.String(16), nullable=False, default='')
    address = db.Column(db.String(128), nullable=False, default='')
    port = db.Column(db.Integer, nullable=True, index=True)
    state = db.Column(db.String(64), nullable=False, default='')
    process_name = db.Column(db.String(512), nullable=False, default='')
    pid = db.Column(db.String(32), nullable=False, default='')




class AssetSourceState(db.Model):
    __tablename__ = 'asset_source_states'
    __table_args__ = (UniqueConstraint('asset_id','source','external_id',
                                       name='uq_asset_source_external'),)
    id = db.Column(db.BigInteger, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id', ondelete='CASCADE'),
                         nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, index=True)
    external_id = db.Column(db.String(512), nullable=False, default='', index=True)
    confidence = db.Column(db.Float, nullable=False, default=0.5)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    observed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    state = db.Column(JSONB, nullable=False, default=dict)


class AssetIdentityConflict(db.Model):
    __tablename__ = 'asset_identity_conflicts'
    id = db.Column(db.BigInteger, primary_key=True)
    kind = db.Column(db.String(64), nullable=False, index=True)
    value = db.Column(db.String(512), nullable=False, index=True)
    source = db.Column(db.String(64), nullable=False, default='')
    candidate_asset_ids = db.Column(JSONB, nullable=False, default=list)
    observed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    resolved = db.Column(db.Boolean, nullable=False, default=False, index=True)


class AssetOutbox(db.Model):
    __tablename__ = 'asset_outbox'
    id = db.Column(db.BigInteger, primary_key=True)
    event_uuid = db.Column(db.String(36), nullable=False, unique=True, index=True)
    topic = db.Column(db.String(255), nullable=False, default='asset.snapshot.v1')
    event_key = db.Column(db.String(255), nullable=False, default='', index=True)
    payload = db.Column(JSONB, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending', index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    next_attempt_at = db.Column(db.DateTime, nullable=True, index=True)
    last_error = db.Column(db.Text, nullable=False, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    published_at = db.Column(db.DateTime, nullable=True)


class AssetDeadLetter(db.Model):
    __tablename__ = 'asset_dead_letters'
    id = db.Column(db.BigInteger, primary_key=True)
    event_uuid = db.Column(db.String(36), nullable=False, index=True)
    topic = db.Column(db.String(255), nullable=False)
    event_key = db.Column(db.String(255), nullable=False, default='')
    payload = db.Column(JSONB, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    last_error = db.Column(db.Text, nullable=False, default='')
    failed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)


class ApiToken(db.Model):
    __tablename__ = 'api_tokens'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    scopes = db.Column(JSONB, nullable=False, default=list)
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)

class InventorySourceState(db.Model):
    __tablename__ = 'inventory_source_states'
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(64), unique=True, nullable=False, index=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    last_run = db.Column(db.DateTime, nullable=True)
    last_success = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32), nullable=False, default='unknown')
    last_error = db.Column(db.Text, nullable=False, default='')
    metadata_json = db.Column(JSONB, nullable=False, default=dict)
