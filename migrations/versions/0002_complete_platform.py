"""Complete Asset Intelligence platform schema.

Revision ID: 0002_complete_platform
Revises: 0001_asset_core
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text
from sqlalchemy.dialects import postgresql

revision = '0002_complete_platform'
down_revision = '0001_asset_core'
branch_labels = None
depends_on = None

def _tables():
    return set(inspect(op.get_bind()).get_table_names())

def _columns(table):
    if table not in _tables():
        return set()
    return {c['name'] for c in inspect(op.get_bind()).get_columns(table)}

def _add(table, column, ddl):
    if table in _tables() and column not in _columns(table):
        op.execute(text(f'ALTER TABLE {table} ADD COLUMN {ddl}'))

def _create(name, *cols, **kw):
    if name not in _tables():
        op.create_table(name, *cols, **kw)

def _index(name, table, cols, unique=False):
    if table not in _tables():
        return
    names={i['name'] for i in inspect(op.get_bind()).get_indexes(table)}
    if name not in names:
        op.create_index(name, table, cols, unique=unique)

def upgrade():
    # Legacy schema previously created implicitly by db.create_all().
    _create('users',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('username',sa.String(80),nullable=False,unique=True),
        sa.Column('full_name',sa.String(120)),
        sa.Column('password_hash',sa.String(120),nullable=False),
        sa.Column('role',sa.String(20),nullable=False,server_default='user'),
        sa.Column('mfa_enabled',sa.Boolean(),server_default=sa.false()),
        sa.Column('mfa_secret',sa.String(32)),
        sa.Column('must_change_password',sa.Boolean(),server_default=sa.false()))
    _create('host_inventory',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('hostname',sa.String(255),nullable=False,unique=True),
        sa.Column('last_updated',sa.DateTime()),
        sa.Column('data',postgresql.JSONB(),nullable=False),
        sa.Column('is_legacy',sa.Boolean(),server_default=sa.true()))
    _create('groups',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('name',sa.String(80),nullable=False,unique=True),
        sa.Column('data',postgresql.JSONB(),nullable=False),
        sa.Column('is_legacy',sa.Boolean(),server_default=sa.true()))
    _create('system_settings',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('key',sa.String(50),nullable=False,unique=True),
        sa.Column('value',postgresql.JSONB(),nullable=False))
    _create('notifications',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('key',sa.String(160),nullable=False),
        sa.Column('kind',sa.String(40),nullable=False),
        sa.Column('params',postgresql.JSONB(),nullable=False),
        sa.Column('category',sa.String(20),nullable=False,server_default='system'),
        sa.Column('severity',sa.String(10),nullable=False,server_default='info'),
        sa.Column('created_at',sa.DateTime()),
        sa.Column('read',sa.Boolean(),server_default=sa.false()))
    _create('chat_messages',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('username',sa.String(80),nullable=False),
        sa.Column('role',sa.String(10),nullable=False),
        sa.Column('content',sa.Text(),nullable=False),
        sa.Column('created_at',sa.DateTime()))
    _create('netscope_devices',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('mac',sa.String(20),unique=True),
        sa.Column('ip',sa.String(64),server_default=''),
        sa.Column('hostname',sa.String(255),server_default=''),
        sa.Column('deleted',sa.Boolean(),server_default=sa.false()),
        sa.Column('last_seen',sa.DateTime()),
        sa.Column('data',postgresql.JSONB(),nullable=False))
    _create('netscope_settings',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('key',sa.String(50),nullable=False,unique=True),
        sa.Column('value',postgresql.JSONB(),nullable=False))
    _create('netscope_snapshots',
        sa.Column('snap_id',sa.String(64),primary_key=True),
        sa.Column('label',sa.String(255),server_default=''),
        sa.Column('notes',sa.Text(),server_default=''),
        sa.Column('auto',sa.Boolean(),server_default=sa.false()),
        sa.Column('created_at',sa.String(40)),
        sa.Column('device_count',sa.Integer(),server_default='0'),
        sa.Column('link_count',sa.Integer(),server_default='0'),
        sa.Column('data',postgresql.JSONB(),nullable=False))
    _create('netscope_scan_history',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('device_uid',sa.String(40),nullable=False),
        sa.Column('hostname',sa.String(255),server_default=''),
        sa.Column('ip',sa.String(64),server_default=''),
        sa.Column('status',sa.String(10),server_default='done'),
        sa.Column('started_at',sa.String(40)),
        sa.Column('finished_at',sa.String(40)),
        sa.Column('duration_s',sa.Float(),server_default='0'),
        sa.Column('tcp_count',sa.Integer(),server_default='0'),
        sa.Column('udp_count',sa.Integer(),server_default='0'),
        sa.Column('udp_closed',sa.Integer(),server_default='0'),
        sa.Column('error',sa.Text(),server_default=''),
        sa.Column('results',postgresql.JSONB(),nullable=False))

    for table in ('asset_addresses','asset_interfaces','asset_hardware',
                  'asset_software','asset_processes','asset_services','asset_ports'):
        _add(table,'entity_key',"entity_key VARCHAR(128) NOT NULL DEFAULT ''")
        _add(table,'active',"active BOOLEAN NOT NULL DEFAULT TRUE")
        _add(table,'first_seen',"first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP")
        _add(table,'last_seen',"last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP")
        _add(table,'valid_to',"valid_to TIMESTAMP NULL")
        _index(f'ix_{table}_entity_key',table,['entity_key'])
        _index(f'ix_{table}_active',table,['active'])

    # Remove old address uniqueness only when it exists.
    if 'asset_addresses' in _tables():
        uniques={u.get('name') for u in inspect(op.get_bind()).get_unique_constraints('asset_addresses')}
        if 'uq_asset_address_source' in uniques:
            op.drop_constraint('uq_asset_address_source','asset_addresses',type_='unique')

    _create('asset_source_states',
        sa.Column('id',sa.BigInteger(),primary_key=True),
        sa.Column('asset_id',sa.Integer(),sa.ForeignKey('assets.id',ondelete='CASCADE'),nullable=False),
        sa.Column('source',sa.String(64),nullable=False),
        sa.Column('external_id',sa.String(512),nullable=False,server_default=''),
        sa.Column('confidence',sa.Float(),nullable=False,server_default='0.5'),
        sa.Column('first_seen',sa.DateTime(),nullable=False),
        sa.Column('last_seen',sa.DateTime(),nullable=False),
        sa.Column('observed_at',sa.DateTime(),nullable=False),
        sa.Column('state',postgresql.JSONB(),nullable=False),
        sa.UniqueConstraint('asset_id','source','external_id',name='uq_asset_source_external'))
    _index('ix_asset_source_states_asset_id','asset_source_states',['asset_id'])
    _index('ix_asset_source_states_source','asset_source_states',['source'])
    _index('ix_asset_source_states_external_id','asset_source_states',['external_id'])
    _index('ix_asset_source_states_last_seen','asset_source_states',['last_seen'])

    _create('asset_identity_conflicts',
        sa.Column('id',sa.BigInteger(),primary_key=True),
        sa.Column('kind',sa.String(64),nullable=False),
        sa.Column('value',sa.String(512),nullable=False),
        sa.Column('source',sa.String(64),nullable=False,server_default=''),
        sa.Column('candidate_asset_ids',postgresql.JSONB(),nullable=False),
        sa.Column('observed_at',sa.DateTime(),nullable=False),
        sa.Column('resolved',sa.Boolean(),nullable=False,server_default=sa.false()))
    _index('ix_asset_identity_conflicts_kind','asset_identity_conflicts',['kind'])
    _index('ix_asset_identity_conflicts_value','asset_identity_conflicts',['value'])
    _index('ix_asset_identity_conflicts_resolved','asset_identity_conflicts',['resolved'])

    _create('asset_outbox',
        sa.Column('id',sa.BigInteger(),primary_key=True),
        sa.Column('event_uuid',sa.String(36),nullable=False,unique=True),
        sa.Column('topic',sa.String(255),nullable=False,server_default='asset.snapshot.v1'),
        sa.Column('event_key',sa.String(255),nullable=False,server_default=''),
        sa.Column('payload',postgresql.JSONB(),nullable=False),
        sa.Column('status',sa.String(20),nullable=False,server_default='pending'),
        sa.Column('attempts',sa.Integer(),nullable=False,server_default='0'),
        sa.Column('next_attempt_at',sa.DateTime()),
        sa.Column('last_error',sa.Text(),nullable=False,server_default=''),
        sa.Column('created_at',sa.DateTime(),nullable=False),
        sa.Column('published_at',sa.DateTime()))
    _index('ix_asset_outbox_status','asset_outbox',['status'])
    _index('ix_asset_outbox_next_attempt_at','asset_outbox',['next_attempt_at'])

    _create('asset_dead_letters',
        sa.Column('id',sa.BigInteger(),primary_key=True),
        sa.Column('event_uuid',sa.String(36),nullable=False),
        sa.Column('topic',sa.String(255),nullable=False),
        sa.Column('event_key',sa.String(255),nullable=False,server_default=''),
        sa.Column('payload',postgresql.JSONB(),nullable=False),
        sa.Column('attempts',sa.Integer(),nullable=False,server_default='0'),
        sa.Column('last_error',sa.Text(),nullable=False,server_default=''),
        sa.Column('failed_at',sa.DateTime(),nullable=False))
    _index('ix_asset_dead_letters_event_uuid','asset_dead_letters',['event_uuid'])

    _create('api_tokens',
        sa.Column('id',sa.Integer(),primary_key=True),
        sa.Column('name',sa.String(120),nullable=False,unique=True),
        sa.Column('token_hash',sa.String(64),nullable=False,unique=True),
        sa.Column('scopes',postgresql.JSONB(),nullable=False),
        sa.Column('active',sa.Boolean(),nullable=False,server_default=sa.true()),
        sa.Column('created_at',sa.DateTime(),nullable=False),
        sa.Column('expires_at',sa.DateTime()),
        sa.Column('last_used_at',sa.DateTime()))
    _index('ix_api_tokens_token_hash','api_tokens',['token_hash'],unique=True)

    # Drop global identifier uniqueness so shared/reused MACs do not force merges.
    if 'asset_identifiers' in _tables():
        uniques={u.get('name') for u in inspect(op.get_bind()).get_unique_constraints('asset_identifiers')}
        if 'uq_asset_identifier_kind_value' in uniques:
            op.drop_constraint('uq_asset_identifier_kind_value','asset_identifiers',type_='unique')
    _index('ix_asset_identifiers_kind_value','asset_identifiers',['kind','value'])
    op.execute(text('DROP TABLE IF EXISTS report_history'))

def downgrade():
    for name in ('api_tokens','asset_dead_letters','asset_outbox',
                 'asset_identity_conflicts','asset_source_states'):
        if name in _tables():
            op.drop_table(name)
