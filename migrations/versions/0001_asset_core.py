"""Asset Core multifuente e histórico temporal.

Revision ID: 0001_asset_core
Revises: None
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001_asset_core'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('assets',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('asset_uuid', sa.String(36), nullable=False, unique=True),
        sa.Column('canonical_name', sa.String(255), nullable=False),
        sa.Column('status', sa.String(32), nullable=False, server_default='Desconhecido'),
        sa.Column('agent_status', sa.String(32), nullable=False, server_default='unknown'),
        sa.Column('network_status', sa.String(32), nullable=False, server_default='unknown'),
        sa.Column('inventory_freshness_seconds', sa.Integer()),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('current_state', postgresql.JSONB(astext_type=sa.Text()), nullable=False))
    op.create_index('ix_assets_asset_uuid', 'assets', ['asset_uuid'], unique=True)
    op.create_index('ix_assets_canonical_name', 'assets', ['canonical_name'])
    op.create_index('ix_assets_last_seen', 'assets', ['last_seen'])
    op.create_table('asset_identifiers',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('value', sa.String(512), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('kind', 'value', name='uq_asset_identifier_kind_value'))
    op.create_index('ix_asset_identifiers_asset_id', 'asset_identifiers', ['asset_id'])
    op.create_index('ix_asset_identifiers_kind_value', 'asset_identifiers', ['kind', 'value'])
    op.create_table('asset_observations',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('external_id', sa.String(512), nullable=False, server_default=''),
        sa.Column('observed_at', sa.DateTime(), nullable=False),
        sa.Column('content_hash', sa.String(64), nullable=False),
        sa.Column('raw_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('normalized_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False))
    op.create_index('ix_asset_observations_asset_id', 'asset_observations', ['asset_id'])
    op.create_index('ix_asset_observations_source_external', 'asset_observations', ['source', 'external_id'])
    op.create_index('ix_asset_observations_content_hash', 'asset_observations', ['content_hash'])
    op.create_table('asset_snapshots',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('snapshot_uuid', sa.String(36), nullable=False, unique=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('observed_at', sa.DateTime(), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('state', postgresql.JSONB(astext_type=sa.Text()), nullable=False))
    op.create_index('ix_asset_snapshots_asset_id', 'asset_snapshots', ['asset_id'])
    op.create_table('asset_changes',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('observed_at', sa.DateTime(), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('path', sa.String(512), nullable=False),
        sa.Column('old_value', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('new_value', postgresql.JSONB(astext_type=sa.Text()), nullable=False))
    op.create_index('ix_asset_changes_asset_id', 'asset_changes', ['asset_id'])
    op.create_index('ix_asset_changes_observed_at', 'asset_changes', ['observed_at'])
    op.create_index('ix_asset_changes_path', 'asset_changes', ['path'])
    op.create_table('asset_addresses',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('address', sa.String(128), nullable=False),
        sa.Column('family', sa.String(16), nullable=False, server_default=''),
        sa.Column('interface_name', sa.String(128), nullable=False, server_default=''),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('asset_id', 'address', 'source', name='uq_asset_address_source'))
    op.create_index('ix_asset_addresses_asset_id', 'asset_addresses', ['asset_id'])
    op.create_index('ix_asset_addresses_address', 'asset_addresses', ['address'])

    op.create_table('asset_interfaces',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(128), nullable=False, server_default=''),
        sa.Column('mac', sa.String(32), nullable=False, server_default=''),
        sa.Column('state', sa.String(32), nullable=False, server_default=''),
        sa.Column('mtu', sa.String(32), nullable=False, server_default=''),
        sa.Column('interface_type', sa.String(64), nullable=False, server_default=''),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False))
    op.create_index('ix_asset_interfaces_asset_id', 'asset_interfaces', ['asset_id'])
    op.create_index('ix_asset_interfaces_mac', 'asset_interfaces', ['mac'])

    op.create_table('asset_hardware',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('serial', sa.String(255), nullable=False, server_default=''),
        sa.Column('cpu_name', sa.String(512), nullable=False, server_default=''),
        sa.Column('cpu_cores', sa.String(32), nullable=False, server_default=''),
        sa.Column('ram_total', sa.BigInteger()),
        sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False))
    op.create_index('ix_asset_hardware_asset_id', 'asset_hardware', ['asset_id'])
    op.create_index('ix_asset_hardware_serial', 'asset_hardware', ['serial'])

    op.create_table('asset_software',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('name', sa.String(512), nullable=False),
        sa.Column('version', sa.String(255), nullable=False, server_default=''),
        sa.Column('architecture', sa.String(128), nullable=False, server_default=''),
        sa.Column('package_format', sa.String(64), nullable=False, server_default=''),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False))
    op.create_index('ix_asset_software_asset_id', 'asset_software', ['asset_id'])
    op.create_index('ix_asset_software_name', 'asset_software', ['name'])

    op.create_table('asset_processes',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('pid', sa.String(32), nullable=False, server_default=''),
        sa.Column('name', sa.String(512), nullable=False, server_default=''),
        sa.Column('user_name', sa.String(255), nullable=False, server_default=''),
        sa.Column('command', sa.Text(), nullable=False, server_default=''),
        sa.Column('state', sa.String(64), nullable=False, server_default=''))
    op.create_index('ix_asset_processes_asset_id', 'asset_processes', ['asset_id'])
    op.create_index('ix_asset_processes_name', 'asset_processes', ['name'])

    op.create_table('asset_services',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('name', sa.String(512), nullable=False, server_default=''),
        sa.Column('state', sa.String(64), nullable=False, server_default=''),
        sa.Column('start_type', sa.String(128), nullable=False, server_default=''),
        sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False))
    op.create_index('ix_asset_services_asset_id', 'asset_services', ['asset_id'])
    op.create_index('ix_asset_services_name', 'asset_services', ['name'])

    op.create_table('asset_ports',
        sa.Column('id', sa.BigInteger(), primary_key=True),
        sa.Column('asset_id', sa.Integer(), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(64), nullable=False),
        sa.Column('protocol', sa.String(16), nullable=False, server_default=''),
        sa.Column('address', sa.String(128), nullable=False, server_default=''),
        sa.Column('port', sa.Integer()),
        sa.Column('state', sa.String(64), nullable=False, server_default=''),
        sa.Column('process_name', sa.String(512), nullable=False, server_default=''),
        sa.Column('pid', sa.String(32), nullable=False, server_default=''))
    op.create_index('ix_asset_ports_asset_id', 'asset_ports', ['asset_id'])
    op.create_index('ix_asset_ports_port', 'asset_ports', ['port'])

    op.create_table('inventory_source_states',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('source', sa.String(64), nullable=False, unique=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('last_run', sa.DateTime()),
        sa.Column('last_success', sa.DateTime()),
        sa.Column('status', sa.String(32), nullable=False, server_default='unknown'),
        sa.Column('last_error', sa.Text(), nullable=False, server_default=''),
        sa.Column('metadata_json', postgresql.JSONB(astext_type=sa.Text()), nullable=False))

def downgrade():
    op.drop_table('inventory_source_states')
    op.drop_table('asset_ports')
    op.drop_table('asset_services')
    op.drop_table('asset_processes')
    op.drop_table('asset_software')
    op.drop_table('asset_hardware')
    op.drop_table('asset_interfaces')
    op.drop_table('asset_addresses')
    op.drop_table('asset_changes')
    op.drop_table('asset_snapshots')
    op.drop_table('asset_observations')
    op.drop_table('asset_identifiers')
    op.drop_table('assets')
