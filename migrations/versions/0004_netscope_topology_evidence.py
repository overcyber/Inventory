"""NetScope topology evidence, passive flow and identity observations.

Revision ID: 0004_netscope_topology_evidence
Revises: 0003_flask_sessions
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

revision = '0004_netscope_topology_evidence'
down_revision = '0003_flask_sessions'
branch_labels = None
depends_on = None


def _tables():
    return set(inspect(op.get_bind()).get_table_names())


def _index(name, table, columns):
    if table not in _tables():
        return
    existing = {i['name'] for i in inspect(op.get_bind()).get_indexes(table)}
    if name not in existing:
        op.create_index(name, table, columns, unique=False)


def upgrade():
    if 'netscope_topology_evidence' not in _tables():
        op.create_table(
            'netscope_topology_evidence',
            sa.Column('id', sa.BigInteger(), primary_key=True),
            sa.Column('evidence_key', sa.String(192), nullable=False, unique=True),
            sa.Column('source', sa.String(32), nullable=False),
            sa.Column('relation', sa.String(48), nullable=False),
            sa.Column('observer', sa.String(128), nullable=False, server_default=''),
            sa.Column('subject_key', sa.String(128), nullable=False, server_default=''),
            sa.Column('peer_key', sa.String(128), nullable=False, server_default=''),
            sa.Column('subject_ip', sa.String(64), nullable=False, server_default=''),
            sa.Column('peer_ip', sa.String(64), nullable=False, server_default=''),
            sa.Column('local_port', sa.String(128), nullable=False, server_default=''),
            sa.Column('remote_port', sa.String(128), nullable=False, server_default=''),
            sa.Column('vlan', sa.String(32), nullable=False, server_default=''),
            sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
            sa.Column('first_seen', sa.DateTime(), nullable=False),
            sa.Column('last_seen', sa.DateTime(), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=True),
            sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column('details', postgresql.JSONB(), nullable=False, server_default='{}'),
        )
    for name, cols in (
        ('ix_nste_source', ['source']),
        ('ix_nste_relation', ['relation']),
        ('ix_nste_observer', ['observer']),
        ('ix_nste_subject', ['subject_key']),
        ('ix_nste_peer', ['peer_key']),
        ('ix_nste_subject_ip', ['subject_ip']),
        ('ix_nste_peer_ip', ['peer_ip']),
        ('ix_nste_last_seen', ['last_seen']),
        ('ix_nste_expires_at', ['expires_at']),
        ('ix_nste_active', ['active']),
    ):
        _index(name, 'netscope_topology_evidence', cols)

    if 'netscope_flow_aggregates' not in _tables():
        op.create_table(
            'netscope_flow_aggregates',
            sa.Column('id', sa.BigInteger(), primary_key=True),
            sa.Column('flow_key', sa.String(192), nullable=False, unique=True),
            sa.Column('sensor_id', sa.String(128), nullable=False, server_default='netscope-local'),
            sa.Column('interface', sa.String(128), nullable=False, server_default=''),
            sa.Column('src_ip', sa.String(64), nullable=False),
            sa.Column('dst_ip', sa.String(64), nullable=False),
            sa.Column('src_mac', sa.String(20), nullable=False, server_default=''),
            sa.Column('dst_mac', sa.String(20), nullable=False, server_default=''),
            sa.Column('src_port', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('dst_port', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('protocol', sa.String(12), nullable=False, server_default='IP'),
            sa.Column('vlan', sa.String(32), nullable=False, server_default=''),
            sa.Column('packets', sa.BigInteger(), nullable=False, server_default='0'),
            sa.Column('bytes', sa.BigInteger(), nullable=False, server_default='0'),
            sa.Column('flow_count', sa.BigInteger(), nullable=False, server_default='0'),
            sa.Column('first_seen', sa.DateTime(), nullable=False),
            sa.Column('last_seen', sa.DateTime(), nullable=False),
        )
    for name, cols in (
        ('ix_nsfa_sensor', ['sensor_id']),
        ('ix_nsfa_src_ip', ['src_ip']),
        ('ix_nsfa_dst_ip', ['dst_ip']),
        ('ix_nsfa_src_mac', ['src_mac']),
        ('ix_nsfa_dst_mac', ['dst_mac']),
        ('ix_nsfa_protocol', ['protocol']),
        ('ix_nsfa_last_seen', ['last_seen']),
    ):
        _index(name, 'netscope_flow_aggregates', cols)

    if 'netscope_identity_observations' not in _tables():
        op.create_table(
            'netscope_identity_observations',
            sa.Column('id', sa.BigInteger(), primary_key=True),
            sa.Column('observation_key', sa.String(192), nullable=False, unique=True),
            sa.Column('ip', sa.String(64), nullable=False),
            sa.Column('mac', sa.String(20), nullable=False, server_default=''),
            sa.Column('hostname', sa.String(255), nullable=False, server_default=''),
            sa.Column('source', sa.String(32), nullable=False),
            sa.Column('sensor_id', sa.String(128), nullable=False, server_default='netscope-local'),
            sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
            sa.Column('first_seen', sa.DateTime(), nullable=False),
            sa.Column('last_seen', sa.DateTime(), nullable=False),
            sa.Column('valid_to', sa.DateTime(), nullable=True),
            sa.Column('details', postgresql.JSONB(), nullable=False, server_default='{}'),
        )
    for name, cols in (
        ('ix_nsio_ip', ['ip']),
        ('ix_nsio_mac', ['mac']),
        ('ix_nsio_source', ['source']),
        ('ix_nsio_last_seen', ['last_seen']),
    ):
        _index(name, 'netscope_identity_observations', cols)


def downgrade():
    for table in ('netscope_identity_observations',
                  'netscope_flow_aggregates',
                  'netscope_topology_evidence'):
        if table in _tables():
            op.drop_table(table)
