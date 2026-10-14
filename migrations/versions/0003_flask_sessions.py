"""Create Flask-Session SQLAlchemy table explicitly.

Revision ID: 0003_flask_sessions
Revises: 0002_complete_platform
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = '0003_flask_sessions'
down_revision = '0002_complete_platform'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if 'flask_sessions' not in tables:
        op.create_table(
            'flask_sessions',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('session_id', sa.String(length=255), nullable=True),
            sa.Column('data', sa.LargeBinary(), nullable=True),
            sa.Column('expiry', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('session_id', name='uq_flask_sessions_session_id'),
        )
        op.create_index(
            'ix_flask_sessions_expiry',
            'flask_sessions',
            ['expiry'],
            unique=False,
        )


def downgrade():
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    if 'flask_sessions' in tables:
        indexes = {
            i['name'] for i in inspect(bind).get_indexes('flask_sessions')
        }
        if 'ix_flask_sessions_expiry' in indexes:
            op.drop_index(
                'ix_flask_sessions_expiry',
                table_name='flask_sessions',
            )
        op.drop_table('flask_sessions')
