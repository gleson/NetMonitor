"""add alert suppressions and alert.match_value

Revision ID: b7c8d9e0f1a2
Revises: a2b3c4d5e6f7
Create Date: 2026-07-17 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'b7c8d9e0f1a2'
down_revision = 'a2b3c4d5e6f7'
branch_labels = None
depends_on = None


# Enum de tipos de alerta (espelha AlertType em app/models.py). Em SQLite o
# db.Enum vira VARCHAR + CHECK; usamos sa.Enum aqui só para consistência de tipo.
_alert_type = sa.Enum(
    'NEW_DEVICE', 'NEW_IP_FOR_MAC', 'NEW_PORT', 'PORT_CLOSED', 'HOST_DOWN',
    'SNMP_FAILURE', 'UNAUTHORIZED_DEVICE', 'IP_CONFLICT', 'ARP_SPOOFING',
    'GHOST_DEVICE', 'TLS_CERT_EXPIRING', 'VULNERABILITY',
    name='alerttype',
)


def upgrade():
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('match_value', sa.String(length=255), nullable=True))

    op.create_table(
        'alert_suppressions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('profile_id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=True),
        sa.Column('alert_type', _alert_type, nullable=False),
        sa.Column('match_value', sa.String(length=255), nullable=True),
        sa.Column('reason', sa.String(length=500), nullable=True),
        sa.Column('created_by', sa.String(length=80), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['profile_id'], ['profiles.id']),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('alert_suppressions', schema=None) as batch_op:
        batch_op.create_index('ix_alert_suppressions_profile_id', ['profile_id'])
        batch_op.create_index('ix_alert_suppressions_device_id', ['device_id'])
        batch_op.create_index('ix_alert_suppressions_alert_type', ['alert_type'])


def downgrade():
    with op.batch_alter_table('alert_suppressions', schema=None) as batch_op:
        batch_op.drop_index('ix_alert_suppressions_alert_type')
        batch_op.drop_index('ix_alert_suppressions_device_id')
        batch_op.drop_index('ix_alert_suppressions_profile_id')
    op.drop_table('alert_suppressions')

    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.drop_column('match_value')
