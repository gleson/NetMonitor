"""add TOTP 2FA columns to users

Revision ID: a2b3c4d5e6f7
Revises: 1a2f3c4d5e6f
Create Date: 2026-07-17 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'a2b3c4d5e6f7'
down_revision = '1a2f3c4d5e6f'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('totp_secret', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('totp_backup_codes', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('totp_backup_codes')
        batch_op.drop_column('totp_enabled')
        batch_op.drop_column('totp_secret')
