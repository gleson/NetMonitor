"""add is_multi_ip to device

Dispositivos legitimamente multi-homed (ex.: roteador/gateway com o mesmo MAC
em várias redes) podem ser marcados com is_multi_ip=True: todos os DeviceIp
conhecidos ficam is_current=True ao mesmo tempo e a alternância entre eles não
gera alerta NEW_IP_FOR_MAC.

Revision ID: 1a2f3c4d5e6f
Revises: 0c70fb898bb8
Create Date: 2026-07-15 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1a2f3c4d5e6f'
down_revision = '0c70fb898bb8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_multi_ip', sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_column('is_multi_ip')
