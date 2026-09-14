"""Adiciona ip_version a device_ips (suporte a IPv6)

Revision ID: c8d9e0f1a2b3
Revises: b7c8d9e0f1a2
Create Date: 2026-09-14

Todo DeviceIp existente é IPv4 (a descoberta anterior só fazia ARP/IPv4), mas o
backfill classifica pela presença de ':' em vez de assumir 4 cegamente — assim
uma base que já tenha recebido algum IPv6 por importação fica correta.
"""
from alembic import op
import sqlalchemy as sa


revision = "c8d9e0f1a2b3"
down_revision = "b7c8d9e0f1a2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "device_ips",
        sa.Column("ip_version", sa.SmallInteger(), nullable=False, server_default="4"),
    )
    op.create_index("ix_device_ips_ip_version", "device_ips", ["ip_version"])
    op.execute("UPDATE device_ips SET ip_version = 6 WHERE ip LIKE '%:%'")


def downgrade():
    op.drop_index("ix_device_ips_ip_version", table_name="device_ips")
    op.drop_column("device_ips", "ip_version")
