"""Adiciona impressão digital TLS a ports (detecção de MITM)

Revision ID: d9e0f1a2b3c4
Revises: c8d9e0f1a2b3
Create Date: 2026-09-14

A coluna alerts.alert_type não precisa ser alterada: os novos valores do enum
(GATEWAY_CHANGED, ROGUE_DHCP, ROGUE_RA, NDP_SPOOFING, TLS_CERT_CHANGED) cabem
no VARCHAR(19) existente, dimensionado por "UNAUTHORIZED_DEVICE".
"""
from alembic import op
import sqlalchemy as sa


revision = "d9e0f1a2b3c4"
down_revision = "c8d9e0f1a2b3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ports", sa.Column("tls_fingerprint", sa.String(length=64), nullable=True))
    op.add_column("ports", sa.Column("tls_issuer", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("ports", "tls_issuer")
    op.drop_column("ports", "tls_fingerprint")
