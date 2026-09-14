"""Adiciona cadeia de hash ao audit log

Revision ID: e0f1a2b3c4d5
Revises: d9e0f1a2b3c4
Create Date: 2026-09-14

Cada entrada passa a carregar o hash da anterior. O histórico existente é
encadeado no upgrade para que a verificação não acuse todas as linhas antigas
como "sem hash" — com a ressalva honesta de que isso atesta apenas que nada
mudou **a partir daqui**, não que o passado é confiável.

A coluna alerts.alert_type também ganha valores novos nesta fase
(INSECURE_CONFIG, com 15 caracteres), que cabem no VARCHAR(19) existente
dimensionado por "UNAUTHORIZED_DEVICE" — por isso não é alterada.
"""
import hashlib

from alembic import op
import sqlalchemy as sa


revision = "e0f1a2b3c4d5"
down_revision = "d9e0f1a2b3c4"
branch_labels = None
depends_on = None

GENESIS = "0" * 64


def upgrade():
    op.add_column(
        "audit_logs",
        sa.Column("entry_hash", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "audit_logs",
        sa.Column("prev_hash", sa.String(length=64), nullable=False, server_default=""),
    )
    op.create_index("ix_audit_logs_entry_hash", "audit_logs", ["entry_hash"])

    # Encadeia o histórico. Feito em SQL direto (sem importar os modelos) para
    # que a migration continue válida se o modelo mudar depois — a fórmula do
    # hash está replicada aqui de propósito, congelada nesta revisão.
    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT id, created_at, user_id, username, action, entity_type, "
        "entity_id, details, ip_address FROM audit_logs ORDER BY id ASC"
    )).fetchall()

    prev = GENESIS
    for r in rows:
        created = r.created_at
        # O SQLite devolve string; outros backends, datetime. O modelo assina
        # com isoformat(sep=" ", timespec="microseconds").
        if hasattr(created, "isoformat"):
            created_txt = created.isoformat(sep=" ", timespec="microseconds")
        else:
            created_txt = _normalize_sqlite_datetime(created)

        payload = "|".join((
            created_txt,
            "" if r.user_id is None else str(r.user_id),
            r.username or "",
            r.action or "",
            r.entity_type or "",
            "" if r.entity_id is None else str(r.entity_id),
            r.details or "",
            r.ip_address or "",
        ))
        entry_hash = hashlib.sha256(f"{prev}|{payload}".encode("utf-8")).hexdigest()
        conn.execute(
            sa.text("UPDATE audit_logs SET entry_hash = :e, prev_hash = :p WHERE id = :i"),
            {"e": entry_hash, "p": prev, "i": r.id},
        )
        prev = entry_hash


def _normalize_sqlite_datetime(value) -> str:
    """'2026-09-14 12:00:00' / '...000000' → formato com microssegundos.

    O SQLite guarda o DATETIME como texto e omite os microssegundos quando são
    zero; o modelo sempre assina com eles, então o preenchimento é necessário
    para o hash bater na primeira verificação.
    """
    txt = str(value or "").strip()
    if not txt:
        return ""
    if "." not in txt:
        return txt + ".000000"
    head, _, frac = txt.partition(".")
    return f"{head}.{frac[:6].ljust(6, '0')}"


def downgrade():
    op.drop_index("ix_audit_logs_entry_hash", table_name="audit_logs")
    op.drop_column("audit_logs", "prev_hash")
    op.drop_column("audit_logs", "entry_hash")
