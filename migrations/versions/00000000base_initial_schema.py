"""initial baseline schema

Cria o schema base do NetMonitor (tabelas e índices que existiam antes da
primeira migration incremental ``4b9b3781130b``). Antes desta migration, um
banco novo só podia ser criado via ``flask init-db`` (``db.create_all``); as
migrations assumiam que as tabelas base já existiam, então ``flask db upgrade``
falhava em uma máquina nova. Esta baseline torna ``flask db upgrade`` suficiente
para um banco do zero.

As colunas/tabelas adicionadas depois (situation, tags, role, audit_logs,
notes, app_settings, etc.) continuam sendo aplicadas pelas migrations
incrementais que seguem esta — por isso aqui o schema é o estado ORIGINAL,
sem essas adições.

Revision ID: 00000000base
Revises:
Create Date: 2026-06-08 10:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "00000000base"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # --- users (sem coluna role; adicionada por 5c1a4e2f8b90) ---
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    # --- profiles (sem webhook_url/notify_email/notify_min_severity/default_ports) ---
    op.create_table(
        "profiles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("host_discovery_interval_minutes", sa.Integer(), nullable=True),
        sa.Column("port_scan_interval_minutes", sa.Integer(), nullable=True),
        sa.Column("snmp_enabled", sa.Boolean(), nullable=True),
        sa.Column("snmp_version", sa.String(length=10), nullable=True),
        sa.Column("snmp_community", sa.Text(), nullable=True),
        sa.Column("max_concurrent_scans", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # --- ip_ranges ---
    op.create_table(
        "ip_ranges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column("cidr", sa.String(length=50), nullable=False),
        sa.Column("description", sa.String(length=200), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("scan_all_ports", sa.Boolean(), nullable=True),
        sa.Column("custom_ports", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["profile_id"], ["profiles.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ip_ranges_profile_id", "ip_ranges", ["profile_id"], unique=False)

    # --- devices (sem situation/tags/alert_on_down/last_port_scanned_at/online_dates) ---
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column("mac", sa.String(length=17), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("friendly_name", sa.String(length=255), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column(
            "device_type",
            sa.Enum(
                "COMPUTER", "LAPTOP", "SMARTPHONE", "CAMERA", "PRINTER",
                "IOT", "ROUTER", "SWITCH", "ACCESS_POINT", "OTHER",
                name="devicetype",
            ),
            nullable=True,
        ),
        sa.Column("os_guess", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["profile_id"], ["profiles.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("profile_id", "mac", name="uq_device_profile_mac"),
    )
    op.create_index("ix_devices_profile_id", "devices", ["profile_id"], unique=False)
    op.create_index("ix_devices_mac", "devices", ["mac"], unique=False)

    # --- device_ips ---
    op.create_table(
        "device_ips",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("is_current", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_device_ips_device_id", "device_ips", ["device_id"], unique=False)
    op.create_index("ix_device_ips_is_current", "device_ips", ["is_current"], unique=False)

    # --- ports ---
    op.create_table(
        "ports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=5), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=True),
        sa.Column("service_name", sa.String(length=120), nullable=True),
        sa.Column("service_version", sa.String(length=255), nullable=True),
        sa.Column("first_open_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_open_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_closed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "protocol", "port", name="uq_port_device_proto_port"),
    )
    op.create_index("ix_ports_device_id", "ports", ["device_id"], unique=False)

    # --- scans (sem result_summary; adicionada por 7d2b5f8a1c04) ---
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column(
            "scan_type",
            sa.Enum("HOST_DISCOVERY", "PORT_SCAN", "SNMP", "MOBILE_SCAN", name="scantype"),
            nullable=False,
        ),
        sa.Column("target_ip", sa.String(length=45), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("RUNNING", "SUCCESS", "ERROR", name="scanstatus"),
            nullable=True,
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("hosts_found", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["profile_id"], ["profiles.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_profile_id", "scans", ["profile_id"], unique=False)

    # --- alerts (sem is_priority; adicionada por d4e5f6a7b8c9) ---
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column(
            "alert_type",
            sa.Enum(
                "NEW_DEVICE", "NEW_IP_FOR_MAC", "NEW_PORT", "PORT_CLOSED",
                "HOST_DOWN", "SNMP_FAILURE", "UNAUTHORIZED_DEVICE", "IP_CONFLICT",
                name="alerttype",
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum("INFO", "WARNING", "CRITICAL", name="severity"),
            nullable=True,
        ),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["profile_id"], ["profiles.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_profile_id", "alerts", ["profile_id"], unique=False)
    op.create_index("ix_alerts_device_id", "alerts", ["device_id"], unique=False)
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"], unique=False)

    # --- vulnerabilities ---
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=5), nullable=True),
        sa.Column("service", sa.String(length=120), nullable=True),
        sa.Column("script_name", sa.String(length=255), nullable=False),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("is_vulnerable", sa.Boolean(), nullable=True),
        sa.Column("found_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vulnerabilities_device_id", "vulnerabilities", ["device_id"], unique=False)


def downgrade():
    op.drop_index("ix_vulnerabilities_device_id", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index("ix_alerts_created_at", table_name="alerts")
    op.drop_index("ix_alerts_device_id", table_name="alerts")
    op.drop_index("ix_alerts_profile_id", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_scans_profile_id", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_ports_device_id", table_name="ports")
    op.drop_table("ports")
    op.drop_index("ix_device_ips_is_current", table_name="device_ips")
    op.drop_index("ix_device_ips_device_id", table_name="device_ips")
    op.drop_table("device_ips")
    op.drop_index("ix_devices_mac", table_name="devices")
    op.drop_index("ix_devices_profile_id", table_name="devices")
    op.drop_table("devices")
    op.drop_index("ix_ip_ranges_profile_id", table_name="ip_ranges")
    op.drop_table("ip_ranges")
    op.drop_table("profiles")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
