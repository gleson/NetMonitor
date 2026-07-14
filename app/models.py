"""Modelos SQLAlchemy para o sistema de monitoramento de rede."""

from datetime import date as _date, datetime, timezone, timedelta
import enum
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from flask_login import UserMixin
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db, login_manager


# ---------------------------------------------------------------------------
# Fernet helpers (SNMP community encryption)
# ---------------------------------------------------------------------------

def _get_fernet():
    key = os.environ.get("FERNET_KEY", "")
    if not key:
        return None
    return Fernet(key.encode())


def _encrypt_str(value: str) -> str:
    f = _get_fernet()
    if f is None:
        return value
    return f.encrypt(value.encode()).decode()


def _decrypt_str(value: str) -> str:
    if not value:
        return value
    f = _get_fernet()
    if f is None:
        return value
    try:
        return f.decrypt(value.encode()).decode()
    except (InvalidToken, Exception):
        # Fallback: valor armazenado ainda em texto puro (antes da ativação do Fernet)
        return value


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DeviceType(enum.Enum):
    COMPUTER = "COMPUTER"
    LAPTOP = "LAPTOP"
    SMARTPHONE = "SMARTPHONE"
    CAMERA = "CAMERA"
    PRINTER = "PRINTER"
    IOT = "IOT"
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    ACCESS_POINT = "ACCESS_POINT"
    OTHER = "OTHER"


class ScanType(enum.Enum):
    HOST_DISCOVERY = "HOST_DISCOVERY"
    PORT_SCAN = "PORT_SCAN"
    SNMP = "SNMP"
    MOBILE_SCAN = "MOBILE_SCAN"


class ScanStatus(enum.Enum):
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"


class AlertType(enum.Enum):
    NEW_DEVICE = "NEW_DEVICE"
    NEW_IP_FOR_MAC = "NEW_IP_FOR_MAC"
    NEW_PORT = "NEW_PORT"
    PORT_CLOSED = "PORT_CLOSED"
    HOST_DOWN = "HOST_DOWN"
    SNMP_FAILURE = "SNMP_FAILURE"
    UNAUTHORIZED_DEVICE = "UNAUTHORIZED_DEVICE"
    IP_CONFLICT = "IP_CONFLICT"
    # Suspeita de ARP spoofing: IP de um device online reivindicado por outro MAC.
    ARP_SPOOFING = "ARP_SPOOFING"
    # Device "fantasma": MAC presente na tabela ARP do sistema com IP fora
    # de todos os ranges configurados.
    GHOST_DEVICE = "GHOST_DEVICE"
    # Certificado TLS expirado ou prestes a expirar.
    TLS_CERT_EXPIRING = "TLS_CERT_EXPIRING"
    # CVE conhecido correlacionado com serviço/versão detectado em porta aberta.
    VULNERABILITY = "VULNERABILITY"


class Severity(enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


# Ordem de severidade para comparações (notificações por nível mínimo).
_SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}


def severity_rank(value) -> int:
    """Rank numérico de uma Severity (enum) ou string. Desconhecido → 0 (INFO)."""
    if isinstance(value, Severity):
        value = value.value
    return _SEVERITY_RANK.get(str(value or "").upper(), 0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow():
    """UTC naive — compatível com colunas `db.DateTime` (sem tz) em SQLite e Postgres.

    Usar sempre esta função ao criar/comparar timestamps de domínio.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# User (autenticação)
# ---------------------------------------------------------------------------

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"
_ROLE_RANK = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}
VALID_ROLES = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), nullable=False, default=ROLE_VIEWER)
    created_at = db.Column(db.DateTime, default=_utcnow)

    def set_password(self, password: str):
        """Valida política e grava o hash. Use `User.validate_password` antes
        quando precisar coletar o erro sem explodir com ValueError.
        """
        err = User.validate_password(password)
        if err:
            raise ValueError(err)
        self.password_hash = generate_password_hash(password)

    @staticmethod
    def validate_password(password: str) -> str | None:
        """Retorna mensagem de erro se a senha violar a política, ou None.

        Política: pelo menos 10 caracteres, contendo letras e números.
        """
        if not password or len(password) < 10:
            return "A senha precisa ter pelo menos 10 caracteres."
        if not any(c.isalpha() for c in password):
            return "A senha precisa conter ao menos uma letra."
        if not any(c.isdigit() for c in password):
            return "A senha precisa conter ao menos um número."
        return None

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def has_role(self, required: str) -> bool:
        """True se o role do usuário for >= ao required.

        Hierarquia: viewer < operator < admin.
        """
        return _ROLE_RANK.get(self.role, 0) >= _ROLE_RANK.get(required, 99)

    def __repr__(self):
        return f"<User {self.username} role={self.role}>"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Profile (perfil de rede)
# ---------------------------------------------------------------------------

class Profile(db.Model):
    __tablename__ = "profiles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    host_discovery_interval_minutes = db.Column(db.Integer, default=45)
    port_scan_interval_minutes = db.Column(db.Integer, default=4)
    snmp_enabled = db.Column(db.Boolean, default=False)
    # "2c" (community) ou "3" (USM — usuário + auth/priv).
    snmp_version = db.Column(db.String(10), default="2c")
    # Armazenado cifrado com Fernet quando FERNET_KEY está configurado.
    _snmp_community = db.Column("snmp_community", db.Text, default="public")

    @property
    def snmp_community(self) -> str:
        return _decrypt_str(self._snmp_community or "public")

    @snmp_community.setter
    def snmp_community(self, value: str) -> None:
        self._snmp_community = _encrypt_str(value or "")

    # --- SNMPv3 (USM) ---
    # Usuário e chaves são cifrados com Fernet (como a community). Os protocolos
    # são metadados não sensíveis. O nível de segurança (noAuthNoPriv /
    # authNoPriv / authPriv) é derivado da presença das chaves em `snmp_v3_level`.
    _snmp_v3_user = db.Column("snmp_v3_user", db.Text, default="", nullable=False)
    snmp_v3_auth_protocol = db.Column(db.String(10), default="SHA", nullable=False)
    _snmp_v3_auth_key = db.Column("snmp_v3_auth_key", db.Text, default="", nullable=False)
    snmp_v3_priv_protocol = db.Column(db.String(10), default="AES", nullable=False)
    _snmp_v3_priv_key = db.Column("snmp_v3_priv_key", db.Text, default="", nullable=False)

    @property
    def snmp_v3_user(self) -> str:
        return _decrypt_str(self._snmp_v3_user or "")

    @snmp_v3_user.setter
    def snmp_v3_user(self, value: str) -> None:
        self._snmp_v3_user = _encrypt_str(value or "")

    @property
    def snmp_v3_auth_key(self) -> str:
        return _decrypt_str(self._snmp_v3_auth_key or "")

    @snmp_v3_auth_key.setter
    def snmp_v3_auth_key(self, value: str) -> None:
        self._snmp_v3_auth_key = _encrypt_str(value or "")

    @property
    def snmp_v3_priv_key(self) -> str:
        return _decrypt_str(self._snmp_v3_priv_key or "")

    @snmp_v3_priv_key.setter
    def snmp_v3_priv_key(self, value: str) -> None:
        self._snmp_v3_priv_key = _encrypt_str(value or "")

    @property
    def snmp_v3_level(self) -> str:
        """Nível de segurança USM derivado das chaves configuradas."""
        if self.snmp_v3_auth_key and self.snmp_v3_priv_key:
            return "authPriv"
        if self.snmp_v3_auth_key:
            return "authNoPriv"
        return "noAuthNoPriv"
    max_concurrent_scans = db.Column(db.Integer, default=3)
    is_active = db.Column(db.Boolean, default=True)
    # --- Notificações de alertas ---
    webhook_url = db.Column(db.String(500), default="", nullable=False)
    notify_email = db.Column(db.String(200), default="", nullable=False)
    # Severidade mínima para disparar notificação externa (webhook/e-mail).
    # Um de INFO / WARNING / CRITICAL. Default CRITICAL preserva o comportamento
    # anterior (só CRITICAL notificava).
    notify_min_severity = db.Column(db.String(10), default="CRITICAL", nullable=False)
    # Lista de portas padrão para este perfil (CSV, ex.: "22,80,443").
    # Vazio → usa DEFAULT_PORTS de app/scanner/ports.py.
    default_ports = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)

    # Relacionamentos
    ip_ranges = db.relationship("IpRange", backref="profile", lazy="dynamic", cascade="all, delete-orphan")
    devices = db.relationship("Device", backref="profile", lazy="dynamic", cascade="all, delete-orphan")
    scans = db.relationship("Scan", backref="profile", lazy="dynamic", cascade="all, delete-orphan")
    alerts = db.relationship("Alert", backref="profile", lazy="dynamic", cascade="all, delete-orphan")
    notes = db.relationship("Note", backref="profile", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Profile {self.name}>"


# ---------------------------------------------------------------------------
# IpRange
# ---------------------------------------------------------------------------

class IpRange(db.Model):
    __tablename__ = "ip_ranges"

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"), nullable=False, index=True)
    cidr = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200), default="")
    enabled = db.Column(db.Boolean, default=True)
    scan_all_ports = db.Column(db.Boolean, default=False)
    custom_ports = db.Column(db.Text, default="")
    # Smart polling: faixa marcada como "somente descoberta passiva" (ARP/ping)
    # NÃO recebe port scan ativo. Pensado para segmentos sensíveis (OT/IoT,
    # impressoras, câmeras) que podem instabilizar sob varredura de portas.
    passive_only = db.Column(db.Boolean, default=False, nullable=False)

    @property
    def ports_display(self):
        """Texto curto descrevendo a config de portas para exibição."""
        if self.passive_only:
            return "Passivo (sem port scan)"
        if self.scan_all_ports:
            return "Todas (1-65535)"
        if self.custom_ports:
            return self.custom_ports[:60] + ("..." if len(self.custom_ports or "") > 60 else "")
        return "Padrão"

    def __repr__(self):
        return f"<IpRange {self.cidr}>"


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------

class Device(db.Model):
    __tablename__ = "devices"
    __table_args__ = (
        db.UniqueConstraint("profile_id", "mac", name="uq_device_profile_mac"),
    )

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"), nullable=False, index=True)
    mac = db.Column(db.String(17), nullable=False, index=True)  # formato AA:BB:CC:DD:EE:FF
    hostname = db.Column(db.String(255), default="")
    friendly_name = db.Column(db.String(255), nullable=True)
    vendor = db.Column(db.String(255), default="")
    device_type = db.Column(db.Enum(DeviceType), default=DeviceType.OTHER)
    os_guess = db.Column(db.String(255), default="")
    situation = db.Column(db.String(100), default="NI", nullable=False)  # NI = Não Identificado
    tags = db.Column(db.String(500), default="")  # tags separadas por vírgula
    notes = db.Column(db.Text, default="")
    alert_on_down = db.Column(db.Boolean, default=False, nullable=False)
    first_seen_at = db.Column(db.DateTime, default=_utcnow)
    last_seen_at = db.Column(db.DateTime, default=_utcnow)
    last_port_scanned_at = db.Column(db.DateTime, nullable=True)
    # Lista JSON de datas (YYYY-MM-DD, UTC) em que o device foi visto online.
    # Populada incrementalmente pelo host discovery / scan on-demand. Usada
    # para o cálculo de Uptime 30d e para o histórico diário em /devices/history.
    online_dates = db.Column(db.Text, default="[]", nullable=False)

    # Relacionamentos
    ips = db.relationship("DeviceIp", backref="device", lazy="dynamic", cascade="all, delete-orphan")
    ports = db.relationship("Port", backref="device", lazy="dynamic", cascade="all, delete-orphan")
    alerts = db.relationship("Alert", backref="device", lazy="dynamic")

    @property
    def current_ip(self):
        """Retorna o IP atual do dispositivo (o mais recente marcado como current)."""
        dip = DeviceIp.query.filter_by(device_id=self.id, is_current=True).first()
        return dip.ip if dip else None

    @property
    def open_ports_count(self):
        """Total de portas ativas (não fechadas), incluindo abertas e filtradas."""
        return Port.query.filter_by(device_id=self.id).filter(Port.last_seen_closed_at.is_(None)).count()

    @property
    def truly_open_ports_count(self):
        """Portas ativas em estado 'open' (exclui 'filtered' e 'open|filtered')."""
        return (
            Port.query.filter_by(device_id=self.id)
            .filter(Port.last_seen_closed_at.is_(None), Port.state == "open")
            .count()
        )

    @property
    def display_name(self):
        return self.friendly_name or self.hostname or self.mac

    def get_online_dates(self) -> list[str]:
        """Retorna a lista de datas (YYYY-MM-DD) em que o device foi visto online."""
        raw = self.online_dates or "[]"
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, str)]
        except (ValueError, TypeError):
            pass
        return []

    def record_online_today(self, today: _date | None = None) -> bool:
        """Marca o device como visto online hoje. Retorna True se foi um novo dia.

        Idempotente: chamar várias vezes no mesmo dia é no-op.
        """
        today = today or _utcnow().date()
        today_str = today.isoformat()
        dates = self.get_online_dates()
        if today_str in dates:
            return False
        dates.append(today_str)
        # Mantém a janela em ~60 dias para evitar crescimento ilimitado;
        # o uptime exibido é de 30d, dobramos a janela para folga.
        cutoff = today - timedelta(days=60)
        cutoff_str = cutoff.isoformat()
        dates = sorted(d for d in dates if d >= cutoff_str)
        self.online_dates = json.dumps(dates)
        return True

    def uptime_details(self, days: int = 30, monitored_days: set[str] | None = None) -> dict:
        """Calcula disponibilidade no período ``days`` usando ``online_dates``.

        Definição: uptime = (dias distintos visto online na janela) / (dias
        MONITORADOS na janela). Dia monitorado = dia com pelo menos um `Scan`
        registrado para o perfil (união com os próprios dias online, que
        implicam monitor ativo — cobre descoberta passiva sem Scan no dia).
        Dias em que o NetMonitor esteve desligado não entram no denominador,
        senão todo device herdaria o "uptime" do próprio monitor.

        A janela começa no MAIOR entre ``now - days`` e a primeira data
        gravada para o device, evitando penalizar histórico que não existia
        antes da ativação do tracking diário.

        ``monitored_days`` aceita um set pré-calculado (via
        ``scan_days_since``) para evitar uma query por device em listagens.

        Retorna ``{"ratio": float|None, "online_days": int, "monitored_days": int}``;
        ``ratio`` é None enquanto não houver histórico.
        """
        empty = {"ratio": None, "online_days": 0, "monitored_days": 0}
        today = _utcnow().date()
        period_start = today - timedelta(days=days - 1)

        online_dates = self.get_online_dates()
        if not online_dates:
            return empty

        earliest_recorded = _date.fromisoformat(min(online_dates))
        window_start = max(period_start, earliest_recorded)
        if window_start > today:
            return empty

        cutoff_str = window_start.isoformat()
        online_set = {d for d in online_dates if d >= cutoff_str}
        if monitored_days is None:
            monitored_days = scan_days_since(self.profile_id, window_start)
        monitored = {d for d in monitored_days if d >= cutoff_str} | online_set
        if not monitored:
            return empty

        ratio = max(0.0, min(1.0, len(online_set) / len(monitored)))
        return {"ratio": ratio, "online_days": len(online_set), "monitored_days": len(monitored)}

    def uptime_estimate(self, days: int = 30, online_threshold_minutes: int = 60,
                        monitored_days: set[str] | None = None) -> float | None:
        """Estima disponibilidade (0.0–1.0) no período ``days``.

        Atalho para ``uptime_details(...)["ratio"]``; ver a definição lá.
        ``online_threshold_minutes`` é mantido por compatibilidade de
        assinatura (não participa do cálculo diário).
        """
        return self.uptime_details(days=days, monitored_days=monitored_days)["ratio"]

    def __repr__(self):
        return f"<Device {self.mac} ({self.display_name})>"


# ---------------------------------------------------------------------------
# DeviceIp
# ---------------------------------------------------------------------------

class DeviceIp(db.Model):
    __tablename__ = "device_ips"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False, index=True)
    ip = db.Column(db.String(45), nullable=False)  # suporta IPv6
    first_seen_at = db.Column(db.DateTime, default=_utcnow)
    last_seen_at = db.Column(db.DateTime, default=_utcnow)
    is_current = db.Column(db.Boolean, default=True, index=True)

    def __repr__(self):
        return f"<DeviceIp {self.ip} current={self.is_current}>"


# ---------------------------------------------------------------------------
# Port
# ---------------------------------------------------------------------------

class Port(db.Model):
    __tablename__ = "ports"
    __table_args__ = (
        db.UniqueConstraint("device_id", "protocol", "port", name="uq_port_device_proto_port"),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False, index=True)
    protocol = db.Column(db.String(5), nullable=False, default="tcp")
    port = db.Column(db.Integer, nullable=False)
    state = db.Column(db.String(20), default="open")  # open, filtered, open|filtered
    service_name = db.Column(db.String(120), default="")
    service_version = db.Column(db.String(255), default="")
    first_open_at = db.Column(db.DateTime, default=_utcnow)
    last_seen_open_at = db.Column(db.DateTime, default=_utcnow)
    last_seen_closed_at = db.Column(db.DateTime, nullable=True)
    # Baseline: porta marcada como esperada/autorizada pelo operador.
    # Portas autorizadas não geram alerta ao reaparecer ou mudar de estado —
    # somente desvios do baseline alertam.
    is_authorized = db.Column(db.Boolean, default=False, nullable=False)

    @property
    def is_open(self) -> bool:
        return self.last_seen_closed_at is None

    def __repr__(self):
        return f"<Port {self.protocol}/{self.port} ({self.service_name})>"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"), nullable=False, index=True)
    scan_type = db.Column(db.Enum(ScanType), nullable=False)
    target_ip = db.Column(db.String(45), nullable=True)  # None = scan de todo o perfil
    started_at = db.Column(db.DateTime, default=_utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.Enum(ScanStatus), default=ScanStatus.RUNNING)
    error_message = db.Column(db.Text, nullable=True)
    # Texto descritivo para scans que terminam em SUCCESS mas carregam
    # informação útil (ex.: resultado do Mobile ID). Manter separado de
    # `error_message` evita confundir sucesso com falha na UI.
    result_summary = db.Column(db.Text, nullable=True)
    hosts_found = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<Scan {self.scan_type.value} status={self.status.value}>"


def scan_days_since(profile_id: int | None, start_date: _date) -> set[str]:
    """Dias distintos (ISO ``YYYY-MM-DD``) com pelo menos um ``Scan`` do
    perfil desde ``start_date`` — proxy de "dias em que o monitor rodou".

    Usado como denominador do uptime diário (``Device.uptime_details``).
    Limitado na prática por ``SCAN_RETENTION_DAYS`` (default 30, mesmo
    tamanho da maior janela de uptime exibida).
    """
    if profile_id is None:
        return set()
    start_dt = datetime.combine(start_date, datetime.min.time())
    rows = (
        db.session.query(func.date(Scan.started_at))
        .filter(Scan.profile_id == profile_id, Scan.started_at >= start_dt)
        .distinct()
        .all()
    )
    # SQLite retorna str; outros backends retornam date — normaliza p/ ISO.
    return {str(r[0]) for r in rows if r[0] is not None}


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"), nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=True, index=True)
    alert_type = db.Column(db.Enum(AlertType), nullable=False)
    severity = db.Column(db.Enum(Severity), default=Severity.INFO)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, index=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    # Alertas prioritários sobem ao topo e são renderizados em alert-danger.
    # Usado para HOST_DOWN confirmados (dupla checagem do quick_host_down_check).
    is_priority = db.Column(db.Boolean, default=False, nullable=False)

    @property
    def is_acknowledged(self) -> bool:
        return self.acknowledged_at is not None

    def __repr__(self):
        return f"<Alert {self.alert_type.value} severity={self.severity.value}>"


# ---------------------------------------------------------------------------
# DeviceOnlineSnapshot
# ---------------------------------------------------------------------------

class DeviceOnlineSnapshot(db.Model):
    """Snapshot do número de dispositivos online ao final de cada host discovery.

    Registrado automaticamente após cada scan de descoberta para permitir
    consultas históricas precisas de quantos dispositivos estavam online.
    """
    __tablename__ = "device_online_snapshots"

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"), nullable=False, index=True)
    recorded_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    online_count = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<DeviceOnlineSnapshot profile={self.profile_id} count={self.online_count} at={self.recorded_at}>"


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False, index=True)
    port = db.Column(db.Integer, default=0)
    protocol = db.Column(db.String(5), default="")
    service = db.Column(db.String(120), default="")
    script_name = db.Column(db.String(255), nullable=False)
    output = db.Column(db.Text, default="")
    is_vulnerable = db.Column(db.Boolean, default=False)
    found_at = db.Column(db.DateTime, default=_utcnow)
    last_seen_at = db.Column(db.DateTime, default=_utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    device = db.relationship("Device", backref=db.backref("vulnerabilities", lazy="dynamic", cascade="all, delete-orphan"))

    @property
    def is_resolved(self) -> bool:
        return self.resolved_at is not None

    def __repr__(self):
        return f"<Vulnerability {self.script_name} port={self.port}>"


# ---------------------------------------------------------------------------
# Note (anotações por perfil)
# ---------------------------------------------------------------------------

class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"), nullable=True, index=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow)

    def __repr__(self):
        return f"<Note {self.title}>"


# ---------------------------------------------------------------------------
# SwitchNeighbor — topologia física de camada 2 (LLDP + FDB via SNMP)
# ---------------------------------------------------------------------------

class SwitchNeighbor(db.Model):
    """Vizinhança física descoberta em um switch gerenciável via SNMP.

    Preenchido pelo job opcional de topologia (``app/scanner/topology.py``),
    desligado por padrão. Cada linha associa uma porta física de um switch
    (``switch_device_id``) a um vizinho — outro switch (via LLDP) ou um
    endpoint (via BRIDGE-MIB FDB, correlacionando o MAC com um Device).
    """
    __tablename__ = "switch_neighbors"
    __table_args__ = (
        db.UniqueConstraint(
            "switch_device_id", "local_port", "remote_mac",
            name="uq_neighbor_switch_port_mac",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"), nullable=False, index=True)
    # Device (device_type SWITCH) que reportou esta vizinhança.
    switch_device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False, index=True)
    # Porta física local do switch (nome LLDP ou ifIndex da FDB).
    local_port = db.Column(db.String(120), default="", nullable=False)
    # Identidade do vizinho.
    remote_mac = db.Column(db.String(17), default="", nullable=False)
    remote_name = db.Column(db.String(255), default="", nullable=False)  # sysName LLDP
    remote_port = db.Column(db.String(120), default="", nullable=False)  # portId LLDP
    # Device correlacionado ao remote_mac neste perfil (quando existe).
    remote_device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=True)
    # "lldp" (switch↔switch) ou "fdb" (endpoint via forwarding database).
    source = db.Column(db.String(10), default="fdb", nullable=False)
    first_seen_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    last_seen_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    switch_device = db.relationship("Device", foreign_keys=[switch_device_id])
    remote_device = db.relationship("Device", foreign_keys=[remote_device_id])

    def __repr__(self):
        return f"<SwitchNeighbor switch={self.switch_device_id} port={self.local_port} mac={self.remote_mac}>"


# ---------------------------------------------------------------------------
# AuditLog — registro de ações sensíveis para auditoria
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=_utcnow, index=True, nullable=False)
    # user_id pode ser NULL em login falho ou ação de sistema.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    # Username duplicado como string para preservar a identidade mesmo que o
    # usuário seja deletado depois.
    username = db.Column(db.String(80), default="", nullable=False)
    action = db.Column(db.String(80), nullable=False, index=True)
    entity_type = db.Column(db.String(50), default="", nullable=False)
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, default="", nullable=False)
    ip_address = db.Column(db.String(45), default="", nullable=False)

    user = db.relationship("User", backref=db.backref("audit_logs", lazy="dynamic"))

    def __repr__(self):
        return f"<AuditLog {self.action} user={self.username} at={self.created_at}>"


# ---------------------------------------------------------------------------
# CveCache — cache de consultas CVE por (produto, versão)
# ---------------------------------------------------------------------------

class CveCache(db.Model):
    """Cache local de consultas à API de CVE (NVD).

    Evita re-consultar a mesma combinação produto+versão a cada execução do
    job de correlação (a API do NVD é lenta e tem rate-limit). Entradas mais
    antigas que CVE_CACHE_TTL_DAYS são re-consultadas.
    """
    __tablename__ = "cve_cache"
    __table_args__ = (
        db.UniqueConstraint("product", "version", name="uq_cve_product_version"),
    )

    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(120), nullable=False)
    version = db.Column(db.String(120), nullable=False)
    fetched_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    # JSON: lista de {"id": "CVE-...", "cvss": float|None, "summary": str}
    payload = db.Column(db.Text, default="[]", nullable=False)

    def get_cves(self) -> list[dict]:
        try:
            data = json.loads(self.payload or "[]")
            return data if isinstance(data, list) else []
        except (ValueError, TypeError):
            return []

    def __repr__(self):
        return f"<CveCache {self.product} {self.version}>"


# ---------------------------------------------------------------------------
# AppSetting — pares chave/valor para configurações editáveis pelo admin
# ---------------------------------------------------------------------------

class AppSetting(db.Model):
    """Configurações globais editáveis sem precisar reiniciar a aplicação.

    Use ``AppSetting.get_int(key, default)`` / ``set_value(key, value)`` para
    ler e escrever. As leituras devem ter um ``default`` que reflete o valor
    de ``Config`` correspondente para evitar dependência de seed inicial.
    """
    __tablename__ = "app_settings"

    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    @classmethod
    def get_value(cls, key: str, default: str = "") -> str:
        row = db.session.get(cls, key)
        return row.value if row else default

    @classmethod
    def get_int(cls, key: str, default: int) -> int:
        raw = cls.get_value(key, "")
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    @classmethod
    def set_value(cls, key: str, value) -> None:
        row = db.session.get(cls, key)
        if row is None:
            row = cls(key=key, value=str(value))
            db.session.add(row)
        else:
            row.value = str(value)
        row.updated_at = _utcnow()

    def __repr__(self):
        return f"<AppSetting {self.key}={self.value}>"
