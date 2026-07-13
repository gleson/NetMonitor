"""Blueprint de exportação/importação — CSV e JSON de devices, alertas e vulnerabilidades."""

import csv
import io
import json
import re
from datetime import datetime, timezone

from flask import Blueprint, request, Response, stream_with_context, redirect, url_for, flash
from flask_login import login_required, current_user

from app.auth_utils import require_role, audit
from app.crypto_export import (
    encrypt_payload, decrypt_payload, is_encrypted_envelope, DecryptError,
)
from app.extensions import db
from app.models import (
    Device, DeviceIp, Port, Alert, Vulnerability, Profile,
    DeviceType,
    ROLE_OPERATOR, _utcnow,
)

export_bp = Blueprint("export", __name__)

_FMT = "%d/%m/%Y %H:%M:%S"
_IMPORT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
# Valores atuais do select: NI / Ok / Não Autorizado. Os demais são mantidos
# para importar arquivos antigos sem perder a situação já gravada.
_VALID_SITUATIONS = {"NI", "Ok", "Não Autorizado", "Autorizado", "Identificado", "Suspeito"}


def _fmt_dt(dt):
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime(_FMT)


def _csv_safe(value):
    """Neutraliza CSV/Formula Injection (CWE-1236).

    Campos como hostname/vendor/os_guess e o output de scripts NSE do nmap vêm
    da rede (não-confiáveis). Prefixa com aspa simples as células que começam
    com um caractere que o Excel/LibreOffice interpretaria como fórmula.
    """
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _safe_row(values):
    """Aplica _csv_safe a cada célula de uma linha de CSV."""
    return [_csv_safe(v) for v in values]


def _export_password() -> str:
    """Senha de criptografia da exportação (form ou query). Vazia = sem cifra."""
    return (request.values.get("password") or "").strip()


def _encrypted_response(payload_text: str, fmt: str, password: str, base_filename: str) -> Response:
    """Cifra `payload_text` com `password` e devolve como anexo .enc."""
    envelope = encrypt_payload(payload_text, password, fmt=fmt)
    return Response(
        envelope,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{base_filename}.{fmt}.enc"'
        },
    )


def _parse_dt(value: str):
    """Converte o timestamp exportado (_FMT, UTC) de volta para datetime naive UTC."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, _FMT)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Helpers de importação
# ---------------------------------------------------------------------------

def _normalize_mac(mac: str) -> str | None:
    """Normaliza MAC para o formato AA:BB:CC:DD:EE:FF."""
    clean = re.sub(r"[:\-\.\s]", "", mac).upper()
    if len(clean) != 12 or not all(c in "0123456789ABCDEF" for c in clean):
        return None
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


def _update_device_from_row(device: Device, row: dict) -> None:
    """Aplica campos importáveis de um dict sobre um Device."""
    def _get(*keys):
        for k in keys:
            v = row.get(k)
            if v is not None:
                return str(v).strip()
        return ""

    fn = _get("friendly_name", "Nome amigável")
    if fn:
        device.friendly_name = fn

    hn = _get("hostname", "Hostname")
    if hn:
        device.hostname = hn

    vendor = _get("vendor", "Vendor")
    if vendor:
        device.vendor = vendor

    os_g = _get("os_guess", "OS")
    if os_g:
        device.os_guess = os_g

    tags = _get("tags", "Tags")
    if tags:
        device.tags = tags

    notes = _get("notes", "Notas")
    if notes:
        device.notes = notes

    # Device type: aceita valor do enum (ex.: "COMPUTER") ou texto (ex.: "computer")
    dt_str = _get("device_type", "Tipo").upper()
    if dt_str:
        matched = next((dt for dt in DeviceType if dt.value.upper() == dt_str), None)
        if matched:
            device.device_type = matched

    # Situação
    sit = _get("situation", "Situação")
    if sit in _VALID_SITUATIONS:
        device.situation = sit


def _set_device_ip(device: Device, ip: str) -> None:
    """Define o IP atual de um device recém-criado."""
    DeviceIp.query.filter_by(device_id=device.id, is_current=True).update({"is_current": False})
    dip = DeviceIp(
        device_id=device.id,
        ip=ip,
        is_current=True,
        first_seen_at=_utcnow(),
        last_seen_at=_utcnow(),
    )
    db.session.add(dip)


def _parse_import_json(text: str) -> list[dict]:
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("devices", [])
    return []


def _parse_import_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    return list(reader)


# ---------------------------------------------------------------------------
# Importação
# ---------------------------------------------------------------------------

@export_bp.route("/devices/import", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def import_devices():
    """Importa dispositivos de arquivo JSON ou CSV para um perfil."""
    profile_id = request.form.get("profile_id", type=int)
    file = request.files.get("file")

    if not profile_id:
        flash("Selecione um perfil.", "danger")
        return redirect(url_for("devices.device_list"))

    profile = db.session.get(Profile, profile_id)
    if not profile:
        flash("Perfil não encontrado.", "danger")
        return redirect(url_for("devices.device_list"))

    if not file or not file.filename:
        flash("Selecione um arquivo para importar.", "danger")
        return redirect(url_for("devices.device_list", profile_id=profile_id))

    # Limite de tamanho
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > _IMPORT_MAX_BYTES:
        flash(f"Arquivo muito grande (máx. 5 MB). Tamanho: {size // 1024} KB.", "danger")
        return redirect(url_for("devices.device_list", profile_id=profile_id))

    try:
        raw_text = file.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("Não foi possível ler o arquivo (codificação inválida).", "danger")
        return redirect(url_for("devices.device_list", profile_id=profile_id))

    fname = file.filename.lower()

    # Arquivo cifrado (.enc): decifra com a senha antes de detectar o formato.
    if is_encrypted_envelope(raw_text):
        password = (request.form.get("password") or "").strip()
        if not password:
            flash("Arquivo cifrado: informe a senha usada na exportação.", "danger")
            return redirect(url_for("devices.device_list", profile_id=profile_id))
        try:
            raw_text, fmt = decrypt_payload(raw_text, password)
        except DecryptError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("devices.device_list", profile_id=profile_id))
    elif fname.endswith(".json"):
        fmt = "json"
    elif fname.endswith(".csv"):
        fmt = "csv"
    else:
        flash("Formato não suportado. Use .json ou .csv gerado pela exportação.", "danger")
        return redirect(url_for("devices.device_list", profile_id=profile_id))

    try:
        if fmt == "json":
            rows = _parse_import_json(raw_text)
        else:
            rows = _parse_import_csv(raw_text)
    except Exception as exc:
        flash(f"Erro ao ler arquivo: {exc}", "danger")
        return redirect(url_for("devices.device_list", profile_id=profile_id))

    created = updated = 0
    errors: list[str] = []

    for i, row in enumerate(rows, 1):
        raw_mac = (row.get("mac") or row.get("MAC") or "").strip()
        if not raw_mac:
            errors.append(f"Linha {i}: campo MAC ausente.")
            continue

        mac = _normalize_mac(raw_mac)
        if not mac:
            errors.append(f"Linha {i}: MAC inválido ({raw_mac!r}).")
            continue

        existing = Device.query.filter_by(profile_id=profile_id, mac=mac).first()
        if existing:
            _update_device_from_row(existing, row)
            updated += 1
        else:
            device = Device(profile_id=profile_id, mac=mac)
            _update_device_from_row(device, row)
            db.session.add(device)
            db.session.flush()

            # Preserva os timestamps do arquivo exportado. Sem eles, NÃO usar
            # "agora": o device importado nunca foi visto nesta instalação e
            # apareceria como Online até o próximo discovery. Atribuído após o
            # flush porque o default da coluna sobrepõe None no INSERT.
            imported_first = _parse_dt(row.get("first_seen_at") or row.get("Primeiro Visto") or "")
            imported_last = _parse_dt(row.get("last_seen_at") or row.get("Último Visto") or "")
            device.first_seen_at = imported_first or imported_last or _utcnow()
            device.last_seen_at = imported_last

            # IP inicial apenas para devices novos (não sobrescreve dados de scan ao atualizar)
            ip = (row.get("current_ip") or row.get("IP atual") or "").strip()
            if ip:
                _set_device_ip(device, ip)

            created += 1

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        flash(f"Erro ao salvar: {exc}", "danger")
        return redirect(url_for("devices.device_list", profile_id=profile_id))

    # Audit log
    summary = f"Importação de ativos no perfil '{profile.name}': {created} criados, {updated} atualizados."
    if errors:
        summary += f" {len(errors)} erros."
    audit(
        "devices.import",
        entity_type="Profile",
        entity_id=profile_id,
        details=summary,
    )
    db.session.commit()

    msg = f"Importação concluída: {created} criado(s), {updated} atualizado(s)."
    if errors:
        msg += f" {len(errors)} linha(s) com erro."
        for err in errors[:5]:
            flash(err, "warning")
    flash(msg, "success")
    return redirect(url_for("devices.device_list", profile_id=profile_id))


# ---------------------------------------------------------------------------
# Exportação — Devices
# ---------------------------------------------------------------------------

@export_bp.route("/devices/export", methods=["GET", "POST"])
@login_required
@require_role(ROLE_OPERATOR)
def export_devices():
    """Exporta inventário de dispositivos em CSV ou JSON.

    Params: profile_id (obrigatório), format=csv|json (default csv).
    Para exportação cifrada, use POST com `password` (deriva a chave por scrypt).
    """
    profile_id = request.values.get("profile_id", type=int)
    fmt = request.values.get("format", "csv").lower()
    password = _export_password()

    if not profile_id:
        return Response("profile_id é obrigatório.", status=400)

    profile = db.session.get(Profile, profile_id)
    if not profile:
        return Response("Perfil não encontrado.", status=404)

    devices = (
        Device.query
        .filter_by(profile_id=profile_id)
        .order_by(Device.last_seen_at.desc())
        .all()
    )

    if fmt == "json":
        rows = []
        for d in devices:
            open_ports = Port.query.filter_by(device_id=d.id).filter(
                Port.last_seen_closed_at.is_(None)
            ).all()
            rows.append({
                "mac": d.mac,
                "friendly_name": d.friendly_name or "",
                "hostname": d.hostname or "",
                "vendor": d.vendor or "",
                "device_type": d.device_type.value if d.device_type else "",
                "os_guess": d.os_guess or "",
                "current_ip": d.current_ip or "",
                "situation": d.situation or "",
                "tags": d.tags or "",
                "notes": d.notes or "",
                "open_ports": [
                    {"protocol": p.protocol, "port": p.port, "service": p.service_name or ""}
                    for p in open_ports
                ],
                "first_seen_at": _fmt_dt(d.first_seen_at),
                "last_seen_at": _fmt_dt(d.last_seen_at),
            })
        payload = json.dumps(
            {"profile": profile.name, "exported_at": _fmt_dt(_utcnow()), "devices": rows},
            ensure_ascii=False,
            indent=2,
        )
        if password:
            return _encrypted_response(payload, "json", password, f"devices_{profile_id}")
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="devices_{profile_id}.json"'},
        )

    # CSV
    def _devices_csv_rows():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "mac", "friendly_name", "hostname", "vendor", "device_type",
            "os_guess", "current_ip", "situation", "tags", "notes",
            "open_ports_count", "first_seen_at", "last_seen_at",
        ])
        yield buf.getvalue()
        for d in devices:
            port_count = Port.query.filter_by(device_id=d.id).filter(
                Port.last_seen_closed_at.is_(None)
            ).count()
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(_safe_row([
                d.mac, d.friendly_name or "", d.hostname or "",
                d.vendor or "",
                d.device_type.value if d.device_type else "",
                d.os_guess or "", d.current_ip or "",
                d.situation or "", d.tags or "", d.notes or "",
                port_count,
                _fmt_dt(d.first_seen_at), _fmt_dt(d.last_seen_at),
            ]))
            yield buf.getvalue()

    if password:
        return _encrypted_response("".join(_devices_csv_rows()), "csv", password, f"devices_{profile_id}")

    return Response(
        stream_with_context(_devices_csv_rows()),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="devices_{profile_id}.csv"'},
    )


# ---------------------------------------------------------------------------
# Exportação — Alertas
# ---------------------------------------------------------------------------

@export_bp.route("/alerts/export", methods=["GET", "POST"])
@login_required
@require_role(ROLE_OPERATOR)
def export_alerts():
    """Exporta alertas em CSV ou JSON.

    Params: profile_id (obrigatório), format=csv|json, status=open|acknowledged.
    Para exportação cifrada, use POST com `password`.
    """
    profile_id = request.values.get("profile_id", type=int)
    fmt = request.values.get("format", "csv").lower()
    status = request.values.get("status", "")
    password = _export_password()

    if not profile_id:
        return Response("profile_id é obrigatório.", status=400)

    profile = db.session.get(Profile, profile_id)
    if not profile:
        return Response("Perfil não encontrado.", status=404)

    query = Alert.query.filter_by(profile_id=profile_id)
    if status == "open":
        query = query.filter(Alert.acknowledged_at.is_(None))
    elif status == "acknowledged":
        query = query.filter(Alert.acknowledged_at.isnot(None))
    alerts = query.order_by(Alert.created_at.desc()).all()

    if fmt == "json":
        rows = []
        for a in alerts:
            rows.append({
                "id": a.id,
                "alert_type": a.alert_type.value,
                "severity": a.severity.value,
                "message": a.message,
                "device_id": a.device_id,
                "created_at": _fmt_dt(a.created_at),
                "acknowledged_at": _fmt_dt(a.acknowledged_at),
            })
        payload = json.dumps({"profile": profile.name, "alerts": rows}, ensure_ascii=False, indent=2)
        if password:
            return _encrypted_response(payload, "json", password, f"alerts_{profile_id}")
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="alerts_{profile_id}.json"'},
        )

    def _alerts_csv_rows():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID", "Tipo", "Severidade", "Mensagem", "Device ID", "Criado em", "Reconhecido em"])
        yield buf.getvalue()
        for a in alerts:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(_safe_row([
                a.id, a.alert_type.value, a.severity.value, a.message,
                a.device_id or "",
                _fmt_dt(a.created_at), _fmt_dt(a.acknowledged_at),
            ]))
            yield buf.getvalue()

    if password:
        return _encrypted_response("".join(_alerts_csv_rows()), "csv", password, f"alerts_{profile_id}")

    return Response(
        stream_with_context(_alerts_csv_rows()),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="alerts_{profile_id}.csv"'},
    )


# ---------------------------------------------------------------------------
# Exportação — Vulnerabilidades
# ---------------------------------------------------------------------------

@export_bp.route("/devices/<int:device_id>/vulns/export", methods=["GET", "POST"])
@login_required
@require_role(ROLE_OPERATOR)
def export_vulns(device_id):
    """Exporta vulnerabilidades de um device em CSV ou JSON.

    Params: format=csv|json. Para exportação cifrada, use POST com `password`.
    """
    device = db.session.get(Device, device_id)
    if not device:
        return Response("Dispositivo não encontrado.", status=404)

    fmt = request.values.get("format", "csv").lower()
    password = _export_password()
    vulns = Vulnerability.query.filter_by(device_id=device_id).order_by(
        Vulnerability.is_vulnerable.desc(), Vulnerability.last_seen_at.desc()
    ).all()

    if fmt == "json":
        rows = [
            {
                "id": v.id,
                "port": v.port,
                "protocol": v.protocol,
                "service": v.service,
                "script_name": v.script_name,
                "is_vulnerable": v.is_vulnerable,
                "output": v.output,
                "found_at": _fmt_dt(v.found_at),
                "resolved_at": _fmt_dt(v.resolved_at),
            }
            for v in vulns
        ]
        payload = json.dumps({
            "device": device.display_name, "mac": device.mac, "vulnerabilities": rows
        }, ensure_ascii=False, indent=2)
        if password:
            return _encrypted_response(payload, "json", password, f"vulns_{device_id}")
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="vulns_{device_id}.json"'},
        )

    def _vulns_csv_rows():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID", "Porta", "Protocolo", "Serviço", "Script", "Vulnerável", "Output", "Encontrado em", "Resolvido em"])
        yield buf.getvalue()
        for v in vulns:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(_safe_row([
                v.id, v.port, v.protocol, v.service, v.script_name,
                "Sim" if v.is_vulnerable else "Não",
                v.output, _fmt_dt(v.found_at), _fmt_dt(v.resolved_at),
            ]))
            yield buf.getvalue()

    if password:
        return _encrypted_response("".join(_vulns_csv_rows()), "csv", password, f"vulns_{device_id}")

    return Response(
        stream_with_context(_vulns_csv_rows()),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vulns_{device_id}.csv"'},
    )


# ---------------------------------------------------------------------------
# Exportação — Histórico de portas
# ---------------------------------------------------------------------------

@export_bp.route("/devices/<int:device_id>/ports/export", methods=["GET", "POST"])
@login_required
@require_role(ROLE_OPERATOR)
def export_port_history(device_id):
    """Exporta o histórico de portas de um device em CSV ou JSON.

    Inclui portas abertas e já fechadas, com os timestamps de abertura/fecho e o
    baseline (is_authorized). Params: format=csv|json. Para exportação cifrada,
    use POST com `password`.
    """
    device = db.session.get(Device, device_id)
    if not device:
        return Response("Dispositivo não encontrado.", status=404)

    fmt = request.values.get("format", "csv").lower()
    password = _export_password()
    ports = (
        Port.query.filter_by(device_id=device_id)
        .order_by(Port.protocol, Port.port)
        .all()
    )

    if fmt == "json":
        rows = [
            {
                "protocol": p.protocol,
                "port": p.port,
                "state": p.state,
                "is_open": p.last_seen_closed_at is None,
                "is_authorized": p.is_authorized,
                "service_name": p.service_name,
                "service_version": p.service_version,
                "first_open_at": _fmt_dt(p.first_open_at),
                "last_seen_open_at": _fmt_dt(p.last_seen_open_at),
                "last_seen_closed_at": _fmt_dt(p.last_seen_closed_at),
            }
            for p in ports
        ]
        payload = json.dumps({
            "device": device.display_name, "mac": device.mac, "ports": rows
        }, ensure_ascii=False, indent=2)
        if password:
            return _encrypted_response(payload, "json", password, f"ports_{device_id}")
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="ports_{device_id}.json"'},
        )

    def _ports_csv_rows():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "Protocolo", "Porta", "Estado", "Aberta agora", "Autorizada",
            "Serviço", "Versão", "Primeira abertura", "Visto aberto por último",
            "Fechada em",
        ])
        yield buf.getvalue()
        for p in ports:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(_safe_row([
                p.protocol, p.port, p.state,
                "Sim" if p.last_seen_closed_at is None else "Não",
                "Sim" if p.is_authorized else "Não",
                p.service_name or "", p.service_version or "",
                _fmt_dt(p.first_open_at), _fmt_dt(p.last_seen_open_at),
                _fmt_dt(p.last_seen_closed_at),
            ]))
            yield buf.getvalue()

    if password:
        return _encrypted_response("".join(_ports_csv_rows()), "csv", password, f"ports_{device_id}")

    return Response(
        stream_with_context(_ports_csv_rows()),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="ports_{device_id}.csv"'},
    )
