"""Blueprint de alertas."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required

from app.auth_utils import audit, require_role
from app.extensions import db
from app.models import (
    Alert, AlertType, Severity, Device, DeviceIp, Profile, ROLE_OPERATOR,
    _utcnow,
)

alerts_bp = Blueprint("alerts", __name__, template_folder="../templates/alerts")


@alerts_bp.route("/")
@login_required
def alert_list():
    """Lista paginada de alertas com filtros."""
    from app.profile_utils import get_active_profile_id
    profile_id = get_active_profile_id()
    alert_type = request.args.get("type", "")
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")  # "open" ou "acknowledged"
    device_search = request.args.get("device", "").strip()
    page = request.args.get("page", 1, type=int)

    # Ordenação por coluna (agrupa por severidade, tipo, dispositivo, etc.).
    _valid_sorts = {"created", "severity", "type", "device", "status"}
    sort = request.args.get("sort", "created")
    if sort not in _valid_sorts:
        sort = "created"
    direction = "asc" if request.args.get("dir") == "asc" else "desc"
    descending = direction == "desc"

    # Banner alert-danger no topo lista todos os HOST_DOWN prioritários abertos
    # (não respeita os filtros — esses casos precisam visibilidade incondicional).
    priority_q = Alert.query.filter(
        Alert.is_priority.is_(True),
        Alert.acknowledged_at.is_(None),
    )
    if profile_id:
        priority_q = priority_q.filter_by(profile_id=profile_id)
    priority_alerts = priority_q.order_by(Alert.created_at.desc()).all()

    query = Alert.query

    if profile_id:
        query = query.filter_by(profile_id=profile_id)
    if alert_type:
        try:
            query = query.filter_by(alert_type=AlertType(alert_type))
        except ValueError:
            pass
    if severity:
        try:
            query = query.filter_by(severity=Severity(severity))
        except ValueError:
            pass
    if status == "open":
        query = query.filter(Alert.acknowledged_at.is_(None))
    elif status == "acknowledged":
        query = query.filter(Alert.acknowledged_at.isnot(None))

    device_joined = False
    if device_search:
        like = f"%{device_search}%"
        # Subquery: device_ids cujo IP atual bate com a busca
        ip_sq = (
            db.select(DeviceIp.device_id)
            .where(DeviceIp.ip.ilike(like))
            .scalar_subquery()
        )
        query = (
            query.join(Device, Alert.device_id == Device.id)
            .filter(
                db.or_(
                    Device.friendly_name.ilike(like),
                    Device.hostname.ilike(like),
                    Device.mac.ilike(like),
                    Device.id.in_(ip_sq),
                )
            )
        )
        device_joined = True

    # Ordenação escolhida pelo usuário (clicando nos cabeçalhos da tabela).
    def _dir(col):
        return col.desc() if descending else col.asc()

    if sort == "severity":
        # Rank explícito: CRITICAL > WARNING > INFO (a ordem alfabética do enum
        # não reflete a gravidade real).
        sev_rank = db.case(
            (Alert.severity == Severity.CRITICAL, 3),
            (Alert.severity == Severity.WARNING, 2),
            (Alert.severity == Severity.INFO, 1),
            else_=0,
        )
        query = query.order_by(_dir(sev_rank), Alert.created_at.desc())
    elif sort == "type":
        query = query.order_by(_dir(Alert.alert_type), Alert.created_at.desc())
    elif sort == "device":
        if not device_joined:
            query = query.outerjoin(Device, Alert.device_id == Device.id)
        name_expr = db.func.coalesce(
            Device.friendly_name, Device.hostname, Device.mac
        )
        query = query.order_by(_dir(name_expr), Alert.created_at.desc())
    elif sort == "status":
        # Agrupa abertos (acknowledged_at IS NULL) vs reconhecidos.
        query = query.order_by(
            _dir(Alert.acknowledged_at.is_(None)), Alert.created_at.desc()
        )
    else:  # "created" (padrão) — prioritários no topo, depois mais recentes.
        query = query.order_by(Alert.is_priority.desc(), _dir(Alert.created_at))

    pagination = query.paginate(page=page, per_page=25, error_out=False)

    return render_template(
        "alerts/list.html",
        alerts=pagination.items,
        pagination=pagination,
        selected_profile_id=profile_id,
        selected_type=alert_type,
        selected_severity=severity,
        selected_status=status,
        device_search=device_search,
        sort=sort,
        direction=direction,
        alert_types=AlertType,
        severities=Severity,
        priority_alerts=priority_alerts,
    )


@alerts_bp.route("/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def acknowledge(alert_id):
    """Marca um alerta como reconhecido."""
    alert = db.session.get(Alert, alert_id)
    if alert and not alert.acknowledged_at:
        alert.acknowledged_at = _utcnow()
        audit("alert.acknowledge", "alert", alert.id)
        db.session.commit()
        flash("Alerta reconhecido.", "success")
    return redirect(request.referrer or url_for("alerts.alert_list"))


@alerts_bp.route("/acknowledge-selected", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def acknowledge_selected():
    """Reconhece apenas os alertas marcados pelo usuário."""
    from app.profile_utils import get_active_profile_id

    alert_ids = request.form.getlist("alert_ids", type=int)
    if not alert_ids:
        flash("Nenhum alerta selecionado.", "warning")
        return redirect(request.referrer or url_for("alerts.alert_list"))

    profile_id = get_active_profile_id()
    now = _utcnow()

    query = Alert.query.filter(
        Alert.id.in_(alert_ids),
        Alert.acknowledged_at.is_(None),
    )
    if profile_id:
        query = query.filter_by(profile_id=profile_id)

    updated = query.update({"acknowledged_at": now}, synchronize_session=False)
    audit(
        "alert.acknowledge_selected",
        "alert",
        None,
        details=f"{updated} alerta(s) ids={alert_ids}",
    )
    db.session.commit()
    flash(f"{updated} alerta(s) reconhecido(s).", "success")
    return redirect(request.referrer or url_for("alerts.alert_list"))


@alerts_bp.route("/acknowledge-all", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def acknowledge_all():
    """Reconhece os alertas abertos de um perfil, respeitando os filtros ativos.

    profile_id é obrigatório para evitar reconhecimento em massa acidental entre
    perfis distintos. Quando a lista está filtrada (tipo/severidade/dispositivo),
    o formulário reenvia esses filtros e só o subconjunto visível é reconhecido —
    sem filtros, o comportamento é reconhecer todos os abertos do perfil.
    """
    profile_id = request.form.get("profile_id", type=int)

    if not profile_id:
        flash(
            "Selecione um perfil antes de reconhecer todos os alertas.",
            "danger",
        )
        return redirect(request.referrer or url_for("alerts.alert_list"))

    profile = db.session.get(Profile, profile_id)
    if not profile:
        flash("Perfil não encontrado.", "danger")
        return redirect(request.referrer or url_for("alerts.alert_list"))

    alert_type = request.form.get("type", "").strip()
    severity = request.form.get("severity", "").strip()
    device_search = request.form.get("device", "").strip()

    now = _utcnow()
    query = Alert.query.filter(
        Alert.acknowledged_at.is_(None),
        Alert.profile_id == profile_id,
    )

    filters_desc = []
    if alert_type:
        try:
            query = query.filter(Alert.alert_type == AlertType(alert_type))
            filters_desc.append(f"tipo={alert_type}")
        except ValueError:
            pass
    if severity:
        try:
            query = query.filter(Alert.severity == Severity(severity))
            filters_desc.append(f"severidade={severity}")
        except ValueError:
            pass
    if device_search:
        like = f"%{device_search}%"
        ip_sq = (
            db.select(DeviceIp.device_id)
            .where(DeviceIp.ip.ilike(like))
            .scalar_subquery()
        )
        dev_sq = (
            db.select(Device.id)
            .where(
                db.or_(
                    Device.friendly_name.ilike(like),
                    Device.hostname.ilike(like),
                    Device.mac.ilike(like),
                    Device.id.in_(ip_sq),
                )
            )
            .scalar_subquery()
        )
        query = query.filter(Alert.device_id.in_(dev_sq))
        filters_desc.append(f"device~{device_search}")

    # synchronize_session=False: a atualização usa subquery (in_) e não roda mais
    # nada nesta sessão antes do commit, então não há estado a sincronizar.
    updated = query.update({"acknowledged_at": now}, synchronize_session=False)
    audit(
        "alert.acknowledge_all",
        "profile",
        profile_id,
        details=(
            f"{updated} alerta(s)"
            + (f" (filtros: {', '.join(filters_desc)})" if filters_desc else "")
        ),
    )
    db.session.commit()
    if filters_desc:
        flash(
            f"{updated} alerta(s) do perfil '{profile.name}' reconhecidos "
            f"(filtros: {', '.join(filters_desc)}).",
            "success",
        )
    else:
        flash(
            f"{updated} alerta(s) do perfil '{profile.name}' reconhecidos.",
            "success",
        )
    return redirect(request.referrer or url_for("alerts.alert_list"))
