"""Endpoints de health-check e métricas para monitoramento externo."""

import hmac
import logging

from flask import jsonify, current_app, request, Response
from sqlalchemy import text

from app.api import api_bp
from app.extensions import db, limiter

logger = logging.getLogger(__name__)


def _escape_prom_label(value: str) -> str:
    """Escapa um valor de label conforme o formato de exposição do Prometheus."""
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


@api_bp.route("/healthz")
@limiter.exempt
def healthz():
    """Retorna status da aplicação e do banco de dados.

    Não requer autenticação — destinado a load balancers e sistemas de
    monitoramento externos como Uptime Kuma, Zabbix ou Nagios.
    """
    db_ok = False
    try:
        db.session.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        # 503 sem nenhum log tornaria o diagnóstico impossível pelo lado
        # do servidor — registra a causa antes de responder "degraded".
        logger.exception("Health-check: banco de dados inacessível")

    status = "ok" if db_ok else "degraded"
    code = 200 if db_ok else 503
    return jsonify({"status": status, "db": "ok" if db_ok else "error"}), code


# Métricas expostas: (nome Prometheus, HELP, chave em compute_dashboard_stats).
_PROM_METRICS = [
    ("netmonitor_devices_total", "Dispositivos cadastrados no perfil.", "total_devices"),
    ("netmonitor_devices_online", "Dispositivos vistos online no perfil.", "online_devices"),
    ("netmonitor_new_devices_24h", "Dispositivos novos nas últimas 24h.", "new_devices_24h"),
    ("netmonitor_open_alerts", "Alertas abertos (não reconhecidos).", "open_alerts"),
    ("netmonitor_critical_port_devices", "Devices com porta crítica aberta.", "critical_port_devices"),
    ("netmonitor_open_vulnerabilities", "Vulnerabilidades confirmadas em aberto.", "open_vulnerabilities"),
    ("netmonitor_unauthorized_online", "Devices 'Não Autorizado' online agora.", "unauthorized_online"),
]


@api_bp.route("/metrics/prometheus")
@limiter.exempt
def prometheus_metrics():
    """Métricas no formato de exposição Prometheus, por perfil ativo.

    Opt-in via METRICS_ENABLED. Reusa compute_dashboard_stats (mesma fonte dos
    cartões do dashboard) para nunca divergir. Sem login — protegido por token
    opcional (METRICS_TOKEN) para não vazar contagens da rede.
    """
    from app.metrics_settings import is_metrics_enabled, get_metrics_token

    if not is_metrics_enabled():
        return Response("metrics disabled\n", status=404, mimetype="text/plain")

    token = get_metrics_token()
    if token:
        provided = ""
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            provided = auth[len("Bearer "):].strip()
        if not provided:
            provided = (request.args.get("token") or "").strip()
        if not hmac.compare_digest(provided, token):
            return Response("unauthorized\n", status=401, mimetype="text/plain")

    from app.models import Profile
    from app.stats import compute_dashboard_stats

    profiles = Profile.query.filter_by(is_active=True).order_by(Profile.name).all()
    stats_by_profile = [(p, compute_dashboard_stats(p.id)) for p in profiles]

    lines = [
        "# HELP netmonitor_up 1 se a aplicação respondeu ao scrape.",
        "# TYPE netmonitor_up gauge",
        "netmonitor_up 1",
    ]
    for name, help_text, key in _PROM_METRICS:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        for profile, stats in stats_by_profile:
            label = _escape_prom_label(profile.name)
            lines.append(
                f'{name}{{profile="{label}",profile_id="{profile.id}"}} {stats[key]}'
            )

    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/plain; version=0.0.4; charset=utf-8")
