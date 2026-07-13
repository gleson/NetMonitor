"""Gerência runtime do endpoint de métricas Prometheus.

O ligar/desligar e o token do endpoint ``/api/metrics/prometheus`` ficam em
``AppSetting`` (editáveis em Admin → Métricas, sem reiniciar). Quando a chave
não existe no banco, cai para a config/variável de ambiente correspondente
(``METRICS_ENABLED`` / ``METRICS_TOKEN``), preservando o comportamento anterior.
"""

import secrets

from flask import current_app

_KEY_ENABLED = "metrics.enabled"
_KEY_TOKEN = "metrics.token"


def is_metrics_enabled() -> bool:
    """True se o endpoint Prometheus deve responder.

    AppSetting tem prioridade; sem ela, usa ``METRICS_ENABLED`` da config.
    """
    from app.models import AppSetting

    raw = AppSetting.get_value(_KEY_ENABLED, "")
    if raw == "":
        return bool(current_app.config.get("METRICS_ENABLED", False))
    return raw == "1"


def get_metrics_token() -> str:
    """Token exigido no scrape (string vazia = endpoint aberto).

    AppSetting tem prioridade; sem ela, usa ``METRICS_TOKEN`` da config.
    """
    from app.models import AppSetting

    raw = AppSetting.get_value(_KEY_TOKEN, "")
    if raw:
        return raw
    return (current_app.config.get("METRICS_TOKEN") or "").strip()


def set_metrics_enabled(enabled: bool) -> None:
    from app.models import AppSetting

    AppSetting.set_value(_KEY_ENABLED, "1" if enabled else "0")


def set_metrics_token(token: str) -> None:
    from app.models import AppSetting

    AppSetting.set_value(_KEY_TOKEN, (token or "").strip())


def generate_metrics_token() -> str:
    """Gera um token aleatório url-safe e o persiste. Retorna o token."""
    token = secrets.token_urlsafe(32)
    set_metrics_token(token)
    return token
