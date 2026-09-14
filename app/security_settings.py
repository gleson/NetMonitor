"""Ligar/desligar em runtime as checagens de higiene de segurança.

Mesmo padrão de ``ipv6_settings``/``metrics_settings``: chave em ``AppSetting``
com fallback para a config quando ainda não foi definida, editável em
**Admin → Configurações de Scan** sem reiniciar a aplicação.

- ``security.service_change_enabled`` — alerta SERVICE_CHANGED quando o banner
  (``-sV``) de uma porta já mapeada muda de serviço ou de versão.
- ``security.tls_quality_enabled`` — alerta WEAK_TLS sobre a configuração TLS
  (protocolo obsoleto, assinatura SHA-1/MD5, chave curta, autoassinado).
  Avaliado dentro do job TLS já existente.
- ``dns.check_enabled`` — job de integridade do DNS (vive em
  ``app.scanner.dns_check`` porque é lá que é consumido; reexportado aqui para
  a view de admin ter um só ponto de importação).
"""

from flask import current_app

from app.scanner.dns_check import is_dns_check_enabled, set_dns_check_enabled  # noqa: F401

_KEY_SERVICE_CHANGE = "security.service_change_enabled"
_KEY_TLS_QUALITY = "security.tls_quality_enabled"

_TRUTHY = ("1", "true", "True", "on", "yes")


def _read_flag(key: str, default: bool, app=None) -> bool:
    from app.models import AppSetting

    try:
        if app is not None:
            with app.app_context():
                raw = AppSetting.get_value(key, "")
        else:
            raw = AppSetting.get_value(key, "")
    except Exception:
        return default
    if raw == "":
        return default
    return raw in _TRUTHY


def _config(app, key: str, default):
    cfg = app.config if app is not None else current_app.config
    return cfg.get(key, default)


def is_service_change_enabled(app=None) -> bool:
    """True se mudanças de serviço/versão em portas conhecidas devem alertar."""
    default = bool(_config(app, "SERVICE_CHANGE_ALERTS_ENABLED", True))
    return _read_flag(_KEY_SERVICE_CHANGE, default, app)


def is_tls_quality_enabled(app=None) -> bool:
    """True se a configuração TLS dos serviços deve ser avaliada."""
    default = bool(_config(app, "TLS_QUALITY_ENABLED", True))
    return _read_flag(_KEY_TLS_QUALITY, default, app)


def set_service_change_enabled(enabled: bool) -> None:
    from app.models import AppSetting
    AppSetting.set_value(_KEY_SERVICE_CHANGE, "1" if enabled else "0")


def set_tls_quality_enabled(enabled: bool) -> None:
    from app.models import AppSetting
    AppSetting.set_value(_KEY_TLS_QUALITY, "1" if enabled else "0")
