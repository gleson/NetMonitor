"""Ligar/desligar em runtime o monitoramento IPv6.

Três chaves independentes, editáveis em **Admin → Configurações de Scan** sem
reiniciar a aplicação (mesmo padrão de ``metrics_settings``/``passive_arp``):

- ``ipv6.discovery_enabled`` — descoberta ATIVA: solicita respostas via ICMPv6
  multicast (ff02::1) e lê a tabela de vizinhança do kernel a cada ciclo de host
  discovery. Não requer root.
- ``ipv6.passive_enabled`` — descoberta PASSIVA: o sniffer já existente passa a
  capturar também NDP/ICMPv6, aprendendo endereços IPv6 sem gerar tráfego.
  Requer root e depende da descoberta passiva estar ligada.
- ``ipv6.port_scan_enabled`` — port scan ATIVO sobre o IPv6 global/ULA dos
  ativos (``nmap -6``), em job próprio.

Quando a chave não existe no banco, cada função cai para a config/variável de
ambiente correspondente, preservando o comportamento definido no deploy.
"""

from flask import current_app

_KEY_DISCOVERY = "ipv6.discovery_enabled"
_KEY_PASSIVE = "ipv6.passive_enabled"
_KEY_PORT_SCAN = "ipv6.port_scan_enabled"

_TRUTHY = ("1", "true", "True", "on", "yes")


def _read_flag(key: str, default: bool, app=None) -> bool:
    """Lê uma flag booleana de AppSetting com fallback para a config.

    ``app`` permite chamar fora de um app context (startup do scheduler), caso
    em que um contexto próprio é aberto — mesmo tratamento de
    ``passive.is_passive_discovery_enabled``.
    """
    from app.models import AppSetting

    try:
        if app is not None:
            with app.app_context():
                raw = AppSetting.get_value(key, "")
        else:
            raw = AppSetting.get_value(key, "")
    except Exception:
        # Tabela ainda não migrada ou sem contexto — usa o default da config.
        return default
    if raw == "":
        return default
    return raw in _TRUTHY


def _config(app, key: str, default):
    cfg = app.config if app is not None else current_app.config
    return cfg.get(key, default)


def is_ipv6_discovery_enabled(app=None) -> bool:
    """True se a descoberta ativa de vizinhos IPv6 deve rodar."""
    default = bool(_config(app, "IPV6_DISCOVERY_ENABLED", True))
    return _read_flag(_KEY_DISCOVERY, default, app)


def is_ipv6_passive_enabled(app=None) -> bool:
    """True se o sniffer passivo deve capturar também NDP/ICMPv6.

    O default acompanha a descoberta ativa: quem liga IPv6 normalmente quer as
    duas vias. A checagem de root e de o sniffer estar ligado é feita em
    ``app.scanner.passive`` — aqui só se responde pela intenção do operador.
    """
    default = bool(_config(app, "IPV6_DISCOVERY_ENABLED", True))
    return _read_flag(_KEY_PASSIVE, default, app)


def is_ipv6_port_scan_enabled(app=None) -> bool:
    """True se o job de port scan sobre IPv6 deve ser registrado.

    Default: ligado quando ``IPV6_PORT_SCAN_INTERVAL_HOURS`` > 0.
    """
    default = int(_config(app, "IPV6_PORT_SCAN_INTERVAL_HOURS", 12)) > 0
    return _read_flag(_KEY_PORT_SCAN, default, app)


def set_ipv6_discovery_enabled(enabled: bool) -> None:
    from app.models import AppSetting
    AppSetting.set_value(_KEY_DISCOVERY, "1" if enabled else "0")


def set_ipv6_passive_enabled(enabled: bool) -> None:
    from app.models import AppSetting
    AppSetting.set_value(_KEY_PASSIVE, "1" if enabled else "0")


def set_ipv6_port_scan_enabled(enabled: bool) -> None:
    from app.models import AppSetting
    AppSetting.set_value(_KEY_PORT_SCAN, "1" if enabled else "0")
