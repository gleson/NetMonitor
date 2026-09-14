"""Detecção de man-in-the-middle na rede local.

O monitor já detectava ARP spoofing de um jeito indireto: durante a descoberta
ativa, quando dois MACs reivindicam o mesmo IP e o dono anterior ainda estava
online (``run_host_discovery`` → ``ARP_SPOOFING``). Isso cobre um caso real,
mas tem duas lacunas grandes:

1. **Só enxerga o que o próprio monitor varre.** Um ataque de ARP poisoning
   clássico envenena o cache da *vítima* e do *gateway*, não necessariamente o
   do monitor. Se o atacante não responder às varreduras do monitor, o conflito
   nunca aparece no scan ativo.
2. **Só cobre IPv4 e só o vetor ARP.** DHCP rogue, Router Advertisement rogue
   (IPv6) e NDP spoofing colocam o atacante no meio do caminho sem gerar
   nenhum conflito de IP.

Este módulo fecha as duas. As detecções são todas **passivas ou de custo
desprezível** — nenhuma gera tráfego de varredura:

- ``check_gateway_integrity``: compara o MAC do gateway padrão (IPv4 e IPv6)
  com um baseline persistido. É o sinal mais direto de MITM bem-sucedido: se o
  tráfego de saída passou a apontar para outro MAC, alguém assumiu o lugar do
  roteador.
- ``observe_dhcp_server`` / ``observe_router_advertisement``: aprendem quem são
  os servidores DHCP e os roteadores IPv6 legítimos e alertam quando aparece um
  novo. Um DHCP rogue entrega gateway e DNS falsos; um RA rogue faz o mesmo em
  IPv6 — e **tem precedência sobre o IPv4** na maioria dos sistemas, o que faz
  dele o vetor de MITM mais eficaz em redes duplo-stack.
- ``observe_neighbor_claim``: detecta um MAC reivindicando um IP que pertence a
  outro ativo ainda online, em IPv4 (ARP) e IPv6 (NDP), a partir do tráfego
  capturado pelo sniffer passivo.

Os baselines ficam em ``AppSetting`` (sem migration), por perfil, e podem ser
revistos e redefinidos em Admin → Configurações de Scan.
"""

import json
import logging
import re
import subprocess

logger = logging.getLogger(__name__)

# Chaves de baseline em AppSetting, por perfil.
_KEY_GATEWAY = "mitm.gateway_baseline"
_KEY_DHCP = "mitm.dhcp_servers"
_KEY_ROUTERS6 = "mitm.ipv6_routers"

# Quantos servidores/roteadores distintos memorizar por perfil. Um teto evita
# que um atacante que rotacione MACs encha a tabela de baseline e, com isso,
# "legitime" qualquer origem futura.
_MAX_BASELINE_ENTRIES = 8


def _utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(tzinfo=None)


def is_mitm_detection_enabled(app=None) -> bool:
    """True se as detecções de MITM devem rodar (AppSetting > config)."""
    from flask import current_app

    from app.models import AppSetting

    cfg = app.config if app is not None else current_app.config
    default = bool(cfg.get("MITM_DETECTION_ENABLED", True))
    try:
        raw = AppSetting.get_value("mitm.enabled", "")
    except Exception:
        return default
    if raw == "":
        return default
    return raw in ("1", "true", "True", "on", "yes")


# ---------------------------------------------------------------------------
# Baseline em AppSetting
# ---------------------------------------------------------------------------

def _baseline_key(key: str, profile_id: int) -> str:
    return f"{key}.{profile_id}"


def get_baseline(key: str, profile_id: int) -> dict:
    """Lê um baseline persistido. Retorna {} quando ainda não há um."""
    from app.models import AppSetting

    raw = AppSetting.get_value(_baseline_key(key, profile_id), "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except ValueError:
        logger.warning("Baseline %s do perfil %d corrompido — ignorado.", key, profile_id)
        return {}


def set_baseline(key: str, profile_id: int, data: dict) -> None:
    from app.models import AppSetting

    AppSetting.set_value(_baseline_key(key, profile_id), json.dumps(data, sort_keys=True))


def reset_baselines(profile_id: int) -> None:
    """Apaga os baselines de MITM de um perfil (re-aprende no próximo ciclo).

    Use depois de uma troca legítima de roteador ou servidor DHCP — sem isso o
    equipamento novo seguiria alertando como suspeito.
    """
    from app.scanner.dns_check import KEY_RESOLVERS

    for key in (_KEY_GATEWAY, _KEY_DHCP, _KEY_ROUTERS6, KEY_RESOLVERS):
        set_baseline(key, profile_id, {})


def baselines_summary(profile_id: int) -> dict:
    """Estado atual dos baselines, para exibição no painel admin.

    Inclui a lista de resolvedores DNS memorizada por ``dns_check``: é baseline
    de infraestrutura pelo mesmo motivo dos outros — um servidor DNS trocado é
    um caminho de MITM — e a mesma caixa de redefinir limpa os quatro.
    """
    from app.scanner.dns_check import KEY_RESOLVERS

    return {
        "gateways": get_baseline(_KEY_GATEWAY, profile_id),
        "dhcp_servers": get_baseline(_KEY_DHCP, profile_id),
        "ipv6_routers": get_baseline(_KEY_ROUTERS6, profile_id),
        "dns_resolvers": get_baseline(KEY_RESOLVERS, profile_id).get("servers") or [],
    }


# ---------------------------------------------------------------------------
# Gateway padrão
# ---------------------------------------------------------------------------

_DEFAULT_VIA_RE = re.compile(r"^default\s+via\s+(\S+)")


def read_default_gateways() -> dict[str, str]:
    """Gateways padrão do sistema. Retorna {ip_do_gateway: mac}.

    Cobre IPv4 e IPv6. O MAC vem das tabelas de vizinhança (ARP/NDP): é o MAC
    para onde o tráfego de saída está efetivamente sendo entregue — exatamente
    o que um ataque de MITM precisa alterar.
    """
    from app.scanner.hosts import _read_all_arp_neighbors, normalize_mac
    from app.scanner.hosts6 import read_ipv6_neighbors, strip_zone

    gateways: dict[str, str] = {}
    gw_ips: list[str] = []

    for family in ("-4", "-6"):
        try:
            proc = subprocess.run(
                ["ip", family, "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        for line in proc.stdout.splitlines():
            match = _DEFAULT_VIA_RE.match(line.strip())
            if match:
                gw_ips.append(strip_zone(match.group(1)))

    if not gw_ips:
        return gateways

    arp = _read_all_arp_neighbors()
    ndp = {n.ip: n.mac for n in read_ipv6_neighbors()}
    for ip in gw_ips:
        mac = normalize_mac(ndp.get(ip, "") if ":" in ip else arp.get(ip, ""))
        if mac:
            gateways[ip] = mac
    return gateways


def check_gateway_integrity(profile) -> dict:
    """Compara o MAC do gateway padrão com o baseline e alerta em mudança.

    Primeira execução apenas aprende o baseline (nada a comparar ainda).

    Returns:
        dict com ``learned`` (gateways memorizados agora) e ``changed``
        (lista de (ip, mac_antigo, mac_novo)).
    """
    from app.extensions import db
    from app.models import AlertType, Device, Severity
    from app.scanner.scheduling import emit_alert

    result = {"learned": {}, "changed": []}
    current = read_default_gateways()
    if not current:
        logger.debug("Nenhum gateway padrão com MAC resolvido (profile %d).", profile.id)
        return result

    baseline = get_baseline(_KEY_GATEWAY, profile.id)

    for ip, mac in current.items():
        known = baseline.get(ip)
        if known is None:
            baseline[ip] = mac
            result["learned"][ip] = mac
            logger.info("Baseline de gateway aprendido (%s): %s -> %s", profile.name, ip, mac)
            continue
        if known == mac:
            continue

        result["changed"].append((ip, known, mac))
        baseline[ip] = mac  # aceita o novo estado para não repetir o alerta

        # Vincula ao ativo que hoje responde por esse MAC, se houver — dá ao
        # alerta um device clicável em vez de só um MAC solto.
        device = Device.query.filter_by(profile_id=profile.id, mac=mac).first()
        emit_alert(
            profile.id, device.id if device else None,
            AlertType.GATEWAY_CHANGED, Severity.CRITICAL,
            (
                f"MAC do gateway {ip} mudou: {known} -> {mac}. "
                "Se o roteador não foi trocado, isto indica que outro host "
                "assumiu o lugar dele (man-in-the-middle)."
            ),
            match_value=ip, is_priority=True,
            notify_profile=profile, notify_device=device,
        )
        logger.warning(
            "GATEWAY_CHANGED (%s): %s mudou de %s para %s", profile.name, ip, known, mac
        )

    set_baseline(_KEY_GATEWAY, profile.id, baseline)
    db.session.commit()
    return result


# ---------------------------------------------------------------------------
# Servidores DHCP e roteadores IPv6 não autorizados
# ---------------------------------------------------------------------------

def _observe_service_source(
    profile, key: str, source_ip: str, source_mac: str,
    alert_type, label: str, explanation: str,
) -> bool:
    """Aprende a origem de um serviço de infraestrutura e alerta se for nova.

    O primeiro conjunto observado vira o baseline (a rede é assumida limpa no
    momento da instalação — a alternativa, alertar de tudo até o operador
    confirmar, geraria ruído sem informação). A partir daí, qualquer origem
    inédita é alertada.

    Returns: True se emitiu alerta.
    """
    from app.extensions import db
    from app.models import Device, Severity
    from app.scanner.scheduling import emit_alert

    if not source_mac:
        return False

    baseline = get_baseline(key, profile.id)
    if source_mac in baseline:
        baseline[source_mac] = source_ip  # mantém o último IP visto
        set_baseline(key, profile.id, baseline)
        db.session.commit()
        return False

    first_time = not baseline
    if len(baseline) >= _MAX_BASELINE_ENTRIES:
        logger.warning(
            "Baseline %s do perfil %d cheio (%d entradas) — não memorizando %s.",
            key, profile.id, len(baseline), source_mac,
        )
    else:
        baseline[source_mac] = source_ip
        set_baseline(key, profile.id, baseline)

    if first_time:
        logger.info(
            "Baseline de %s aprendido (%s): %s em %s",
            label, profile.name, source_mac, source_ip,
        )
        db.session.commit()
        return False

    device = Device.query.filter_by(profile_id=profile.id, mac=source_mac).first()
    emit_alert(
        profile.id, device.id if device else None,
        alert_type, Severity.CRITICAL,
        (
            f"{label} não autorizado detectado: {source_mac} em {source_ip}. "
            f"{explanation}"
        ),
        match_value=source_mac, is_priority=True,
        notify_profile=profile, notify_device=device,
    )
    logger.warning("%s (%s): %s em %s", alert_type.value, profile.name, source_mac, source_ip)
    db.session.commit()
    return True


def observe_dhcp_server(profile, source_ip: str, source_mac: str) -> bool:
    """Registra um servidor DHCP observado; alerta se não estiver no baseline."""
    from app.models import AlertType

    return _observe_service_source(
        profile, _KEY_DHCP, source_ip, source_mac, AlertType.ROGUE_DHCP,
        "Servidor DHCP",
        "Um DHCP rogue entrega gateway e DNS falsos aos clientes, colocando o "
        "atacante no caminho de todo o tráfego.",
    )


def observe_router_advertisement(profile, source_ip: str, source_mac: str) -> bool:
    """Registra um roteador IPv6 (RA) observado; alerta se for inédito."""
    from app.models import AlertType

    return _observe_service_source(
        profile, _KEY_ROUTERS6, source_ip, source_mac, AlertType.ROGUE_RA,
        "Roteador IPv6 (Router Advertisement)",
        "Um RA rogue faz os hosts rotearem por ele; como o IPv6 tem precedência "
        "sobre o IPv4 na escolha de destino, o desvio acontece mesmo em rede "
        "predominantemente IPv4.",
    )
