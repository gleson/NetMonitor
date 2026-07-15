"""Descoberta passiva de dispositivos por sniffing de ARP e multicast.

Complementa o host discovery ativo (ARP/nmap a cada ~45 min): escutando o
tráfego ARP e os protocolos "faladores" de multicast/broadcast da sub-rede
(mDNS, SSDP, LLMNR, NetBIOS, DHCP) em background, um dispositivo novo aparece
em segundos em vez de esperar o próximo ciclo. O ramo multicast cobre devices
que quase não emitem ARP (ex.: só anunciam serviços via mDNS na 5353) e ativos
sensíveis (OT/IoT) que não toleram varredura ativa — aqui só observamos
pacotes que eles já emitem.

Requisitos e travas:
- Precisa de root (sniff usa raw sockets) — sem root, não inicia.
- Desligado por padrão. Ligado via ``AppSetting('passive_arp_enabled')`` ou
  ``PASSIVE_ARP_DISCOVERY_ENABLED`` na config.
- Iniciado apenas no processo dono do scheduler (ver app/__init__.py), então
  não duplica sob múltiplos workers do gunicorn.

Arquitetura: um ``AsyncSniffer`` do scapy empurra (ip, mac) para um buffer
com debounce; um thread worker drena o buffer periodicamente e faz o upsert
no banco dentro de um app_context próprio.
"""

import ipaddress
import logging
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Estado do módulo (processo único — dono do scheduler).
_sniffer = None
_worker_thread: threading.Thread | None = None
_stop_event: threading.Event | None = None
_app = None

# Buffer de observações pendentes: mac -> (ip, first_seen_monotonic).
# Protegido por _buffer_lock. O callback do sniffer (thread do scapy) só
# escreve aqui; o worker lê e limpa.
_buffer: dict[str, str] = {}
_buffer_lock = threading.Lock()

# Cooldown por MAC: evita reprocessar o mesmo host repetidamente (ARP é
# frequente). mac -> monotonic da última ingestão.
_recent_macs: dict[str, float] = {}
_INGEST_COOLDOWN_S = 60.0

# Intervalo do worker que drena o buffer.
_WORKER_INTERVAL_S = 5.0

# Filtro BPF do sniffer: ARP + protocolos de descoberta que devices emitem
# espontaneamente por multicast/broadcast — mDNS (5353), LLMNR (5355),
# SSDP (1900), NetBIOS (137/138) e DHCP (67/68).
_SNIFF_FILTER = (
    "arp or (udp and (port 5353 or port 5355 or port 1900 "
    "or port 137 or port 138 or port 67 or port 68))"
)


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _has_root() -> bool:
    import os
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def is_passive_discovery_enabled(app) -> bool:
    """Lê a flag efetiva (AppSetting tem prioridade sobre a config)."""
    default = bool(app.config.get("PASSIVE_ARP_DISCOVERY_ENABLED", False))
    try:
        from app.models import AppSetting
        # app_context próprio: no startup somos chamados fora de contexto
        # (após o bloco `with app.app_context()` do _init_scheduler).
        with app.app_context():
            raw = AppSetting.get_value("passive_arp_enabled", "")
        if raw == "":
            return default
        return raw in ("1", "true", "True", "on")
    except Exception:
        logger.debug("Falha ao ler AppSetting passive_arp_enabled — usando default.", exc_info=True)
        return default


def is_passive_discovery_running() -> bool:
    return _sniffer is not None


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

def _is_local_only_dst(dst: str) -> bool:
    """True se o destino é multicast/broadcast (tráfego que nunca foi roteado).

    Em unicast roteado, o MAC de origem do quadro é o do roteador, não o do
    device dono do IP — parear os dois criaria devices falsos. Multicast
    link-local e broadcast só circulam no segmento L2 de origem, então o MAC
    de origem é do próprio emissor.
    """
    try:
        first = int(dst.split(".", 1)[0])
    except (ValueError, AttributeError):
        return False
    return (224 <= first <= 239) or dst == "255.255.255.255" or dst.endswith(".255")


def _on_packet(pkt):
    """Callback do sniffer (thread do scapy). Mantém-se mínimo: só bufferiza.

    Aceita ARP (request/reply) e UDP multicast/broadcast (mDNS, SSDP, LLMNR,
    NetBIOS, DHCP) — em ambos os casos extrai o par (IP origem, MAC origem).
    """
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.l2 import ARP

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            ip = arp.psrc
            mac = (arp.hwsrc or "").upper()
        elif pkt.haslayer(IP) and pkt.haslayer(UDP):
            if not _is_local_only_dst(pkt[IP].dst):
                return
            ip = pkt[IP].src
            # MAC de origem do quadro Ethernet (camada mais externa).
            mac = (getattr(pkt, "src", "") or "").upper()
        else:
            return

        # Ignora endereços nulos/broadcast e MAC inválido — validação forte
        # acontece na ingestão. (src 0.0.0.0 acontece em DHCP DISCOVER.)
        if not ip or ip == "0.0.0.0" or not mac or mac in (
            "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF",
        ):
            return
        with _buffer_lock:
            _buffer[mac] = ip
    except Exception:
        # Nunca deixa uma exceção escapar do callback do sniffer.
        logger.debug("Erro ao processar pacote capturado", exc_info=True)


def _drain_buffer() -> list[tuple[str, str]]:
    """Retorna e limpa as observações pendentes, aplicando o cooldown por MAC."""
    now = time.monotonic()
    with _buffer_lock:
        pending = list(_buffer.items())
        _buffer.clear()

    fresh: list[tuple[str, str]] = []
    for mac, ip in pending:
        last = _recent_macs.get(mac, 0.0)
        if now - last < _INGEST_COOLDOWN_S:
            continue
        _recent_macs[mac] = now
        fresh.append((ip, mac))

    # Poda o dict de cooldown para não crescer sem limite.
    if len(_recent_macs) > 4096:
        cutoff = now - _INGEST_COOLDOWN_S
        for k in [k for k, v in _recent_macs.items() if v < cutoff]:
            _recent_macs.pop(k, None)

    return fresh


def _worker_loop(app, stop_event: threading.Event):
    """Drena o buffer e ingere no banco periodicamente."""
    logger.info("Worker de descoberta passiva iniciado.")
    while not stop_event.is_set():
        stop_event.wait(_WORKER_INTERVAL_S)
        if stop_event.is_set():
            break
        fresh = _drain_buffer()
        if not fresh:
            continue
        try:
            with app.app_context():
                _ingest_observations(fresh)
        except Exception:
            logger.exception("Erro ao ingerir observações passivas")
    logger.info("Worker de descoberta passiva encerrado.")


# ---------------------------------------------------------------------------
# Ingestão no banco
# ---------------------------------------------------------------------------

def _build_profile_range_index():
    """Retorna [(profile, [ip_network,...])] dos perfis ativos com ranges habilitados.

    Usado para mapear cada IP observado ao perfil correto.
    """
    from app.models import Profile, IpRange

    index = []
    for profile in Profile.query.filter_by(is_active=True).all():
        nets = []
        for r in IpRange.query.filter_by(profile_id=profile.id, enabled=True).all():
            try:
                nets.append(ipaddress.ip_network(r.cidr, strict=False))
            except ValueError:
                continue
        if nets:
            index.append((profile, nets))
    return index


def _match_profile(ip_str: str, index):
    """Primeiro perfil cujo range habilitado contém o IP, ou None."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for profile, nets in index:
        if any(addr in n for n in nets):
            return profile
    return None


def _ingest_observations(observations: list[tuple[str, str]]):
    """Cria/atualiza devices a partir de observações ARP (ip, mac)."""
    from app.extensions import db
    from app.models import Device, DeviceIp, Alert, AlertType, Severity
    from app.scanner.hosts import normalize_mac, is_valid_mac, get_vendor_from_mac
    from app.scanner.scheduling import (
        prepend_to_port_scan_queue, _ack_open_host_down_alerts, _maybe_notify,
        _upsert_device_ip,
    )

    index = _build_profile_range_index()
    if not index:
        return

    new_count = 0
    for ip, raw_mac in observations:
        mac = normalize_mac(raw_mac)
        if not is_valid_mac(mac):
            continue
        profile = _match_profile(ip, index)
        if profile is None:
            continue  # IP fora de qualquer range monitorado

        now = _utcnow()
        device = Device.query.filter_by(profile_id=profile.id, mac=mac).first()

        if device is None:
            # Um placeholder pode existir para este IP (descoberto sem MAC real).
            dip = DeviceIp.query.filter_by(ip=ip, is_current=True).first()
            if dip:
                placeholder = db.session.get(Device, dip.device_id)
                if (placeholder and placeholder.profile_id == profile.id
                        and placeholder.mac.startswith("02:00:")):
                    placeholder.mac = mac
                    if not placeholder.vendor:
                        placeholder.vendor = get_vendor_from_mac(mac)
                    device = placeholder

        if device is None:
            # Dispositivo novo — descoberto passivamente.
            device = Device(
                profile_id=profile.id,
                mac=mac,
                vendor=get_vendor_from_mac(mac),
                first_seen_at=now,
                last_seen_at=now,
            )
            device.record_online_today(now.date())
            db.session.add(device)
            db.session.flush()

            new_dev_alert = Alert(
                profile_id=profile.id,
                device_id=device.id,
                alert_type=AlertType.NEW_DEVICE,
                severity=Severity.INFO,
                message=f"Novo dispositivo (descoberta passiva): {mac} ({ip})",
            )
            db.session.add(new_dev_alert)
            _maybe_notify(new_dev_alert, profile, device)
            new_count += 1
            logger.info("Descoberta passiva: novo device %s (%s)", mac, ip)

            db.session.add(DeviceIp(
                device_id=device.id, ip=ip,
                first_seen_at=now, last_seen_at=now, is_current=True,
            ))
            db.session.commit()

            # Enfileira para port scan (a própria fila respeita passive_only).
            prepend_to_port_scan_queue(profile.id, device.id, device.display_name, ip)
            continue

        # Dispositivo existente — atualiza presença.
        device.last_seen_at = now
        device.record_online_today(now.date())
        _ack_open_host_down_alerts(device.id, now)

        # Multi-IP ciente: roteadores/gateways com o mesmo MAC em várias redes
        # mantêm todos os IPs atuais sem alerta de troca.
        _upsert_device_ip(profile, device, ip, now, via=" (descoberta passiva)")

        db.session.commit()

    if new_count:
        logger.info("Descoberta passiva: %d novo(s) device(s) nesta rodada.", new_count)


# ---------------------------------------------------------------------------
# Ciclo de vida
# ---------------------------------------------------------------------------

def start_passive_discovery(app) -> bool:
    """Inicia o sniffer + worker se habilitado e com root. Idempotente.

    Returns:
        True se ficou rodando (ou já rodava), False se não iniciou.
    """
    global _sniffer, _worker_thread, _stop_event, _app

    if _sniffer is not None:
        return True

    if not is_passive_discovery_enabled(app):
        logger.info("Descoberta passiva desabilitada — não iniciada.")
        return False

    if not _has_root():
        logger.warning("Descoberta passiva requer root (sniff ARP) — não iniciada.")
        return False

    try:
        from scapy.all import AsyncSniffer
    except Exception:
        logger.warning("scapy indisponível — descoberta passiva não iniciada.", exc_info=True)
        return False

    _app = app
    _stop_event = threading.Event()
    _worker_thread = threading.Thread(
        target=_worker_loop, args=(app, _stop_event),
        name="passive-arp-worker", daemon=True,
    )
    _worker_thread.start()

    try:
        _sniffer = AsyncSniffer(filter=_SNIFF_FILTER, prn=_on_packet, store=False)
        _sniffer.start()
    except Exception:
        logger.exception("Falha ao iniciar o sniffer passivo — abortando descoberta passiva.")
        _stop_event.set()
        _sniffer = None
        return False

    logger.info("Descoberta passiva ARP+multicast iniciada (sniffer + worker).")
    return True


def stop_passive_discovery() -> None:
    """Para o sniffer e o worker. Idempotente."""
    global _sniffer, _worker_thread, _stop_event

    if _sniffer is not None:
        try:
            _sniffer.stop()
        except Exception:
            logger.debug("Erro ao parar o sniffer ARP", exc_info=True)
        _sniffer = None

    if _stop_event is not None:
        _stop_event.set()
    _worker_thread = None
    logger.info("Descoberta passiva ARP parada.")


def restart_passive_discovery(app) -> bool:
    """Reaplica o estado da flag: para se estava rodando e reinicia conforme config.

    Chamado quando o admin alterna a configuração em runtime.
    """
    stop_passive_discovery()
    return start_passive_discovery(app)
