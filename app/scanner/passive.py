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
# Chave (MAC, versão do IP) -> último IP observado. A família faz parte da
# chave porque um mesmo ativo fala IPv4 e IPv6 ao mesmo tempo: com a chave só
# no MAC, a observação IPv6 sobrescreveria a IPv4 (ou vice-versa) e metade da
# informação se perderia a cada janela.
_buffer: dict[tuple[str, int], str] = {}
_buffer_lock = threading.Lock()

# Cooldown por (MAC, família): evita reprocessar o mesmo host repetidamente
# (ARP e NDP são frequentes). chave -> monotonic da última ingestão.
_recent_macs: dict[tuple[str, int], float] = {}
_INGEST_COOLDOWN_S = 60.0

# Observações de infraestrutura para a detecção de MITM: quem responde DHCP e
# quem emite Router Advertisement IPv6. Buffer separado do de hosts porque a
# semântica é outra — aqui não interessa inventariar o ativo, e sim comparar a
# origem do serviço com o baseline conhecido.
# {(tipo, ip, mac)} onde tipo ∈ {"dhcp", "ra"}.
_infra_buffer: set[tuple[str, str, str]] = set()

# Intervalo do worker que drena o buffer.
_WORKER_INTERVAL_S = 5.0

# Filtro BPF do sniffer: ARP + protocolos de descoberta que devices emitem
# espontaneamente por multicast/broadcast — mDNS (5353), LLMNR (5355),
# SSDP (1900), NetBIOS (137/138) e DHCP (67/68).
_SNIFF_FILTER = (
    "arp or (udp and (port 5353 or port 5355 or port 1900 "
    "or port 137 or port 138 or port 67 or port 68))"
)

# Acréscimo quando o monitoramento IPv6 passivo está ligado: ICMPv6 cobre todo
# o NDP (Neighbor/Router Solicitation e Advertisement), que é o equivalente
# IPv6 do ARP. O ramo UDP do filtro acima já captura mDNS/SSDP/LLMNR sobre
# IPv6 — falta apenas tratá-los em _on_packet.
_SNIFF_FILTER_IPV6 = "icmp6"


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


def effective_sniff_filter(app) -> str:
    """Filtro BPF efetivo, ampliado com ICMPv6/NDP quando o IPv6 está ligado."""
    from app.ipv6_settings import is_ipv6_passive_enabled

    if is_ipv6_passive_enabled(app):
        return f"{_SNIFF_FILTER} or {_SNIFF_FILTER_IPV6}"
    return _SNIFF_FILTER


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


def _is_on_link_ipv6_src(src: str, dst: str) -> bool:
    """True se o par (origem, destino) IPv6 garante que o emissor é on-link.

    Mesma preocupação do ``_is_local_only_dst`` do IPv4: em unicast roteado o
    MAC do quadro é o do roteador, não o do dono do endereço. Dois casos são
    seguros: origem link-local (fe80::/10 nunca é roteada) e destino multicast
    (ff00::/8 link-local não atravessa roteador). O NDP cai nos dois.
    """
    import ipaddress

    try:
        source = ipaddress.ip_address(src.split("%", 1)[0])
        target = ipaddress.ip_address(dst.split("%", 1)[0])
    except ValueError:
        return False
    if source.version != 6:
        return False
    return source.is_link_local or target.is_multicast


def _capture_infra_source(pkt, ip: str, mac: str) -> None:
    """Anota a origem de serviços de infraestrutura vistos no quadro.

    Dois vetores clássicos de man-in-the-middle se revelam aqui:

    - **DHCP rogue**: só um servidor manda de ``sport=67``. Um segundo servidor
      respondendo na rede entrega gateway e DNS falsos aos clientes.
    - **Router Advertisement rogue**: ICMPv6 tipo 134. Um RA forjado faz os
      hosts rotearem pelo atacante e, como o IPv6 tem precedência sobre o IPv4
      na escolha de destino, o desvio funciona mesmo em rede quase toda IPv4.
      Depende do IPv6 passivo estar ligado (é ele que põe ``icmp6`` no filtro).
    """
    try:
        from scapy.layers.inet import UDP
        from scapy.layers.inet6 import ICMPv6ND_RA

        kind = ""
        if pkt.haslayer(ICMPv6ND_RA):
            kind = "ra"
        elif pkt.haslayer(UDP) and pkt[UDP].sport == 67:
            # sport 67 = servidor DHCP falando (OFFER/ACK). Cliente usa 68.
            kind = "dhcp"

        if kind:
            with _buffer_lock:
                _infra_buffer.add((kind, ip, mac))
    except Exception:
        logger.debug("Erro ao inspecionar origem de infraestrutura", exc_info=True)


def _on_packet(pkt):
    """Callback do sniffer (thread do scapy). Mantém-se mínimo: só bufferiza.

    Aceita ARP (request/reply), NDP/ICMPv6, e UDP multicast/broadcast (mDNS,
    SSDP, LLMNR, NetBIOS, DHCP) em IPv4 e IPv6 — em todos os casos extrai o par
    (IP origem, MAC origem).
    """
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.inet6 import IPv6
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
        elif pkt.haslayer(IPv6):
            v6 = pkt[IPv6]
            if not _is_on_link_ipv6_src(v6.src, v6.dst):
                return
            ip = v6.src
            mac = (getattr(pkt, "src", "") or "").upper()
        else:
            return

        _capture_infra_source(pkt, ip, mac)

        # Ignora endereços nulos/broadcast e MAC inválido — validação forte
        # acontece na ingestão. (src 0.0.0.0 acontece em DHCP DISCOVER; "::"
        # acontece na Duplicate Address Detection do IPv6.)
        if not ip or ip in ("0.0.0.0", "::") or not mac or mac in (
            "00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF",
        ):
            return
        with _buffer_lock:
            _buffer[(mac, 6 if ":" in ip else 4)] = ip
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
    for key, ip in pending:
        last = _recent_macs.get(key, 0.0)
        if now - last < _INGEST_COOLDOWN_S:
            continue
        _recent_macs[key] = now
        fresh.append((ip, key[0]))

    # Poda o dict de cooldown para não crescer sem limite.
    if len(_recent_macs) > 4096:
        cutoff = now - _INGEST_COOLDOWN_S
        for k in [k for k, v in _recent_macs.items() if v < cutoff]:
            _recent_macs.pop(k, None)

    return fresh


def _drain_infra_buffer() -> list[tuple[str, str, str]]:
    """Retorna e limpa as observações de infraestrutura pendentes."""
    with _buffer_lock:
        pending = list(_infra_buffer)
        _infra_buffer.clear()
    return pending


def _profiles_for_infra(ip: str, mac: str, index):
    """Perfis a quem uma observação de infraestrutura diz respeito.

    Preferência: (1) perfis cuja faixa habilitada contém o IP; (2) perfis onde o
    MAC já é um ativo conhecido; (3) todos os perfis ativos. O último caso é
    deliberado — uma origem de DHCP/RA que não casa com faixa nem com ativo
    conhecido é exatamente a situação mais alarmante, e silenciá-la por não
    saber a quem atribuir perderia o alerta que mais importa.
    """
    from app.models import Device, Profile

    matched = _match_profile(ip, index)
    if matched is not None:
        return [matched]

    by_mac = [
        db_profile
        for db_profile in Profile.query.filter_by(is_active=True).all()
        if Device.query.filter_by(profile_id=db_profile.id, mac=mac).first()
    ]
    if by_mac:
        return by_mac

    return Profile.query.filter_by(is_active=True).all()


def _ingest_infra_observations(observations: list[tuple[str, str, str]]):
    """Compara origens de DHCP/RA observadas com o baseline de cada perfil."""
    from flask import current_app

    from app.extensions import db
    from app.scanner.hosts import is_valid_mac, normalize_mac
    from app.scanner.mitm import (
        is_mitm_detection_enabled, observe_dhcp_server,
        observe_router_advertisement,
    )

    if not is_mitm_detection_enabled(current_app):
        return

    index = _build_profile_range_index()
    for kind, ip, raw_mac in observations:
        mac = normalize_mac(raw_mac)
        if not is_valid_mac(mac):
            continue
        observer = observe_router_advertisement if kind == "ra" else observe_dhcp_server
        for profile in _profiles_for_infra(ip, mac, index):
            try:
                observer(profile, ip, mac)
            except Exception:
                db.session.rollback()
                logger.exception(
                    "Erro ao avaliar origem de %s: %s (%s)", kind, ip, mac
                )


def _worker_loop(app, stop_event: threading.Event):
    """Drena o buffer e ingere no banco periodicamente."""
    logger.info("Worker de descoberta passiva iniciado.")
    while not stop_event.is_set():
        stop_event.wait(_WORKER_INTERVAL_S)
        if stop_event.is_set():
            break
        fresh = _drain_buffer()
        infra = _drain_infra_buffer()
        if not fresh and not infra:
            continue
        try:
            with app.app_context():
                if fresh:
                    _ingest_observations(fresh)
                if infra:
                    _ingest_infra_observations(infra)
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


def _ingest_ipv6_observation(ip: str, mac: str) -> bool:
    """Anexa um IPv6 observado passivamente ao ativo de mesmo MAC.

    Ao contrário do IPv4, uma observação IPv6 **nunca cria** um device novo: só
    a vizinhança on-link identifica o dono real do endereço, e o escopo do
    perfil é definido pelas faixas IPv4 configuradas. Sem um ativo já
    cadastrado com aquele MAC não há como dizer a que perfil o endereço
    pertence — e chutar abriria a porta para agrupar hosts errados.

    Aplica-se a todos os perfis ativos que tenham o MAC (o par perfil+MAC é
    único, mas o mesmo equipamento pode estar cadastrado em mais de um perfil).

    Returns:
        True se o endereço era inédito em algum dos ativos.
    """
    from flask import current_app

    from app.extensions import db
    from app.models import Device, Profile
    from app.scanner.mitm import is_mitm_detection_enabled
    from app.scanner.scheduling import (
        _ack_open_host_down_alerts, _upsert_device_ipv6, check_ip_claim,
    )

    mitm_enabled = is_mitm_detection_enabled(current_app)
    active_ids = [p.id for p in Profile.query.filter_by(is_active=True).all()]
    if not active_ids:
        return False

    devices = Device.query.filter(
        Device.profile_id.in_(active_ids), Device.mac == mac
    ).all()
    if not devices:
        logger.debug("IPv6 passivo %s (%s): nenhum ativo com esse MAC.", ip, mac)
        return False

    now = _utcnow()
    is_new = False
    for device in devices:
        profile = db.session.get(Profile, device.profile_id)
        if profile is None:
            continue
        # NDP spoofing: um ativo online já reivindica este IPv6. Aqui a detecção
        # é passiva — pega o anúncio mesmo quando o atacante ignora as varreduras.
        if mitm_enabled:
            check_ip_claim(profile, device, ip, now, via=" (descoberta passiva IPv6)")
        if _upsert_device_ipv6(profile, device, ip, now, via=" (descoberta passiva IPv6)"):
            is_new = True
        # O pacote acabou de ser capturado: é prova direta de presença.
        device.last_seen_at = now
        device.record_online_today(now.date())
        _ack_open_host_down_alerts(device.id, now)
    db.session.commit()
    return is_new


def _ingest_observations(observations: list[tuple[str, str]]):
    """Cria/atualiza devices a partir de observações ARP/NDP (ip, mac)."""
    from flask import current_app

    from app.extensions import db
    from app.models import Device, DeviceIp, AlertType, Severity
    from app.ipv6_settings import is_ipv6_passive_enabled
    from app.scanner.hosts import normalize_mac, is_valid_mac, get_vendor_from_mac
    from app.scanner.mitm import is_mitm_detection_enabled
    from app.scanner.scheduling import (
        prepend_to_port_scan_queue, _ack_open_host_down_alerts, emit_alert,
        _upsert_device_ip, check_ip_claim,
    )

    ipv6_enabled = is_ipv6_passive_enabled(current_app)
    mitm_enabled = is_mitm_detection_enabled(current_app)

    index = _build_profile_range_index()
    if not index:
        return

    new_count = 0
    for ip, raw_mac in observations:
        mac = normalize_mac(raw_mac)
        if not is_valid_mac(mac):
            continue

        if ":" in ip:
            # Observação IPv6 — agrupada pelo MAC, sem passar pelo casamento
            # por faixa (as faixas configuradas são IPv4). Revalida a flag aqui
            # porque ela pode ter sido desligada depois da captura.
            if ipv6_enabled:
                try:
                    _ingest_ipv6_observation(ip, mac)
                except Exception:
                    db.session.rollback()
                    logger.exception("Erro ao ingerir observação IPv6 %s (%s)", ip, mac)
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

            emit_alert(
                profile.id, device.id, AlertType.NEW_DEVICE, Severity.INFO,
                f"Novo dispositivo (descoberta passiva): {mac} ({ip})",
                match_value=mac, notify_profile=profile, notify_device=device,
            )
            new_count += 1
            logger.info("Descoberta passiva: novo device %s (%s)", mac, ip)

            db.session.add(DeviceIp(
                device_id=device.id, ip=ip, ip_version=4,
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

        # ARP spoofing: outro ativo online já reivindica este IP. É justamente
        # aqui que a detecção passiva agrega — o envenenamento de cache mira a
        # vítima e o gateway, e pode nunca aparecer numa varredura ativa.
        if mitm_enabled:
            check_ip_claim(profile, device, ip, now, via=" (descoberta passiva)")

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
        _sniffer = AsyncSniffer(
            filter=effective_sniff_filter(app), prn=_on_packet, store=False,
        )
        _sniffer.start()
    except Exception:
        logger.exception("Falha ao iniciar o sniffer passivo — abortando descoberta passiva.")
        _stop_event.set()
        _sniffer = None
        return False

    from app.ipv6_settings import is_ipv6_passive_enabled
    logger.info(
        "Descoberta passiva ARP+multicast iniciada (sniffer + worker); IPv6/NDP: %s.",
        "ligado" if is_ipv6_passive_enabled(app) else "desligado",
    )
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
