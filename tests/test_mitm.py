"""Testes da detecção de man-in-the-middle.

O foco é a distinção que define o valor do alerta: reuso de endereço (DHCP
devolvendo um IP liberado) é rotina; o mesmo IP sendo reivindicado enquanto o
dono legítimo continua online é ataque.
"""

from datetime import timedelta

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import ICMPv6ND_RA, IPv6
from scapy.layers.l2 import Ether

from app.models import Alert, AlertType, Device, DeviceIp, Port, Severity
from app.scanner import mitm, passive
from app.scanner.scheduling import _utcnow, check_ip_claim


@pytest.fixture
def dono(db, sample_profile):
    """Ativo legítimo, online agora, dono de 192.168.1.50."""
    dev = Device(profile_id=sample_profile.id, mac="AA:AA:AA:AA:AA:AA",
                 friendly_name="Servidor", last_seen_at=_utcnow())
    db.session.add(dev)
    db.session.flush()
    db.session.add(DeviceIp(device_id=dev.id, ip="192.168.1.50", is_current=True))
    db.session.commit()
    return dev


@pytest.fixture
def intruso(db, sample_profile):
    dev = Device(profile_id=sample_profile.id, mac="BB:BB:BB:BB:BB:BB",
                 friendly_name="Intruso", last_seen_at=_utcnow())
    db.session.add(dev)
    db.session.commit()
    return dev


# ---------------------------------------------------------------------------
# ARP / NDP spoofing
# ---------------------------------------------------------------------------

def test_dono_online_vira_arp_spoofing(db, sample_profile, dono, intruso):
    assert check_ip_claim(sample_profile, intruso, "192.168.1.50", _utcnow()) is True
    db.session.commit()

    alert = Alert.query.filter_by(alert_type=AlertType.ARP_SPOOFING).one()
    assert alert.severity == Severity.CRITICAL
    assert alert.is_priority is True
    assert "BB:BB:BB:BB:BB:BB" in alert.message


def test_dono_sumido_e_so_conflito(db, app, sample_profile, dono, intruso):
    """Reatribuição de DHCP não é ataque — WARNING, não CRITICAL."""
    limite = app.config["HOST_ONLINE_THRESHOLD_MINUTES"]
    dono.last_seen_at = _utcnow() - timedelta(minutes=limite + 10)
    db.session.commit()

    assert check_ip_claim(sample_profile, intruso, "192.168.1.50", _utcnow()) is True
    db.session.commit()

    assert Alert.query.filter_by(alert_type=AlertType.ARP_SPOOFING).count() == 0
    alert = Alert.query.filter_by(alert_type=AlertType.IP_CONFLICT).one()
    assert alert.severity == Severity.WARNING
    assert alert.is_priority is False


def test_ipv6_gera_ndp_spoofing(db, sample_profile, dono, intruso):
    """Mesmo mecanismo de ataque, protocolo diferente."""
    db.session.add(DeviceIp(device_id=dono.id, ip="2001:db8::50", is_current=True))
    db.session.commit()

    assert check_ip_claim(sample_profile, intruso, "2001:db8::50", _utcnow()) is True
    db.session.commit()

    alert = Alert.query.filter_by(alert_type=AlertType.NDP_SPOOFING).one()
    assert alert.severity == Severity.CRITICAL
    assert "NDP spoofing" in alert.message


def test_sem_conflito_nao_alerta(db, sample_profile, dono, intruso):
    assert check_ip_claim(sample_profile, intruso, "192.168.1.99", _utcnow()) is False
    assert Alert.query.count() == 0


def test_dedupe_nao_repete_enquanto_aberto(db, sample_profile, dono, intruso):
    check_ip_claim(sample_profile, intruso, "192.168.1.50", _utcnow())
    db.session.commit()
    assert check_ip_claim(sample_profile, intruso, "192.168.1.50", _utcnow()) is False
    db.session.commit()
    assert Alert.query.filter_by(alert_type=AlertType.ARP_SPOOFING).count() == 1


def test_dedupe_nao_confunde_ips_com_prefixo_comum(db, sample_profile, dono, intruso):
    """'192.168.1.5' não pode suprimir um conflito real em '192.168.1.50'."""
    outro = Device(profile_id=sample_profile.id, mac="CC:CC:CC:CC:CC:CC",
                   last_seen_at=_utcnow())
    db.session.add(outro)
    db.session.flush()
    db.session.add(DeviceIp(device_id=outro.id, ip="192.168.1.5", is_current=True))
    db.session.commit()

    check_ip_claim(sample_profile, intruso, "192.168.1.5", _utcnow())
    db.session.commit()
    assert check_ip_claim(sample_profile, intruso, "192.168.1.50", _utcnow()) is True
    db.session.commit()
    assert Alert.query.filter_by(alert_type=AlertType.ARP_SPOOFING).count() == 2


# ---------------------------------------------------------------------------
# Integridade do gateway
# ---------------------------------------------------------------------------

def test_gateway_primeira_leitura_so_aprende(db, monkeypatch, sample_profile):
    monkeypatch.setattr(
        mitm, "read_default_gateways", lambda: {"192.168.1.1": "AA:BB:CC:00:00:01"}
    )
    result = mitm.check_gateway_integrity(sample_profile)

    assert result["learned"] == {"192.168.1.1": "AA:BB:CC:00:00:01"}
    assert result["changed"] == []
    assert Alert.query.count() == 0


def test_gateway_estavel_nao_alerta(db, monkeypatch, sample_profile):
    monkeypatch.setattr(
        mitm, "read_default_gateways", lambda: {"192.168.1.1": "AA:BB:CC:00:00:01"}
    )
    mitm.check_gateway_integrity(sample_profile)
    result = mitm.check_gateway_integrity(sample_profile)

    assert result["changed"] == []
    assert Alert.query.count() == 0


def test_gateway_trocado_alerta_critico(db, monkeypatch, sample_profile):
    macs = ["AA:BB:CC:00:00:01", "DD:EE:FF:00:00:99"]
    monkeypatch.setattr(
        mitm, "read_default_gateways", lambda: {"192.168.1.1": macs[0]}
    )
    mitm.check_gateway_integrity(sample_profile)

    macs[0] = macs[1]
    result = mitm.check_gateway_integrity(sample_profile)

    assert result["changed"] == [("192.168.1.1", "AA:BB:CC:00:00:01", "DD:EE:FF:00:00:99")]
    alert = Alert.query.filter_by(alert_type=AlertType.GATEWAY_CHANGED).one()
    assert alert.severity == Severity.CRITICAL
    assert alert.is_priority is True

    # Baseline passa a ser o novo MAC: o mesmo desvio não realerta em loop.
    assert mitm.check_gateway_integrity(sample_profile)["changed"] == []
    assert Alert.query.filter_by(alert_type=AlertType.GATEWAY_CHANGED).count() == 1


def test_reset_baseline_faz_reaprender(db, monkeypatch, sample_profile):
    monkeypatch.setattr(
        mitm, "read_default_gateways", lambda: {"192.168.1.1": "AA:BB:CC:00:00:01"}
    )
    mitm.check_gateway_integrity(sample_profile)
    assert mitm.baselines_summary(sample_profile.id)["gateways"]

    mitm.reset_baselines(sample_profile.id)
    db.session.commit()
    assert mitm.baselines_summary(sample_profile.id)["gateways"] == {}


# ---------------------------------------------------------------------------
# DHCP e Router Advertisement não autorizados
# ---------------------------------------------------------------------------

def test_primeiro_dhcp_vira_baseline(db, sample_profile):
    assert mitm.observe_dhcp_server(sample_profile, "192.168.1.1", "AA:BB:CC:00:00:01") is False
    assert Alert.query.count() == 0
    # Repetição do mesmo servidor segue silenciosa.
    assert mitm.observe_dhcp_server(sample_profile, "192.168.1.1", "AA:BB:CC:00:00:01") is False
    assert Alert.query.count() == 0


def test_segundo_dhcp_alerta(db, sample_profile):
    mitm.observe_dhcp_server(sample_profile, "192.168.1.1", "AA:BB:CC:00:00:01")
    assert mitm.observe_dhcp_server(sample_profile, "192.168.1.77", "99:99:99:99:99:99") is True

    alert = Alert.query.filter_by(alert_type=AlertType.ROGUE_DHCP).one()
    assert alert.severity == Severity.CRITICAL
    assert alert.is_priority is True
    assert alert.match_value == "99:99:99:99:99:99"


def test_ra_de_origem_nova_alerta(db, sample_profile):
    mitm.observe_router_advertisement(sample_profile, "fe80::1", "AA:BB:CC:00:00:01")
    assert mitm.observe_router_advertisement(sample_profile, "fe80::666", "66:66:66:66:66:66") is True

    alert = Alert.query.filter_by(alert_type=AlertType.ROGUE_RA).one()
    assert alert.severity == Severity.CRITICAL
    assert "precedência sobre o IPv4" in alert.message


def test_baselines_de_perfis_nao_se_misturam(db, sample_profile):
    from app.models import Profile

    outro = Profile(name="Outra rede")
    db.session.add(outro)
    db.session.commit()

    mitm.observe_dhcp_server(sample_profile, "192.168.1.1", "AA:BB:CC:00:00:01")
    # Para o outro perfil este servidor é inédito → vira o baseline dele, sem alertar.
    assert mitm.observe_dhcp_server(outro, "192.168.1.1", "AA:BB:CC:00:00:01") is False
    assert Alert.query.count() == 0
    assert mitm.baselines_summary(outro.id)["dhcp_servers"] == {"AA:BB:CC:00:00:01": "192.168.1.1"}


# ---------------------------------------------------------------------------
# Captura no sniffer
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_buffers():
    with passive._buffer_lock:
        passive._buffer.clear()
        passive._infra_buffer.clear()
    yield
    with passive._buffer_lock:
        passive._buffer.clear()
        passive._infra_buffer.clear()


def _infra():
    with passive._buffer_lock:
        return set(passive._infra_buffer)


def test_resposta_de_servidor_dhcp_capturada():
    pkt = (
        Ether(src="aa:bb:cc:00:00:01")
        / IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)  # servidor -> cliente
    )
    passive._on_packet(pkt)
    assert _infra() == {("dhcp", "192.168.1.1", "AA:BB:CC:00:00:01")}


def test_pedido_de_cliente_dhcp_ignorado():
    """Cliente fala de sport=68; só a resposta do servidor identifica um DHCP."""
    pkt = (
        Ether(src="aa:bb:cc:00:00:02")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
    )
    passive._on_packet(pkt)
    assert _infra() == set()


def test_router_advertisement_capturado():
    pkt = (
        Ether(src="cc:cc:cc:00:00:01")
        / IPv6(src="fe80::1", dst="ff02::1")
        / ICMPv6ND_RA()
    )
    passive._on_packet(pkt)
    assert _infra() == {("ra", "fe80::1", "CC:CC:CC:00:00:01")}


# ---------------------------------------------------------------------------
# Certificado TLS
# ---------------------------------------------------------------------------

def _porta_tls(db, profile, fingerprint=None, issuer=None):
    dev = Device(profile_id=profile.id, mac="EE:EE:EE:EE:EE:EE",
                 friendly_name="Web", last_seen_at=_utcnow())
    db.session.add(dev)
    db.session.flush()
    db.session.add(DeviceIp(device_id=dev.id, ip="192.168.1.80", is_current=True))
    port = Port(device_id=dev.id, protocol="tcp", port=443, state="open",
                tls_fingerprint=fingerprint, tls_issuer=issuer)
    db.session.add(port)
    db.session.commit()
    return dev, port


def _info(fp, issuer):
    return {
        "not_after": _utcnow() + timedelta(days=300),
        "subject": "CN=web.local", "issuer": issuer, "fingerprint": fp,
    }


def test_primeira_leitura_grava_baseline_sem_alertar(db, sample_profile):
    from app.scanner.scheduling import _check_cert_identity_change

    dev, port = _porta_tls(db, sample_profile)
    assert _check_cert_identity_change(
        sample_profile, dev, port, _info("a" * 64, "CN=CA Real"), _utcnow()
    ) is False
    db.session.commit()
    assert port.tls_fingerprint == "a" * 64


def test_renovacao_mesmo_emissor_e_warning(db, sample_profile):
    from app.scanner.scheduling import _check_cert_identity_change

    dev, port = _porta_tls(db, sample_profile, "a" * 64, "CN=CA Real")
    assert _check_cert_identity_change(
        sample_profile, dev, port, _info("b" * 64, "CN=CA Real"), _utcnow()
    ) is True
    db.session.commit()

    alert = Alert.query.filter_by(alert_type=AlertType.TLS_CERT_CHANGED).one()
    assert alert.severity == Severity.WARNING
    assert alert.is_priority is False
    assert "renovação de rotina" in alert.message


def test_troca_de_emissor_e_critico(db, sample_profile):
    """Impressão nova + emissor novo = assinatura de proxy de interceptação."""
    from app.scanner.scheduling import _check_cert_identity_change

    dev, port = _porta_tls(db, sample_profile, "a" * 64, "CN=CA Real")
    assert _check_cert_identity_change(
        sample_profile, dev, port, _info("c" * 64, "CN=Proxy Corporativo"), _utcnow()
    ) is True
    db.session.commit()

    alert = Alert.query.filter_by(alert_type=AlertType.TLS_CERT_CHANGED).one()
    assert alert.severity == Severity.CRITICAL
    assert alert.is_priority is True
    assert "interceptação" in alert.message


def test_certificado_estavel_nao_alerta(db, sample_profile):
    from app.scanner.scheduling import _check_cert_identity_change

    dev, port = _porta_tls(db, sample_profile, "a" * 64, "CN=CA Real")
    assert _check_cert_identity_change(
        sample_profile, dev, port, _info("a" * 64, "CN=CA Real"), _utcnow()
    ) is False
    assert Alert.query.count() == 0
