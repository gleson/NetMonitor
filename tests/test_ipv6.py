"""Testes do monitoramento IPv6.

O ponto central é o agrupamento pelo MAC: um mesmo ativo tem IPv4 e IPv6 ao
mesmo tempo, e nenhuma das duas famílias pode rebaixar a outra.
"""

from datetime import timedelta

import pytest
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6
from scapy.layers.l2 import Ether

from app.models import Alert, AlertType, Device, DeviceIp, Severity
from app.scanner import hosts6, passive
from app.scanner.hosts6 import Host6Info
from app.scanner.scheduling import (
    _expire_stale_ipv6, _ipv6_proto, _upsert_device_ip, _upsert_device_ipv6,
    _utcnow, discover_ipv6_for_profile,
)


@pytest.fixture
def device(db, sample_profile):
    dev = Device(profile_id=sample_profile.id, mac="AA:BB:CC:DD:EE:01", hostname="maquina-x")
    db.session.add(dev)
    db.session.flush()
    db.session.add(DeviceIp(device_id=dev.id, ip="192.168.1.10", is_current=True))
    db.session.commit()
    return dev


# ---------------------------------------------------------------------------
# Classificação de endereços
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ("fe80::1", hosts6.SCOPE_LINK_LOCAL),
    ("fe80::1%eth0", hosts6.SCOPE_LINK_LOCAL),
    ("fd00:1234::5", hosts6.SCOPE_ULA),
    ("2001:db8::5", hosts6.SCOPE_GLOBAL),
    ("ff02::1", ""),        # multicast não é endereço de ativo
    ("::1", ""),            # loopback
    ("::", ""),             # não especificado (DAD)
    ("192.168.1.1", ""),    # IPv4
    ("lixo", ""),
])
def test_ipv6_scope(ip, expected):
    assert hosts6.ipv6_scope(ip) == expected


def test_prefix64_agrupa_privacy_extensions():
    """Endereços temporários (RFC 4941) diferem no sufixo, não no prefixo."""
    a = hosts6.ipv6_prefix64("2001:db8:1:2:aaaa::1")
    b = hosts6.ipv6_prefix64("2001:db8:1:2:bbbb::9")
    assert a == b == "2001:db8:1:2::/64"
    assert hosts6.ipv6_prefix64("2001:db8:9:9::1") != a


def test_apenas_global_e_ula_sao_escaneaveis():
    assert hosts6.is_routable_ipv6("2001:db8::1")
    assert hosts6.is_routable_ipv6("fd00::1")
    # Link-local depende de zone id/interface de saída — não é alvo de scan.
    assert not hosts6.is_routable_ipv6("fe80::1")


def test_ip_version_derivado_do_endereco(db, device):
    """Nenhum ponto de criação precisa informar a família explicitamente."""
    db.session.add(DeviceIp(device_id=device.id, ip="2001:db8::5", is_current=True))
    db.session.commit()
    rows = {r.ip: r.ip_version for r in DeviceIp.query.all()}
    assert rows == {"192.168.1.10": 4, "2001:db8::5": 6}


# ---------------------------------------------------------------------------
# Agrupamento pelo MAC: IPv4 e IPv6 coexistem
# ---------------------------------------------------------------------------

def test_ipv6_nao_rebaixa_ipv4(db, sample_profile, device):
    now = _utcnow()
    _upsert_device_ipv6(sample_profile, device, "2001:db8::5", now)
    db.session.commit()

    assert device.current_ipv4s == ["192.168.1.10"]
    assert device.current_ipv6s == ["2001:db8::5"]
    # O scan ativo continua mirando o IPv4.
    assert device.current_ip == "192.168.1.10"


def test_ipv4_nao_rebaixa_ipv6(db, sample_profile, device):
    """A descoberta IPv4 seguinte não pode derrubar o IPv6 já catalogado."""
    now = _utcnow()
    _upsert_device_ipv6(sample_profile, device, "2001:db8::5", now)
    db.session.commit()

    _upsert_device_ip(sample_profile, device, "192.168.1.10", now)
    db.session.commit()
    assert device.current_ipv6s == ["2001:db8::5"]

    # Mesmo quando o IPv4 muda (troca de DHCP), o IPv6 permanece.
    _upsert_device_ip(sample_profile, device, "192.168.1.99", now)
    db.session.commit()
    assert device.current_ipv4s == ["192.168.1.99"]
    assert device.current_ipv6s == ["2001:db8::5"]


def test_varios_ipv6_coexistem_ordenados(db, sample_profile, device):
    """Global/ULA primeiro, link-local por último — todos atuais ao mesmo tempo."""
    now = _utcnow()
    for ip in ("fe80::abcd", "2001:db8::5", "2001:db8::6"):
        _upsert_device_ipv6(sample_profile, device, ip, now)
    db.session.commit()

    assert device.current_ipv6s[-1] == "fe80::abcd"
    assert set(device.current_ipv6s[:2]) == {"2001:db8::5", "2001:db8::6"}
    assert device.current_ips[0] == "192.168.1.10"


def test_reobservar_ipv6_nao_duplica_linha(db, sample_profile, device):
    now = _utcnow()
    assert _upsert_device_ipv6(sample_profile, device, "2001:db8::5", now) is True
    db.session.commit()
    assert _upsert_device_ipv6(sample_profile, device, "2001:db8::5", now) is False
    db.session.commit()

    rows = DeviceIp.query.filter_by(device_id=device.id, ip="2001:db8::5").all()
    assert len(rows) == 1


def test_alerta_info_para_ipv6_inedito(db, sample_profile, device):
    now = _utcnow()
    _upsert_device_ipv6(sample_profile, device, "2001:db8::5", now)
    db.session.commit()

    alert = Alert.query.filter_by(alert_type=AlertType.NEW_IP_FOR_MAC).one()
    assert alert.severity == Severity.INFO
    # match_value é o endereço: permite silenciar por prefixo nas regras de
    # supressão (ex.: "fe80:" para ignorar todo link-local).
    assert alert.match_value == "2001:db8::5"
    assert "primeiro endereço IPv6" in alert.message


def test_mensagem_distingue_prefixo_novo_de_privacy_extension(db, sample_profile, device):
    now = _utcnow()
    _upsert_device_ipv6(sample_profile, device, "2001:db8:1:2::1", now)
    _upsert_device_ipv6(sample_profile, device, "2001:db8:1:2::2", now)
    _upsert_device_ipv6(sample_profile, device, "2001:db8:9:9::1", now)
    db.session.commit()

    msgs = [a.message for a in Alert.query.order_by(Alert.id).all()]
    assert "primeiro endereço IPv6" in msgs[0]
    assert "privacy extension" in msgs[1]
    assert "novo prefixo 2001:db8:9:9::/64" in msgs[2]


# ---------------------------------------------------------------------------
# Expiração (privacy extensions)
# ---------------------------------------------------------------------------

def test_ipv6_antigo_deixa_de_ser_atual(db, app, sample_profile, device):
    now = _utcnow()
    _upsert_device_ipv6(sample_profile, device, "2001:db8::5", now)
    db.session.commit()

    row = DeviceIp.query.filter_by(ip="2001:db8::5").one()
    retention = app.config["IPV6_ADDRESS_RETENTION_DAYS"]
    row.last_seen_at = now - timedelta(days=retention + 1)
    db.session.commit()

    assert _expire_stale_ipv6(sample_profile.id, now) == 1
    db.session.commit()
    assert device.current_ipv6s == []
    # O IPv4 não é tocado pela expiração IPv6.
    assert device.current_ipv4s == ["192.168.1.10"]


def test_ipv6_reaparecendo_volta_a_ser_atual(db, sample_profile, device):
    now = _utcnow()
    _upsert_device_ipv6(sample_profile, device, "2001:db8::5", now)
    db.session.commit()
    DeviceIp.query.filter_by(ip="2001:db8::5").one().is_current = False
    db.session.commit()

    _upsert_device_ipv6(sample_profile, device, "2001:db8::5", now)
    db.session.commit()
    assert device.current_ipv6s == ["2001:db8::5"]


# ---------------------------------------------------------------------------
# Descoberta por vizinhança
# ---------------------------------------------------------------------------

def test_descoberta_anexa_por_mac_e_ignora_desconhecidos(
    db, monkeypatch, sample_profile, device
):
    neighbors = [
        Host6Info(ip="2001:db8::5", mac=device.mac, iface="eth0",
                  scope="global", state="REACHABLE"),
        Host6Info(ip="fe80::abcd", mac=device.mac, iface="eth0",
                  scope="link-local", state="STALE"),
        # MAC sem ativo cadastrado: não pode criar device (pode ser um host
        # remoto chegando com o MAC do roteador).
        Host6Info(ip="2001:db8::99", mac="FF:EE:DD:CC:BB:AA", iface="eth0",
                  scope="global", state="REACHABLE"),
    ]
    monkeypatch.setattr(
        "app.scanner.hosts6.discover_ipv6_neighbors", lambda *a, **k: neighbors
    )

    stats = discover_ipv6_for_profile(sample_profile)

    assert stats["neighbors"] == 3
    assert stats["attached"] == 2
    assert stats["new_addresses"] == 2
    assert stats["unmatched"] == 1
    assert Device.query.count() == 1  # nenhum device criado a partir de IPv6
    assert set(device.current_ipv6s) == {"2001:db8::5", "fe80::abcd"}


def test_apenas_vizinho_confirmado_conta_como_online(
    db, monkeypatch, sample_profile, device
):
    """Entrada STALE sobrevive ~30 min ao host sumir — não prova presença."""
    monkeypatch.setattr(
        "app.scanner.hosts6.discover_ipv6_neighbors",
        lambda *a, **k: [
            Host6Info(ip="2001:db8::5", mac=device.mac, scope="global", state="STALE"),
        ],
    )
    assert discover_ipv6_for_profile(sample_profile)["online_device_ids"] == set()

    monkeypatch.setattr(
        "app.scanner.hosts6.discover_ipv6_neighbors",
        lambda *a, **k: [
            Host6Info(ip="2001:db8::6", mac=device.mac, scope="global", state="REACHABLE"),
        ],
    )
    assert discover_ipv6_for_profile(sample_profile)["online_device_ids"] == {device.id}


def test_descoberta_desligada_nao_faz_nada(db, monkeypatch, sample_profile, device):
    monkeypatch.setattr("app.ipv6_settings.is_ipv6_discovery_enabled", lambda *a: False)

    def _boom(*a, **k):
        raise AssertionError("não deveria sondar a rede com o IPv6 desligado")

    monkeypatch.setattr("app.scanner.hosts6.discover_ipv6_neighbors", _boom)

    stats = discover_ipv6_for_profile(sample_profile)
    assert stats["neighbors"] == 0
    assert device.current_ipv6s == []


def test_link_local_pode_ser_excluido_por_config(
    db, app, monkeypatch, sample_profile, device
):
    monkeypatch.setitem(app.config, "IPV6_INCLUDE_LINK_LOCAL", False)
    monkeypatch.setattr(
        "app.scanner.hosts6.discover_ipv6_neighbors",
        lambda *a, **k: [
            Host6Info(ip="fe80::abcd", mac=device.mac, scope="link-local", state="REACHABLE"),
            Host6Info(ip="2001:db8::5", mac=device.mac, scope="global", state="REACHABLE"),
        ],
    )
    discover_ipv6_for_profile(sample_profile)
    assert device.current_ipv6s == ["2001:db8::5"]


# ---------------------------------------------------------------------------
# Port scan IPv6
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("proto,expected", [
    ("tcp", "tcp6"), ("udp", "udp6"), ("tcp6", "tcp6"), ("", "tcp6"),
])
def test_protocolo_ipv6_rotulado(proto, expected):
    """Portas IPv6 são registros próprios: o nmap reporta 'tcp' mesmo com -6."""
    assert _ipv6_proto(proto) == expected


# ---------------------------------------------------------------------------
# Descoberta passiva (NDP)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean_passive_buffer():
    with passive._buffer_lock:
        passive._buffer.clear()
    yield
    with passive._buffer_lock:
        passive._buffer.clear()


def _buffer():
    with passive._buffer_lock:
        return dict(passive._buffer)


def test_ndp_link_local_bufferizado():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:11")
        / IPv6(src="fe80::11", dst="ff02::1:ff00:1")
        / ICMPv6ND_NS(tgt="fe80::22")
    )
    passive._on_packet(pkt)
    assert _buffer() == {("AA:BB:CC:DD:EE:11", 6): "fe80::11"}


def test_ipv6_multicast_global_bufferizado():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:12")
        / IPv6(src="2001:db8::12", dst="ff02::fb")  # mDNS sobre IPv6
    )
    passive._on_packet(pkt)
    assert _buffer() == {("AA:BB:CC:DD:EE:12", 6): "2001:db8::12"}


def test_ipv6_unicast_roteado_ignorado():
    """Em unicast roteado o MAC do quadro é o do roteador, não o do dono do IP."""
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:13")
        / IPv6(src="2001:db8:aaaa::13", dst="2001:db8:bbbb::99")
    )
    passive._on_packet(pkt)
    assert _buffer() == {}


def test_dad_com_origem_nao_especificada_ignorado():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:14")
        / IPv6(src="::", dst="ff02::1:ff00:14")
        / ICMPv6ND_NS(tgt="fe80::14")
    )
    passive._on_packet(pkt)
    assert _buffer() == {}


def test_ipv4_e_ipv6_do_mesmo_mac_coexistem_no_buffer():
    """A chave inclui a família: uma observação não sobrescreve a outra."""
    from scapy.layers.l2 import ARP

    passive._on_packet(
        Ether(src="aa:bb:cc:dd:ee:15")
        / ARP(psrc="192.168.1.15", hwsrc="aa:bb:cc:dd:ee:15", op=1)
    )
    passive._on_packet(
        Ether(src="aa:bb:cc:dd:ee:15") / IPv6(src="fe80::15", dst="ff02::1")
    )
    assert _buffer() == {
        ("AA:BB:CC:DD:EE:15", 4): "192.168.1.15",
        ("AA:BB:CC:DD:EE:15", 6): "fe80::15",
    }
