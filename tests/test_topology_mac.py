"""Testes do alerta de MAC aprendido em portas de acesso distintas.

A FDB (``dot1dTpFdbPort``) é indexada pelo MAC: um switch nunca reporta o mesmo
endereço em duas portas numa leitura. O sinal aparece no conjunto — entre
switches, ou entre janelas de observação sobrepostas no mesmo switch.
"""

from datetime import timedelta

import pytest

from app.models import Alert, AlertType, Device, DeviceType, Severity, SwitchNeighbor
from app.scanner import topology
from app.scanner.topology import _utcnow


@pytest.fixture
def switches(db, sample_profile):
    """Dois switches cadastrados no perfil."""
    a = Device(profile_id=sample_profile.id, mac="00:11:11:11:11:11",
               hostname="SW-Terreo", device_type=DeviceType.SWITCH)
    b = Device(profile_id=sample_profile.id, mac="00:22:22:22:22:22",
               hostname="SW-Primeiro", device_type=DeviceType.SWITCH)
    db.session.add_all([a, b])
    db.session.commit()
    return a, b


def _fdb(db, profile, switch, port, mac, first=None, last=None):
    now = _utcnow()
    row = SwitchNeighbor(
        profile_id=profile.id, switch_device_id=switch.id, local_port=port,
        remote_mac=mac, source="fdb",
        first_seen_at=first or now, last_seen_at=last or now,
    )
    db.session.add(row)
    db.session.commit()
    return row


def _alertas(profile):
    return Alert.query.filter_by(
        profile_id=profile.id, alert_type=AlertType.MAC_PORT_CONFLICT).all()


# ---------------------------------------------------------------------------
# Classificação de uplink
# ---------------------------------------------------------------------------

class _Row:
    def __init__(self, switch_device_id, local_port, remote_mac):
        self.switch_device_id = switch_device_id
        self.local_port = local_port
        self.remote_mac = remote_mac


def test_porta_com_muitos_macs_e_tratada_como_uplink():
    rows = [_Row(1, "Gi0/24", f"AA:BB:CC:00:00:{i:02X}") for i in range(10)]
    rows.append(_Row(1, "Gi0/1", "DD:EE:FF:00:00:01"))
    uplinks = topology.classify_uplinks(rows, set(), mac_threshold=4)
    assert (1, "Gi0/24") in uplinks
    assert (1, "Gi0/1") not in uplinks


def test_lldp_marca_uplink_mesmo_com_poucos_macs():
    rows = [_Row(1, "Gi0/24", "AA:BB:CC:00:00:01")]
    uplinks = topology.classify_uplinks(rows, {(1, "Gi0/24")}, mac_threshold=4)
    assert (1, "Gi0/24") in uplinks


def test_contagem_de_macs_cobre_rotulo_lldp_divergente():
    """lldpLocPortId nem sempre coincide com o ifName usado pela FDB."""
    rows = [_Row(1, "GigabitEthernet0/24", f"AA:BB:CC:00:00:{i:02X}") for i in range(8)]
    # O LLDP reportou a mesma porta com outro rótulo.
    uplinks = topology.classify_uplinks(rows, {(1, "Gi0/24")}, mac_threshold=4)
    assert (1, "GigabitEthernet0/24") in uplinks


# ---------------------------------------------------------------------------
# Sobreposição de janelas
# ---------------------------------------------------------------------------

class _Janela:
    def __init__(self, first, last):
        self.first_seen_at, self.last_seen_at = first, last


def test_janelas_disjuntas_nao_sao_sobreposicao():
    t0 = _utcnow()
    a = _Janela(t0 - timedelta(hours=10), t0 - timedelta(hours=6))
    b = _Janela(t0 - timedelta(hours=5), t0)
    assert topology._overlapping([a, b]) is False


def test_janelas_sobrepostas_sao_detectadas():
    t0 = _utcnow()
    a = _Janela(t0 - timedelta(hours=10), t0 - timedelta(hours=1))
    b = _Janela(t0 - timedelta(hours=5), t0)
    assert topology._overlapping([a, b]) is True


# ---------------------------------------------------------------------------
# Detecção ponta a ponta
# ---------------------------------------------------------------------------

def test_mac_em_switches_distintos_alerta(db, sample_profile, switches):
    sw_a, sw_b = switches
    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01")
    _fdb(db, sample_profile, sw_b, "Gi0/7", "DE:AD:BE:EF:00:01")

    achados = topology.check_mac_port_anomalies(sample_profile, set(), _utcnow())

    assert len(achados) == 1
    assert achados[0]["reason"] == "switches distintos"
    alertas = _alertas(sample_profile)
    assert len(alertas) == 1
    assert alertas[0].match_value == "DE:AD:BE:EF:00:01"
    assert "SW-Terreo:Gi0/1" in alertas[0].message
    assert "SW-Primeiro:Gi0/7" in alertas[0].message


def test_mac_de_ativo_cadastrado_e_critico_e_prioritario(db, sample_profile, switches):
    sw_a, sw_b = switches
    alvo = Device(profile_id=sample_profile.id, mac="DE:AD:BE:EF:00:01", hostname="PC-Financeiro")
    db.session.add(alvo)
    db.session.commit()

    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01")
    _fdb(db, sample_profile, sw_b, "Gi0/7", "DE:AD:BE:EF:00:01")
    topology.check_mac_port_anomalies(sample_profile, set(), _utcnow())

    alerta = _alertas(sample_profile)[0]
    assert alerta.severity == Severity.CRITICAL
    assert alerta.is_priority is True
    assert alerta.device_id == alvo.id
    assert "PC-Financeiro" in alerta.message


def test_mac_desconhecido_fica_em_aviso(db, sample_profile, switches):
    sw_a, sw_b = switches
    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01")
    _fdb(db, sample_profile, sw_b, "Gi0/7", "DE:AD:BE:EF:00:01")
    topology.check_mac_port_anomalies(sample_profile, set(), _utcnow())

    alerta = _alertas(sample_profile)[0]
    assert alerta.severity == Severity.WARNING
    assert alerta.is_priority is False
    assert alerta.device_id is None


def test_uplink_nao_gera_falso_positivo(db, sample_profile, switches):
    """O caminho normal: MAC na porta de acesso de um switch e no uplink do outro."""
    sw_a, sw_b = switches
    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01")
    _fdb(db, sample_profile, sw_b, "Gi0/24", "DE:AD:BE:EF:00:01")

    achados = topology.check_mac_port_anomalies(
        sample_profile, {(sw_b.id, "Gi0/24")}, _utcnow())

    assert achados == []
    assert _alertas(sample_profile) == []


def test_mudanca_de_tomada_nao_alerta(db, sample_profile, switches):
    """Janelas disjuntas no mesmo switch: o ativo mudou de porta, não foi clonado."""
    sw_a, _ = switches
    agora = _utcnow()
    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01",
         first=agora - timedelta(hours=10), last=agora - timedelta(hours=6))
    _fdb(db, sample_profile, sw_a, "Gi0/2", "DE:AD:BE:EF:00:01",
         first=agora - timedelta(hours=5), last=agora)

    achados = topology.check_mac_port_anomalies(sample_profile, set(), agora)
    assert achados == []
    assert _alertas(sample_profile) == []


def test_oscilacao_no_mesmo_switch_alerta(db, sample_profile, switches):
    sw_a, _ = switches
    agora = _utcnow()
    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01",
         first=agora - timedelta(hours=10), last=agora - timedelta(hours=1))
    _fdb(db, sample_profile, sw_a, "Gi0/2", "DE:AD:BE:EF:00:01",
         first=agora - timedelta(hours=5), last=agora)

    achados = topology.check_mac_port_anomalies(sample_profile, set(), agora)
    assert len(achados) == 1
    assert achados[0]["reason"] == "portas alternadas no mesmo switch"


def test_entrada_antiga_e_ignorada(db, sample_profile, switches):
    """Só entradas frescas contam — a poda ainda não rodou, mas o dado é velho."""
    sw_a, sw_b = switches
    agora = _utcnow()
    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01")
    _fdb(db, sample_profile, sw_b, "Gi0/7", "DE:AD:BE:EF:00:01",
         first=agora - timedelta(days=30), last=agora - timedelta(days=30))

    assert topology.check_mac_port_anomalies(sample_profile, set(), agora) == []


def test_entrada_lldp_nao_entra_na_analise(db, sample_profile, switches):
    """Vizinhança LLDP tem remote_mac vazio e descreve switch, não endpoint."""
    sw_a, sw_b = switches
    row = _fdb(db, sample_profile, sw_a, "Gi0/24", "")
    row.source = "lldp"
    db.session.commit()
    _fdb(db, sample_profile, sw_b, "Gi0/24", "")

    assert topology.check_mac_port_anomalies(sample_profile, set(), _utcnow()) == []


def test_dedupe_nao_repete_o_alerta(db, sample_profile, switches):
    sw_a, sw_b = switches
    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01")
    _fdb(db, sample_profile, sw_b, "Gi0/7", "DE:AD:BE:EF:00:01")

    for _ in range(3):
        achados = topology.check_mac_port_anomalies(sample_profile, set(), _utcnow())
        assert len(achados) == 1  # o achado continua sendo reportado ao job...

    assert len(_alertas(sample_profile)) == 1  # ...mas o alerta sai uma vez só


def test_flag_desligada_nao_analisa(db, sample_profile, switches):
    sw_a, sw_b = switches
    _fdb(db, sample_profile, sw_a, "Gi0/1", "DE:AD:BE:EF:00:01")
    _fdb(db, sample_profile, sw_b, "Gi0/7", "DE:AD:BE:EF:00:01")

    topology.set_mac_port_alerts_enabled(False)
    db.session.commit()
    assert topology.check_mac_port_anomalies(sample_profile, set(), _utcnow()) == []
    assert _alertas(sample_profile) == []

    topology.set_mac_port_alerts_enabled(True)
    db.session.commit()
    assert len(topology.check_mac_port_anomalies(sample_profile, set(), _utcnow())) == 1


def test_perfil_sem_fdb_nao_quebra(db, sample_profile):
    assert topology.check_mac_port_anomalies(sample_profile, set(), _utcnow()) == []
