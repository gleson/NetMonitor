"""Testes das checagens de configuração insegura (SMB e SNMP).

O valor destas checagens está em não gerar ruído: ausência de resposta nunca
pode virar achado, e um achado já conhecido não pode realertar a cada ciclo.
"""

import pytest

from app.models import (
    Alert, AlertType, Device, DeviceIp, Port, Severity, Vulnerability,
)
from app.scanner import hardening
from app.scanner.scheduling import _utcnow, upsert_vulnerability_row


# ---------------------------------------------------------------------------
# Interpretação da saída do NSE de SMB
# ---------------------------------------------------------------------------

_SMBV1 = """
  dialects:
    NT LM 0.12 (SMBv1)
    2.02
    2.10
"""

_SO_SMB2 = """
  dialects:
    2.02
    2.10
    3.1.1
"""

_ASSINATURA_FRACA_SMB2 = """
  3.1.1:
    Message signing enabled but not required
"""

_ASSINATURA_OK = """
  3.1.1:
    Message signing enabled and required
"""

_ASSINATURA_FRACA_SMB1 = """
  account_used: guest
  authentication_level: user
  challenge_response: supported
  message_signing: disabled (dangerous, but default)
"""


def test_smbv1_detectado():
    achados = hardening.parse_smb_output({"smb-protocols": _SMBV1})
    assert len(achados) == 1
    assert achados[0]["severidade"] == "CRITICAL"
    assert "SMBv1" in achados[0]["titulo"]


def test_so_smb2_nao_acusa():
    assert hardening.parse_smb_output({"smb-protocols": _SO_SMB2}) == []


def test_assinatura_nao_exigida_detectada():
    achados = hardening.parse_smb_output({"smb2-security-mode": _ASSINATURA_FRACA_SMB2})
    assert len(achados) == 1
    assert achados[0]["severidade"] == "WARNING"
    assert "Assinatura SMB" in achados[0]["titulo"]


def test_assinatura_desabilitada_smb1_detectada():
    achados = hardening.parse_smb_output({"smb-security-mode": _ASSINATURA_FRACA_SMB1})
    assert len(achados) == 1
    assert "NTLM relay" in achados[0]["detalhe"]


def test_assinatura_exigida_nao_acusa():
    assert hardening.parse_smb_output({"smb2-security-mode": _ASSINATURA_OK}) == []


def test_assinatura_fraca_nos_dois_gera_um_achado():
    """SMB1 e SMB2 dizendo a mesma coisa não viram dois alertas."""
    achados = hardening.parse_smb_output({
        "smb2-security-mode": _ASSINATURA_FRACA_SMB2,
        "smb-security-mode": _ASSINATURA_FRACA_SMB1,
    })
    assert len([a for a in achados if "Assinatura" in a["titulo"]]) == 1


def test_saida_vazia_nao_acusa():
    assert hardening.parse_smb_output({}) == []
    assert hardening.parse_smb_output({"smb-protocols": ""}) == []


def test_smbv1_e_assinatura_juntos():
    achados = hardening.parse_smb_output({
        "smb-protocols": _SMBV1, "smb2-security-mode": _ASSINATURA_FRACA_SMB2,
    })
    assert len(achados) == 2
    assert {a["severidade"] for a in achados} == {"CRITICAL", "WARNING"}


# ---------------------------------------------------------------------------
# SNMP
# ---------------------------------------------------------------------------

def test_comunidade_padrao_aceita_e_achado(monkeypatch):
    def fake_get(ip, oid, timeout=5, credential=None, **kw):
        return "Linux impressora 5.4" if credential.community == "public" else None

    monkeypatch.setattr("app.scanner.snmp.snmp_get", fake_get)
    achados = hardening.check_snmp_defaults("192.168.1.10")
    assert len(achados) == 1
    assert achados[0]["community"] == "public"
    assert achados[0]["severidade"] == "CRITICAL"
    assert "Linux impressora" in achados[0]["detalhe"]


def test_comunidade_private_menciona_escrita(monkeypatch):
    monkeypatch.setattr(
        "app.scanner.snmp.snmp_get",
        lambda ip, oid, timeout=5, credential=None, **kw:
            "AP" if credential.community == "private" else None,
    )
    achados = hardening.check_snmp_defaults("192.168.1.10")
    assert len(achados) == 1
    assert "escrita" in achados[0]["detalhe"]


def test_sem_resposta_nao_e_achado(monkeypatch):
    monkeypatch.setattr("app.scanner.snmp.snmp_get",
                        lambda *a, **kw: None)
    assert hardening.check_snmp_defaults("192.168.1.10") == []


def test_erro_de_snmp_nao_e_achado(monkeypatch):
    def explode(*a, **kw):
        raise OSError("network unreachable")

    monkeypatch.setattr("app.scanner.snmp.snmp_get", explode)
    assert hardening.check_snmp_defaults("192.168.1.10") == []


def test_ambas_as_comunidades_geram_achados_separados(monkeypatch):
    monkeypatch.setattr("app.scanner.snmp.snmp_get",
                        lambda ip, oid, timeout=5, credential=None, **kw: "resposta")
    achados = hardening.check_snmp_defaults("192.168.1.10")
    assert {a["community"] for a in achados} == {"public", "private"}


# ---------------------------------------------------------------------------
# Upsert compartilhado de Vulnerability
# ---------------------------------------------------------------------------

@pytest.fixture
def device(db, sample_profile):
    dev = Device(profile_id=sample_profile.id, mac="AA:BB:CC:DD:EE:01",
                 friendly_name="Impressora", last_seen_at=_utcnow())
    db.session.add(dev)
    db.session.flush()
    db.session.add(DeviceIp(device_id=dev.id, ip="192.168.1.10", is_current=True))
    db.session.commit()
    return dev


def _upsert(device, vulneravel=True, output="x", script="smb-protocols"):
    return upsert_vulnerability_row(
        device_id=device.id, script_name=script, port=0, protocol="",
        service="smb", output=output, is_vulnerable=vulneravel, now=_utcnow(),
    )


def test_achado_inedito_e_novo(db, device):
    assert _upsert(device) is True
    assert Vulnerability.query.count() == 1


def test_achado_repetido_nao_e_novo(db, device):
    _upsert(device)
    db.session.commit()
    assert _upsert(device) is False
    assert Vulnerability.query.count() == 1


def test_achado_que_some_e_resolvido(db, device):
    _upsert(device)
    db.session.commit()
    assert _upsert(device, vulneravel=False) is False
    db.session.commit()
    v = Vulnerability.query.one()
    assert v.resolved_at is not None and v.is_vulnerable is False


def test_achado_que_volta_realerta(db, device):
    _upsert(device)
    _upsert(device, vulneravel=False)
    db.session.commit()
    assert _upsert(device) is True
    assert Vulnerability.query.one().resolved_at is None


def test_output_e_atualizado(db, device):
    _upsert(device, output="antigo")
    db.session.commit()
    _upsert(device, output="novo")
    db.session.commit()
    assert Vulnerability.query.one().output == "novo"


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

@pytest.fixture
def _sem_smb(monkeypatch):
    monkeypatch.setattr(hardening, "check_smb", lambda ip, timeout=60: [])


def test_job_emite_alerta_e_vulnerabilidade(db, app, sample_profile, device,
                                            _sem_smb, monkeypatch):
    monkeypatch.setattr(hardening, "check_snmp_defaults", lambda ip, **kw: [{
        "script": "snmp-default-community", "titulo": "Comunidade SNMP padrão aceita ('public')",
        "detalhe": "detalhe", "severidade": "CRITICAL", "community": "public",
    }])
    stats = hardening.run_hardening_checks(sample_profile.id)
    assert stats["findings"] == 1 and stats["alerts"] == 1

    alert = Alert.query.filter_by(alert_type=AlertType.INSECURE_CONFIG).one()
    assert alert.severity == Severity.CRITICAL and alert.is_priority is True
    assert alert.match_value == "snmp-default-community:public"
    assert Vulnerability.query.count() == 1


def test_job_nao_realerta_achado_conhecido(db, sample_profile, device,
                                           _sem_smb, monkeypatch):
    monkeypatch.setattr(hardening, "check_snmp_defaults", lambda ip, **kw: [{
        "script": "snmp-default-community", "titulo": "t", "detalhe": "d",
        "severidade": "CRITICAL", "community": "public",
    }])
    hardening.run_hardening_checks(sample_profile.id)
    hardening.run_hardening_checks(sample_profile.id)
    assert Alert.query.filter_by(alert_type=AlertType.INSECURE_CONFIG).count() == 1


def test_job_resolve_achado_corrigido(db, sample_profile, device, _sem_smb, monkeypatch):
    achado = [{"script": "snmp-default-community", "titulo": "t", "detalhe": "d",
               "severidade": "CRITICAL", "community": "public"}]
    monkeypatch.setattr(hardening, "check_snmp_defaults", lambda ip, **kw: achado)
    hardening.run_hardening_checks(sample_profile.id)

    # Equipamento corrigido: a comunidade padrão deixa de responder.
    monkeypatch.setattr(hardening, "check_snmp_defaults", lambda ip, **kw: [])
    hardening.run_hardening_checks(sample_profile.id)
    assert Vulnerability.query.one().resolved_at is not None


def test_host_offline_nao_perde_o_achado(db, app, sample_profile, device,
                                         _sem_smb, monkeypatch):
    """Sumir da varredura não é o mesmo que o equipamento ter sido corrigido."""
    from datetime import timedelta
    monkeypatch.setattr(hardening, "check_snmp_defaults", lambda ip, **kw: [{
        "script": "snmp-default-community", "titulo": "t", "detalhe": "d",
        "severidade": "CRITICAL", "community": "public"}])
    hardening.run_hardening_checks(sample_profile.id)

    limite = app.config["HOST_ONLINE_THRESHOLD_MINUTES"]
    device.last_seen_at = _utcnow() - timedelta(minutes=limite + 10)
    db.session.commit()

    hardening.run_hardening_checks(sample_profile.id)
    assert Vulnerability.query.one().resolved_at is None


def test_job_respeita_o_interruptor(db, sample_profile, device, monkeypatch):
    chamou = []
    monkeypatch.setattr(hardening, "check_smb",
                        lambda ip, timeout=60: chamou.append(1) or [])
    monkeypatch.setattr(hardening, "check_snmp_defaults",
                        lambda ip, **kw: chamou.append(1) or [])

    hardening.set_hardening_enabled(False)
    db.session.commit()
    assert hardening.run_hardening_checks(sample_profile.id)["devices"] == 0
    assert chamou == []

    hardening.set_hardening_enabled(True)
    db.session.commit()
    hardening.run_hardening_checks(sample_profile.id)
    assert chamou != []


def test_smb_so_e_perguntado_a_quem_tem_a_porta(db, sample_profile, device, monkeypatch):
    perguntou = []
    monkeypatch.setattr(hardening, "check_smb",
                        lambda ip, timeout=60: perguntou.append(ip) or [])
    monkeypatch.setattr(hardening, "check_snmp_defaults", lambda ip, **kw: [])

    hardening.run_hardening_checks(sample_profile.id)
    assert perguntou == []

    db.session.add(Port(device_id=device.id, protocol="tcp", port=445, state="open",
                        first_open_at=_utcnow(), last_seen_open_at=_utcnow()))
    db.session.commit()
    hardening.run_hardening_checks(sample_profile.id)
    assert perguntou == ["192.168.1.10"]
