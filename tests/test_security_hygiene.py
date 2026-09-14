"""Testes das checagens de higiene de segurança.

Três detecções que não dependem de ataque em curso, mas de *desvio do que
estava estabelecido*: mudança de serviço/versão numa porta conhecida,
configuração TLS fraca e DNS da rede respondendo o que não deveria.
"""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.models import Alert, AlertType, Device, DeviceIp, Port, Severity
from app.scanner import dns_check
from app.scanner.scheduling import (
    _check_service_change, _check_tls_quality, _utcnow,
)


@pytest.fixture
def device(db, sample_profile):
    dev = Device(profile_id=sample_profile.id, mac="AA:BB:CC:00:11:22",
                 friendly_name="Servidor", last_seen_at=_utcnow())
    db.session.add(dev)
    db.session.flush()
    db.session.add(DeviceIp(device_id=dev.id, ip="192.168.1.50", is_current=True))
    db.session.commit()
    return dev


@pytest.fixture
def porta(db, device):
    p = Port(device_id=device.id, protocol="tcp", port=22, state="open",
             service_name="ssh", service_version="OpenSSH 8.9p1",
             first_open_at=_utcnow(), last_seen_open_at=_utcnow())
    db.session.add(p)
    db.session.commit()
    return p


def _scan_result(name="ssh", version="OpenSSH 8.9p1"):
    """Imita o PortInfo devolvido pelo scanner (só os campos usados aqui)."""
    return SimpleNamespace(service_name=name, service_version=version,
                           protocol="tcp", port=22, state="open")


# ---------------------------------------------------------------------------
# SERVICE_CHANGED
# ---------------------------------------------------------------------------

def test_versao_diferente_alerta(db, sample_profile, device, porta):
    changed = _check_service_change(
        sample_profile.id, device.id, device.display_name, "192.168.1.50",
        porta, _scan_result(version="OpenSSH 9.6p1"),
    )
    db.session.commit()
    assert changed is True
    alert = Alert.query.filter_by(alert_type=AlertType.SERVICE_CHANGED).one()
    assert alert.severity == Severity.WARNING
    assert "OpenSSH 8.9p1" in alert.message and "OpenSSH 9.6p1" in alert.message
    assert alert.match_value == "tcp/22"


def test_servico_diferente_alerta(db, sample_profile, device, porta):
    assert _check_service_change(
        sample_profile.id, device.id, device.display_name, "192.168.1.50",
        porta, _scan_result(name="http", version="OpenSSH 8.9p1"),
    ) is True
    db.session.commit()
    assert "'ssh' -> 'http'" in Alert.query.one().message


def test_mesma_versao_nao_alerta(db, sample_profile, device, porta):
    assert _check_service_change(
        sample_profile.id, device.id, device.display_name, "192.168.1.50",
        porta, _scan_result(),
    ) is False
    assert Alert.query.count() == 0


def test_banner_vazio_nao_alerta(db, sample_profile, device, porta):
    """Scan sem -sV (critical_ports_check) devolve banner vazio.

    Comparar contra vazio geraria "mudou para nada" em todo ciclo.
    """
    assert _check_service_change(
        sample_profile.id, device.id, device.display_name, "192.168.1.50",
        porta, _scan_result(name="", version=""),
    ) is False
    assert Alert.query.count() == 0


def test_primeira_leitura_nao_alerta(db, sample_profile, device, porta):
    """Sem valor anterior não há mudança — só o baseline sendo formado."""
    porta.service_version = ""
    porta.service_name = ""
    db.session.commit()
    assert _check_service_change(
        sample_profile.id, device.id, device.display_name, "192.168.1.50",
        porta, _scan_result(version="OpenSSH 9.6p1"),
    ) is False
    assert Alert.query.count() == 0


def test_porta_autorizada_ainda_alerta(db, sample_profile, device, porta):
    """is_authorized diz que a porta pode estar aberta, não que o software pode mudar."""
    porta.is_authorized = True
    db.session.commit()
    assert _check_service_change(
        sample_profile.id, device.id, device.display_name, "192.168.1.50",
        porta, _scan_result(version="OpenSSH 9.6p1"),
    ) is True


def test_dedupe_na_janela(db, sample_profile, device, porta):
    args = (sample_profile.id, device.id, device.display_name, "192.168.1.50")
    assert _check_service_change(*args, porta, _scan_result(version="9.6p1")) is True
    db.session.commit()
    # Segunda detecção idêntica dentro da janela não repete o alerta.
    assert _check_service_change(*args, porta, _scan_result(version="9.9p1")) is False
    assert Alert.query.filter_by(alert_type=AlertType.SERVICE_CHANGED).count() == 1


def test_dedupe_expira(db, sample_profile, device, porta, app):
    args = (sample_profile.id, device.id, device.display_name, "192.168.1.50")
    assert _check_service_change(*args, porta, _scan_result(version="9.6p1")) is True
    db.session.commit()
    horas = app.config.get("SERVICE_CHANGE_DEDUP_HOURS", 24)
    antigo = Alert.query.one()
    antigo.created_at = _utcnow() - timedelta(hours=horas + 1)
    db.session.commit()
    assert _check_service_change(*args, porta, _scan_result(version="9.9p1")) is True


def test_desligado_nao_alerta(db, app, sample_profile, device, porta, monkeypatch):
    monkeypatch.setitem(app.config, "SERVICE_CHANGE_ALERTS_ENABLED", False)
    assert _check_service_change(
        sample_profile.id, device.id, device.display_name, "192.168.1.50",
        porta, _scan_result(version="OpenSSH 9.6p1"),
    ) is False


# ---------------------------------------------------------------------------
# WEAK_TLS
# ---------------------------------------------------------------------------

def _cert_info(**over):
    """Certificado moderno e bem configurado, exceto pelo que o teste alterar."""
    base = {
        "protocol": "TLSv1.3", "self_signed": False, "sig_hash": "sha256",
        "key_type": "RSA", "key_bits": 2048, "legacy_accepted": False,
    }
    base.update(over)
    return base


@pytest.fixture
def porta443(db, device):
    p = Port(device_id=device.id, protocol="tcp", port=443, state="open",
             first_open_at=_utcnow(), last_seen_open_at=_utcnow())
    db.session.add(p)
    db.session.commit()
    return p


def test_tls_moderno_nao_alerta(db, sample_profile, device, porta443):
    assert _check_tls_quality(sample_profile, device, porta443, _cert_info(), _utcnow()) is False
    assert Alert.query.count() == 0


def test_protocolo_obsoleto_alerta(db, sample_profile, device, porta443):
    assert _check_tls_quality(
        sample_profile, device, porta443, _cert_info(protocol="TLSv1"), _utcnow()
    ) is True
    db.session.commit()
    alert = Alert.query.filter_by(alert_type=AlertType.WEAK_TLS).one()
    assert alert.severity == Severity.WARNING
    assert "TLSv1" in alert.message
    assert alert.match_value == "tcp/443"


def test_aceita_protocolo_legado_alerta(db, sample_profile, device, porta443):
    """Servidor que negocia TLS 1.3 mas ainda aceita 1.1 continua exposto."""
    assert _check_tls_quality(
        sample_profile, device, porta443, _cert_info(legacy_accepted=True), _utcnow()
    ) is True
    db.session.commit()
    assert "TLS 1.1 ou inferior" in Alert.query.one().message


def test_assinatura_sha1_alerta(db, sample_profile, device, porta443):
    assert _check_tls_quality(
        sample_profile, device, porta443, _cert_info(sig_hash="sha1"), _utcnow()
    ) is True
    db.session.commit()
    assert "SHA1" in Alert.query.one().message


def test_chave_rsa_curta_alerta(db, sample_profile, device, porta443):
    assert _check_tls_quality(
        sample_profile, device, porta443, _cert_info(key_bits=1024), _utcnow()
    ) is True
    db.session.commit()
    assert "1024 bits" in Alert.query.one().message


def test_chave_ec_256_nao_alerta(db, sample_profile, device, porta443):
    """256 bits em curva elíptica é forte — o piso só vale por tipo de chave."""
    assert _check_tls_quality(
        sample_profile, device, porta443,
        _cert_info(key_type="EC", key_bits=256), _utcnow(),
    ) is False


def test_autoassinado_sozinho_e_info(db, sample_profile, device, porta443):
    """Numa LAN todo equipamento vem autoassinado — registra, mas sem peso."""
    assert _check_tls_quality(
        sample_profile, device, porta443, _cert_info(self_signed=True), _utcnow()
    ) is True
    db.session.commit()
    assert Alert.query.one().severity == Severity.INFO


def test_autoassinado_com_sha1_sobe_para_warning(db, sample_profile, device, porta443):
    assert _check_tls_quality(
        sample_profile, device, porta443,
        _cert_info(self_signed=True, sig_hash="sha1"), _utcnow(),
    ) is True
    db.session.commit()
    alert = Alert.query.one()
    assert alert.severity == Severity.WARNING
    assert "autoassinado" in alert.message and "SHA1" in alert.message


def test_tls_dedupe_mesmo_achado(db, sample_profile, device, porta443):
    info = _cert_info(protocol="TLSv1")
    assert _check_tls_quality(sample_profile, device, porta443, info, _utcnow()) is True
    db.session.commit()
    assert _check_tls_quality(sample_profile, device, porta443, info, _utcnow()) is False
    assert Alert.query.count() == 1


def test_tls_achado_novo_realerta(db, sample_profile, device, porta443):
    """Se a configuração piora, a mensagem muda e o alerta sai de novo."""
    assert _check_tls_quality(
        sample_profile, device, porta443, _cert_info(protocol="TLSv1"), _utcnow()
    ) is True
    db.session.commit()
    assert _check_tls_quality(
        sample_profile, device, porta443,
        _cert_info(protocol="TLSv1", key_bits=1024), _utcnow(),
    ) is True
    assert Alert.query.count() == 2


def test_info_sem_campos_novos_nao_quebra(db, sample_profile, device, porta443):
    """_fetch_cert_info antigo (só expiração) não pode derrubar a avaliação."""
    assert _check_tls_quality(sample_profile, device, porta443, {}, _utcnow()) is False


# ---------------------------------------------------------------------------
# DNS — codificação e parsing do protocolo
# ---------------------------------------------------------------------------

def test_encode_name():
    assert dns_check._encode_name("dns.google") == b"\x03dns\x06google\x00"
    assert dns_check._encode_name("a.b.") == b"\x01a\x01b\x00"


def test_encode_name_label_invalido():
    with pytest.raises(ValueError):
        dns_check._encode_name("x" * 64 + ".com")


def test_skip_name_com_ponteiro():
    # 0xC0 0x0C é um ponteiro de compressão: 2 bytes, independente do alvo.
    assert dns_check._skip_name(b"\xc0\x0crest", 0) == 2
    assert dns_check._skip_name(b"\x03dns\x00x", 0) == 5


def _dns_response(qid, ips, rcode=0, qname="dns.google"):
    """Monta uma resposta DNS mínima para o parser consumir."""
    import struct
    q = dns_check._encode_name(qname) + struct.pack("!HH", 1, 1)
    header = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(ips), 0, 0)
    answers = b""
    for ip in ips:
        import socket
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4)
        answers += socket.inet_aton(ip)
    return header + q + answers


def test_parse_resposta(monkeypatch):
    captured = {}

    class FakeSocket:
        def __init__(self, *a): pass
        def settimeout(self, t): pass
        def connect(self, addr): captured["addr"] = addr
        def send(self, data): captured["qid"] = int.from_bytes(data[:2], "big")
        def recv(self, n): return _dns_response(captured["qid"], ["8.8.8.8", "8.8.4.4"])
        def close(self): pass

    monkeypatch.setattr(dns_check.socket, "socket", FakeSocket)
    res = dns_check.query_a_record("192.168.1.1", "dns.google")
    assert res["ips"] == ["8.8.8.8", "8.8.4.4"]
    assert res["rcode"] == 0 and res["error"] == ""
    assert captured["addr"] == ("192.168.1.1", 53)


def test_id_divergente_e_rejeitado(monkeypatch):
    """Resposta com outro ID é forjada ou fora de ordem — não pode virar achado."""
    class FakeSocket:
        def __init__(self, *a): pass
        def settimeout(self, t): pass
        def connect(self, addr): pass
        def send(self, data): pass
        def recv(self, n): return _dns_response(0xBEEF, ["1.2.3.4"])
        def close(self): pass

    monkeypatch.setattr(dns_check.socket, "socket", FakeSocket)
    res = dns_check.query_a_record("192.168.1.1", "dns.google")
    assert res["ips"] == [] and "ID" in res["error"]


def test_timeout_vira_erro(monkeypatch):
    class FakeSocket:
        def __init__(self, *a): pass
        def settimeout(self, t): pass
        def connect(self, addr): pass
        def send(self, data): raise OSError("network unreachable")
        def close(self): pass

    monkeypatch.setattr(dns_check.socket, "socket", FakeSocket)
    res = dns_check.query_a_record("192.168.1.1", "dns.google")
    assert res["ips"] == [] and "OSError" in res["error"]


# ---------------------------------------------------------------------------
# DNS — leitura dos resolvedores
# ---------------------------------------------------------------------------

def test_read_resolvers_prefere_systemd(tmp_path, monkeypatch):
    """Com systemd-resolved o /etc/resolv.conf só mostra o stub 127.0.0.53.

    O servidor da rede — que é o que queremos vigiar — fica no arquivo do
    resolved.
    """
    systemd = tmp_path / "resolved.conf"
    systemd.write_text("nameserver 192.168.100.1\nsearch .\n")
    etc = tmp_path / "resolv.conf"
    etc.write_text("nameserver 127.0.0.53\n")
    monkeypatch.setattr(dns_check, "_RESOLV_FILES", (str(systemd), str(etc)))
    assert dns_check.read_resolvers() == ["192.168.100.1"]


def test_read_resolvers_ignora_linhas_invalidas(tmp_path, monkeypatch):
    f = tmp_path / "resolv.conf"
    f.write_text(
        "# comentário\nnameserver 10.0.0.1\nnameserver nao-e-ip\n"
        "options edns0\nnameserver 10.0.0.2\nnameserver 10.0.0.1\n"
    )
    monkeypatch.setattr(dns_check, "_RESOLV_FILES", (str(f),))
    assert dns_check.read_resolvers() == ["10.0.0.1", "10.0.0.2"]


def test_read_resolvers_so_loopback(tmp_path, monkeypatch):
    """Sem alternativa, o stub local é melhor que nada."""
    f = tmp_path / "resolv.conf"
    f.write_text("nameserver 127.0.0.53\n")
    monkeypatch.setattr(dns_check, "_RESOLV_FILES", (str(f),))
    assert dns_check.read_resolvers() == ["127.0.0.53"]


# ---------------------------------------------------------------------------
# DNS — baseline de resolvedores
# ---------------------------------------------------------------------------

def test_primeira_execucao_aprende(db, sample_profile, monkeypatch):
    monkeypatch.setattr(dns_check, "read_resolvers", lambda: ["192.168.1.1"])
    out = dns_check.check_resolver_list(sample_profile)
    assert out["learned"] is True
    assert Alert.query.count() == 0


def test_resolvedor_novo_alerta(db, sample_profile, monkeypatch):
    monkeypatch.setattr(dns_check, "read_resolvers", lambda: ["192.168.1.1"])
    dns_check.check_resolver_list(sample_profile)

    monkeypatch.setattr(dns_check, "read_resolvers", lambda: ["192.168.1.1", "10.6.6.6"])
    out = dns_check.check_resolver_list(sample_profile)
    assert out["added"] == ["10.6.6.6"]
    alert = Alert.query.filter_by(alert_type=AlertType.DNS_HIJACK).one()
    assert alert.severity == Severity.CRITICAL
    assert alert.is_priority is True
    assert "10.6.6.6" in alert.message


def test_resolvedor_removido_e_warning(db, sample_profile, monkeypatch):
    monkeypatch.setattr(dns_check, "read_resolvers", lambda: ["192.168.1.1", "192.168.1.2"])
    dns_check.check_resolver_list(sample_profile)
    monkeypatch.setattr(dns_check, "read_resolvers", lambda: ["192.168.1.1"])
    dns_check.check_resolver_list(sample_profile)
    assert Alert.query.one().severity == Severity.WARNING


def test_nao_repete_alerta_do_mesmo_estado(db, sample_profile, monkeypatch):
    """O novo estado vira baseline — senão o alerta sairia em todo ciclo."""
    monkeypatch.setattr(dns_check, "read_resolvers", lambda: ["192.168.1.1"])
    dns_check.check_resolver_list(sample_profile)
    monkeypatch.setattr(dns_check, "read_resolvers", lambda: ["10.6.6.6"])
    dns_check.check_resolver_list(sample_profile)
    dns_check.check_resolver_list(sample_profile)
    assert Alert.query.count() == 1


def test_reset_limpa_baseline_de_dns(db, sample_profile, monkeypatch):
    from app.scanner.mitm import baselines_summary, reset_baselines

    monkeypatch.setattr(dns_check, "read_resolvers", lambda: ["192.168.1.1"])
    dns_check.check_resolver_list(sample_profile)
    assert baselines_summary(sample_profile.id)["dns_resolvers"] == ["192.168.1.1"]

    reset_baselines(sample_profile.id)
    assert baselines_summary(sample_profile.id)["dns_resolvers"] == []


# ---------------------------------------------------------------------------
# DNS — domínios âncora
# ---------------------------------------------------------------------------

def _fake_query(mapping):
    """Devolve um query_a_record falso a partir de {domínio: resultado}."""
    def _q(server, domain, timeout=3.0):
        return mapping.get(domain, {"ips": [], "rcode": None, "error": "sem resposta"})
    return _q


def test_resposta_correta_nao_alerta(db, sample_profile, monkeypatch):
    mapping = {
        d: {"ips": [sorted(exp)[0]], "rcode": 0, "error": ""}
        for d, exp in dns_check.ANCHOR_DOMAINS.items()
    }
    monkeypatch.setattr(dns_check, "query_a_record", _fake_query(mapping))
    out = dns_check.check_anchor_domains(sample_profile, ["192.168.1.1"])
    assert out["mismatches"] == [] and Alert.query.count() == 0


def test_resposta_divergente_alerta(db, sample_profile, monkeypatch):
    mapping = {"dns.google": {"ips": ["10.6.6.6"], "rcode": 0, "error": ""}}
    monkeypatch.setattr(dns_check, "query_a_record", _fake_query(mapping))
    out = dns_check.check_anchor_domains(sample_profile, ["192.168.1.1"])
    assert len(out["mismatches"]) == 1
    alert = Alert.query.filter_by(alert_type=AlertType.DNS_HIJACK).one()
    assert alert.severity == Severity.CRITICAL and alert.is_priority is True
    assert "10.6.6.6" in alert.message and "dns.google" in alert.message


def test_nxdomain_para_ancora_alerta(db, sample_profile, monkeypatch):
    """O domínio existe: dizer que não é reescrita de resposta."""
    mapping = {"dns.google": {"ips": [], "rcode": 3, "error": ""}}
    monkeypatch.setattr(dns_check, "query_a_record", _fake_query(mapping))
    dns_check.check_anchor_domains(sample_profile, ["192.168.1.1"])
    assert "NXDOMAIN" in Alert.query.one().message


def test_servfail_nao_alerta(db, sample_profile, monkeypatch):
    """O servidor não respondeu — não mentiu. Ruído operacional, não achado."""
    mapping = {d: {"ips": [], "rcode": 2, "error": ""} for d in dns_check.ANCHOR_DOMAINS}
    monkeypatch.setattr(dns_check, "query_a_record", _fake_query(mapping))
    out = dns_check.check_anchor_domains(sample_profile, ["192.168.1.1"])
    assert out["mismatches"] == [] and Alert.query.count() == 0


def test_noerror_sem_registro_nao_alerta(db, sample_profile, monkeypatch):
    """Filtro de conteúdo e resolvedor sobrecarregado dão o mesmo resultado."""
    mapping = {d: {"ips": [], "rcode": 0, "error": ""} for d in dns_check.ANCHOR_DOMAINS}
    monkeypatch.setattr(dns_check, "query_a_record", _fake_query(mapping))
    assert Alert.query.count() == 0
    dns_check.check_anchor_domains(sample_profile, ["192.168.1.1"])
    assert Alert.query.count() == 0


def test_erro_de_rede_nao_alerta(db, sample_profile, monkeypatch):
    monkeypatch.setattr(dns_check, "query_a_record", _fake_query({}))
    out = dns_check.check_anchor_domains(sample_profile, ["192.168.1.1"])
    assert out["errors"] == len(dns_check.ANCHOR_DOMAINS)
    assert Alert.query.count() == 0


def test_job_respeita_o_interruptor(db, app, sample_profile, monkeypatch):
    from app.security_settings import set_dns_check_enabled

    chamou = []
    monkeypatch.setattr(dns_check, "read_resolvers", lambda: chamou.append(1) or ["1.1.1.1"])
    set_dns_check_enabled(False)
    db.session.commit()
    dns_check.check_dns_integrity()
    assert chamou == []

    set_dns_check_enabled(True)
    db.session.commit()
    dns_check.check_dns_integrity()
    assert chamou == [1]
