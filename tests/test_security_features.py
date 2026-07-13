"""Testes das funcionalidades de segurança: importação, baseline de portas,
dedupe de alertas, devices fantasma, correlação CVE, verificação TLS e
estatísticas do dashboard."""

import io
import json
from datetime import timedelta

import pytest

from app.models import (
    Alert, AlertType, CveCache, Device, DeviceIp, Port, Severity, User,
    Vulnerability, _utcnow,
)


def _login_as(app, db, role):
    user = User(username=f"user_{role}", role=role)
    user.set_password("testpass123")
    db.session.add(user)
    db.session.commit()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
    return client


# ---------------------------------------------------------------------------
# Importação de devices — status offline + timestamps preservados
# ---------------------------------------------------------------------------

def test_import_devices_not_marked_online(app, db, sample_profile):
    """Devices importados NÃO podem aparecer como online (bug corrigido)."""
    client = _login_as(app, db, "operator")

    payload = json.dumps({"devices": [
        # Com timestamps exportados (instalação antiga)
        {
            "mac": "AA:BB:CC:00:00:01",
            "friendly_name": "Servidor X",
            "current_ip": "192.168.1.50",
            "first_seen_at": "01/01/2026 10:00:00",
            "last_seen_at": "15/05/2026 18:30:00",
        },
        # Sem timestamps
        {"mac": "AA:BB:CC:00:00:02", "friendly_name": "Sem Timestamps"},
    ]})

    resp = client.post(
        "/export/devices/import",
        data={
            "profile_id": str(sample_profile.id),
            "file": (io.BytesIO(payload.encode("utf-8")), "devices.json"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code == 302  # redirect de sucesso (sem erro 500)

    d1 = Device.query.filter_by(profile_id=sample_profile.id, mac="AA:BB:CC:00:00:01").first()
    d2 = Device.query.filter_by(profile_id=sample_profile.id, mac="AA:BB:CC:00:00:02").first()
    assert d1 is not None and d2 is not None

    # Timestamps do arquivo preservados — last_seen antigo => offline
    assert d1.first_seen_at.year == 2026 and d1.first_seen_at.month == 1
    assert d1.last_seen_at.month == 5 and d1.last_seen_at.day == 15

    # Sem timestamps no arquivo => last_seen_at NULL (nunca visto aqui) => offline
    assert d2.last_seen_at is None

    online_cutoff = _utcnow() - timedelta(minutes=70)
    assert not (d1.last_seen_at and d1.last_seen_at >= online_cutoff)


def test_import_devices_audit_log_does_not_crash(app, db, sample_profile):
    """O AuditLog da importação usa os kwargs corretos (bug de TypeError)."""
    from app.models import AuditLog

    client = _login_as(app, db, "operator")
    payload = json.dumps({"devices": [{"mac": "AA:BB:CC:00:00:03"}]})
    resp = client.post(
        "/export/devices/import",
        data={
            "profile_id": str(sample_profile.id),
            "file": (io.BytesIO(payload.encode("utf-8")), "devices.json"),
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    log = AuditLog.query.filter_by(action="devices.import").first()
    assert log is not None
    assert "1 criados" in log.details


# ---------------------------------------------------------------------------
# Exportação cifrada por senha (crypto_export) + round-trip de importação
# ---------------------------------------------------------------------------

def test_crypto_export_roundtrip_unit():
    """encrypt/decrypt: senha correta decifra, senha errada falha."""
    from app.crypto_export import (
        encrypt_payload, decrypt_payload, is_encrypted_envelope, DecryptError,
    )

    env = encrypt_payload("mac,ip\n00:11,1.2.3.4\n", "segredo123", fmt="csv")
    assert is_encrypted_envelope(env)
    assert not is_encrypted_envelope('{"devices": []}')
    assert not is_encrypted_envelope("mac,ip\n")

    plaintext, fmt = decrypt_payload(env, "segredo123")
    assert fmt == "csv" and plaintext.startswith("mac,ip")

    with pytest.raises(DecryptError):
        decrypt_payload(env, "errada")


def test_export_encrypted_then_import(app, db, sample_profile):
    """Exporta cifrado e reimporta o .enc com a senha — dados preservados."""
    from app.crypto_export import is_encrypted_envelope

    client = _login_as(app, db, "operator")
    db.session.add(Device(
        profile_id=sample_profile.id, mac="AA:BB:CC:DD:EE:01", friendly_name="Roteador",
    ))
    db.session.commit()

    # Exportação cifrada (POST com senha)
    resp = client.post("/export/devices/export", data={
        "profile_id": str(sample_profile.id),
        "format": "json",
        "password": "segredo123",
    })
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].endswith('.json.enc"')
    enc = resp.data
    assert is_encrypted_envelope(enc.decode("utf-8"))
    assert b"Roteador" not in enc  # conteúdo não vaza em claro

    # Reimporta o arquivo cifrado com a senha correta
    resp = client.post("/export/devices/import", data={
        "profile_id": str(sample_profile.id),
        "file": (io.BytesIO(enc), "devices_1.json.enc"),
        "password": "segredo123",
    }, content_type="multipart/form-data")
    assert resp.status_code == 302
    d = Device.query.filter_by(mac="AA:BB:CC:DD:EE:01").first()
    assert d is not None and d.friendly_name == "Roteador"


def test_import_encrypted_wrong_password(app, db, sample_profile):
    """Importar .enc com senha errada não cria devices e avisa o usuário."""
    from app.crypto_export import encrypt_payload

    client = _login_as(app, db, "operator")
    enc = encrypt_payload(json.dumps({"devices": [{"mac": "AA:BB:CC:DD:EE:02"}]}),
                          "certa123", fmt="json").encode("utf-8")

    resp = client.post("/export/devices/import", data={
        "profile_id": str(sample_profile.id),
        "file": (io.BytesIO(enc), "devices.json.enc"),
        "password": "errada",
    }, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert Device.query.filter_by(mac="AA:BB:CC:DD:EE:02").first() is None


def test_import_encrypted_missing_password(app, db, sample_profile):
    """Importar .enc sem senha é rejeitado."""
    from app.crypto_export import encrypt_payload

    client = _login_as(app, db, "operator")
    enc = encrypt_payload(json.dumps({"devices": [{"mac": "AA:BB:CC:DD:EE:03"}]}),
                          "certa123", fmt="json").encode("utf-8")

    resp = client.post("/export/devices/import", data={
        "profile_id": str(sample_profile.id),
        "file": (io.BytesIO(enc), "devices.json.enc"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert Device.query.filter_by(mac="AA:BB:CC:DD:EE:03").first() is None


# ---------------------------------------------------------------------------
# Baseline de portas (is_authorized) + rota de toggle
# ---------------------------------------------------------------------------

def _make_device_with_port(db, profile, mac="AA:BB:CC:11:22:33", port=22,
                           state="open", ip="192.168.1.10"):
    device = Device(profile_id=profile.id, mac=mac)
    db.session.add(device)
    db.session.flush()
    db.session.add(DeviceIp(device_id=device.id, ip=ip, is_current=True))
    port_row = Port(device_id=device.id, protocol="tcp", port=port, state=state)
    db.session.add(port_row)
    db.session.commit()
    return device, port_row


def test_device_list_renders_batched_ip_and_ports(app, db, sample_profile):
    """A lista de devices mostra IP atual e contagem de portas via dados
    batelados na view (sem N+1 por device.current_ip / *_ports_count)."""
    device, _port = _make_device_with_port(
        db, sample_profile, mac="AA:BB:CC:44:55:66", port=443,
        state="open", ip="192.168.1.77",
    )
    # Segunda porta filtrada: total=2, abertas=1.
    db.session.add(Port(device_id=device.id, protocol="tcp", port=8080, state="filtered"))
    db.session.commit()

    client = _login_as(app, db, "viewer")
    resp = client.get(f"/devices/?profile_id={sample_profile.id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "192.168.1.77" in body          # IP atual batelado
    assert '2 porta(s) no total' in body   # total=2 (open + filtered)


def test_export_port_history_json_and_encrypted(app, db, sample_profile):
    """Exporta o histórico de portas em JSON puro e cifrado (.enc)."""
    from app.crypto_export import is_encrypted_envelope

    device, _port = _make_device_with_port(
        db, sample_profile, mac="AA:BB:CC:9A:9B:9C", port=22, state="open",
    )
    client = _login_as(app, db, "operator")

    # JSON puro
    resp = client.get(f"/export/devices/{device.id}/ports/export?format=json")
    assert resp.status_code == 200
    data = json.loads(resp.get_data(as_text=True))
    assert data["mac"] == "AA:BB:CC:9A:9B:9C"
    assert any(p["port"] == 22 and p["is_open"] for p in data["ports"])

    # Cifrado (POST com senha) — não vaza conteúdo em claro
    resp = client.post(f"/export/devices/{device.id}/ports/export", data={
        "format": "json", "password": "segredo123",
    })
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].endswith('.json.enc"')
    assert is_encrypted_envelope(resp.get_data(as_text=True))


def test_export_port_history_requires_operator(app, db, sample_profile):
    device, _port = _make_device_with_port(db, sample_profile, mac="AA:BB:CC:9A:9B:9D")
    viewer = _login_as(app, db, "viewer")
    resp = viewer.get(f"/export/devices/{device.id}/ports/export?format=json")
    assert resp.status_code == 403


def test_acknowledge_all_respects_severity_filter(app, db, sample_profile):
    """Reconhecer com filtro de severidade só afeta os alertas correspondentes."""
    crit = Alert(profile_id=sample_profile.id, alert_type=AlertType.HOST_DOWN,
                 severity=Severity.CRITICAL, message="host down")
    info = Alert(profile_id=sample_profile.id, alert_type=AlertType.NEW_DEVICE,
                 severity=Severity.INFO, message="novo device")
    db.session.add_all([crit, info])
    db.session.commit()
    crit_id, info_id = crit.id, info.id

    client = _login_as(app, db, "operator")
    resp = client.post("/alerts/acknowledge-all", data={
        "profile_id": str(sample_profile.id),
        "severity": "CRITICAL",
    }, follow_redirects=False)
    assert resp.status_code == 302

    db.session.expire_all()
    assert db.session.get(Alert, crit_id).acknowledged_at is not None
    assert db.session.get(Alert, info_id).acknowledged_at is None  # INFO preservado


def test_acknowledge_all_no_filter_acknowledges_all(app, db, sample_profile):
    a1 = Alert(profile_id=sample_profile.id, alert_type=AlertType.HOST_DOWN,
               severity=Severity.CRITICAL, message="a1")
    a2 = Alert(profile_id=sample_profile.id, alert_type=AlertType.NEW_DEVICE,
               severity=Severity.INFO, message="a2")
    db.session.add_all([a1, a2])
    db.session.commit()

    client = _login_as(app, db, "operator")
    client.post("/alerts/acknowledge-all", data={"profile_id": str(sample_profile.id)})

    db.session.expire_all()
    remaining = Alert.query.filter_by(profile_id=sample_profile.id).filter(
        Alert.acknowledged_at.is_(None)).count()
    assert remaining == 0


def test_prometheus_metrics_disabled_by_default(app, db, sample_profile):
    client = _login_as(app, db, "viewer")
    resp = client.get("/api/metrics/prometheus")
    assert resp.status_code == 404


def test_prometheus_metrics_enabled_without_token(app, db, sample_profile):
    _make_device_with_port(db, sample_profile, mac="AA:BB:CC:CA:FE:01")
    client = app.test_client()  # sem login — endpoint é público quando habilitado
    app.config["METRICS_ENABLED"] = True
    app.config["METRICS_TOKEN"] = ""
    try:
        resp = client.get("/api/metrics/prometheus")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "netmonitor_up 1" in body
        assert "netmonitor_devices_total{" in body
        assert f'profile_id="{sample_profile.id}"' in body
    finally:
        app.config["METRICS_ENABLED"] = False
        app.config["METRICS_TOKEN"] = ""


def test_prometheus_metrics_token_required(app, db, sample_profile):
    client = app.test_client()
    app.config["METRICS_ENABLED"] = True
    app.config["METRICS_TOKEN"] = "s3cr3t"
    try:
        assert client.get("/api/metrics/prometheus").status_code == 401
        assert client.get("/api/metrics/prometheus?token=errado").status_code == 401
        assert client.get("/api/metrics/prometheus?token=s3cr3t").status_code == 200
        ok = client.get("/api/metrics/prometheus",
                        headers={"Authorization": "Bearer s3cr3t"})
        assert ok.status_code == 200
    finally:
        app.config["METRICS_ENABLED"] = False
        app.config["METRICS_TOKEN"] = ""


def test_metrics_admin_page_requires_admin(app, db, sample_profile):
    """A página de métricas é admin-only (operator não acessa)."""
    # Um único login por teste: o fixture mantém o app context aberto e o
    # Flask-Login cacheia current_user em g, então dois logins no mesmo teste
    # se contaminariam.
    operator = _login_as(app, db, "operator")
    assert operator.get("/admin/metrics-settings").status_code == 403


def test_metrics_admin_page_generates_token(app, db, sample_profile):
    """O primeiro acesso admin gera um token e o exibe na página."""
    from app.metrics_settings import get_metrics_token

    admin = _login_as(app, db, "admin")
    resp = admin.get("/admin/metrics-settings")
    assert resp.status_code == 200
    token = get_metrics_token()
    assert token                       # token gerado automaticamente
    assert token in resp.get_data(as_text=True)


def test_metrics_enable_via_admin_then_scrape(app, db, sample_profile):
    """Habilitar pela UI faz o endpoint responder; o token gerado é exigido."""
    from app.metrics_settings import get_metrics_token

    admin = _login_as(app, db, "admin")
    admin.get("/admin/metrics-settings")            # gera o token
    token = get_metrics_token()
    admin.post("/admin/metrics-settings", data={"action": "save", "enabled": "on"})

    client = app.test_client()
    assert client.get("/api/metrics/prometheus").status_code == 401
    ok = client.get(f"/api/metrics/prometheus?token={token}")
    assert ok.status_code == 200
    assert "netmonitor_devices_total{" in ok.get_data(as_text=True)


def test_metrics_clear_token_opens_endpoint(app, db, sample_profile):
    """Remover o token (via UI) deixa o endpoint aberto quando habilitado."""
    admin = _login_as(app, db, "admin")
    admin.get("/admin/metrics-settings")
    admin.post("/admin/metrics-settings", data={"action": "save", "enabled": "on"})
    admin.post("/admin/metrics-settings", data={"action": "clear_token"})

    client = app.test_client()
    assert client.get("/api/metrics/prometheus").status_code == 200


def test_metrics_disabled_via_admin_returns_404(app, db, sample_profile):
    """Salvar desabilitado faz o endpoint voltar a responder 404."""
    admin = _login_as(app, db, "admin")
    admin.get("/admin/metrics-settings")
    admin.post("/admin/metrics-settings", data={"action": "save", "enabled": "on"})
    admin.post("/admin/metrics-settings", data={"action": "save"})  # sem 'enabled'

    client = app.test_client()
    assert client.get("/api/metrics/prometheus").status_code == 404


def test_port_toggle_authorized_requires_operator(app, db, sample_profile):
    device, port = _make_device_with_port(db, sample_profile)

    viewer = _login_as(app, db, "viewer")
    resp = viewer.post(f"/devices/{device.id}/ports/{port.id}/toggle-authorized")
    assert resp.status_code == 403
    assert port.is_authorized is False


def test_port_toggle_authorized(app, db, sample_profile):
    device, port = _make_device_with_port(db, sample_profile)

    operator = _login_as(app, db, "operator")
    resp = operator.post(f"/devices/{device.id}/ports/{port.id}/toggle-authorized")
    assert resp.status_code == 302
    db.session.refresh(port)
    assert port.is_authorized is True


def test_record_detected_open_port_respects_baseline(app, db, sample_profile):
    """Porta autorizada que reaparece aberta NÃO gera alerta; nova porta gera."""
    from app.scanner.ports import PortInfo
    from app.scanner.scheduling import _record_detected_open_port

    device, port = _make_device_with_port(db, sample_profile, port=445, state="filtered")
    port.is_authorized = True
    db.session.commit()

    now = _utcnow()
    # Porta autorizada transiciona para open → sem alerta
    pi = PortInfo(port=445, protocol="tcp", state="open", service_name="smb")
    alerted = _record_detected_open_port(
        sample_profile, device.id, "dev", "192.168.1.10", pi, now, source="teste",
    )
    assert alerted is False
    assert Alert.query.count() == 0

    # Porta nova (sem baseline) aberta → alerta CRITICAL (445 é crítica? sim, mas
    # aqui usamos 3389 para variar)
    pi2 = PortInfo(port=3389, protocol="tcp", state="open", service_name="rdp")
    alerted2 = _record_detected_open_port(
        sample_profile, device.id, "dev", "192.168.1.10", pi2, now, source="teste",
    )
    db.session.commit()
    assert alerted2 is True
    alert = Alert.query.filter_by(alert_type=AlertType.NEW_PORT).first()
    assert alert is not None
    assert alert.severity == Severity.CRITICAL  # 3389 está em CRITICAL_PORTS


def test_recent_port_alert_dedup(app, db, sample_profile):
    """Segunda detecção da mesma porta dentro da janela não re-alerta."""
    from app.scanner.ports import PortInfo
    from app.scanner.scheduling import _record_detected_open_port

    device, _ = _make_device_with_port(db, sample_profile, port=80, state="filtered")
    now = _utcnow()

    pi = PortInfo(port=8080, protocol="tcp", state="open", service_name="http")
    assert _record_detected_open_port(
        sample_profile, device.id, "dev", "192.168.1.10", pi, now, source="teste",
    ) is True
    db.session.commit()

    # Fecha a porta e detecta de novo (flapping) — dedupe ativa
    port_row = Port.query.filter_by(device_id=device.id, port=8080).first()
    port_row.last_seen_closed_at = now
    db.session.commit()

    assert _record_detected_open_port(
        sample_profile, device.id, "dev", "192.168.1.10", pi, now, source="teste",
    ) is False
    db.session.commit()
    assert Alert.query.filter_by(alert_type=AlertType.NEW_PORT).count() == 1


# ---------------------------------------------------------------------------
# Devices fantasma — helper puro
# ---------------------------------------------------------------------------

def test_find_ghost_entries():
    from app.scanner.scheduling import _find_ghost_entries

    arp = [
        ("192.168.1.10", "AA:BB:CC:00:00:01"),   # dentro do range
        ("10.99.0.5", "AA:BB:CC:00:00:02"),       # fora → fantasma
        ("169.254.1.1", "AA:BB:CC:00:00:03"),     # link-local → ignorado
        ("127.0.0.1", "AA:BB:CC:00:00:04"),       # loopback → ignorado
    ]
    ghosts = _find_ghost_entries(arp, ["192.168.1.0/24"])
    assert ghosts == [("10.99.0.5", "AA:BB:CC:00:00:02")]

    # CIDR inválido é ignorado sem explodir
    ghosts2 = _find_ghost_entries(arp, ["not-a-cidr", "192.168.1.0/24"])
    assert ghosts2 == ghosts


# ---------------------------------------------------------------------------
# Correlação CVE (com lookup mockado)
# ---------------------------------------------------------------------------

def test_correlate_cves_creates_vuln_and_alert(app, db, sample_profile, monkeypatch):
    from app.scanner import cve as cve_mod

    device, port = _make_device_with_port(db, sample_profile, port=22)
    port.service_name = "openssh"
    port.service_version = "7.4"
    db.session.commit()

    monkeypatch.setitem(app.config, "CVE_LOOKUP_ENABLED", True)
    monkeypatch.setattr(cve_mod, "lookup_cves", lambda p, v, timeout=20: [
        {"id": "CVE-2023-0001", "cvss": 9.8, "summary": "RCE em openssh"},
        {"id": "CVE-2023-0002", "cvss": 5.0, "summary": "irrelevante (abaixo do mínimo)"},
    ])
    monkeypatch.setattr(cve_mod, "_NVD_SLEEP_SECONDS", 0)

    stats = cve_mod.correlate_cves()
    assert stats["vulns_created"] == 1
    assert stats["alerts"] == 1

    vuln = Vulnerability.query.filter_by(device_id=device.id).first()
    assert vuln is not None
    assert vuln.script_name == "cve:CVE-2023-0001"
    assert vuln.is_vulnerable is True

    alert = Alert.query.filter_by(alert_type=AlertType.VULNERABILITY).first()
    assert alert is not None
    assert alert.severity == Severity.CRITICAL  # CVSS 9.8 >= 9.0
    # IP na mensagem distingue devices com o mesmo nome
    assert "192.168.1.10" in alert.message

    # Cache populado
    assert CveCache.query.filter_by(product="openssh", version="7.4").first() is not None

    # Segunda execução: usa cache e não duplica vuln/alerta
    stats2 = cve_mod.correlate_cves()
    assert stats2["vulns_created"] == 0
    assert stats2["alerts"] == 0
    assert Vulnerability.query.count() == 1


def test_cpe_version_matching():
    """Filtragem por faixa de versão das configurações CPE do CVE."""
    from app.scanner import cve as cve_mod

    # Faixa: >= 1.0 e < 2.0 (versionStartIncluding / versionEndExcluding)
    cm = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.0",
        "versionEndExcluding": "2.0",
    }
    assert cve_mod._cpe_match_version(cm, "1.5") is True
    assert cve_mod._cpe_match_version(cm, "2.0") is False
    assert cve_mod._cpe_match_version(cm, "0.9") is False

    # Versão exata embutida no CPE
    exact = {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:prod:7.4:*:*:*:*:*:*:*"}
    assert cve_mod._cpe_match_version(exact, "7.4") is True
    assert cve_mod._cpe_match_version(exact, "7.5") is False

    # Curinga sem faixa → indeterminado (None)
    wild = {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*"}
    assert cve_mod._cpe_match_version(wild, "7.4") is None


def test_cve_matches_version_conservative():
    """CVE sem configurações utilizáveis é mantido (conservador)."""
    from app.scanner import cve as cve_mod

    # Sem configurações → mantém
    assert cve_mod._cve_matches_version({}, "1.0") is True

    # Configuração com faixa que NÃO inclui a versão → descarta
    cve = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "2.0"},
    ]}]}]}
    assert cve_mod._cve_matches_version(cve, "3.0") is False
    assert cve_mod._cve_matches_version(cve, "1.5") is True


def test_correlate_cves_kev_escalates(app, db, sample_profile, monkeypatch):
    """CVE abaixo do mínimo mas em CISA KEV gera alerta CRITICAL is_priority."""
    from app.models import AppSetting
    from app.scanner import cve as cve_mod

    device, port = _make_device_with_port(db, sample_profile, port=445, ip="192.168.1.40")
    port.service_name = "samba"
    port.service_version = "4.0"
    db.session.commit()

    # CVE com CVSS 5.0 (abaixo do mínimo 7.0) mas presente na KEV.
    AppSetting.set_value(cve_mod._KEV_SETTING_KEY, json.dumps(["CVE-2017-7494"]))
    db.session.commit()

    monkeypatch.setitem(app.config, "CVE_LOOKUP_ENABLED", True)
    monkeypatch.setitem(app.config, "CVE_KEV_ENABLED", True)
    monkeypatch.setattr(cve_mod, "_refresh_kev_if_stale", lambda *a, **k: None)
    monkeypatch.setattr(cve_mod, "lookup_cves", lambda p, v, timeout=20: [
        {"id": "CVE-2017-7494", "cvss": 5.0, "summary": "SambaCry"},
    ])
    monkeypatch.setattr(cve_mod, "_NVD_SLEEP_SECONDS", 0)

    stats = cve_mod.correlate_cves()
    assert stats["alerts"] == 1

    alert = Alert.query.filter_by(alert_type=AlertType.VULNERABILITY).first()
    assert alert is not None
    assert alert.severity == Severity.CRITICAL  # KEV força CRITICAL
    assert alert.is_priority is True
    assert "CISA KEV" in alert.message


def test_correlate_cves_skips_generic_versions(app, db, sample_profile, monkeypatch):
    from app.scanner import cve as cve_mod

    _, port = _make_device_with_port(db, sample_profile, port=80)
    port.service_name = "http"
    port.service_version = ""  # sem versão → não correlaciona
    db.session.commit()

    monkeypatch.setitem(app.config, "CVE_LOOKUP_ENABLED", True)
    called = []
    monkeypatch.setattr(cve_mod, "lookup_cves", lambda *a, **k: called.append(1) or [])

    stats = cve_mod.correlate_cves()
    assert stats["combos"] == 0
    assert not called


# ---------------------------------------------------------------------------
# Verificação TLS (com fetch mockado)
# ---------------------------------------------------------------------------

def test_check_tls_certificates_alerts_on_expired(app, db, sample_profile, monkeypatch):
    from app.scanner import scheduling

    device, _ = _make_device_with_port(db, sample_profile, port=443, ip="192.168.1.20")
    device.last_seen_at = _utcnow()
    db.session.commit()

    expired = _utcnow() - timedelta(days=3)
    monkeypatch.setattr(
        scheduling, "_fetch_cert_not_after",
        lambda ip, port, timeout=8: (expired, "CN=teste.local"),
    )

    scheduling.check_tls_certificates()

    alert = Alert.query.filter_by(alert_type=AlertType.TLS_CERT_EXPIRING).first()
    assert alert is not None
    assert alert.severity == Severity.CRITICAL
    assert "EXPIRADO" in alert.message

    # Dedupe: segunda execução não duplica
    scheduling.check_tls_certificates()
    assert Alert.query.filter_by(alert_type=AlertType.TLS_CERT_EXPIRING).count() == 1


def test_check_tls_certificates_ignores_valid(app, db, sample_profile, monkeypatch):
    from app.scanner import scheduling

    device, _ = _make_device_with_port(db, sample_profile, port=443, ip="192.168.1.21")
    device.last_seen_at = _utcnow()
    db.session.commit()

    valid = _utcnow() + timedelta(days=200)
    monkeypatch.setattr(
        scheduling, "_fetch_cert_not_after",
        lambda ip, port, timeout=8: (valid, "CN=ok.local"),
    )

    scheduling.check_tls_certificates()
    assert Alert.query.filter_by(alert_type=AlertType.TLS_CERT_EXPIRING).count() == 0


# ---------------------------------------------------------------------------
# Lista de alertas — sem forms aninhados (bug do 1º item "Nenhum alerta selecionado")
# ---------------------------------------------------------------------------

def test_alert_list_has_no_nested_forms(app, db, sample_profile):
    """O form de bulk NÃO pode envolver a tabela: os forms de reconhecimento
    por linha ficariam aninhados e o botão da primeira linha submeteria o
    bulk form vazio ("Nenhum alerta selecionado.")."""
    for i in range(2):
        db.session.add(Alert(
            profile_id=sample_profile.id,
            alert_type=AlertType.NEW_PORT,
            severity=Severity.WARNING,
            message=f"Alerta de teste {i}",
        ))
    db.session.commit()

    client = _login_as(app, db, "operator")
    with client.session_transaction() as sess:
        sess["active_profile_id"] = sample_profile.id
    resp = client.get("/alerts/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    table_start = html.index('<table')
    table_html = html[table_start:html.index('</table>')]

    # O form de bulk fecha antes da tabela e nenhum form com
    # acknowledge_selected aparece dentro dela.
    bulk_start = html.index('id="bulkForm"')
    assert bulk_start < table_start
    assert "</form>" in html[bulk_start:table_start]
    assert "acknowledge-selected" not in table_html

    # Checkboxes referenciam o bulk form via atributo form=
    assert 'form="bulkForm"' in table_html
    # Forms por linha (reconhecer individual) continuam dentro da tabela
    assert table_html.count("/acknowledge") == 2


# ---------------------------------------------------------------------------
# Estatísticas do dashboard (cards de segurança)
# ---------------------------------------------------------------------------

def test_compute_dashboard_stats_security_cards(app, db, sample_profile):
    from app.stats import compute_dashboard_stats

    # Device com porta crítica aberta (445 = SMB) e não autorizado online
    device, port = _make_device_with_port(db, sample_profile, port=445)
    device.situation = "Não Autorizado"
    device.last_seen_at = _utcnow()
    db.session.add(Vulnerability(
        device_id=device.id, port=445, script_name="cve:CVE-X", is_vulnerable=True,
    ))
    # Porta filtered crítica em outro device NÃO conta
    _make_device_with_port(db, sample_profile, mac="AA:BB:CC:99:99:99",
                           port=3389, state="filtered", ip="192.168.1.30")
    db.session.commit()

    stats = compute_dashboard_stats(sample_profile.id)
    assert stats["critical_port_devices"] == 1
    assert stats["open_vulnerabilities"] == 1
    assert stats["unauthorized_online"] == 1
    assert stats["total_devices"] == 2
