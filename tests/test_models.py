"""Testes dos modelos SQLAlchemy."""

from app.models import (
    User, Profile, Device, DeviceIp, Port, Alert,
    DeviceType, AlertType, Severity, _utcnow,
)


def test_user_password(db):
    """Verifica hash/check de senha."""
    user = User(username="admin")
    user.set_password("s3cr3tpass42")
    db.session.add(user)
    db.session.commit()

    assert user.check_password("s3cr3tpass42")
    assert not user.check_password("wrong")


def test_user_password_policy(db):
    """Senhas fracas devem ser rejeitadas."""
    import pytest
    user = User(username="weak")
    for bad in ("short", "toolongbutnodigits", "1234567890", ""):
        with pytest.raises(ValueError):
            user.set_password(bad)
    # Válida não explode
    user.set_password("Valid1pass99")


def test_device_display_name(db, sample_profile):
    """Display name deve priorizar friendly_name > hostname > mac."""
    device = Device(
        profile_id=sample_profile.id,
        mac="AA:BB:CC:DD:EE:FF",
        hostname="myhost",
    )
    db.session.add(device)
    db.session.commit()

    assert device.display_name == "myhost"

    device.friendly_name = "Meu PC"
    assert device.display_name == "Meu PC"

    device.friendly_name = None
    device.hostname = ""
    assert device.display_name == "AA:BB:CC:DD:EE:FF"


def test_device_current_ip(db, sample_profile):
    """Verifica que current_ip retorna o IP marcado como is_current."""
    device = Device(profile_id=sample_profile.id, mac="11:22:33:44:55:66")
    db.session.add(device)
    db.session.flush()

    dip = DeviceIp(device_id=device.id, ip="192.168.1.10", is_current=True)
    db.session.add(dip)
    db.session.commit()

    assert device.current_ip == "192.168.1.10"


def test_port_is_open(db, sample_profile):
    """Porta sem last_seen_closed_at deve ser considerada aberta."""
    device = Device(profile_id=sample_profile.id, mac="AA:BB:CC:00:11:22")
    db.session.add(device)
    db.session.flush()

    port = Port(device_id=device.id, protocol="tcp", port=80, service_name="http")
    db.session.add(port)
    db.session.commit()

    assert port.is_open is True
    assert device.open_ports_count == 1
    assert device.truly_open_ports_count == 1


def test_device_ports_count_separates_filtered(db, sample_profile):
    """open_ports_count conta todas as ativas; truly_open_ports_count só as 'open'."""
    device = Device(profile_id=sample_profile.id, mac="AA:BB:CC:00:11:33")
    db.session.add(device)
    db.session.flush()

    db.session.add(Port(device_id=device.id, protocol="tcp", port=22, state="open"))
    db.session.add(Port(device_id=device.id, protocol="tcp", port=80, state="filtered"))
    db.session.add(Port(device_id=device.id, protocol="tcp", port=443, state="open|filtered"))
    # Porta fechada não conta em nenhum dos dois
    db.session.add(Port(
        device_id=device.id, protocol="tcp", port=8080, state="open",
        last_seen_closed_at=_utcnow(),
    ))
    db.session.commit()

    assert device.open_ports_count == 3
    assert device.truly_open_ports_count == 1


def test_alert_acknowledged(db, sample_profile):
    """Alerta é reconhecido quando acknowledged_at está preenchido."""
    from datetime import datetime, timezone

    alert = Alert(
        profile_id=sample_profile.id,
        alert_type=AlertType.NEW_DEVICE,
        severity=Severity.INFO,
        message="Novo device",
    )
    db.session.add(alert)
    db.session.commit()

    assert not alert.is_acknowledged

    alert.acknowledged_at = datetime.now(timezone.utc)
    assert alert.is_acknowledged


def _make_device_with_online_days(db, profile_id, mac, days_ago_list):
    """Cria device com online_dates preenchido para os dias `hoje - n`."""
    import json
    from datetime import timedelta

    today = _utcnow().date()
    dates = sorted((today - timedelta(days=n)).isoformat() for n in days_ago_list)
    device = Device(profile_id=profile_id, mac=mac, online_dates=json.dumps(dates))
    db.session.add(device)
    db.session.commit()
    return device


def _add_scan_days(db, profile_id, days_ago_list):
    """Registra um Scan HOST_DISCOVERY por dia para os dias `hoje - n`."""
    from datetime import datetime, timedelta, time as _time
    from app.models import Scan, ScanType, ScanStatus

    today = _utcnow().date()
    for n in days_ago_list:
        started = datetime.combine(today - timedelta(days=n), _time(hour=12))
        db.session.add(Scan(
            profile_id=profile_id,
            scan_type=ScanType.HOST_DISCOVERY,
            status=ScanStatus.SUCCESS,
            started_at=started,
        ))
    db.session.commit()


def test_uptime_denominator_uses_monitored_days(db, sample_profile):
    """Dias sem nenhum Scan (monitor desligado) não penalizam o uptime.

    Cenário do bug: device online em TODOS os dias em que o monitor rodou,
    mas o monitor só rodou em parte da janela — uptime deve ser 100%, não
    dias_online/janela_corrida.
    """
    online_days = [0, 1, 4, 5, 6]  # visto online nesses dias
    device = _make_device_with_online_days(
        db, sample_profile.id, "AA:AA:AA:00:00:01", online_days,
    )
    # Scans só rodaram exatamente nos mesmos dias (fins de semana desligado).
    _add_scan_days(db, sample_profile.id, online_days)

    detail = device.uptime_details(days=7)
    assert detail["monitored_days"] == 5
    assert detail["online_days"] == 5
    assert detail["ratio"] == 1.0
    assert device.uptime_estimate(days=7) == 1.0


def test_uptime_penalizes_offline_on_monitored_day(db, sample_profile):
    """Device offline num dia em que o monitor rodou continua penalizado."""
    device = _make_device_with_online_days(
        db, sample_profile.id, "AA:AA:AA:00:00:02", [0, 1, 4],
    )
    _add_scan_days(db, sample_profile.id, [0, 1, 2, 4, 5, 6])

    detail = device.uptime_details(days=7)
    # Janela começa na 1ª data online (dia -4): scans dos dias -5/-6 ficam
    # fora do denominador. Monitorados na janela: dias {0, 1, 2, 4} = 4.
    assert detail["monitored_days"] == 4
    assert detail["online_days"] == 3
    assert detail["ratio"] == 0.75


def test_uptime_window_starts_at_first_online_date(db, sample_profile):
    """Scans anteriores à primeira data online do device não entram no
    denominador (não penaliza histórico pré-existência do device)."""
    device = _make_device_with_online_days(
        db, sample_profile.id, "AA:AA:AA:00:00:03", [0, 1, 2],
    )
    # Monitor rodou a janela toda, mas o device só existe há 3 dias.
    _add_scan_days(db, sample_profile.id, list(range(7)))

    detail = device.uptime_details(days=7)
    assert detail["monitored_days"] == 3
    assert detail["online_days"] == 3
    assert detail["ratio"] == 1.0


def test_uptime_online_day_without_scan_counts_as_monitored(db, sample_profile):
    """Dia visto online sem Scan registrado (descoberta passiva) entra no
    denominador — e o ratio nunca passa de 1.0."""
    device = _make_device_with_online_days(
        db, sample_profile.id, "AA:AA:AA:00:00:04", [0, 1, 2],
    )
    _add_scan_days(db, sample_profile.id, [0, 1])  # dia -2 só via passiva

    detail = device.uptime_details(days=7)
    assert detail["monitored_days"] == 3
    assert detail["online_days"] == 3
    assert detail["ratio"] == 1.0


def test_uptime_none_without_history(db, sample_profile):
    """Sem online_dates registrado, uptime é None (histórico ainda não
    consolidado)."""
    device = Device(profile_id=sample_profile.id, mac="AA:AA:AA:00:00:05")
    db.session.add(device)
    db.session.commit()
    _add_scan_days(db, sample_profile.id, [0, 1, 2])

    assert device.uptime_estimate(days=7) is None
    assert device.uptime_details(days=7)["monitored_days"] == 0


def test_uptime_precomputed_monitored_days(db, sample_profile):
    """`monitored_days` pré-calculado (listagem) dá o mesmo resultado do
    cálculo interno via query."""
    from datetime import timedelta
    from app.models import scan_days_since

    device = _make_device_with_online_days(
        db, sample_profile.id, "AA:AA:AA:00:00:06", [0, 2],
    )
    _add_scan_days(db, sample_profile.id, [0, 1, 2])

    window_start = _utcnow().date() - timedelta(days=29)
    precomputed = scan_days_since(sample_profile.id, window_start)
    assert device.uptime_estimate(30, monitored_days=precomputed) == \
        device.uptime_estimate(30)
    assert device.uptime_details(days=30)["ratio"] == 2 / 3
