"""Testes da supressão de alertas (Feature 3).

Cobre a lógica de casamento de AlertSuppression, o helper emit_alert e as rotas
de gestão (gated por reconfirmação de identidade / step-up + auditoria).
"""

from datetime import timedelta

from app.models import (
    Alert, AlertSuppression, AlertType, Severity, Device, User, AuditLog, _utcnow,
)
from app.scanner.scheduling import emit_alert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_device(db, profile, mac="aa:bb:cc:dd:ee:ff"):
    dev = Device(profile_id=profile.id, mac=mac, hostname="dev")
    db.session.add(dev)
    db.session.commit()
    return dev


def _rule(db, profile, **kw):
    kw.setdefault("alert_type", AlertType.NEW_IP_FOR_MAC)
    rule = AlertSuppression(profile_id=profile.id, **kw)
    db.session.add(rule)
    db.session.commit()
    return rule


# ---------------------------------------------------------------------------
# Lógica de casamento (matches / is_suppressed)
# ---------------------------------------------------------------------------

def test_no_rules_means_not_suppressed(db, sample_profile):
    assert not AlertSuppression.is_suppressed(
        sample_profile.id, 1, AlertType.NEW_IP_FOR_MAC, "192.168.1.5"
    )


def test_type_scoped_rule_without_value_matches_all(db, sample_profile):
    dev = _make_device(db, sample_profile)
    _rule(db, sample_profile, device_id=dev.id, match_value=None)
    assert AlertSuppression.is_suppressed(
        sample_profile.id, dev.id, AlertType.NEW_IP_FOR_MAC, "10.0.0.9"
    )
    # tipo diferente não casa
    assert not AlertSuppression.is_suppressed(
        sample_profile.id, dev.id, AlertType.NEW_PORT, "tcp/22"
    )


def test_value_prefix_match(db, sample_profile):
    dev = _make_device(db, sample_profile)
    _rule(db, sample_profile, device_id=dev.id, match_value="192.168.1.")
    assert AlertSuppression.is_suppressed(
        sample_profile.id, dev.id, AlertType.NEW_IP_FOR_MAC, "192.168.1.50"
    )
    assert not AlertSuppression.is_suppressed(
        sample_profile.id, dev.id, AlertType.NEW_IP_FOR_MAC, "192.168.2.50"
    )


def test_device_scope_is_respected(db, sample_profile):
    dev = _make_device(db, sample_profile, mac="aa:aa:aa:aa:aa:aa")
    other = _make_device(db, sample_profile, mac="bb:bb:bb:bb:bb:bb")
    _rule(db, sample_profile, device_id=dev.id, match_value=None)
    # regra do device dev não silencia alertas do device other
    assert not AlertSuppression.is_suppressed(
        sample_profile.id, other.id, AlertType.NEW_IP_FOR_MAC, "10.0.0.1"
    )


def test_any_device_rule_matches_every_device(db, sample_profile):
    dev = _make_device(db, sample_profile)
    _rule(db, sample_profile, device_id=None, match_value="tcp/",
          alert_type=AlertType.NEW_PORT)
    assert AlertSuppression.is_suppressed(
        sample_profile.id, dev.id, AlertType.NEW_PORT, "tcp/8080"
    )
    assert AlertSuppression.is_suppressed(
        sample_profile.id, 999, AlertType.NEW_PORT, "tcp/443"
    )


def test_expired_rule_does_not_suppress(db, sample_profile):
    dev = _make_device(db, sample_profile)
    _rule(db, sample_profile, device_id=dev.id, match_value=None,
          expires_at=_utcnow() - timedelta(minutes=1))
    assert not AlertSuppression.is_suppressed(
        sample_profile.id, dev.id, AlertType.NEW_IP_FOR_MAC, "10.0.0.1"
    )


def test_future_expiry_still_active(db, sample_profile):
    dev = _make_device(db, sample_profile)
    _rule(db, sample_profile, device_id=dev.id, match_value=None,
          expires_at=_utcnow() + timedelta(days=1))
    assert AlertSuppression.is_suppressed(
        sample_profile.id, dev.id, AlertType.NEW_IP_FOR_MAC, "10.0.0.1"
    )


# ---------------------------------------------------------------------------
# emit_alert
# ---------------------------------------------------------------------------

def test_emit_alert_creates_and_stores_match_value(db, sample_profile):
    dev = _make_device(db, sample_profile)
    alert = emit_alert(
        sample_profile.id, dev.id, AlertType.NEW_PORT, Severity.WARNING,
        "porta nova", match_value="tcp/22",
    )
    db.session.commit()
    assert alert is not None
    assert alert.match_value == "tcp/22"
    assert Alert.query.count() == 1


def test_emit_alert_suppressed_returns_none_and_creates_nothing(db, sample_profile):
    dev = _make_device(db, sample_profile)
    _rule(db, sample_profile, device_id=dev.id, match_value="tcp/22",
          alert_type=AlertType.NEW_PORT)
    alert = emit_alert(
        sample_profile.id, dev.id, AlertType.NEW_PORT, Severity.WARNING,
        "porta nova", match_value="tcp/22",
    )
    db.session.commit()
    assert alert is None
    assert Alert.query.count() == 0


def test_emit_alert_not_suppressed_when_value_differs(db, sample_profile):
    dev = _make_device(db, sample_profile)
    _rule(db, sample_profile, device_id=dev.id, match_value="tcp/22",
          alert_type=AlertType.NEW_PORT)
    alert = emit_alert(
        sample_profile.id, dev.id, AlertType.NEW_PORT, Severity.WARNING,
        "outra porta", match_value="tcp/443",
    )
    db.session.commit()
    assert alert is not None
    assert Alert.query.count() == 1


# ---------------------------------------------------------------------------
# Rotas — gating por step-up + auditoria
# ---------------------------------------------------------------------------

def _operator_client(app, db, with_sudo=True):
    user = User(username="op", role="operator")
    user.set_password("senha123456")
    db.session.add(user)
    db.session.commit()
    client = app.test_client()
    from app.profile_utils import get_active_profile_id  # noqa: F401
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        if with_sudo:
            sess["sudo_until"] = (_utcnow() + timedelta(hours=1)).isoformat()
    return client, user


def test_create_requires_stepup(app, db, sample_profile):
    client, _ = _operator_client(app, db, with_sudo=False)
    with client.session_transaction() as sess:
        sess["active_profile_id"] = sample_profile.id
    resp = client.post(
        "/alerts/suppressions/create",
        data={"alert_type": "NEW_PORT", "match_value": "tcp/22"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/account/confirm" in resp.headers["Location"]
    assert AlertSuppression.query.count() == 0


def test_create_with_sudo_persists_and_audits(app, db, sample_profile):
    client, _ = _operator_client(app, db, with_sudo=True)
    dev = _make_device(db, sample_profile)
    with client.session_transaction() as sess:
        sess["active_profile_id"] = sample_profile.id
    resp = client.post(
        "/alerts/suppressions/create",
        data={
            "alert_type": "NEW_IP_FOR_MAC",
            "device_id": dev.id,
            "match_value": "192.168.1.",
            "reason": "DHCP esperado",
            "expires_in_days": "7",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    rule = AlertSuppression.query.one()
    assert rule.alert_type == AlertType.NEW_IP_FOR_MAC
    assert rule.device_id == dev.id
    assert rule.match_value == "192.168.1."
    assert rule.expires_at is not None
    assert rule.created_by == "op"
    assert AuditLog.query.filter_by(action="alert.suppression_create").count() == 1


def test_delete_requires_stepup_and_audits(app, db, sample_profile):
    dev = _make_device(db, sample_profile)
    rule = _rule(db, sample_profile, device_id=dev.id, match_value=None)

    # Sem sudo → redireciona para confirmação, regra permanece.
    client, _ = _operator_client(app, db, with_sudo=False)
    with client.session_transaction() as sess:
        sess["active_profile_id"] = sample_profile.id
    resp = client.post(f"/alerts/suppressions/{rule.id}/delete", follow_redirects=False)
    assert "/account/confirm" in resp.headers["Location"]
    assert AlertSuppression.query.count() == 1

    # Com sudo → remove e audita.
    with client.session_transaction() as sess:
        sess["sudo_until"] = (_utcnow() + timedelta(hours=1)).isoformat()
    resp = client.post(f"/alerts/suppressions/{rule.id}/delete", follow_redirects=False)
    assert resp.status_code == 302
    assert AlertSuppression.query.count() == 0
    assert AuditLog.query.filter_by(action="alert.suppression_delete").count() == 1


def test_viewer_cannot_create(app, db, sample_profile):
    user = User(username="viewer", role="viewer")
    user.set_password("senha123456")
    db.session.add(user)
    db.session.commit()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.id)
        sess["active_profile_id"] = sample_profile.id
        sess["sudo_until"] = (_utcnow() + timedelta(hours=1)).isoformat()
    resp = client.post(
        "/alerts/suppressions/create",
        data={"alert_type": "NEW_PORT", "match_value": "tcp/22"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 403)
    assert AlertSuppression.query.count() == 0


def test_suppressions_page_loads(app, db, sample_profile):
    client, _ = _operator_client(app, db, with_sudo=True)
    with client.session_transaction() as sess:
        sess["active_profile_id"] = sample_profile.id
    resp = client.get("/alerts/suppressions")
    assert resp.status_code == 200
    assert "supress" in resp.get_data(as_text=True).lower()
