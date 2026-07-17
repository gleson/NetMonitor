"""Testes do modo sudo (reconfirmação de identidade) em ações sensíveis."""

from datetime import datetime, timedelta

import pyotp

from app.models import User, AuditLog


def _make_admin(db, username="adm", password="senha123456", with_totp=False):
    user = User(username=username, role="admin")
    user.set_password(password)
    secret = None
    if with_totp:
        secret = pyotp.random_base32()
        user.set_totp_secret(secret)
        user.totp_enabled = True
    db.session.add(user)
    db.session.commit()
    return user, secret


def _login(client, username="adm", password="senha123456", secret=None):
    client.post("/login", data={"username": username, "password": password})
    if secret:
        client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now()})


SENSITIVE_GET = "/admin/scan-settings"


# --- Sem 2FA: reconfirmação por senha ---

def test_sensitive_route_redirects_to_confirm(client, db):
    _make_admin(db)
    _login(client)
    resp = client.get(SENSITIVE_GET, follow_redirects=False)
    assert resp.status_code == 302
    assert "/account/confirm" in resp.headers["Location"]


def test_wrong_password_does_not_grant_sudo(client, db):
    _make_admin(db)
    _login(client)
    client.post("/account/confirm", data={"password": "errada", "next": SENSITIVE_GET})
    resp = client.get(SENSITIVE_GET, follow_redirects=False)
    assert "/account/confirm" in resp.headers["Location"]
    assert AuditLog.query.filter_by(action="sudo.failed").count() == 1


def test_correct_password_grants_sudo_within_window(client, db):
    _make_admin(db)
    _login(client)
    resp = client.post(
        "/account/confirm",
        data={"password": "senha123456", "next": SENSITIVE_GET},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(SENSITIVE_GET)
    assert client.get(SENSITIVE_GET, follow_redirects=False).status_code == 200
    assert AuditLog.query.filter_by(action="sudo.confirmed").count() == 1


def test_external_next_is_blocked(client, db):
    _make_admin(db)
    _login(client)
    resp = client.post(
        "/account/confirm",
        data={"password": "senha123456", "next": "http://evil.example/x"},
        follow_redirects=False,
    )
    assert "evil.example" not in resp.headers["Location"]


def test_sudo_window_expires(client, db):
    _make_admin(db)
    _login(client)
    client.post("/account/confirm", data={"password": "senha123456", "next": SENSITIVE_GET})
    assert client.get(SENSITIVE_GET, follow_redirects=False).status_code == 200
    # Expira a janela manualmente.
    with client.session_transaction() as s:
        s["sudo_until"] = (datetime.utcnow() - timedelta(minutes=1)).isoformat()
    resp = client.get(SENSITIVE_GET, follow_redirects=False)
    assert "/account/confirm" in resp.headers["Location"]


# --- Com 2FA: reconfirmação exige código do autenticador ---

def test_totp_admin_confirm_requires_code_not_password(client, db):
    _admin, secret = _make_admin(db, with_totp=True)
    _login(client, secret=secret)
    # senha não concede sudo quando o 2FA está ativo
    client.post("/account/confirm", data={"password": "senha123456", "next": SENSITIVE_GET})
    assert "/account/confirm" in client.get(SENSITIVE_GET, follow_redirects=False).headers["Location"]
    # código TOTP concede
    resp = client.post(
        "/account/confirm",
        data={"code": pyotp.TOTP(secret).now(), "next": SENSITIVE_GET},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert client.get(SENSITIVE_GET, follow_redirects=False).status_code == 200


def test_all_user_mutation_routes_are_gated(client, db):
    """Cada rota de mutação de usuário exige reconfirmação."""
    admin, _ = _make_admin(db)
    _login(client)
    target = admin.id
    routes = [
        ("get", "/admin/users/new"),
        ("get", f"/admin/users/{target}/edit"),
        ("get", f"/admin/users/{target}/set-password"),
        ("post", f"/admin/users/{target}/toggle-active"),
        ("post", f"/admin/users/{target}/delete"),
        ("get", "/admin/metrics-settings"),
    ]
    for method, url in routes:
        resp = getattr(client, method)(url, follow_redirects=False)
        assert resp.status_code == 302 and "/account/confirm" in resp.headers["Location"], url
