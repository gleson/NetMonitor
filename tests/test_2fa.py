"""Testes do 2FA (TOTP): enrollment, login em duas etapas e códigos de backup."""

import re

import pyotp

from app.models import User, AuditLog


def _make_user(db, username="bob", password="senha123456"):
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def _enroll(client, db, user_id):
    """Ativa o 2FA para o usuário logado e retorna (secret, backup_codes)."""
    client.get("/account/2fa/setup")
    with client.session_transaction() as s:
        secret = s["totp_setup_secret"]
    resp = client.post("/account/2fa/setup", data={"code": pyotp.TOTP(secret).now()})
    codes = re.findall(r">(\d{8})<", resp.data.decode())
    return secret, codes


# --- Model layer ---

def test_totp_secret_roundtrip_and_verify(db):
    user = _make_user(db)
    secret = pyotp.random_base32()
    user.set_totp_secret(secret)
    assert user.get_totp_secret() == secret
    assert user.verify_totp(pyotp.TOTP(secret).now())
    assert not user.verify_totp("000000")


def test_backup_codes_single_use(db):
    user = _make_user(db)
    codes = user.generate_backup_codes(10)
    assert user.backup_codes_remaining() == 10
    assert user.verify_and_consume_backup(codes[3])
    assert not user.verify_and_consume_backup(codes[3])  # já consumido
    assert user.backup_codes_remaining() == 9


# --- Enrollment ---

def test_enrollment_enables_2fa_and_shows_backup_codes(client, db):
    user = _make_user(db)
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    secret, codes = _enroll(client, db, user.id)
    assert len(codes) == 10
    refreshed = db.session.get(User, user.id)
    assert refreshed.totp_enabled
    assert refreshed.get_totp_secret() == secret
    assert AuditLog.query.filter_by(action="2fa.enabled").count() == 1


def test_enrollment_rejects_wrong_code(client, db):
    user = _make_user(db)
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    client.get("/account/2fa/setup")
    resp = client.post("/account/2fa/setup", data={"code": "000000"})
    assert resp.status_code == 200
    assert not db.session.get(User, user.id).totp_enabled


# --- Login em duas etapas ---

def test_login_requires_second_factor_when_enabled(client, db):
    user = _make_user(db)
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    _enroll(client, db, user.id)
    client.get("/logout")

    resp = client.post(
        "/login",
        data={"username": "bob", "password": "senha123456"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login/2fa")
    # Ainda não autenticado: página protegida redireciona ao login.
    assert client.get("/account/security", follow_redirects=False).status_code == 302


def test_login_completes_with_valid_totp(client, db):
    user = _make_user(db)
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    secret, _ = _enroll(client, db, user.id)
    client.get("/logout")

    client.post("/login", data={"username": "bob", "password": "senha123456"})
    resp = client.post(
        "/login/2fa",
        data={"code": pyotp.TOTP(secret).now()},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert client.get("/account/security", follow_redirects=False).status_code == 200


def test_login_rejects_invalid_totp_and_audits_fail(client, db):
    user = _make_user(db)
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    _enroll(client, db, user.id)
    client.get("/logout")

    client.post("/login", data={"username": "bob", "password": "senha123456"})
    resp = client.post("/login/2fa", data={"code": "000000"})
    assert resp.status_code == 200
    assert client.get("/account/security", follow_redirects=False).status_code == 302
    assert AuditLog.query.filter_by(action="login.fail").count() >= 1


def test_login_with_backup_code_consumes_it(client, db):
    user = _make_user(db)
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    _secret, codes = _enroll(client, db, user.id)
    client.get("/logout")

    client.post("/login", data={"username": "bob", "password": "senha123456"})
    resp = client.post(
        "/login/2fa", data={"code": codes[0]}, follow_redirects=False
    )
    assert resp.status_code == 302
    assert db.session.get(User, user.id).backup_codes_remaining() == 9
    # O mesmo código não serve uma segunda vez.
    client.get("/logout")
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    resp = client.post("/login/2fa", data={"code": codes[0]})
    assert resp.status_code == 200  # rejeitado, fica na página


# --- Desativação ---

def test_disable_requires_valid_code(client, db):
    user = _make_user(db)
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    secret, _ = _enroll(client, db, user.id)

    # Código errado: continua ativo.
    client.post("/account/2fa/disable", data={"code": "000000"})
    assert db.session.get(User, user.id).totp_enabled

    # Código certo: desativa e limpa o segredo.
    client.post("/account/2fa/disable", data={"code": pyotp.TOTP(secret).now()})
    refreshed = db.session.get(User, user.id)
    assert not refreshed.totp_enabled
    assert refreshed.get_totp_secret() is None


# --- Interação com o bloqueio por tentativas ---

def test_2fa_failures_count_toward_lockout(client, db, app):
    user = _make_user(db)
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    secret, _ = _enroll(client, db, user.id)
    client.get("/logout")

    max_attempts = app.config["LOGIN_MAX_FAILED_ATTEMPTS"]
    client.post("/login", data={"username": "bob", "password": "senha123456"})
    for _ in range(max_attempts):
        client.post("/login/2fa", data={"code": "000000"})

    # Estando bloqueado, uma nova senha correta é barrada com 429.
    resp = client.post("/login", data={"username": "bob", "password": "senha123456"})
    assert resp.status_code == 429
