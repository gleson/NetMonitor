"""Blueprint de autenticação (login/logout) e 2FA (TOTP)."""

import base64
import io
from datetime import datetime, timedelta

import pyotp
import qrcode
import qrcode.image.svg
from flask import (
    Blueprint, render_template, redirect, url_for, flash, request, current_app,
    session,
)
from flask_login import login_user, logout_user, login_required, current_user

from app.auth_utils import audit
from app.extensions import db, limiter
from app.models import User, AuditLog, _utcnow

auth_bp = Blueprint("auth", __name__, template_folder="../templates/auth")

# Chaves de sessão do estágio intermediário de login (senha OK, falta o 2FA).
# Este estado NÃO autentica o usuário — só guarda quem está no meio do fluxo.
_PENDING_UID = "pending_2fa_user_id"
_PENDING_AT = "pending_2fa_started_at"
_PENDING_NEXT = "pending_2fa_next"
# Segredo em enrollment ainda não confirmado (não gravado no usuário).
_SETUP_SECRET = "totp_setup_secret"
# Janela para concluir o 2FA após a senha (segundos).
_PENDING_2FA_MAX_SECONDS = 300


def _failed_attempts_since_success(
    username: str, window_minutes: int, ip: str | None = None,
) -> int:
    """Conta logins falhos de ``username`` na janela, desde o último sucesso.

    Um login bem-sucedido zera efetivamente o contador (a contagem só considera
    falhas posteriores ao último ``login.success``). Baseado no AuditLog, então
    sobrevive a reinícios e funciona com múltiplos workers.

    Com ``ip`` informado, conta apenas falhas originadas daquele endereço
    (o ``audit('login.fail')`` grava ``request.remote_addr`` em ``ip_address``).
    """
    window_start = _utcnow() - timedelta(minutes=window_minutes)

    last_success = (
        AuditLog.query
        .filter(AuditLog.action == "login.success", AuditLog.username == username)
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    effective_start = window_start
    if last_success and last_success.created_at and last_success.created_at > window_start:
        effective_start = last_success.created_at

    q = AuditLog.query.filter(
        AuditLog.action == "login.fail",
        AuditLog.username == username,
        AuditLog.created_at >= effective_start,
    )
    if ip:
        q = q.filter(AuditLog.ip_address == ip)
    return q.count()


def _is_locked_out(username: str) -> bool:
    """True se a conta excedeu o limite de falhas na janela de bloqueio.

    Dois limites independentes:
    - Por (usuário, IP de origem): ``LOGIN_MAX_FAILED_ATTEMPTS`` falhas vindas
      do MESMO IP bloqueiam apenas aquele IP. Assim um atacante que erre senhas
      de propósito não nega acesso ao usuário legítimo conectando de outro
      endereço (DoS de conta).
    - Global por usuário: ``LOGIN_MAX_FAILED_ATTEMPTS_GLOBAL`` falhas somadas de
      qualquer origem ainda bloqueiam a conta inteira — backstop contra
      brute-force distribuído (que escaparia do limite por IP). 0 desativa.
    """
    max_attempts = int(current_app.config.get("LOGIN_MAX_FAILED_ATTEMPTS", 5))
    window = int(current_app.config.get("LOGIN_LOCKOUT_MINUTES", 15))
    if max_attempts <= 0 or not username:
        return False

    ip = request.remote_addr or ""
    if ip and _failed_attempts_since_success(username, window, ip=ip) >= max_attempts:
        return True

    max_global = int(current_app.config.get("LOGIN_MAX_FAILED_ATTEMPTS_GLOBAL", 30))
    if max_global > 0:
        return _failed_attempts_since_success(username, window) >= max_global
    return False


def _clear_pending_2fa() -> None:
    for key in (_PENDING_UID, _PENDING_AT, _PENDING_NEXT):
        session.pop(key, None)


def _complete_login(user: User, next_page: str | None):
    """Efetiva a sessão autenticada e registra o sucesso. Zera o estado de 2FA
    pendente e o contador de falhas (via login.success)."""
    _clear_pending_2fa()
    login_user(user, remember=True)
    audit(
        "login.success",
        entity_type="user",
        entity_id=user.id,
        username=user.username,
        user_id=user.id,
    )
    db.session.commit()
    flash("Login realizado com sucesso.", "success")
    return redirect(next_page or url_for("main.dashboard"))


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute; 50 per hour", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Bloqueio por tentativas falhas (antes de verificar a senha).
        if _is_locked_out(username):
            window = int(current_app.config.get("LOGIN_LOCKOUT_MINUTES", 15))
            audit(
                "login.locked",
                entity_type="user",
                details=f"Conta bloqueada por excesso de tentativas (janela {window}min)",
                username=username or "(vazio)",
            )
            db.session.commit()
            flash(
                f"Muitas tentativas falhas. Tente novamente em até {window} minutos.",
                "danger",
            )
            return render_template("auth/login.html"), 429

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.is_active:
                audit(
                    "login.blocked",
                    entity_type="user",
                    entity_id=user.id,
                    details="Conta desativada",
                    username=user.username,
                    user_id=user.id,
                )
                db.session.commit()
                flash("Esta conta está desativada. Contate o administrador.", "danger")
                return render_template("auth/login.html"), 403

            next_page = request.args.get("next")

            # Segundo fator: senha correta não autentica ainda. Guarda o usuário
            # no estágio pendente e exige o código do autenticador.
            if user.totp_enabled:
                session[_PENDING_UID] = user.id
                session[_PENDING_AT] = _utcnow().isoformat()
                session[_PENDING_NEXT] = next_page or ""
                audit(
                    "login.2fa_required",
                    entity_type="user",
                    entity_id=user.id,
                    username=user.username,
                    user_id=user.id,
                )
                db.session.commit()
                return redirect(url_for("auth.login_2fa"))

            return _complete_login(user, next_page)

        audit(
            "login.fail",
            entity_type="user",
            details="Tentativa de login falhou",
            username=username or "(vazio)",
        )
        db.session.commit()
        flash("Usuário ou senha inválidos.", "danger")

    return render_template("auth/login.html")


@auth_bp.route("/login/2fa", methods=["GET", "POST"])
@limiter.limit("10 per minute; 50 per hour", methods=["POST"])
def login_2fa():
    """Segundo estágio do login: valida o código TOTP (ou um código de backup)."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    uid = session.get(_PENDING_UID)
    started_at_raw = session.get(_PENDING_AT)
    if not uid or not started_at_raw:
        flash("Sessão de login expirada. Entre novamente.", "warning")
        return redirect(url_for("auth.login"))

    # Expira o estágio pendente (janela curta entre senha e código).
    try:
        started_at = datetime.fromisoformat(started_at_raw)
        expired = (_utcnow() - started_at).total_seconds() > _PENDING_2FA_MAX_SECONDS
    except (ValueError, TypeError):
        expired = True
    if expired:
        _clear_pending_2fa()
        flash("Tempo para o segundo fator esgotado. Entre novamente.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, uid)
    if not user or not user.is_active or not user.totp_enabled:
        _clear_pending_2fa()
        flash("Não foi possível continuar o login. Tente novamente.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        # O bloqueio por tentativas cobre também o segundo fator, para que
        # códigos TOTP não possam ser adivinhados por força bruta.
        if _is_locked_out(user.username):
            window = int(current_app.config.get("LOGIN_LOCKOUT_MINUTES", 15))
            audit(
                "login.locked",
                entity_type="user",
                entity_id=user.id,
                details=f"Conta bloqueada no 2FA (janela {window}min)",
                username=user.username,
                user_id=user.id,
            )
            _clear_pending_2fa()
            db.session.commit()
            flash(
                f"Muitas tentativas falhas. Tente novamente em até {window} minutos.",
                "danger",
            )
            return redirect(url_for("auth.login"))

        code = request.form.get("code", "")
        used_backup = False
        ok = user.verify_totp(code)
        if not ok and user.verify_and_consume_backup(code):
            ok = True
            used_backup = True

        if ok:
            next_page = session.get(_PENDING_NEXT) or None
            if used_backup:
                audit(
                    "login.2fa_backup_used",
                    entity_type="user",
                    entity_id=user.id,
                    details=f"Código de backup usado (restam {user.backup_codes_remaining()})",
                    username=user.username,
                    user_id=user.id,
                )
                flash(
                    f"Código de backup usado. Restam {user.backup_codes_remaining()}.",
                    "warning",
                )
            return _complete_login(user, next_page)

        audit(
            "login.fail",
            entity_type="user",
            entity_id=user.id,
            details="Código 2FA inválido",
            username=user.username,
            user_id=user.id,
        )
        db.session.commit()
        flash("Código de verificação inválido.", "danger")

    return render_template("auth/login_2fa.html")


@auth_bp.route("/logout")
@login_required
def logout():
    uid = current_user.id
    uname = current_user.username
    logout_user()
    audit("logout", entity_type="user", entity_id=uid, username=uname, user_id=uid)
    db.session.commit()
    flash("Logout realizado.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# 2FA — enrollment / gerenciamento (conta do próprio usuário)
# ---------------------------------------------------------------------------

def _totp_qr_data_uri(uri: str) -> str:
    """Gera o QR do otpauth:// como data URI SVG (embutível sem recurso externo)."""
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=10)
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


@auth_bp.route("/account/security")
@login_required
def security():
    """Página de segurança da conta: estado do 2FA e ações."""
    return render_template(
        "auth/security.html",
        backup_remaining=current_user.backup_codes_remaining(),
    )


@auth_bp.route("/account/2fa/setup", methods=["GET", "POST"])
@login_required
def totp_setup():
    """Enrollment do TOTP: mostra o QR e exige um código válido para ativar."""
    if current_user.totp_enabled:
        flash("O 2FA já está ativo nesta conta.", "info")
        return redirect(url_for("auth.security"))

    # Segredo mantido na sessão até a confirmação — só é gravado no usuário
    # depois que ele prova ter configurado o app corretamente.
    secret = session.get(_SETUP_SECRET)
    if not secret:
        secret = pyotp.random_base32()
        session[_SETUP_SECRET] = secret

    if request.method == "POST":
        code = request.form.get("code", "").strip().replace(" ", "")
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            current_user.set_totp_secret(secret)
            current_user.totp_enabled = True
            codes = current_user.generate_backup_codes()
            session.pop(_SETUP_SECRET, None)
            audit(
                "2fa.enabled",
                entity_type="user",
                entity_id=current_user.id,
                username=current_user.username,
                user_id=current_user.id,
            )
            db.session.commit()
            # Mostra os códigos de backup uma única vez.
            return render_template("auth/backup_codes.html", codes=codes, first_time=True)
        flash("Código inválido. Verifique o horário do dispositivo e tente de novo.", "danger")

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username, issuer_name="NetMonitor"
    )
    return render_template(
        "auth/totp_setup.html",
        qr_data_uri=_totp_qr_data_uri(uri),
        secret=secret,
    )


@auth_bp.route("/account/2fa/disable", methods=["POST"])
@login_required
def totp_disable():
    """Desativa o 2FA. Exige um código válido (TOTP ou backup) — provar posse
    evita que uma sessão sequestrada desligue a proteção sem o dispositivo."""
    if not current_user.totp_enabled:
        return redirect(url_for("auth.security"))

    code = request.form.get("code", "")
    if not (current_user.verify_totp(code) or current_user.verify_and_consume_backup(code)):
        audit(
            "2fa.disable_failed",
            entity_type="user",
            entity_id=current_user.id,
            details="Código inválido ao tentar desativar 2FA",
            username=current_user.username,
            user_id=current_user.id,
        )
        db.session.commit()
        flash("Código inválido. O 2FA continua ativo.", "danger")
        return redirect(url_for("auth.security"))

    current_user.totp_enabled = False
    current_user.set_totp_secret("")
    current_user.totp_backup_codes = None
    audit(
        "2fa.disabled",
        entity_type="user",
        entity_id=current_user.id,
        username=current_user.username,
        user_id=current_user.id,
    )
    db.session.commit()
    flash("2FA desativado.", "warning")
    return redirect(url_for("auth.security"))


@auth_bp.route("/account/2fa/backup-codes", methods=["POST"])
@login_required
def totp_regenerate_backup():
    """Gera novos códigos de backup (invalida os antigos). Exige código válido."""
    if not current_user.totp_enabled:
        return redirect(url_for("auth.security"))

    code = request.form.get("code", "")
    if not current_user.verify_totp(code):
        flash("Código inválido. Os códigos de backup não foram alterados.", "danger")
        return redirect(url_for("auth.security"))

    codes = current_user.generate_backup_codes()
    audit(
        "2fa.backup_regenerated",
        entity_type="user",
        entity_id=current_user.id,
        username=current_user.username,
        user_id=current_user.id,
    )
    db.session.commit()
    return render_template("auth/backup_codes.html", codes=codes, first_time=False)
