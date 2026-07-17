"""Helpers de autorização (RBAC), auditoria e reconfirmação de identidade."""

from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import abort, current_app, flash, redirect, request, session, url_for
from flask_login import current_user

from app.extensions import db
from app.models import AuditLog, ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER, _utcnow


def require_role(min_role: str):
    """Decorator que exige que o usuário autenticado tenha `min_role` ou superior.

    Hierarquia: viewer < operator < admin.

    Exemplo:
        @require_role(ROLE_ADMIN)
        def some_view(): ...
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login", next=request.path))
            if not current_user.has_role(min_role):
                flash(
                    f"Acesso negado. Esta ação exige nível '{min_role}' ou superior.",
                    "danger",
                )
                abort(403)
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


def audit(
    action: str,
    entity_type: str = "",
    entity_id: int | None = None,
    details: str = "",
    username: str | None = None,
    user_id: int | None = None,
):
    """Registra uma ação no AuditLog.

    Não faz commit — o chamador decide quando persistir, para manter a ação
    e o log atômicos na mesma transação. Se o chamador preferir commit
    separado, usar `audit(...); db.session.commit()`.

    Args:
        action: identificador da ação (ex.: "login.success", "device.delete").
        entity_type: tipo de entidade afetada (ex.: "device", "profile").
        entity_id: id da entidade afetada.
        details: texto livre com contexto extra.
        username: usado em ações sem usuário autenticado (ex.: login falho).
        user_id: idem.
    """
    # current_user pode não estar disponível fora de um request context
    # (ex.: jobs do scheduler, comandos CLI). Tenta ler e trata ausência.
    try:
        is_auth = bool(current_user and current_user.is_authenticated)
    except (RuntimeError, AttributeError):
        is_auth = False

    if username is None:
        username = current_user.username if is_auth else ""
    if user_id is None and is_auth:
        user_id = current_user.id

    try:
        ip = request.remote_addr or ""
    except RuntimeError:
        # Fora de contexto de request (ex.: CLI / scheduler).
        ip = ""

    log = AuditLog(
        user_id=user_id,
        username=username or "",
        action=action,
        entity_type=entity_type or "",
        entity_id=entity_id,
        details=details or "",
        ip_address=ip,
    )
    db.session.add(log)
    return log


# ---------------------------------------------------------------------------
# Reconfirmação de identidade ("sudo mode") para ações sensíveis
# ---------------------------------------------------------------------------
#
# Certas mutações de configuração de segurança (gestão de usuários, ajustes de
# scan, token de métricas) exigem que o usuário reprove a identidade mesmo já
# logado — com o código do autenticador (TOTP) se o 2FA estiver ativo, ou a
# senha da conta caso contrário. Isso limita o estrago de uma sessão sequestrada:
# o atacante teria o cookie, mas não o dispositivo TOTP nem a senha.
#
# Após a confirmação, a sessão fica "fresca" por SUDO_GRACE_MINUTES para não
# pedir o código a cada clique dentro de um fluxo administrativo.

_SUDO_UNTIL = "sudo_until"


def _sudo_grace_minutes() -> int:
    return int(current_app.config.get("SUDO_GRACE_MINUTES", 10))


def sudo_is_fresh() -> bool:
    """True se o usuário reconfirmou a identidade dentro da janela de graça."""
    raw = session.get(_SUDO_UNTIL)
    if not raw:
        return False
    try:
        return _utcnow() < datetime.fromisoformat(raw)
    except (ValueError, TypeError):
        return False


def mark_sudo_fresh() -> None:
    """Marca a sessão como recém-reconfirmada (inicia a janela de graça)."""
    session[_SUDO_UNTIL] = (
        _utcnow() + timedelta(minutes=_sudo_grace_minutes())
    ).isoformat()


def clear_sudo() -> None:
    session.pop(_SUDO_UNTIL, None)


def is_safe_redirect_url(target: str | None) -> bool:
    """True se ``target`` for uma URL local (mesmo host) — evita open redirect."""
    if not target:
        return False
    ref = urlparse(request.host_url)
    test = urlparse(target)
    return (not test.netloc or test.netloc == ref.netloc) and test.scheme in ("", "http", "https")


def require_fresh_confirmation(view_func):
    """Exige reconfirmação de identidade (sudo mode) antes de executar a view.

    Se a sessão não estiver fresca, redireciona para a página de confirmação
    guardando o destino. Deve vir DEPOIS de ``require_role`` na pilha de
    decorators, para que a checagem de papel ocorra primeiro.
    """

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.path))
        if sudo_is_fresh():
            return view_func(*args, **kwargs)
        # Num GET (formulário), o destino é a própria página. Num POST, os dados
        # do formulário se perderiam no redirect, então voltamos para a página de
        # origem (o usuário refaz a ação já dentro da janela fresca) — caso raro,
        # já que normalmente a sessão foi confirmada ao abrir o formulário.
        target = request.url if request.method == "GET" else (
            request.referrer or url_for("main.dashboard")
        )
        return redirect(url_for("auth.confirm_identity", next=target))

    return wrapper


__all__ = [
    "require_role",
    "require_fresh_confirmation",
    "sudo_is_fresh",
    "mark_sudo_fresh",
    "clear_sudo",
    "is_safe_redirect_url",
    "audit",
    "ROLE_ADMIN",
    "ROLE_OPERATOR",
    "ROLE_VIEWER",
]
