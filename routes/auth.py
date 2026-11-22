"""Authentication blueprint (Stage 7 session/CSRF + Stage 8 accounts + Stage 9 UI).

Working routes
--------------
    GET  /auth/session     current session facts (and which routes exist)
    GET  /auth/csrf-token  signed token for POSTs (header X-CSRF-Token)
    GET  /login            HTML sign-in form
    POST /login            JSON or form; sets a fresh signed session
    GET  /register         HTML registration form
    POST /register         JSON or form; creates a role='user' account
    POST /logout           clears the session (CSRF protected)

Stage 9 replaced the two fixed inline HTML strings with real Jinja2 templates
(``templates/login.html``, ``templates/register.html``,
``templates/auth_result.html``) that extend ``templates/base.html``. The
POST contracts, validation, hashing and status codes are UNCHANGED: browser
forms receive HTML, JSON clients receive JSON, and errors never echo a
password.

Security notes
--------------
* Passwords are handled only by ``services.auth_service`` (scrypt hashing).
  They are never logged, echoed in an error, or stored in a response or cookie.
* Self-registration cannot choose a role: any ``role`` field in a request is
  ignored and a plain ``user`` account is created.
* Login clears the session before ``login_user`` (session-fixation defence)
  and returns one generic failure for unknown users / wrong passwords /
  disabled accounts, so the endpoint cannot enumerate accounts.
* If the schema has not been created, account POSTs return
  ``503 DATABASE_UNAVAILABLE`` rather than a misleading 500.
"""
from __future__ import annotations

from typing import Any

from flask import (
    Blueprint, Response, current_app, jsonify, render_template, request,
    session, url_for,
)
from flask_login import current_user, login_user, logout_user
from flask_wtf.csrf import generate_csrf

from extensions import limiter, limits_disabled
from services.auth_service import (
    RegistrationError, authenticate, create_user, record_login,
    validate_registration,
)
from services.database_service import database_status
from services.http_security import ServiceError

auth_bp = Blueprint("auth", __name__)


def _payload() -> dict[str, Any]:
    """Accept either a JSON body or a normal HTML form. Never echo the body."""
    if request.is_json:
        data = request.get_json(silent=True)
        return dict(data) if isinstance(data, dict) else {}
    return {key: request.form.get(key, "") for key in request.form.keys()}


def _wants_json() -> bool:
    return bool(request.is_json or request.args.get("format") == "json")


def _form_values(mode: str) -> dict[str, Any]:
    """Shared template values for the login and register forms."""
    register = mode == "register"
    return {
        "mode": mode,
        "action": url_for("auth.register" if register else "auth.login"),
        "token": generate_csrf(),
        "switch_text": "Already registered?" if register else "No account yet?",
        "switch_label": "Sign in" if register else "Create one",
        "switch_url": url_for("auth.login" if register else "auth.register"),
    }


def _render_form(
    mode: str, problems: list[str] | None = None, status: int = 200
) -> tuple[str, int]:
    template = "register.html" if mode == "register" else "login.html"
    values = _form_values(mode)
    values["problems"] = problems or []
    return render_template(template, **values), status


def _error(
    status: int, code: str, message: str, problems: list[str], mode: str
) -> Response | tuple[str, int]:
    if _wants_json():
        payload: dict[str, Any] = {
            "error": {"code": code, "message": message, "status": status}
        }
        if problems:
            payload["error"]["details"] = problems
        return jsonify(payload), status
    return _render_form(mode, problems or [message], status)


def _success(
    title: str, message: str, detail: str, user_json: dict[str, Any],
    status: int, *, authenticated: bool,
) -> Response | tuple[str, int]:
    if _wants_json():
        return jsonify({
            "authenticated": authenticated,
            "user": user_json,
            "message": message,
        }), status
    return render_template(
        "auth_result.html",
        title=title, message=message, detail=detail,
        authenticated=authenticated,
    ), status


@auth_bp.before_request
def _require_schema_for_account_routes() -> None:
    """Account POSTs need tables; /logout must keep working without them."""
    if request.method == "POST" and request.endpoint in ("auth.login", "auth.register"):
        if database_status()["status"] != "ready":
            raise ServiceError(
                503, "DATABASE_UNAVAILABLE",
                "The database schema is not initialised. Run python scripts/init_db.py.",
            )


@auth_bp.get("/auth/session")
def session_state() -> Response:
    """Return facts about the current session, never assumptions."""
    authenticated = bool(current_user.is_authenticated)
    return jsonify({
        "authenticated": authenticated,
        "user_id": current_user.get_id() if authenticated else None,
        "user": current_user.to_dict() if authenticated else None,
        "guest_scans_allowed": True,
        "user_persistence": "sqlite",
        "session_protection": current_app.login_manager.session_protection,
        "csrf_protection_enabled": bool(current_app.config["WTF_CSRF_ENABLED"]),
        "login_available": "auth.login" in current_app.view_functions,
        "register_available": "auth.register" in current_app.view_functions,
        "note": "Guest scans remain enabled; authentication is optional.",
    })


@auth_bp.get("/auth/csrf-token")
def csrf_token() -> Response:
    """Issue a CSRF token for a subsequent state-changing request."""
    return jsonify({
        "csrf_token": generate_csrf(),
        "header_name": "X-CSRF-Token",
        "form_field": "csrf_token",
    })


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(
    lambda: current_app.config["RATE_LIMIT_AUTH"],
    methods=["POST"], exempt_when=limits_disabled,
)
def login() -> Response | tuple[str, int]:
    """Authenticate and start a fresh session."""
    if request.method == "GET":
        return _render_form("login")

    data = _payload()
    identifier = data.get("username") or data.get("email") or ""
    password = data.get("password")
    if not isinstance(identifier, str) or not identifier.strip() \
            or not isinstance(password, str) or not password:
        return _error(400, "BAD_REQUEST",
                      "Enter your username or email and password.", [], "login")

    user = authenticate(identifier, password)
    if user is None:
        return _error(401, "UNAUTHENTICATED",
                      "Invalid credentials or inactive account.", [], "login")

    # Clear the pre-login session so an attacker-supplied session identifier
    # cannot survive privilege elevation (session fixation defence).
    session.clear()
    login_user(user, remember=False)
    record_login(user)
    return _success(
        "Signed in",
        f"Welcome, {user.username}. A fresh session has been started.",
        "No plaintext password was stored; only a scrypt hash is kept.",
        user.to_dict(), 200, authenticated=True,
    )


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit(
    lambda: current_app.config["RATE_LIMIT_AUTH"],
    methods=["POST"], exempt_when=limits_disabled,
)
def register() -> Response | tuple[str, int]:
    """Create a normal (non-admin) account."""
    if request.method == "GET":
        return _render_form("register")

    data = _payload()
    # A caller-supplied role is deliberately ignored: self-registration can
    # never grant administrator privileges.
    username, email, problems = validate_registration(
        data.get("username"),
        data.get("email"),
        data.get("password"),
        data.get("confirm_password") if "confirm_password" in data else None,
    )
    if problems:
        return _error(400, "INVALID_REGISTRATION",
                      "Registration details were not accepted.", problems, "register")

    try:
        user = create_user(username, email, data.get("password"), role="user")
    except RegistrationError as exc:
        return _error(400, "INVALID_REGISTRATION", str(exc), [str(exc)], "register")

    return _success(
        "Account created",
        f"Account {user.username} was created with the ordinary user role.",
        "Sign in to associate future scans with this account. No performance "
        "figures are stored here.",
        user.to_dict(), 201, authenticated=False,
    )


@auth_bp.post("/logout")
def logout() -> Response:
    """Clear the signed session. Safe to call when already anonymous."""
    logout_user()
    session.clear()
    return jsonify({"logged_out": True, "authenticated": False})


__all__ = ["auth_bp"]
