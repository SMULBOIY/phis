"""Security, CSRF, rate-limit and SSRF tests (Stage 13).

Scope
-----
The guarantees a marker will look for first:

* the EXACT Content-Security-Policy string from Stage 7/12 (unchanged), plus
  the production-only framing and HSTS policy;
* CSRF enforced on every state-changing request, INCLUDING ``/api/v1/scan``
  (there is no exemption anywhere in the codebase);
* per-route, config-driven rate limiting with the documented 429 contract;
* scrypt password hashing, no plaintext anywhere, safe cookies;
* Jinja2 autoescaping against reflected XSS, and generic errors that leak
  nothing (no traceback, no path, no secret);
* **no outbound network access at all** - proved behaviourally by making the
  socket layer unusable and showing that a scan still succeeds. That is the
  SSRF defence: the URL is only ever a string.

Everything runs against local, synthetic URLs.
"""
from __future__ import annotations

import json
import re
import socket
from pathlib import Path

import pytest

from models.database_models import User

ROOT = Path(__file__).resolve().parents[1]

EXACT_CSP = (
    "default-src 'self'; base-uri 'self'; object-src 'none'; "
    "form-action 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'"
)

SAFE_URL = "https://example.com/"
STRONG_PASSWORD = "Str0ng-Passw0rd!2026"

HARDENING_HEADERS = (
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "Origin-Agent-Cluster",
    "X-XSS-Protection",
)


def _error_code(response) -> str | None:
    payload = response.get_json(silent=True)
    if isinstance(payload, dict):
        return (payload.get("error") or {}).get("code")
    return None


# --------------------------------------------------------------------------- #
# 1. Content-Security-Policy and hardening headers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "path", ["/", "/scan", "/dashboard", "/history", "/login", "/api/v1/health"]
)
def test_every_response_carries_the_exact_csp(client, path):
    response = client.get(path)
    assert response.headers.get("Content-Security-Policy") == EXACT_CSP


def test_the_csp_never_relaxes_scripts_styles_or_connections(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "*" not in csp
    for scheme in ("http://", "https://"):
        assert scheme not in csp, "no remote origin may be allowed"
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "connect-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp


def test_hardening_headers_are_present_on_success_and_error(client):
    for response in (client.get("/"), client.get("/definitely-not-a-route"),
                     client.get("/api/v1/health")):
        for header in HARDENING_HEADERS:
            assert header in response.headers, header
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["X-XSS-Protection"] == "0"


def test_development_and_testing_omit_framing_for_the_live_preview(client):
    """Documented, config-driven relaxation (ADR-025); production is strict."""
    response = client.get("/")
    assert "X-Frame-Options" not in response.headers
    assert "frame-ancestors" not in response.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" not in response.headers


def test_production_enforces_framing_hsts_and_secure_cookies(production_app):
    # ProductionConfig keeps WTF_CSRF_SSL_STRICT, so the simulated browser must
    # speak HTTPS - exactly as it would behind a TLS terminator in deployment.
    https = {"base_url": "https://localhost"}
    client = production_app.test_client()

    response = client.get("/", **https)
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")

    token = client.get("/api/v1/csrf-token", **https).get_json()["csrf_token"]
    # Over TLS, Flask-WTF's WTF_CSRF_SSL_STRICT also requires a same-origin
    # Referer - a real browser always sends one.
    login = client.post("/login", json={
        "username": "testmember", "password": STRONG_PASSWORD,
    }, headers={"X-CSRF-Token": token, "Referer": "https://localhost/login"},
        **https)
    assert login.status_code == 200
    cookie = login.headers.get("Set-Cookie", "")
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_sensitive_paths_are_never_cached(client):
    for path in ("/scan", "/history", "/dashboard", "/admin", "/api/v1/scans"):
        response = client.get(path)
        assert response.headers.get("Cache-Control") == "no-store", path


def test_templates_load_only_local_assets():
    """Offline/vendored only: no runtime CDN, no inline script or style."""
    external: list[str] = []
    inline: list[str] = []
    for template in (ROOT / "templates").rglob("*.html"):
        text = template.read_text(encoding="utf-8")
        external += re.findall(
            r"""(?:src|href)\s*=\s*["'](?:https?:)?//[^"']+""", text, re.IGNORECASE
        )
        inline += [chunk for chunk in re.findall(
            r"<script\b[^>]*>(.*?)</script>", text, re.DOTALL | re.IGNORECASE
        ) if chunk.strip()]
        inline += re.findall(r"""<[^>]+\sstyle\s*=\s*["'][^"']+["']""", text)
    assert external == [], external
    assert inline == [], inline


# --------------------------------------------------------------------------- #
# 2. CSRF - enforced everywhere, exempt nowhere
# --------------------------------------------------------------------------- #
def test_the_html_scan_form_requires_a_csrf_token(csrf_app):
    with csrf_app.test_client() as client:
        response = client.post("/scan", data={"url": SAFE_URL})
        assert response.status_code == 400
        body = response.get_data(as_text=True)
        assert "CSRF_FAILED" in body
        assert "security token is missing, invalid or expired" in body


def test_the_html_scan_form_accepts_the_session_token(csrf_app, csrf_token_for):
    with csrf_app.test_client() as client:
        token = csrf_token_for(client)
        response = client.post(
            "/scan", data={"url": SAFE_URL, "csrf_token": token}
        )
        assert response.status_code == 200
        # A token is single-session; reuse in the same session must work too.
        assert client.post(
            "/scan", data={"url": SAFE_URL, "csrf_token": token}
        ).status_code == 200


def test_the_rest_api_post_is_not_exempt_from_csrf(csrf_app, csrf_token_for):
    with csrf_app.test_client() as client:
        tokenless = client.post("/api/v1/scan", json={"url": SAFE_URL})
        assert tokenless.status_code == 400
        assert _error_code(tokenless) == "CSRF_FAILED"

        token = csrf_token_for(client)
        accepted = client.post(
            "/api/v1/scan", json={"url": SAFE_URL},
            headers={"X-CSRF-Token": token},
        )
        assert accepted.status_code == 200
        assert accepted.get_json()["scan"]["prediction"] in {
            "LEGITIMATE", "SUSPICIOUS", "PHISHING"
        }


def test_a_wrong_csrf_token_is_rejected(csrf_app):
    with csrf_app.test_client() as client:
        response = client.post(
            "/api/v1/scan", json={"url": SAFE_URL},
            headers={"X-CSRF-Token": "not-a-real-token"},
        )
        assert response.status_code == 400
        assert _error_code(response) == "CSRF_FAILED"


def test_login_and_register_are_csrf_protected(csrf_app, csrf_token_for):
    with csrf_app.test_client() as client:
        assert _error_code(client.post("/login", json={
            "username": "testmember", "password": STRONG_PASSWORD,
        })) == "CSRF_FAILED"
        assert _error_code(client.post("/register", json={
            "username": "csrfuser", "email": "csrfuser@example.com",
            "password": STRONG_PASSWORD, "confirm_password": STRONG_PASSWORD,
        })) == "CSRF_FAILED"

        token = csrf_token_for(client)
        assert client.post("/login", json={
            "username": "testmember", "password": STRONG_PASSWORD,
        }, headers={"X-CSRF-Token": token}).status_code == 200


def test_get_requests_never_require_a_token(csrf_app):
    with csrf_app.test_client() as client:
        for path in ("/", "/scan", "/login", "/register", "/dashboard", "/history"):
            assert client.get(path).status_code == 200, path


def test_no_route_exempts_itself_from_csrf():
    """A static check of the source: `csrf.exempt` must not exist anywhere."""
    offenders = []
    for path in list((ROOT / "routes").glob("*.py")) + list((ROOT / "services").glob("*.py")) \
            + [ROOT / "app.py", ROOT / "extensions.py"]:
        text = path.read_text(encoding="utf-8")
        if "csrf.exempt" in text or "csrf_exempt" in text:
            offenders.append(path.name)
    assert offenders == [], offenders


# --------------------------------------------------------------------------- #
# 3. Rate limiting
# --------------------------------------------------------------------------- #
def test_login_is_throttled_with_the_documented_429_contract(limited_app):
    with limited_app.test_client() as client:
        statuses = [
            client.post("/login", json={"username": "x", "password": "y"}).status_code
            for _ in range(3)
        ]
        assert statuses == [401, 401, 429], statuses

        throttled = client.post("/login", json={"username": "x", "password": "y"})
        assert throttled.status_code == 429
        assert _error_code(throttled) == "RATE_LIMITED"
        assert throttled.headers["Retry-After"].isdigit()
        assert int(throttled.headers["Retry-After"]) >= 1
        assert throttled.headers["Cache-Control"] == "no-store"
        assert "Traceback" not in throttled.get_data(as_text=True)

        # A throttled POST must not disable the GET form.
        assert client.get("/login").status_code == 200


def test_the_scan_endpoint_has_its_own_quota(limited_app):
    with limited_app.test_client() as client:
        statuses = [
            client.post("/scan", data={"url": SAFE_URL}).status_code
            for _ in range(4)
        ]
        assert statuses == [200, 200, 200, 429], statuses


def test_the_api_scan_is_throttled_and_keeps_the_json_shape(limited_app, csrf_token_for):
    with limited_app.test_client() as client:
        statuses = [
            client.post("/api/v1/scan", json={"url": SAFE_URL}).status_code
            for _ in range(3)
        ]
        assert statuses == [200, 200, 429], statuses
        response = client.post("/api/v1/scan", json={"url": SAFE_URL})
        assert response.status_code == 429
        assert response.mimetype == "application/json"
        assert response.get_json()["error"]["status"] == 429


def test_monitoring_endpoints_survive_a_rate_limit_breach(limited_app):
    with limited_app.test_client() as client:
        for _ in range(3):
            client.post("/login", json={"username": "x", "password": "y"})
        assert client.get("/api/v1/health").status_code == 200
        assert client.get("/api/v1/csrf-token").status_code == 200
        assert client.get("/health").status_code == 200


def test_testing_configuration_is_not_throttled(client):
    """Deterministic tests need limits OFF; the limits are proved above."""
    statuses = [
        client.post("/login", json={"username": "x", "password": "y"}).status_code
        for _ in range(6)
    ]
    assert statuses == [401] * 6, statuses


def test_rate_limiting_has_no_blanket_default_limit(app):
    """Only decorated routes are limited; static pages are not."""
    from extensions import limiter

    assert app.config["RATELIMIT_ENABLED"] is False
    assert "RATE_LIMIT_SCAN" in app.config
    assert "RATE_LIMIT_AUTH" in app.config
    assert "RATE_LIMIT_API" in app.config
    assert limiter is not None


# --------------------------------------------------------------------------- #
# 4. Password hashing and account hygiene
# --------------------------------------------------------------------------- #
def test_passwords_are_stored_only_as_scrypt_hashes(app):
    with app.app_context():
        user = User.query.filter_by(username="testmember").one()
        assert user.password_hash.startswith("scrypt:")
        assert STRONG_PASSWORD not in user.password_hash
        assert STRONG_PASSWORD not in json.dumps(user.to_dict())
        assert "password" not in json.dumps(user.to_dict()).lower()


def test_user_objects_expose_no_plaintext_password_attribute(app):
    with app.app_context():
        user = User.query.filter_by(username="testmember").one()
        assert not hasattr(user, "password")
        assert hasattr(user, "password_hash")


def test_password_verification_accepts_only_the_right_password(app):
    with app.app_context():
        user = User.query.filter_by(username="testmember").one()
        assert user.check_password(STRONG_PASSWORD) is True
        assert user.check_password(STRONG_PASSWORD + "x") is False
        assert user.check_password("") is False
        assert user.check_password(None) is False


def test_two_accounts_with_the_same_password_get_different_hashes(app):
    """A per-user salt must make identical passwords indistinguishable."""
    with app.app_context():
        from extensions import db

        from models.database_models import utcnow

        first = User(username="saltone", email="saltone@example.com",
                     password_hash="pending", created_at=utcnow())
        second = User(username="salttwo", email="salttwo@example.com",
                      password_hash="pending", created_at=utcnow())
        first.set_password(STRONG_PASSWORD)
        second.set_password(STRONG_PASSWORD)
        assert first.password_hash != second.password_hash
        assert first.check_password(STRONG_PASSWORD)
        db.session.rollback()


def test_the_hash_is_never_included_in_a_response(client):
    body = client.get("/auth/session").get_data(as_text=True)
    assert "scrypt" not in body
    assert "password" not in body.lower()


# --------------------------------------------------------------------------- #
# 5. XSS, escaping and generic errors
# --------------------------------------------------------------------------- #
def test_a_reflected_script_in_a_url_is_escaped_on_the_result_page(client, app):
    payload = "https://example.com/<svg/onload=alert(1)>"
    response = client.post("/scan", data={"url": payload})
    body = response.get_data(as_text=True)
    assert response.status_code == 200, "the payload is a valid URL string"
    assert "<svg/onload=alert(1)>" not in body
    assert "&lt;svg" in body


def test_a_report_page_escapes_a_stored_url(client, app):
    from models.database_models import ScanHistory

    client.post("/scan", data={"url": "https://example.com/<script>alert(1)</script>"})
    with app.app_context():
        scan_id = ScanHistory.query.one().id
    body = client.get(f"/scan/{scan_id}/report").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_a_script_tag_in_a_username_is_rejected(client, app):
    response = client.post("/register", json={
        "username": "<script>alert(1)</script>",
        "email": "xss@example.com",
        "password": STRONG_PASSWORD,
        "confirm_password": STRONG_PASSWORD,
    })
    assert response.status_code == 400
    with app.app_context():
        assert User.query.filter_by(email="xss@example.com").first() is None


def test_internal_errors_are_generic_in_both_formats(raising_app):
    with raising_app.test_client() as client:
        html = client.get("/boom-for-tests")
        assert html.status_code == 500
        assert "INTERNAL_ERROR" in html.get_data(as_text=True)
        assert "deliberate failure" not in html.get_data(as_text=True)

        as_json = client.get("/boom-for-tests?format=json")
        assert as_json.status_code == 500
        assert as_json.get_json()["error"]["code"] == "INTERNAL_ERROR"
        assert "deliberate failure" not in as_json.get_data(as_text=True)


def test_no_response_contains_the_secret_key_or_a_database_path(client, app):
    secret = app.config["SECRET_KEY"]
    for path in ("/", "/health", "/auth/session", "/api/v1/health", "/api/v1/model/info"):
        body = client.get(path).get_data(as_text=True)
        assert secret not in body, path
        assert "sqlite:///" not in body, path
        assert "phishing.db" not in body, path


def test_no_route_performs_an_open_redirect():
    """`next=`/`redirect()` patterns are a classic phishing enabler."""
    offenders = []
    for path in (ROOT / "routes").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "redirect(" in text and "url_for" not in text:
            offenders.append(path.name)
    assert offenders == []


def test_an_oversized_request_body_is_refused(client):
    response = client.post(
        "/api/v1/scan",
        data=json.dumps({"url": "https://example.com/" + "a" * 200000}),
        content_type="application/json",
    )
    assert response.status_code == 413
    assert _error_code(response) == "PAYLOAD_TOO_LARGE"


# --------------------------------------------------------------------------- #
# 6. SSRF: proved by making the socket layer unusable
# --------------------------------------------------------------------------- #
def test_a_scan_succeeds_even_when_the_network_layer_is_broken(client, monkeypatch):
    """If the app opened a connection, this test would fail. It does not."""

    def _no_network(*_args, **_kwargs):
        raise AssertionError("the detection path must never open a connection")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(socket, "gethostbyname", _no_network)

    response = client.post("/api/v1/scan", json={"url": "https://example.com/"})
    assert response.status_code == 200
    assert response.get_json()["scan"]["persisted"] is True


@pytest.mark.parametrize(
    "ssrf_target",
    [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/internal",
        "http://[::1]:8080/",
        "http://localhost/",
    ],
)
def test_internal_targets_are_analysed_as_strings_never_fetched(
    client, monkeypatch, ssrf_target, scan_count
):
    """Loopback/metadata addresses are ordinary strings to a lexical model."""
    calls: list[object] = []

    def _record(*args, **_kwargs):
        calls.append(args)
        raise AssertionError("no connection may be attempted")

    monkeypatch.setattr(socket, "socket", _record)
    monkeypatch.setattr(socket, "create_connection", _record)
    monkeypatch.setattr(socket, "getaddrinfo", _record)

    response = client.post("/api/v1/scan", json={"url": ssrf_target})
    assert response.status_code == 200, response.get_data(as_text=True)[:300]
    assert calls == []
    assert scan_count() == 1
    monkeypatch.undo()


def test_no_network_library_is_imported_by_the_application():
    """Static confirmation of the behavioural tests above."""
    offenders = []
    for path in list((ROOT / "services").glob("*.py")) + \
            list((ROOT / "models").glob("*.py")) + \
            list((ROOT / "routes").glob("*.py")) + \
            [ROOT / "app.py"]:
        text = path.read_text(encoding="utf-8").lower()
        for forbidden in ("import requests", "import httpx", "import socket",
                          "urllib.request", "urlopen(", "http.client"):
            if forbidden in text:
                offenders.append(f"{path.name}:{forbidden}")
    assert offenders == [], offenders


def test_the_scan_path_never_imports_a_network_client():
    """The four modules that compute a verdict import no network client.

    Imports are read with ``ast`` so that docstring prose mentioning "socket"
    cannot produce a false positive.
    """
    import ast

    forbidden_roots = {"socket", "requests", "httpx", "urllib3", "aiohttp",
                       "ftplib", "telnetlib", "smtplib", "paramiko"}
    for relative in ("ml/feature_extraction.py", "models/prediction_model.py",
                     "services/detection_service.py", "services/validation.py"):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
                if node.module.startswith("urllib"):
                    imported.add(node.module)
        assert not (imported & forbidden_roots), (relative, imported & forbidden_roots)
        assert "urllib.request" not in imported, relative
