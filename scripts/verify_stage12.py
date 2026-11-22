#!/usr/bin/env python3
"""Stage 12 exit gate: REST API, per-route rate limits and security hardening.

Run from the project root (Windows or Linux):

    python scripts\\verify_stage12.py       (Windows)
    ./scripts/verify_stage12.py            (Linux/macOS)
    ./.venv/bin/python scripts/verify_stage12.py

This is an EXECUTABLE acceptance test. It builds isolated Flask applications
against temporary SQLite databases and verifies, with real HTTP requests:

  * config-driven per-route rate limits, 429 RATE_LIMITED JSON/HTML shapes,
    Retry-After, POST-only auth limits, no blanket throttle, and no throttling
    under TestingConfig;
  * the versioned /api/v1 JSON contract (token, health, model card, scan,
    scoped list, single row), all documented fields, three decision states,
    exactly one audit row per scan and NO re-inference on reads;
  * CSRF enforcement, generic errors, session-fixation defence, role-escalation
    resistance, scrypt hashes, XSS escaping, no URL enumeration;
  * the byte-for-byte unchanged CSP, unchanged offline vendor hashes, new
    hardening headers, no-store on sensitive paths, and socket-patched SSRF
    probes;
  * explicit 503 MODEL_UNAVAILABLE / 503 DATABASE_UNAVAILABLE paths;
  * Gates 1-11 still pass and pip check is clean.

All test URLs are reserved / synthetic strings. No live site, no malicious URL
and no external network service is ever contacted.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Set by a parent gate (Stage 13+) to avoid exponentially nested historical
# regressions. A standalone run keeps its complete behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"

with contextlib.redirect_stderr(io.StringIO()):
    from config import TestingConfig, describe_config  # noqa: E402
    from app import create_app  # noqa: E402
    from extensions import db, limiter  # noqa: E402
    from flask import g, has_app_context  # noqa: E402
    from sqlalchemy import func  # noqa: E402
    from models.database_models import ScanHistory, User  # noqa: E402
    from routes import BLUEPRINTS  # noqa: E402
    from services.auth_service import create_user  # noqa: E402
    from services.database_service import initialise_schema  # noqa: E402

CHECKS = 0
SKIPPED = 0
FAILURES: list[str] = []


def check(label: str, condition: Any, detail: str = "") -> None:
    """Record one binary assertion."""
    global CHECKS
    CHECKS += 1
    ok = bool(condition)
    if not ok:
        FAILURES.append(f"{label} :: {detail}" if detail else label)
        print(f"  FAIL  {label}" + (f" :: {detail}" if detail else ""))


def skip(label: str, reason: str) -> None:
    global SKIPPED
    SKIPPED += 1
    print(f"  SKIP  {label} ({reason})")


def read(rel: str) -> str:
    path = ROOT / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def sha256(rel: str) -> str:
    return hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# Constants and controlled fixtures
# --------------------------------------------------------------------------- #
REQUIRED_FILES = (
    "routes/api.py", "docs/SECURITY.md", "scripts/verify_stage12.py",
)

# Stage 13 replaced this gate's "no tests yet" rule with the real suite. The
# names below are therefore split: STAGE_13_FILES must now EXIST, while the
# Stage 14 artefacts stay forbidden. Stage 13's own gate is `pytest`, so
# scripts/verify_stage13.py is intentionally never created.
STAGE_13_FILES = frozenset({
    "tests/conftest.py", "tests/test_features.py", "tests/test_model.py",
    "tests/test_routes.py", "tests/test_api.py", "tests/test_security.py",
    "docs/TEST_PLAN.md",
})
STAGE_13_DELIVERED = all((ROOT / rel).is_file() for rel in STAGE_13_FILES)
# Stage 14 delivers the academic report and the deployment guide, so those two
# names are subtracted from this gate's forbidden list. scripts/verify_stage13.py
# stays forbidden forever: Stage 13's gate is `pytest`, not a bespoke script.
STAGE_14_FILES = frozenset({"docs/REPORT.md", "docs/DEPLOYMENT.md"})
STAGE_14_DELIVERED = all((ROOT / rel).is_file() for rel in STAGE_14_FILES)
FORBIDDEN_AFTER_13 = tuple(
    rel for rel in ("scripts/verify_stage13.py", "docs/DEPLOYMENT.md",
                    "docs/REPORT.md")
    if rel not in STAGE_14_FILES
)

VENDOR_HASHES = {
    "static/vendor/bootstrap.min.css": "3c8f27e6009ccfd710a905e6dcf12d0ee3c6f2ac7da05b0572d3e0d12e736fc8",
    "static/vendor/bootstrap.bundle.min.js": "0833b2e9c3a26c258476c46266e6877fc75218625162e0460be9a3a098a61c6c",
    "static/vendor/chart.umd.min.js": "b38076762f7363bc9e912b68b8e034826798db5df26bb61f000ec2e7a3137bc7",
}

EXACT_CSP = (
    "default-src 'self'; base-uri 'self'; object-src 'none'; "
    "form-action 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'"
)

RUNTIME_RELS = (
    "app.py", "config.py", "extensions.py", "wsgi.py",
    "routes/__init__.py", "routes/core.py", "routes/auth.py",
    "routes/scanning.py", "routes/dashboard.py", "routes/history.py",
    "routes/admin.py", "routes/api.py",
    "services/__init__.py", "services/validation.py", "services/model_metadata.py",
    "services/http_security.py", "services/auth_service.py",
    "services/database_service.py", "services/detection_service.py",
    "services/decision_service.py", "services/explanation_service.py",
    "services/stats_service.py", "services/report_service.py",
    "models/__init__.py", "models/database_models.py",
    "models/prediction_model.py",
    "ml/__init__.py", "ml/url_utils.py", "ml/preprocess.py",
    "ml/feature_extraction.py", "ml/thresholds.py",
)

NETWORK_MARKERS = (
    "import requests", "import httpx", "import aiohttp", "from pycurl",
    "import socket", "urllib.request", "urlopen(", "http.client",
    "socket.create_connection", "requests.get(", "requests.post(",
)

ALL_TEMPLATES = (
    "templates/base.html", "templates/index.html", "templates/login.html",
    "templates/register.html", "templates/auth_result.html",
    "templates/errors/error.html", "templates/scan.html",
    "templates/scan_report.html", "templates/partials/scan_result.html",
    "templates/dashboard.html", "templates/history.html",
    "templates/admin.html",
)

SECURITY_SECTIONS = (
    "## 1. What Stage 12 builds", "## 2. Threat model and trust boundaries",
    "## 3. Per-route rate limiting", "## 4. REST API contract",
    "## 5. CSRF, sessions and password hashing",
    "## 6. Headers, CSP, XSS and SSRF",
    "## 7. Error contract and information disclosure",
    "## 8. What is deliberately NOT in Stage 12", "## 9. Run and test",
    "## 10. Common errors and fixes", "## 11. Stage 12 exit criteria",
)

METRIC_WORDS = (
    "accuracy", "precision", "recall", "f1", "roc_auc", "roc-auc",
    "confusion_matrix", "confusion matrix", "false_negatives",
)
PUBLISHED_LITERALS = ("0.983854", "0.993307", "0.967803", "0.980389", "0.998055")

API_CONTRACT_FIELDS = (
    "scan_id", "submitted_url", "normalized_url", "prediction",
    "model_score", "score_meaning", "risk_level", "decision_band",
    "flagged_features", "recommended_action", "caveats", "scanned_at",
    "model", "report_url", "persisted",
)

CONTROLLED_CASES = (
    ("https://example.com", "LEGITIMATE", "LOW"),
    ("https://example.com/", "SUSPICIOUS", "MEDIUM"),
    ("https://www.example.org/about", "PHISHING", "HIGH"),
)
SSRF_STRINGS = (
    "http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.1/internal", "https://paypal.com.login.verify.example.invalid/secure",
)

STRONG_PASSWORD = "Str0ng!Passphrase2026"
ADMIN_USER = "admin12"
MEMBER_USER = "member12"

METRICS = json.loads(read("ml/saved_model/metrics.json"))
METADATA = json.loads(read("ml/saved_model/metadata.json"))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def build_app(**overrides: Any):
    """Create a TestingConfig app with a safe fixed secret."""
    settings: dict[str, Any] = {"SECRET_KEY": "s" * 64}
    settings.update(overrides)
    return create_app(TestingConfig, overrides=settings)


def temp_db(folder: str, name: str = "s12.db") -> str:
    return f"sqlite:///{Path(folder) / name}"


def seed(app) -> None:
    with app.app_context():
        initialise_schema(app)
        create_user(ADMIN_USER, "admin12@example.com", STRONG_PASSWORD, role="admin")
        create_user(MEMBER_USER, "member12@example.com", STRONG_PASSWORD)


def fresh_client(app):
    """A new browser; clears Flask-Login's g-cached user in a shared context."""
    if has_app_context():
        g.pop("_login_user", None)
    return app.test_client()


def login(client, username: str, password: str = STRONG_PASSWORD):
    """CSRF-free login helper for apps that leave WTF_CSRF_ENABLED=False."""
    return client.post("/login", json={"username": username, "password": password})


def login_csrf(client, username: str, token: str,
               password: str = STRONG_PASSWORD):
    """Login for apps with CSRF enabled (the token comes from /auth/csrf-token)."""
    return client.post("/login", json={"username": username, "password": password},
                       headers={"X-CSRF-Token": token})


def token_for(client) -> str:
    response = client.get("/api/v1/csrf-token")
    return str(response.get_json().get("csrf_token", ""))


def api_scan(client, url: str, token: str | None = None):
    headers = {"X-CSRF-Token": token} if token else {}
    return client.post("/api/v1/scan", json={"url": url}, headers=headers)


def inline_scripts(text: str) -> list[str]:
    return [m.strip() for m in re.findall(
        r"<script\b[^>]*>(.*?)</script>", text, re.DOTALL | re.IGNORECASE
    ) if m.strip()]


def external_assets(text: str) -> list[str]:
    return re.findall(
        r"(?:src|href)\s*=\s*[\"'](?:https?:)?//[^\"']+", text, re.IGNORECASE
    )


def metric_free(value: str) -> bool:
    lowered = value.lower()
    return not any(word in lowered for word in METRIC_WORDS)


def error_code(response) -> str | None:
    payload = response.get_json(silent=True)
    if isinstance(payload, dict):
        return (payload.get("error") or {}).get("code")
    return None


# --------------------------------------------------------------------------- #
# 1. Inventory, stage discipline and compilation
# --------------------------------------------------------------------------- #
def check_inventory() -> None:
    print("\n[1] Stage 12 file inventory, stage discipline and compilation")
    for rel in REQUIRED_FILES:
        check(f"required file exists :: {rel}", (ROOT / rel).is_file())
    for rel in FORBIDDEN_AFTER_13:
        check(f"never-created artefact absent :: {rel}", not (ROOT / rel).exists())
    if STAGE_13_DELIVERED:
        for rel in sorted(STAGE_13_FILES):
            check(f"Stage 13 delivered file exists :: {rel}", (ROOT / rel).is_file())
    else:
        for rel in sorted(STAGE_13_FILES):
            check(f"Stage 13 file absent :: {rel}", not (ROOT / rel).exists())

    expected = {
        "routes": {"__init__.py", "core.py", "auth.py", "scanning.py",
                   "dashboard.py", "history.py", "admin.py", "api.py"},
        "services": {"__init__.py", "validation.py", "model_metadata.py",
                     "http_security.py", "auth_service.py", "database_service.py",
                     "detection_service.py", "decision_service.py",
                     "explanation_service.py", "stats_service.py",
                     "report_service.py"},
        "models": {"__init__.py", "database_models.py", "prediction_model.py"},
    }
    for directory, names in expected.items():
        actual = {p.name for p in (ROOT / directory).glob("*.py")}
        check(f"{directory}/ contains exactly the delivered modules",
              actual == names, f"extra={sorted(actual - names)} missing={sorted(names - actual)}")

    html = {str(p.relative_to(ROOT)).replace("\\", "/")
            for p in (ROOT / "templates").rglob("*.html")}
    check("templates/ contains exactly the twelve delivered pages",
          html == set(ALL_TEMPLATES), ", ".join(sorted(html)))
    check("no new JS file was introduced",
          {p.name for p in (ROOT / "static" / "js").glob("*.js")}
          == {"theme.js", "main.js"})
    check("no new CSS file was introduced",
          {p.name for p in (ROOT / "static" / "css").glob("*.css")}
          == {"backend.css", "main.css"})

    blueprints = {bp.name for bp in BLUEPRINTS}
    check("exactly seven blueprints are registered",
          blueprints == {"core", "auth", "scanning", "dashboard", "history",
                         "admin", "api"}, ", ".join(sorted(blueprints)))

    py_files = sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")
                      if ".venv" not in p.parts and "__pycache__" not in p.parts)
    for rel in py_files:
        try:
            py_compile.compile(str(ROOT / rel), doraise=True)
            check(f"compiles :: {rel}", True)
        except py_compile.PyCompileError as exc:
            check(f"compiles :: {rel}", False, str(exc))


# --------------------------------------------------------------------------- #
# 2. Source-level discipline
# --------------------------------------------------------------------------- #
def check_sources() -> None:
    print("\n[2] Source discipline, exact CSP, headers and offline assets")
    for rel in ALL_TEMPLATES:
        text = read(rel)
        check(f"{rel} has no inline script", not inline_scripts(text))
        check(f"{rel} has no inline style attribute",
              re.search(r"\sstyle\s*=", text, re.IGNORECASE) is None)
        check(f"{rel} loads no external asset", not external_assets(text))
        check(f"{rel} has no inline event handler",
              re.search(r"\son(click|load|error|mouseover)\s*=", text, re.IGNORECASE) is None)

    for rel, expected in VENDOR_HASHES.items():
        check(f"vendored asset unchanged :: {rel}", sha256(rel) == expected)

    security = read("services/http_security.py")
    check("CSP directive list is unchanged",
          all(line in security for line in (
              "\"default-src 'self'\"", "\"base-uri 'self'\"",
              "\"object-src 'none'\"", "\"form-action 'self'\"",
              "\"script-src 'self'\"", "\"style-src 'self'\"",
              "\"img-src 'self' data:\"", "\"font-src 'self'\"",
              "\"connect-src 'self'\"")))
    check("CSP was not relaxed", "unsafe-inline" not in security
          and "cdn" not in security.lower())
    for header in ("Cross-Origin-Opener-Policy",
                   "X-Permitted-Cross-Domain-Policies", "Origin-Agent-Cluster"):
        check(f"Stage 12 hardening header in source :: {header}", header in security)
    check("429 handler preserves the generic contract and Retry-After",
          "@app.errorhandler(429)" in security and "Retry-After" in security
          and "RATE_LIMITED" in security)
    check("no-store covers the sensitive route prefixes",
          all(prefix in security for prefix in
              ('"/api/"', '"/auth/"', '"/scan"', '"/history"',
               '"/admin"', '"/dashboard"')))
    check("429 error page explains the limit without diagnostics",
          "status_code == 429" in read("templates/errors/error.html")
          and "Retry-After" in read("templates/errors/error.html"))

    all_python = "\n".join(read(rel) for rel in RUNTIME_RELS)
    for rel in RUNTIME_RELS:
        check(f"runtime module is present :: {rel}", bool(read(rel)))
    for marker in NETWORK_MARKERS:
        check(f"runtime source contains no '{marker}'", marker not in all_python)

    extensions = read("extensions.py")
    check("limiter still has no blanket default throttle",
          "default_limits=[]" in extensions)
    check("limits_disabled reads the effective config",
          "def limits_disabled" in extensions
          and "current_app.config.get(\"RATELIMIT_ENABLED\"" in extensions)

    auth = read("routes/auth.py")
    scanning = read("routes/scanning.py")
    api = read("routes/api.py")
    check("auth POST routes carry config-driven limits",
          auth.count("@limiter.limit") == 2
          and "RATE_LIMIT_AUTH" in auth and 'methods=["POST"]' in auth)
    check("scan POST route carries a config-driven limit",
          "@limiter.limit" in scanning and "RATE_LIMIT_SCAN" in scanning)
    check("API routes carry config-driven limits",
          api.count("@limiter.limit") >= 5 and "RATE_LIMIT_API" in api)
    check("every limit is a no-op when disabled",
          all("exempt_when=limits_disabled" in read(rel) for rel in
              ("routes/auth.py", "routes/scanning.py", "routes/api.py")))
    check("API scans add a per-account key", "key_func=_viewer_key" in api)

    check("API reuses the ONE detection pipeline",
          "get_detection_registry().scan(" in api
          and "predict_proba" not in api and "joblib.load" not in api)
    check("API never exempts CSRF", "csrf.exempt" not in api
          and "generate_csrf" in api)
    check("API introduces no bearer token or second auth scheme",
          "Bearer" not in api and "api_key" not in api.lower()
          and "Authorization" not in api)
    check("API contains no invented performance literal",
          all(literal not in api for literal in PUBLISHED_LITERALS))
    check("API performs no writes of its own",
          all(token not in api for token in
              ("db.session.add(", ".commit()", "db.session.delete(")))
    check("API documents the six versioned routes",
          all(route in api for route in (
              '"/csrf-token"', '"/health"', '"/model/info"',
              '"/scan"', '"/scans"', '"/scans/<int:scan_id>"')))
    check("API reuses Stage 10/11 authorisation",
          "can_view_scan" in api and "viewer_scope" in api
          and "stats_service.history_page" in api)
    check("config exposes all three rate-limit keys",
          all(key in read("config.py") for key in
              ("RATE_LIMIT_SCAN", "RATE_LIMIT_AUTH", "RATE_LIMIT_API",
               "RATELIMIT_ENABLED", "RATELIMIT_HEADERS_ENABLED")))
    check(".env.example documents all three rate-limit keys",
          all(key in read(".env.example") for key in
              ("RATE_LIMIT_SCAN", "RATE_LIMIT_AUTH", "RATE_LIMIT_API")))
    check("routes/__init__.py registers the API blueprint",
          "api_bp" in read("routes/__init__.py"))


# --------------------------------------------------------------------------- #
# 3. Rate limiting behaviour
# --------------------------------------------------------------------------- #
def check_rate_limits() -> None:
    print("\n[3] Config-driven per-route rate limiting and 429 contract")
    with tempfile.TemporaryDirectory() as folder:
        app = build_app(
            SQLALCHEMY_DATABASE_URI=temp_db(folder),
            RATELIMIT_ENABLED=True, WTF_CSRF_ENABLED=True,
            RATE_LIMIT_AUTH="2 per minute", RATE_LIMIT_SCAN="3 per minute",
            RATE_LIMIT_API="2 per minute",
        )
        seed(app)
        check("limiter is enabled by the effective config", limiter.enabled is True)
        client = fresh_client(app)
        token = token_for(client)

        def post_login():
            return client.post("/login", json={"username": "x", "password": "y"},
                               headers={"X-CSRF-Token": token})

        statuses = [post_login().status_code for _ in range(3)]
        check("POST /login is throttled after its quota", statuses == [401, 401, 429],
              str(statuses))
        throttled = post_login()
        check("429 JSON error code is RATE_LIMITED",
              throttled.status_code == 429
              and error_code(throttled) == "RATE_LIMITED")
        check("429 response carries Retry-After",
              throttled.headers.get("Retry-After", "").isdigit())
        check("429 response is not cached",
              throttled.headers.get("Cache-Control") == "no-store")
        check("429 JSON never leaks a traceback",
              "Traceback" not in throttled.get_data(as_text=True)
              and "/home/user" not in throttled.get_data(as_text=True))
        check("GET /login is NOT throttled (methods=POST only)",
              client.get("/login").status_code == 200)

        form_429 = client.post("/login", data={
            "username": "x", "password": "y", "csrf_token": token})
        check("HTML-form 429 returns the themed error page",
              form_429.status_code == 429
              and b"RATE_LIMITED" in form_429.data
              and b"Retry-After" in form_429.data)

        reg = [client.post("/register", json={
            "username": f"user{i}", "email": f"user{i}@example.com",
            "password": STRONG_PASSWORD, "confirm_password": STRONG_PASSWORD,
        }, headers={"X-CSRF-Token": token}).status_code for i in range(3)]
        check("POST /register has its own quota", reg[-1] == 429, str(reg))

        scan_client = fresh_client(app)
        scan_token = token_for(scan_client)
        scan_statuses = [scan_client.post(
            "/scan", data={"url": "https://example.com", "csrf_token": scan_token}
        ).status_code for _ in range(4)]
        check("POST /scan is throttled by RATE_LIMIT_SCAN",
              scan_statuses == [200, 200, 200, 429], str(scan_statuses))

        api_client = fresh_client(app)
        api_token = token_for(api_client)
        api_statuses = [api_scan(api_client, "https://example.com", api_token).status_code
                        for _ in range(3)]
        check("POST /api/v1/scan is throttled by RATE_LIMIT_API",
              api_statuses == [200, 200, 429], str(api_statuses))
        api_429 = api_scan(api_client, "https://example.com", api_token)
        check("API 429 has the documented JSON error shape",
              api_429.status_code == 429 and error_code(api_429) == "RATE_LIMITED"
              and api_429.get_json()["error"]["status"] == 429)

        # Health and CSRF setup must stay reachable even after a breach.
        check("GET /api/v1/health is never throttled",
              client.get("/api/v1/health").status_code == 200)
        check("GET /api/v1/csrf-token is never throttled",
              client.get("/api/v1/csrf-token").status_code == 200)

    with tempfile.TemporaryDirectory() as folder:
        plain = build_app(SQLALCHEMY_DATABASE_URI=temp_db(folder))
        seed(plain)
        check("TestingConfig keeps limiter disabled", limiter.enabled is False)
        plain_client = fresh_client(plain)
        statuses = [plain_client.post(
            "/login", json={"username": "x", "password": "y"}
        ).status_code for _ in range(6)]
        check("no throttling under TestingConfig", all(s == 401 for s in statuses),
              str(statuses))
        check("API scans are unthrottled under TestingConfig",
              [api_scan(plain_client, "https://example.com").status_code
               for _ in range(4)] == [200, 200, 200, 200])


# --------------------------------------------------------------------------- #
# 4. REST API contract
# --------------------------------------------------------------------------- #
def check_api_contract() -> None:
    print("\n[4] Versioned REST API contract and audit persistence")
    with tempfile.TemporaryDirectory() as folder:
        app = build_app(SQLALCHEMY_DATABASE_URI=temp_db(folder),
                        WTF_CSRF_ENABLED=True)
        seed(app)
        client = fresh_client(app)
        rules = {str(rule) for rule in app.url_map.iter_rules()}
        for rule in ("/api/v1/csrf-token", "/api/v1/health",
                     "/api/v1/model/info", "/api/v1/scan", "/api/v1/scans",
                     "/api/v1/scans/<int:scan_id>"):
            check(f"url_map contains {rule}", rule in rules)

        # --- token and health -------------------------------------------- #
        token_response = client.get("/api/v1/csrf-token")
        check("GET /api/v1/csrf-token returns 200 JSON",
              token_response.status_code == 200
              and token_response.get_json()["header_name"] == "X-CSRF-Token")
        token = token_response.get_json()["csrf_token"]
        check("CSRF token is a non-trivial string",
              isinstance(token, str) and len(token) > 20)
        health = client.get("/api/v1/health")
        body = health.get_data(as_text=True)
        check("GET /api/v1/health returns 200 readiness JSON",
              health.status_code == 200 and health.get_json()["status"] == "ok")
        check("/api/v1/health reports build_stage 12 or later",
              health.get_json()["build_stage"] >= 12)
        check("/api/v1/health contains NO measured model figures",
              metric_free(body), body[:200])
        check("/api/v1/health is not cached",
              health.headers.get("Cache-Control") == "no-store")

        # --- CSRF and malformed input ------------------------------------ #
        blocked = api_scan(client, "https://example.com")
        check("API POST without CSRF returns 400 CSRF_FAILED JSON",
              blocked.status_code == 400 and error_code(blocked) == "CSRF_FAILED")
        not_json = client.post("/api/v1/scan", data={"url": "https://example.com"},
                               headers={"X-CSRF-Token": token})
        check("non-JSON API POST returns 400 BAD_REQUEST",
              not_json.status_code == 400 and error_code(not_json) == "BAD_REQUEST")
        malformed = client.post("/api/v1/scan", data="{not json",
                                content_type="application/json",
                                headers={"X-CSRF-Token": token})
        check("malformed JSON returns 400 BAD_REQUEST",
              malformed.status_code == 400 and error_code(malformed) == "BAD_REQUEST")
        missing = client.post("/api/v1/scan", json={"hello": "world"},
                              headers={"X-CSRF-Token": token})
        check("missing url field returns 400 BAD_REQUEST",
              missing.status_code == 400 and error_code(missing) == "BAD_REQUEST")
        wrong_type = client.post("/api/v1/scan", json={"url": 123},
                                 headers={"X-CSRF-Token": token})
        check("non-string url returns 400 INVALID_URL",
              wrong_type.status_code == 400 and error_code(wrong_type) == "INVALID_URL")
        bad_url = api_scan(client, "javascript:alert(1)", token)
        check("unsupported URL scheme returns 400 INVALID_URL",
              bad_url.status_code == 400 and error_code(bad_url) == "INVALID_URL")
        check("all API errors use the JSON shape",
              all(isinstance(r.get_json(silent=True), dict)
                  and "error" in r.get_json() for r in
                  (blocked, not_json, malformed, missing, wrong_type, bad_url)))

        # --- successful scans -------------------------------------------- #
        responses = {}
        for url, expected_state, expected_risk in CONTROLLED_CASES:
            with app.app_context():
                before = db.session.query(func.count(ScanHistory.id)).scalar()
            response = api_scan(client, url, token)
            with app.app_context():
                after = db.session.query(func.count(ScanHistory.id)).scalar()
            responses[expected_state] = response
            check(f"POST /api/v1/scan {expected_state} returns 200",
                  response.status_code == 200)
            check(f"{expected_state} scan writes exactly one audit row",
                  after == before + 1, f"{before} -> {after}")
        for state, response in responses.items():
            payload = response.get_json()
            scan = payload.get("scan", {})
            check(f"{state} response has status ok", payload.get("status") == "ok")
            check(f"{state} response has every documented field",
                  all(field in scan for field in API_CONTRACT_FIELDS),
                  str(sorted(set(API_CONTRACT_FIELDS) - set(scan))))
            check(f"{state} prediction is correct",
                  scan.get("prediction") == state)
            check(f"{state} risk level is correct",
                  scan.get("risk_level") == dict(
                      (s, r) for _, s, r in CONTROLLED_CASES)[state])
            check(f"{state} model score is a bounded number",
                  isinstance(scan.get("model_score"), (int, float))
                  and 0.0 <= scan["model_score"] <= 1.0)
            check(f"{state} score meaning is not a guarantee",
                  "not a probability" in scan.get("score_meaning", "").lower()
                  or "not a guarantee" in scan.get("score_meaning", "").lower()
                  or "uncalibrated" in scan.get("score_meaning", "").lower())
            check(f"{state} timestamps are UTC",
                  str(scan.get("scanned_at", "")).endswith("+00:00"))
            check(f"{state} decision band names its measured source",
                  scan.get("decision_band", {}).get("source")
                  == "ml/saved_model/metadata.json#thresholds")
            check(f"{state} carries the exact HTTPS caveat",
                  any("HTTPS alone does not mean a website is legitimate" in c
                      for c in scan.get("caveats", [])))
            check(f"{state} model identity comes from the artefact",
                  scan.get("model", {}).get("name") == METADATA["model_name"])
            check(f"{state} result is marked persisted",
                  scan.get("persisted") is True)
            check(f"{state} report link is correct",
                  scan.get("report_url") == f"/scan/{scan.get('scan_id')}/report")

        # --- measured model card ----------------------------------------- #
        info = client.get("/api/v1/model/info")
        check("GET /api/v1/model/info returns 200",
              info.status_code == 200 and info.get_json()["status"] == "ok")
        payload = info.get_json()
        standard = METRICS["test"]["standard_0.5"]
        check("model card values equal metrics.json at runtime",
              [row["value"] for row in payload["measured"]["rows"]]
              == [f"{standard[key]:.6f}" for key in
                  ("accuracy", "precision", "recall", "f1", "roc_auc")])
        check("model card names the runtime source",
              payload["measured"]["source"]
              == "ml/saved_model/metrics.json#test.standard_0.5")
        check("model card publishes the three decision states",
              set(payload["decision_states"])
              == {"LEGITIMATE", "SUSPICIOUS", "PHISHING"})
        check("model card thresholds come from metadata.json",
              payload["decision_thresholds"]["low"] == METADATA["thresholds"]["low"]
              and payload["decision_thresholds"]["high"] == METADATA["thresholds"]["high"])
        check("model card lists all 15 features",
              payload["model"]["feature_count"] == 15
              and len(payload["model"]["feature_order"]) == 15)
        check("model card carries caveats",
              any("HTTPS" in c for c in payload["measured"]["caveats"]))
        check("model card never leaks a password hash",
              "password_hash" not in info.get_data(as_text=True))

        # --- scoped list and single row ----------------------------------- #
        listing = client.get("/api/v1/scans")
        listed = listing.get_json()
        check("GET /api/v1/scans returns 200 with three own scans",
              listing.status_code == 200 and listed["total"] == 3
              and len(listed["scans"]) == 3)
        check("list response names its runtime source",
              listed["source"] == "sqlite://instance/phishing.db#scan_history")
        check("list response declares the guest-session scope",
              listed["scope"] == "session")
        first_id = listed["scans"][0]["id"]
        detail = client.get(f"/api/v1/scans/{first_id}")
        check("GET /api/v1/scans/<id> returns 200 for an own scan",
              detail.status_code == 200
              and detail.get_json()["scan"]["scan_id"] == first_id)
        check("single-row response uses the documented contract",
              all(field in detail.get_json()["scan"] for field in API_CONTRACT_FIELDS))
        with app.app_context():
            before = db.session.query(func.count(ScanHistory.id)).scalar()
        client.get(f"/api/v1/scans/{first_id}")
        with app.app_context():
            after = db.session.query(func.count(ScanHistory.id)).scalar()
        check("reading a scan performs NO re-inference or write", before == after)
        filtered = client.get("/api/v1/scans?prediction=PHISHING&risk=HIGH").get_json()
        check("list filters match the database",
              filtered["total"] == 1
              and filtered["scans"][0]["prediction"] == "PHISHING")
        paged = client.get("/api/v1/scans?per_page=2&page=2").get_json()
        check("list pagination is honest",
              paged["total"] == 3 and paged["pages"] == 2
              and len(paged["scans"]) == 1)
        check("invalid filter values are clamped, not interpolated",
              client.get("/api/v1/scans?prediction=DROP%20TABLE&page=-5").status_code == 200)

        missing_row = client.get("/api/v1/scans/99999")
        check("missing id returns generic 404 NOT_FOUND",
              missing_row.status_code == 404
              and error_code(missing_row) == "NOT_FOUND")
        stranger = fresh_client(app)
        check("a different browser sees an empty list",
              stranger.get("/api/v1/scans").get_json()["total"] == 0)
        check("a different browser cannot read a guest row",
              stranger.get(f"/api/v1/scans/{first_id}").status_code == 404)
        check("missing and unauthorised ids share the same error shape",
              stranger.get(f"/api/v1/scans/{first_id}").get_json()
              == missing_row.get_json())

        # --- authenticated linkage ---------------------------------------- #
        member = fresh_client(app)
        pre_token = token_for(member)
        check("member login succeeds",
              login_csrf(member, MEMBER_USER, pre_token).status_code == 200)
        # login() clears the session, so the CSRF secret is regenerated.
        member_token = token_for(member)
        member_scan = api_scan(member, "https://member.example.invalid/one", member_token)
        check("authenticated API scan succeeds", member_scan.status_code == 200)
        member_id = member_scan.get_json()["scan"]["scan_id"]
        with app.app_context():
            row = db.session.get(ScanHistory, member_id)
            linked = row.user_id
            expected_user = db.session.query(User.id).filter(
                User.username == MEMBER_USER).scalar()
        check("authenticated scan is linked to its account",
              linked == expected_user, f"{linked} vs {expected_user}")
        check("member list shows only their own scan",
              member.get("/api/v1/scans").get_json()["total"] == 1)
        check("member cannot read a guest scan",
              member.get(f"/api/v1/scans/{first_id}").status_code == 404)
        check("admin console remains role-restricted",
              member.get("/admin").status_code == 403)

        # --- explicit failure paths --------------------------------------- #
        no_schema = build_app(SQLALCHEMY_DATABASE_URI=temp_db(folder, "empty.db"),
                              WTF_CSRF_ENABLED=True)
        no_schema_client = fresh_client(no_schema)
        no_schema_token = token_for(no_schema_client)
        schema_error = api_scan(no_schema_client, "https://example.com", no_schema_token)
        check("missing schema yields 503 DATABASE_UNAVAILABLE",
              schema_error.status_code == 503
              and error_code(schema_error) == "DATABASE_UNAVAILABLE")

        broken_bundle = build_app(
            SQLALCHEMY_DATABASE_URI=temp_db(folder, "broken.db"),
            MODEL_BUNDLE_PATH=str(Path(folder) / "missing-bundle.joblib"),
            WTF_CSRF_ENABLED=True,
        )
        with broken_bundle.app_context():
            initialise_schema(broken_bundle)
        broken_client = fresh_client(broken_bundle)
        broken_token = token_for(broken_client)
        model_error = api_scan(broken_client, "https://example.com", broken_token)
        check("missing bundle yields 503 MODEL_UNAVAILABLE",
              model_error.status_code == 503
              and error_code(model_error) == "MODEL_UNAVAILABLE")

        no_metrics = build_app(
            SQLALCHEMY_DATABASE_URI=temp_db(folder),
            METRICS_PATH=str(Path(folder) / "missing-metrics.json"),
        )
        metrics_error = fresh_client(no_metrics).get("/api/v1/model/info")
        check("missing measured artefact yields 503 MODEL_UNAVAILABLE",
              metrics_error.status_code == 503
              and error_code(metrics_error) == "MODEL_UNAVAILABLE")


# --------------------------------------------------------------------------- #
# 5. Security regressions
# --------------------------------------------------------------------------- #
def check_security() -> None:
    print("\n[5] CSRF, sessions, hashing, XSS, CSP, SSRF and generic errors")
    with tempfile.TemporaryDirectory() as folder:
        app = build_app(SQLALCHEMY_DATABASE_URI=temp_db(folder),
                        WTF_CSRF_ENABLED=True)
        seed(app)
        client = fresh_client(app)

        # CSRF on the HTML form and the API, both inherited from Stage 8.
        csrf_app_form = client.get("/scan").get_data(as_text=True)
        form_token = re.search(r'name="csrf_token" value="([^"]+)"', csrf_app_form).group(1)
        check("POST /scan without CSRF is rejected",
              client.post("/scan", data={"url": "https://example.com"}).status_code == 400)
        check("POST /scan with CSRF succeeds",
              client.post("/scan", data={"url": "https://example.com",
                                         "csrf_token": form_token}).status_code == 200)

        # Generic auth failures and role-escalation resistance. CSRF is enabled
        # on this app, so every POST echoes the session token.
        auth_token = client.get("/auth/csrf-token").get_json()["csrf_token"]
        auth_headers = {"X-CSRF-Token": auth_token}
        unknown = client.post("/login", json={"username": "nobody", "password": "wrong"},
                              headers=auth_headers)
        wrong = client.post("/login", json={"username": MEMBER_USER, "password": "wrong"},
                            headers=auth_headers)
        check("unknown user and wrong password share one generic 401",
              unknown.status_code == 401 and wrong.status_code == 401
              and unknown.get_json() == wrong.get_json())
        escalation = client.post("/register", json={
            "username": "attacker12", "email": "attacker12@example.com",
            "password": STRONG_PASSWORD, "confirm_password": STRONG_PASSWORD,
            "role": "admin", "is_admin": True,
        }, headers=auth_headers)
        check("registration with an injected role still succeeds as a user",
              escalation.status_code == 201)
        with app.app_context():
            attacker = db.session.query(User).filter(
                User.username == "attacker12").one()
            role = attacker.role
            stored_hash = attacker.password_hash
            safe = attacker.to_dict()
        check("injected role is ignored", role == "user")
        check("password is stored as a scrypt hash, never plaintext",
              stored_hash.startswith("scrypt:")
              and STRONG_PASSWORD not in stored_hash)
        check("User.to_dict never contains a password hash",
              "password_hash" not in safe)

        # Session fixation: a pre-login value must not survive authentication.
        pre = fresh_client(app)
        with pre.session_transaction() as sess:
            sess["attacker_supplied"] = "fixed-value"
        check("pre-login value is present",
              pre.get("/auth/session").status_code == 200)
        pre_token = pre.get("/auth/csrf-token").get_json()["csrf_token"]
        check("login succeeds",
              login_csrf(pre, MEMBER_USER, pre_token).status_code == 200)
        with pre.session_transaction() as sess:
            check("session fixation value is cleared on login",
                  "attacker_supplied" not in sess)

        # XSS: a stored URL containing markup is escaped in HTML and inert in JSON.
        xss_client = fresh_client(app)
        xss_token = token_for(xss_client)
        xss_scan = api_scan(xss_client, "https://example.invalid/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", xss_token)
        check("encoded markup URL is accepted as a string",
              xss_scan.status_code == 200)
        history_html = xss_client.get("/history").get_data(as_text=True)
        check("history page has no executable inline script",
              "<script>alert(1)</script>" not in history_html)
        check("API JSON keeps URL text but adds no HTML",
              "<script>" not in xss_scan.get_data(as_text=True))

        # Exact CSP and hardening headers on every kind of response.
        for path in ("/", "/scan", "/dashboard", "/history", "/api/v1/health",
                     "/static/js/main.js"):
            response = client.get(path)
            check(f"exact CSP on {path}",
                  response.headers.get("Content-Security-Policy") == EXACT_CSP)
        page = client.get("/dashboard")
        for header, value in (("X-Content-Type-Options", "nosniff"),
                              ("Referrer-Policy", "no-referrer"),
                              ("Cross-Origin-Opener-Policy", "same-origin"),
                              ("X-Permitted-Cross-Domain-Policies", "none"),
                              ("Origin-Agent-Cluster", "?1")):
            check(f"hardening header {header}",
                  page.headers.get(header) == value, str(page.headers.get(header)))
        for path in ("/scan", "/history", "/admin", "/dashboard", "/api/v1/health"):
            check(f"no-store on sensitive path {path}",
                  client.get(path).headers.get("Cache-Control") == "no-store")
        check("development still omits framing headers for the preview",
              "X-Frame-Options" not in page.headers)
        check("development still omits HSTS",
              "Strict-Transport-Security" not in page.headers)

        # Generic errors: no traceback, no absolute path.
        not_found = client.get("/api/v1/no-such-endpoint")
        check("API 404 is generic JSON",
              not_found.status_code == 404 and error_code(not_found) == "NOT_FOUND")
        check("no error leaks a traceback or absolute path",
              "Traceback" not in not_found.get_data(as_text=True)
              and "/home/user" not in not_found.get_data(as_text=True))
        check("anonymous /admin keeps 401 UNAUTHENTICATED",
              client.get("/admin").status_code == 401
              and b"UNAUTHENTICATED" in client.get("/admin").data)

        # SSRF: patch the socket so ANY outbound connection would fail loudly.
        def _refuse(*args, **kwargs):
            raise AssertionError("outbound network connection attempted")

        with mock.patch("socket.socket.connect", side_effect=_refuse):
            ssrf_client = fresh_client(app)
            ssrf_token = token_for(ssrf_client)
            results = [api_scan(ssrf_client, url, ssrf_token).status_code
                       for url in SSRF_STRINGS]
        check("loopback/link-local/reserved URL strings scan with NO network",
              results == [200] * len(SSRF_STRINGS), str(results))


# --------------------------------------------------------------------------- #
# 6. A real local HTTP server
# --------------------------------------------------------------------------- #
def check_live_server() -> None:
    print("\n[6] Real local HTTP smoke of the versioned API")
    from werkzeug.serving import make_server

    with tempfile.TemporaryDirectory() as folder:
        app = build_app(SQLALCHEMY_DATABASE_URI=temp_db(folder))
        seed(app)
        server = make_server("127.0.0.1", 0, app, threaded=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base = f"http://127.0.0.1:{int(server.server_port)}"
            for path in ("/api/v1/health", "/api/v1/csrf-token",
                         "/api/v1/model/info", "/api/v1/scans"):
                try:
                    with urllib.request.urlopen(base + path, timeout=15) as reply:
                        payload = reply.read()
                        check(f"live GET {path} returns 200 JSON",
                              reply.status == 200 and len(payload) > 20)
                        if path == "/api/v1/health":
                            check("live API health keeps the exact CSP",
                                  reply.headers.get("Content-Security-Policy") == EXACT_CSP)
                except urllib.error.HTTPError as exc:
                    check(f"live GET {path} returns 200 JSON", False, str(exc))
        finally:
            server.shutdown()
            worker.join(timeout=10)


# --------------------------------------------------------------------------- #
# 7. Configuration and documentation
# --------------------------------------------------------------------------- #
def check_config_and_docs() -> None:
    print("\n[7] Configuration and Stage 12 documentation")
    summary = describe_config()
    # Stage-aware: Stage 12 delivered 0.12.0/12; later stages bump the number,
    # so this gate asserts the floor rather than an exact value.
    check("config reports Stage 12 or later", (summary.get("build_stage") or 0) >= 12)
    check("config version is 0.12.0 or later",
          re.fullmatch(r"0\.(?:1[2-9]|[2-9]\d)\.\d+", str(summary.get("app_version"))) is not None,
          str(summary.get("app_version")))
    app = build_app()
    check("app.config BUILD_STAGE is 12 or later", app.config["BUILD_STAGE"] >= 12)
    for name in ("core", "auth", "scanning", "dashboard", "history", "admin", "api"):
        check(f"{name} blueprint is registered", name in app.blueprints)

    doc = read("docs/SECURITY.md")
    for section in SECURITY_SECTIONS:
        check(f"SECURITY.md :: {section}", section in doc)
    for marker in ("HTTPS alone does not mean a website is legitimate",
                   "SSRF", "429 RATE_LIMITED", "Retry-After", "scrypt",
                   "CSRF_FAILED", "no invented", "Stage 13",
                   "MODEL_UNAVAILABLE", "DATABASE_UNAVAILABLE",
                   "RATE_LIMIT_SCAN", "RATE_LIMIT_AUTH", "RATE_LIMIT_API",
                   "verify_stage12.py"):
        check(f"SECURITY.md documents :: {marker}",
              marker.lower() in doc.lower())
    check("SECURITY.md gives Windows-first commands",
          ".\\.venv\\Scripts\\Activate.ps1" in doc
          or "python scripts\\verify_stage12.py" in doc)

    readme = read("README.md")
    check("README marks Stage 12 complete",
          re.search(r"\|\s*12\s*\|.*✅", readme) is not None)
    check("README lists docs/SECURITY.md", "docs/SECURITY.md" in readme)
    check("README lists the Stage 12 gate", "scripts/verify_stage12.py" in readme)
    plan = read("docs/STAGE_PLAN.md")
    check("STAGE_PLAN records Stage 12 as delivered", "Stage 12 — delivered" in plan)
    check("STAGE_PLAN previews Stage 13", "Stage 13" in plan)
    decisions = read("docs/DECISIONS.md")
    for adr in ("ADR-036", "ADR-037", "ADR-038"):
        check(f"DECISIONS.md contains {adr}", adr in decisions)
    for rel, marker in (
        ("docs/ARCHITECTURE.md", "Stage 12 implementation note"),
        ("docs/BACKEND.md", "Stage 12 update"),
        ("docs/UI.md", "Stage 12 update"),
        ("docs/SETUP.md", "Stage 12"),
        ("docs/DETECTION.md", "Stage 12"),
        ("docs/DASHBOARD.md", "Stage 12"),
        ("docs/DATABASE.md", "Stage 12"),
    ):
        check(f"{rel} has its Stage 12 note", marker in read(rel))
    check("UI.md keeps the Stage 9 no-scan honesty rule for Gate 9",
          "no scan" in read("docs/UI.md").lower()
          or "not wired" in read("docs/UI.md").lower())


# --------------------------------------------------------------------------- #
# 8. Historical regressions and dependency health
# --------------------------------------------------------------------------- #
def check_regressions() -> None:
    print("\n[8] Historical exit gates 1-11 and dependency health")
    env = os.environ.copy()
    env["PDS_GATE_NESTED"] = "1"
    for stage in range(1, 12):
        script = f"verify_stage{stage}.py"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script)],
            cwd=str(ROOT), capture_output=True, text=True, timeout=900, env=env,
        )
        check(f"Gate {stage} still passes",
              completed.returncode == 0 and "RESULT: PASS" in completed.stdout,
              f"exit={completed.returncode} tail={completed.stdout[-400:]}")
    pip = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
    )
    check("pip check reports no broken requirements",
          pip.returncode == 0 and "No broken requirements" in pip.stdout,
          pip.stdout.strip()[:200])


def main() -> int:
    print("=" * 78)
    print("STAGE 12 EXIT GATE - REST API, rate limits and security hardening")
    print("=" * 78)
    check_inventory()
    check_sources()
    check_rate_limits()
    check_api_contract()
    check_security()
    check_live_server()
    check_config_and_docs()
    check_regressions()
    print("\n" + "=" * 78)
    print(f"CHECKS: {CHECKS}  SKIPPED: {SKIPPED}  FAILURES: {len(FAILURES)}")
    if FAILURES:
        for item in FAILURES:
            print(f"  - {item}")
        print("RESULT: FAIL - Stage 12 is NOT complete")
        return 1
    print("RESULT: PASS - all Stage 12 checks passed")
    print("Stage 12 exit gate satisfied. You may proceed to Stage 13.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
