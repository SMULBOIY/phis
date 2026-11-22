#!/usr/bin/env python3
"""Stage 7 exit gate: Flask application factory, wiring, routes and security.

    cd phishing-detection-system
    python scripts/verify_stage7.py

This gate does not trust the documentation or the source text alone. It BUILDS
several isolated applications (development, testing, production, missing model,
tampered metadata, tampered bundle) and exercises them through Flask's test
client and a real local HTTP server. It also re-runs Gates 1-6 as regressions.

All test data is local and synthetic. No live or malicious URL is contacted.
"""
from __future__ import annotations

import contextlib
import io
import json
import logging
import re
import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# Set by a parent gate (e.g. verify_stage10.py) to avoid running
# the same historical gate exponentially many times. A standalone
# run has this unset and keeps its complete regression behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# config.py prints an ephemeral-key notice when SECRET_KEY is unset in dev.
# Keep the gate's own output readable.
with contextlib.redirect_stderr(io.StringIO()):
    from config import (  # noqa: E402
        DevelopmentConfig, ProductionConfig, TestingConfig, describe_config,
        get_config,
    )
    from app import create_app  # noqa: E402
    from extensions import csrf, db, limiter, login_manager  # noqa: E402
    from routes import BLUEPRINTS, register_blueprints  # noqa: E402
    from services.http_security import ServiceError  # noqa: E402
    from services.model_metadata import (  # noqa: E402
        ModelMetadataError, ModelRegistry, get_registry, load_model_metadata,
    )
    from flask import jsonify  # noqa: E402
    from flask_login import login_required  # noqa: E402
    from werkzeug.security import check_password_hash, generate_password_hash  # noqa: E402
    from werkzeug.serving import make_server  # noqa: E402

REQUIRED_FILES = (
    "app.py", "wsgi.py", "extensions.py",
    "routes/__init__.py", "routes/core.py", "routes/auth.py",
    "services/model_metadata.py", "services/http_security.py",
    "static/css/backend.css", "docs/BACKEND.md", "scripts/verify_stage7.py",
)

BACKEND_PY = (
    "app.py", "wsgi.py", "extensions.py",
    "routes/__init__.py", "routes/core.py", "routes/auth.py",
    "services/model_metadata.py", "services/http_security.py",
)

METRIC_WORDS = (
    "accuracy", "precision", "recall", "f1", "roc_auc", "roc-auc",
    "confusion_matrix", "confusion matrix", "false_negatives",
)

FORBIDDEN_NETWORK = (
    "import requests", "import socket", "import httpx", "import aiohttp",
    "urllib.request", "urlopen(", "from pycurl", "http.client",
)

PLACEHOLDER_MARKERS = (
    "NotImplemented" + "Error", "TODO: imple" + "ment", "placeholder" + " function",
)

# Files that belong to LATER stages and must not exist while at Stage 7.
FORBIDDEN_NOW = (
    "models/__init__.py", "models/database_models.py", "models/prediction_model.py",
    "scripts/init_db.py", "scripts/create_admin.py",
    "services/detection_service.py", "services/decision_service.py",
    "services/explanation_service.py", "services/stats_service.py",
    "services/report_service.py",
    "routes/scanning.py", "routes/dashboard.py", "routes/admin.py",
    "routes/api.py", "routes/history.py",
    "templates/base.html", "templates/index.html", "templates/scan.html",
    "templates/dashboard.html", "templates/history.html", "templates/admin.html",
    "static/vendor/bootstrap.min.css", "static/vendor/chart.umd.min.js",
    "static/js/main.js", "instance/phishing.db",
    "tests/conftest.py", "tests/test_features.py",
    "docs/SECURITY.md", "docs/TEST_PLAN.md", "docs/DEPLOYMENT.md",
    "docs/REPORT.md",
)

STAGE_8_DELIVERED = (
    (ROOT / "models" / "database_models.py").is_file()
    and (ROOT / "scripts" / "verify_stage8.py").is_file()
)
# Stage 10 delivered /scan; the "no later-stage routes" assertion is
# stage-aware rather than deleted, so Gate 7 still protects Stage 11+ routes.
STAGE_10_DELIVERED = (
    (ROOT / "services" / "detection_service.py").is_file()
    and (ROOT / "scripts" / "verify_stage10.py").is_file()
)
# Stage 11 delivered /dashboard, /history and /admin. The "no later-stage
# routes" assertion is stage-aware, not deleted.
STAGE_11_DELIVERED = (
    (ROOT / "services" / "stats_service.py").is_file()
    and (ROOT / "scripts" / "verify_stage11.py").is_file()
)
# Stage 12 delivered the versioned REST API and per-route rate limits. Once
# detected, Gate 7 checks that the route EXISTS and that the throttle is
# config-driven, instead of falsely requiring their absence.
STAGE_12_DELIVERED = (
    (ROOT / "routes" / "api.py").is_file()
    and (ROOT / "scripts" / "verify_stage12.py").is_file()
)

DOC_SECTIONS = (
    "## 1. What Stage 7 builds", "## 2. Why an application factory",
    "## 3. File-by-file map", "## 4. Extension wiring",
    "## 5. HTTP contract at Stage 7", "## 6. Security behaviour",
    "## 7. What is deliberately NOT in Stage 7", "## 8. Run and test",
    "## 9. Common errors and fixes", "## 10. Stage 7 exit criteria",
)

failures: list[str] = []
checks = 0


def check(label: str, condition: bool, hint: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        failures.append(label)
        print(f"  FAIL  {label}" + (f" :: {hint}" if hint else ""))


def skip(label: str, reason: str) -> None:
    print(f"  SKIP  {label} ({reason})")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def metric_free(text: str) -> bool:
    lowered = text.lower()
    return not any(word in lowered for word in METRIC_WORDS)


def published_metric_literals() -> list[str]:
    """Collect measured numbers from metrics.json to prove none is hard-coded."""
    metrics = json.loads(read("ml/saved_model/metrics.json"))
    literals: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, float) and 0.0 < node < 1.0:
            literals.add(f"{node:.6f}")
            literals.add(f"{node:.4f}")

    walk(metrics)
    return sorted(literals)


# --------------------------------------------------------------------------- #
# 1. Files and source-level contracts
# --------------------------------------------------------------------------- #
def check_files_and_sources() -> None:
    print("\n[1] Delivered files and source contracts")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"exists and non-empty :: {rel}",
              path.is_file() and path.stat().st_size > 0)

    sources = {rel: read(rel) for rel in BACKEND_PY}
    joined = "\n".join(sources.values())
    app_src = sources["app.py"]

    check("app.py defines create_app()", "def create_app(" in app_src)
    check("app.py does NOT build a module-level Flask() object",
          re.search(r"^app\s*=\s*Flask\(", app_src, re.MULTILINE) is None)
    for call in ("db.init_app(app)", "csrf.init_app(app)",
                 "limiter.init_app(app)", "login_manager.init_app(app)",
                 "register_blueprints(app)", "install_security_headers(app)",
                 "install_error_handlers(app)", "install_request_guards(app)",
                 "ModelRegistry(", "_validate_runtime_config(app)"):
        check(f"app.py calls {call}", call in app_src)
    check("app.py attaches the registry to app.extensions",
          'app.extensions["model_registry"]' in app_src)
    check("app.py refuses boot on broken metadata", "ModelMetadataError" in app_src)

    check("wsgi.py calls create_app()", "create_app()" in sources["wsgi.py"])
    check("wsgi.py exposes both app and application",
          "application = app" in sources["wsgi.py"])
    check("wsgi.py uses waitress", "waitress" in sources["wsgi.py"])
    for name in ("db", "csrf", "login_manager", "limiter"):
        check(f"extensions.py creates {name}",
              re.search(rf"^{name}\s*=", sources["extensions.py"], re.MULTILINE) is not None)
    check("limiter is wired with no blanket throttle",
          "default_limits=[]" in sources["extensions.py"])
    if STAGE_12_DELIVERED:
        check("Stage 12 applies config-driven per-route limits",
              "@limiter.limit" in joined and "RATE_LIMIT_AUTH" in joined
              and "limits_disabled" in joined)
        check("Stage 12 keeps no blanket default throttle",
              "default_limits=[]" in sources["extensions.py"])
    else:
        check("no route claims a rate limit before Stage 12",
              "@limiter.limit" not in joined)

    check("routes/__init__.py exposes BLUEPRINTS",
          "BLUEPRINTS" in sources["routes/__init__.py"])
    check("core blueprint defines /", '@core_bp.get("/")' in sources["routes/core.py"])
    check("core blueprint defines /health",
          '@core_bp.get("/health")' in sources["routes/core.py"])
    for path in ("/auth/session", "/auth/csrf-token", "/logout"):
        check(f"auth blueprint defines {path}", path in sources["routes/auth.py"])

    # The web layer must not load the estimator yet (Stage 10) and must not
    # display measured numbers (Stage 11).
    check("Stage 7 backend never loads a joblib estimator",
          "joblib.load(" not in joined and "import joblib" not in joined)
    check("Stage 7 backend never calls predict_proba",
          "predict_proba(" not in joined)
    check("Stage 7 backend does not read METRICS_PATH",
          "METRICS_PATH" not in joined)
    literals = published_metric_literals()
    leaked = [value for value in literals if value in joined]
    check("no measured metric literal is hard-coded in backend code",
          not leaked, ", ".join(leaked[:5]))

    for token in FORBIDDEN_NETWORK:
        check(f"no outbound-network import :: {token}", token not in joined)
    for marker in PLACEHOLDER_MARKERS:
        check(f"no placeholder marker :: {marker}", marker not in joined)
    check("no bare pass statement in backend code",
          re.search(r"^\s*pass\s*$", joined, re.MULTILINE) is None)

    css = read("static/css/backend.css")
    check("backend.css defines .backend-body", ".backend-body" in css)
    check("backend.css has no external @import", "@import" not in css)
    check("backend.css has no remote URLs", "http://" not in css and "https://" not in css)
    check("backend.css is responsive", "@media" in css)


# --------------------------------------------------------------------------- #
# 2. Configuration and application factory
# --------------------------------------------------------------------------- #
def check_factory() -> None:
    print("\n[2] Configuration and application factory")
    summary = describe_config()
    check("describe_config() reports build stage >= 7",
          isinstance(summary.get("build_stage"), int) and summary["build_stage"] >= 7)
    check("describe_config() reports a WSGI bind",
          isinstance(summary.get("wsgi_bind"), str))
    check("get_config() resolves a config class", isinstance(get_config(), type))

    app = create_app(TestingConfig)
    check("create_app returns a Flask object", type(app).__name__ == "Flask")
    check("app is in testing mode", app.config["TESTING"] is True)
    check("testing DB is in-memory SQLite",
          app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///:memory:")
    check("testing disables CSRF", app.config["WTF_CSRF_ENABLED"] is False)
    check("testing disables rate limiting", app.config["RATELIMIT_ENABLED"] is False)
    check("build stage is 7 or later", app.config["BUILD_STAGE"] >= 7)
    check("app version follows the stage 0.x.0 series",
          re.fullmatch(r"0\.\d+\.0", str(app.config["APP_VERSION"])) is not None)
    check("SECRET_KEY is at least 32 characters", len(app.config["SECRET_KEY"] or "") >= 32)
    check("MAX_CONTENT_LENGTH is 64 KB", app.config["MAX_CONTENT_LENGTH"] == 64 * 1024)

    other = create_app(TestingConfig)
    check("two factory calls return distinct applications", other is not app)

    check("SQLAlchemy extension is bound", "sqlalchemy" in app.extensions)
    check("model registry is bound", isinstance(app.extensions.get("model_registry"), ModelRegistry))
    check("Flask-Login is bound", hasattr(app, "login_manager"))
    check("CSRFProtect is bound", "csrf" in app.extensions or hasattr(app, "csrf"))
    check("limiter honours testing config", limiter.enabled is False)

    before = dict(app.blueprints)
    register_blueprints(app)
    check("register_blueprints() is idempotent", dict(app.blueprints) == before)
    check("exactly the Stage 7 blueprints are registered",
          set(app.blueprints) == {bp.name for bp in BLUEPRINTS},
          ", ".join(sorted(app.blueprints)))

    rules = {str(rule) for rule in app.url_map.iter_rules()}
    for rule in ("/", "/health", "/auth/session", "/auth/csrf-token", "/logout", "/favicon.ico"):
        check(f"url_map contains {rule}", rule in rules)
    later_rules: list[str] = []
    if not STAGE_12_DELIVERED:
        later_rules.append("/api/v1/scan")  # Stage 12: absent before Stage 12
    if not STAGE_11_DELIVERED:
        later_rules += ["/dashboard", "/history", "/admin"]
    if not STAGE_10_DELIVERED:
        later_rules.append("/scan")
    if not STAGE_8_DELIVERED:
        later_rules += ["/login", "/register"]
    for rule in later_rules:
        check(f"url_map correctly omits {rule} at this stage", rule not in rules)
    if STAGE_8_DELIVERED:
        for rule in ("/login", "/register"):
            check(f"Stage 8 adds {rule}", rule in rules)
    if STAGE_11_DELIVERED:
        for rule in ("/dashboard", "/history", "/admin"):
            check(f"Stage 11 adds {rule}", rule in rules)
    if STAGE_12_DELIVERED:
        for rule in ("/api/v1/scan", "/api/v1/model/info", "/api/v1/scans",
                     "/api/v1/health", "/api/v1/csrf-token"):
            check(f"Stage 12 adds {rule}", rule in rules)

    if not STAGE_8_DELIVERED:
        check("no database file was created by booting",
              not (ROOT / "instance" / "phishing.db").exists())
    else:
        skip("no database file on boot",
             "Stage 8 creates instance/phishing.db only via scripts/init_db.py")
    check("testing config omits framing headers", app.config["X_FRAME_OPTIONS"] is None)
    check("production config keeps framing headers",
          ProductionConfig.X_FRAME_OPTIONS == "DENY")

    dev_app = create_app(DevelopmentConfig, overrides={"DEBUG": False})
    check("limiter is enabled in development", limiter.enabled is True)
    check("development omits X-Frame-Options for the live preview",
          dev_app.config["X_FRAME_OPTIONS"] is None)

    # The hashing primitive that Stage 8's User entity will use is available
    # and never stores a plaintext password.
    hashed = generate_password_hash("CorrectHorseBatteryStaple!42")
    check("Werkzeug hashes passwords (never plaintext)",
          "CorrectHorseBatteryStaple!42" not in hashed
          and check_password_hash(hashed, "CorrectHorseBatteryStaple!42")
          and not check_password_hash(hashed, "wrong-password"))


# --------------------------------------------------------------------------- #
# 3. Routes and responses
# --------------------------------------------------------------------------- #
def check_routes() -> None:
    print("\n[3] Routes and responses")
    metadata = json.loads(read("ml/saved_model/metadata.json"))
    app = create_app(TestingConfig)

    with app.test_client() as client:
        page = client.get("/")
        check("GET / returns 200 HTML", page.status_code == 200
              and "text/html" in page.content_type)
        body = page.get_data(as_text=True)
        check("status page names the app", "Intelligent Phishing Website Detection System" in body)
        check("status page announces the current build stage",
              f"STAGE {app.config['BUILD_STAGE']}" in body)
        check("status page shows the selected model name",
              metadata["model_name"] in body)
        check("status page shows the selected model version",
              metadata["model_version"] in body)
        check("status page shows the calibrated thresholds",
              str(metadata["thresholds"]["low"]) in body
              and str(metadata["thresholds"]["high"]) in body)
        check("status page has NO non-functional SCAN WEBSITE button",
              "SCAN WEBSITE" not in body)
        check("status page contains no performance figures", metric_free(body))
        check("status page uses the local stylesheet",
              "/static/css/backend.css" in body)
        css = client.get("/static/css/backend.css")
        check("GET /static/css/backend.css returns 200",
              css.status_code == 200 and "css" in css.content_type)

        health = client.get("/health")
        check("GET /health returns 200", health.status_code == 200)
        payload = health.get_json()
        check("/health status is ok", payload["status"] == "ok")
        check("/health reports build_stage >= 7", payload["build_stage"] >= 7)
        check("/health model name comes from metadata.json",
              payload["model"]["model_name"] == metadata["model_name"])
        check("/health model version comes from metadata.json",
              payload["model"]["model_version"] == metadata["model_version"])
        check("/health schema version comes from metadata.json",
              payload["model"]["schema_version"] == metadata["schema_version"])
        check("/health thresholds come from metadata.json",
              payload["model"]["decision_thresholds"]["low"] == metadata["thresholds"]["low"]
              and payload["model"]["decision_thresholds"]["high"] == metadata["thresholds"]["high"])
        check("/health lists exactly the three decision states",
              sorted(payload["model"]["decision_states"]) == ["LEGITIMATE", "PHISHING", "SUSPICIOUS"])
        check("/health confirms 15 features", payload["model"]["feature_count"] == 15)
        check("/health verifies the bundle hash", payload["bundle"]["available"] is True)
        if not STAGE_8_DELIVERED:
            check("/health reports database as Stage 8 work",
                  payload["database"]["status"] == "not_initialised"
                  and payload["database"]["scheduled_stage"] == 8)
        else:
            check("/health reports real schema status",
                  payload["database"]["status"] in ("ready", "not_initialised", "error")
                  and payload["database"]["introduced_stage"] == 8
                  and "tables" in payload["database"])
        if not STAGE_10_DELIVERED:
            check("/health reports detection as Stage 10 work",
                  payload["detection"]["status"] == "not_wired"
                  and payload["detection"]["scheduled_stage"] == 10)
        else:
            check("Stage 10 /health reports the live detection engine",
                  payload["detection"]["status"] == "ready"
                  and payload["detection"]["scheduled_stage"] == 10
                  and payload["detection"]["delivered_stage"] == 10
                  and payload["detection"]["feature_count"] == 15)
        check("/health contains no performance figures",
              metric_free(json.dumps(payload)))
        check("/health is not cached", health.headers.get("Cache-Control") == "no-store")
        check("/health has security headers",
              "Content-Security-Policy" in health.headers
              and health.headers.get("X-Content-Type-Options") == "nosniff")

        favicon = client.get("/favicon.ico")
        check("GET /favicon.ico returns 204", favicon.status_code == 204)

        session_state = client.get("/auth/session")
        check("GET /auth/session returns 200", session_state.status_code == 200)
        state = session_state.get_json()
        check("session is anonymous for a fresh client", state["authenticated"] is False)
        if not STAGE_8_DELIVERED:
            check("session reports no /login route yet", state["login_available"] is False)
            check("session reports no /register route yet", state["register_available"] is False)
        else:
            check("Stage 8 adds /login", state["login_available"] is True)
            check("Stage 8 adds /register", state["register_available"] is True)
            check("session reports SQLite persistence",
                  state["user_persistence"] == "sqlite")
        check("guest scans remain allowed", state["guest_scans_allowed"] is True)
        check("session protection is strong", state["session_protection"] == "strong")

        token_response = client.get("/auth/csrf-token")
        check("GET /auth/csrf-token returns 200", token_response.status_code == 200)
        token = token_response.get_json().get("csrf_token", "")
        check("CSRF token is a non-trivial string", isinstance(token, str) and len(token) > 20)
        check("CSRF token endpoint names the header",
              token_response.get_json()["header_name"] == "X-CSRF-Token")
        cookie = token_response.headers.getlist("Set-Cookie")
        check("session cookie is HttpOnly", any("HttpOnly" in c for c in cookie))
        check("session cookie is SameSite=Lax", any("SameSite=Lax" in c for c in cookie))

        logout = client.post("/logout")
        check("POST /logout clears the session (CSRF off in tests)",
              logout.status_code == 200 and logout.get_json()["logged_out"] is True)


# --------------------------------------------------------------------------- #
# 4. Security behaviour
# --------------------------------------------------------------------------- #
def check_security() -> None:
    print("\n[4] Security behaviour")
    dev = create_app(DevelopmentConfig, overrides={"DEBUG": False, "WTF_CSRF_ENABLED": True})

    @dev.route("/api/_echo", methods=["POST"])
    def _echo() -> Any:
        return jsonify({"ok": True})

    with dev.test_client() as client:
        bare = client.post("/logout")
        check("POST without CSRF token is rejected with 400",
              bare.status_code == 400 and b"CSRF_FAILED" in bare.data)
        bare_api = client.post("/api/_echo")
        check("API POST without CSRF token returns JSON 400 CSRF_FAILED",
              bare_api.status_code == 400
              and bare_api.get_json()["error"]["code"] == "CSRF_FAILED")
        token = client.get("/auth/csrf-token").get_json()["csrf_token"]
        # Run the API call BEFORE /logout, because /logout clears the session
        # and therefore invalidates the CSRF secret stored in that session.
        good_api = client.post("/api/_echo", headers={"X-CSRF-Token": token})
        check("API POST with a valid CSRF token succeeds", good_api.status_code == 200)
        good = client.post("/logout", headers={"X-CSRF-Token": token})
        check("POST with a valid CSRF token succeeds",
              good.status_code == 200 and good.get_json()["logged_out"] is True)

        page = client.get("/")
        headers = page.headers
        check("X-Content-Type-Options is nosniff",
              headers.get("X-Content-Type-Options") == "nosniff")
        check("Referrer-Policy is no-referrer",
              headers.get("Referrer-Policy") == "no-referrer")
        check("Permissions-Policy restricts sensitive APIs",
              "camera=()" in headers.get("Permissions-Policy", ""))
        csp = headers.get("Content-Security-Policy", "")
        check("CSP defaults to self only", "default-src 'self'" in csp)
        check("CSP blocks inline scripts", "script-src 'self'" in csp
              and "unsafe-inline" not in csp)
        check("CSP disallows objects and non-self form actions",
              "object-src 'none'" in csp and "form-action 'self'" in csp)
        check("development omits X-Frame-Options for the iframe preview",
              "X-Frame-Options" not in headers)
        check("development omits HSTS", "Strict-Transport-Security" not in headers)

        not_found = client.get("/this-page-does-not-exist")
        check("404 returns a generic HTML error page",
              not_found.status_code == 404 and b"NOT_FOUND" in not_found.data)
        check("404 never leaks a traceback", b"Traceback" not in not_found.data)
        check("404 never leaks an absolute server path",
              b"/home/user" not in not_found.data)
        check("404 error page is not cached",
              not_found.headers.get("Cache-Control") == "no-store")
        api_404 = client.get("/api/does-not-exist")
        check("404 on /api/* is JSON with contract code",
              api_404.status_code == 404
              and api_404.get_json()["error"]["code"] == "NOT_FOUND")
        method = client.post("/")
        check("405 returns METHOD_NOT_ALLOWED",
              method.status_code == 405 and b"METHOD_NOT_ALLOWED" in method.data)
    # The body cap is asserted on a CSRF-disabled app so that CSRF validation
    # cannot mask the 413 with its own (also correct) 400 response.
    cap_app = create_app(TestingConfig)
    with cap_app.test_client() as cap:
        oversized = cap.post(
            "/logout", data=b"x" * (cap_app.config["MAX_CONTENT_LENGTH"] + 10),
            content_type="application/octet-stream",
        )
        check("oversized body returns 413 PAYLOAD_TOO_LARGE",
              oversized.status_code == 413 and b"PAYLOAD_TOO_LARGE" in oversized.data)

    # Typed service errors and @login_required (registered before first request).
    authz = create_app(TestingConfig)

    @authz.route("/_need_login")
    @login_required
    def _need() -> Any:
        return jsonify({"ok": True})

    @authz.route("/api/_need_login")
    @login_required
    def _need_api() -> Any:
        return jsonify({"ok": True})

    @authz.route("/_invalid")
    def _invalid() -> Any:
        raise ServiceError(400, "INVALID_URL", "Enter an http or https URL.")

    @authz.route("/_unavailable")
    def _unavailable() -> Any:
        raise ServiceError(503, "MODEL_UNAVAILABLE")

    with authz.test_client() as client:
        denied = client.get("/_need_login")
        check("@login_required yields 401 UNAUTHENTICATED",
              denied.status_code == 401 and b"UNAUTHENTICATED" in denied.data)
        denied_api = client.get("/api/_need_login")
        check("API 401 is JSON UNAUTHENTICATED",
              denied_api.status_code == 401
              and denied_api.get_json()["error"]["code"] == "UNAUTHENTICATED")
        invalid = client.get("/_invalid")
        check("ServiceError(400, INVALID_URL) is honoured",
              invalid.status_code == 400 and b"INVALID_URL" in invalid.data)
        unavailable = client.get("/_unavailable")
        check("ServiceError(503, MODEL_UNAVAILABLE) is honoured",
              unavailable.status_code == 503 and b"MODEL_UNAVAILABLE" in unavailable.data)

    # 500 handling requires exception propagation to be disabled (Flask
    # propagates by design when TESTING or DEBUG is on).
    quiet = create_app(DevelopmentConfig, overrides={
        "DEBUG": False, "TESTING": False, "PROPAGATE_EXCEPTIONS": False,
        "WTF_CSRF_ENABLED": False,
    })

    @quiet.route("/_raise")
    def _raise() -> Any:
        raise ValueError("secret diagnostic detail must not reach the client")

    @quiet.route("/api/_raise")
    def _raise_api() -> Any:
        raise ValueError("secret diagnostic detail must not reach the client")

    with quiet.test_client() as client:
        html_500 = client.get("/_raise")
        check("500 is a generic HTML page",
              html_500.status_code == 500 and b"INTERNAL_ERROR" in html_500.data)
        check("500 never leaks the exception text",
              b"secret diagnostic detail" not in html_500.data
              and b"Traceback" not in html_500.data)
        json_500 = client.get("/api/_raise")
        check("API 500 is generic JSON",
              json_500.status_code == 500
              and json_500.get_json()["error"]["code"] == "INTERNAL_ERROR")

    # Production posture.
    prod = create_app(ProductionConfig, overrides={"SECRET_KEY": "p" * 64})
    with prod.test_client() as client:
        response = client.get("/")
        check("production sends X-Frame-Options: DENY",
              response.headers.get("X-Frame-Options") == "DENY")
        check("production sends HSTS",
              "max-age=" in response.headers.get("Strict-Transport-Security", ""))
        check("production CSP pins frame-ancestors",
              "frame-ancestors 'self'" in response.headers.get("Content-Security-Policy", ""))
        check("production has DEBUG off", prod.config["DEBUG"] is False)
        check("production has secure cookies", prod.config["SESSION_COOKIE_SECURE"] is True)
        check("production enables CSRF", prod.config["WTF_CSRF_ENABLED"] is True)

    # "Production must refuse to start without SECRET_KEY" can only be proved
    # when the key is genuinely absent. A developer who follows docs/SETUP.md
    # has a real .env on disk, and config.py loads it at import time, so an
    # empty overrides dict would inherit that key and the check would pass for
    # the wrong reason. Clear the class attribute for the duration of the
    # assertion instead of depending on the machine's environment.
    saved_secret = ProductionConfig.SECRET_KEY
    try:
        ProductionConfig.SECRET_KEY = None
        for label, overrides, expected in (
            ("production without SECRET_KEY", {}, "SECRET_KEY"),
            ("inverted decision defaults",
             {"DECISION_LOW_DEFAULT": 0.9, "DECISION_HIGH_DEFAULT": 0.1},
             "decision defaults"),
            ("unsafe MAX_URL_LENGTH", {"MAX_URL_LENGTH": 10}, "MAX_URL_LENGTH"),
        ):
            base = ProductionConfig if label.startswith("production") else TestingConfig
            try:
                create_app(base, overrides=overrides)
                check(f"refuses {label}", False, "no exception raised")
            except RuntimeError as exc:
                check(f"refuses {label}", expected in str(exc), str(exc)[:120])
    finally:
        ProductionConfig.SECRET_KEY = saved_secret


# --------------------------------------------------------------------------- #
# 5. Model artefact validation and explicit failure modes
# --------------------------------------------------------------------------- #
def check_model_contract() -> None:
    print("\n[5] Model artefact contract and explicit failure modes")
    metadata = json.loads(read("ml/saved_model/metadata.json"))
    loaded = load_model_metadata(ROOT / "ml" / "saved_model" / "metadata.json")
    check("load_model_metadata reads 15 features", len(loaded.feature_order) == 15)
    check("load_model_metadata uses the measured thresholds",
          loaded.threshold_low == metadata["thresholds"]["low"]
          and loaded.threshold_high == metadata["thresholds"]["high"])
    check("ModelRegistry verifies the real bundle SHA-256",
          ModelRegistry(ROOT / "ml" / "saved_model" / "metadata.json",
                        ROOT / "ml" / "saved_model" / "model_bundle.joblib").bundle_available)

    registry = create_app(TestingConfig).extensions["model_registry"]
    check("public_info() has no performance keys",
          metric_free(json.dumps(registry.public_info())))
    with create_app(TestingConfig).test_request_context("/health"):
        check("get_registry() resolves inside a request",
              get_registry() is not None)

    tmp = Path(tempfile.mkdtemp(prefix="stage7-"))
    try:
        missing = tmp / "missing-metadata.json"
        try:
            create_app(TestingConfig, overrides={"METADATA_PATH": missing})
            check("missing metadata refuses application startup", False, "no exception")
        except RuntimeError as exc:
            check("missing metadata refuses application startup",
                  "model metadata file is missing" in str(exc))

        tampered_cases = {
            "short feature_order": lambda d: d.update(feature_order=d["feature_order"][:-1]),
            "inverted thresholds": lambda d: d.update(thresholds={"low": 0.9, "high": 0.1}),
            "changed decision state": lambda d: d["decision_states"]["PHISHING"].update(message="changed"),
            "changed score wording": lambda d: d.update(score_meaning="a guarantee of maliciousness"),
        }
        for label, mutate in tampered_cases.items():
            data = json.loads(json.dumps(metadata))
            mutate(data)
            path = tmp / f"tampered-{label.replace(' ', '-')}.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            try:
                create_app(TestingConfig, overrides={"METADATA_PATH": path})
                check(f"tampered metadata rejected :: {label}", False, "started anyway")
            except (RuntimeError, ModelMetadataError) as exc:
                check(f"tampered metadata rejected :: {label}", True)
            except Exception as exc:  # noqa: BLE001
                check(f"tampered metadata rejected :: {label}", False, f"{type(exc).__name__}: {exc}")

        # A WRONG recorded hash is not a metadata validation error (the file
        # itself is well formed); it is an integrity failure that must degrade
        # to an explicit 503 rather than a fake "ok".
        wrong_hash = json.loads(json.dumps(metadata))
        wrong_hash["model_bundle_sha256"] = "0" * 64
        wrong_path = tmp / "wrong-recorded-hash.json"
        wrong_path.write_text(json.dumps(wrong_hash), encoding="utf-8")
        hash_app = create_app(TestingConfig, overrides={"METADATA_PATH": wrong_path})
        with hash_app.test_client() as client:
            health = client.get("/health")
            check("wrong recorded bundle hash degrades to 503",
                  health.status_code == 503
                  and "SHA-256" in health.get_json()["bundle"]["detail"])

        # Missing bundle: the app boots but reports the truth (no rule fallback).
        degraded = create_app(TestingConfig, overrides={
            "MODEL_BUNDLE_PATH": tmp / "no-such-bundle.joblib"
        })
        with degraded.test_client() as client:
            health = client.get("/health")
            body = health.get_json()
            check("missing bundle yields HTTP 503", health.status_code == 503)
            check("503 uses MODEL_UNAVAILABLE code", body["error"]["code"] == "MODEL_UNAVAILABLE")
            check("503 reports the bundle as unavailable", body["bundle"]["available"] is False)
            page = client.get("/")
            check("status page shows DEGRADED instead of faking a result",
                  page.status_code == 200 and b"DEGRADED" in page.data)

        # Corrupt bundle: hash mismatch is also an explicit failure.
        corrupt = tmp / "corrupt.joblib"
        corrupt.write_bytes(b"not a trained model")
        corrupt_app = create_app(TestingConfig, overrides={"MODEL_BUNDLE_PATH": corrupt})
        with corrupt_app.test_client() as client:
            health = client.get("/health")
            check("hash mismatch yields HTTP 503", health.status_code == 503)
            check("hash mismatch is reported as such",
                  "SHA-256" in health.get_json()["bundle"]["detail"])
    finally:
        for item in tmp.iterdir():
            item.unlink()
        tmp.rmdir()


# --------------------------------------------------------------------------- #
# 6. Real HTTP server and CLI
# --------------------------------------------------------------------------- #
def check_real_server() -> None:
    print("\n[6] Real HTTP server and Flask CLI")
    app = create_app(TestingConfig, overrides={"TESTING": False, "PROPAGATE_EXCEPTIONS": False})
    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
            check("real HTTP GET /health returns 200", response.status == 200)
            check("real HTTP health reports ok", payload["status"] == "ok")
            check("real HTTP response carries the CSP",
                  "Content-Security-Policy" in response.headers)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as response:
            check("real HTTP GET / returns HTML", response.status == 200
                  and "text/html" in response.headers.get("Content-Type", ""))
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/missing", timeout=10)
            check("real HTTP 404 is served", False, "no HTTPError raised")
        except urllib.error.HTTPError as exc:
            check("real HTTP 404 is served", exc.code == 404)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    check("server thread stopped cleanly", not thread.is_alive())

    cli = subprocess.run(
        [sys.executable, "-m", "flask", "--app", "app", "routes"],
        capture_output=True, text=True, timeout=90, cwd=ROOT,
    )
    listing = cli.stdout + cli.stderr
    check("flask --app app routes discovers the factory", cli.returncode == 0)
    check("CLI lists the /health endpoint", "/health" in listing)


# --------------------------------------------------------------------------- #
# 7. Documentation, stage discipline and historical regressions
# --------------------------------------------------------------------------- #
def check_docs_and_discipline() -> None:
    print("\n[7] Documentation, stage discipline and regressions")
    backend = read("docs/BACKEND.md")
    for section in DOC_SECTIONS:
        check(f"BACKEND.md :: {section}", section in backend)
    check("BACKEND.md states there is no SCAN WEBSITE button yet",
          "SCAN WEBSITE" in backend)
    check("BACKEND.md explains the model-score wording rule",
          "calibrated" in backend.lower() or "score" in backend.lower())

    readme = read("README.md")
    check("README marks Stage 7 complete",
          re.search(r"\|\s*7\s*\|.*✅", readme) is not None)
    plan = read("docs/STAGE_PLAN.md")
    check("STAGE_PLAN records Stage 7 as delivered", "Stage 7 — delivered" in plan
          or "Stage 7 delivered" in plan or "Stage 7 — delivered" in plan)
    decisions = read("docs/DECISIONS.md")
    check("DECISIONS.md contains ADR-024", "ADR-024" in decisions)
    check("DECISIONS.md contains ADR-025", "ADR-025" in decisions)
    architecture = read("docs/ARCHITECTURE.md")
    check("ARCHITECTURE.md has a Stage 7 implementation note",
          "Stage 7 implementation note" in architecture)
    check(".env.example documents HOST and PORT",
          "HOST=" in read(".env.example") and "PORT=" in read(".env.example"))

    if not STAGE_8_DELIVERED:
        for rel in FORBIDDEN_NOW:
            check(f"not created yet :: {rel}", not (ROOT / rel).exists())
        expected = {
            "ml": {"__init__.py", "url_utils.py", "preprocess.py",
                   "feature_extraction.py", "train_model.py",
                   "evaluate_model.py", "thresholds.py"},
            "services": {"__init__.py", "validation.py",
                         "model_metadata.py", "http_security.py"},
            "models": set(),
            "routes": {"__init__.py", "core.py", "auth.py"},
            "tests": set(), "templates": set(),
        }
        for directory, names in expected.items():
            stray = [p.name for p in (ROOT / directory).glob("*.py") if p.name not in names]
            check(f"{directory}/ contains only Stage 1-7 modules", not stray,
                  ", ".join(stray))
        root_py = {p.name for p in ROOT.glob("*.py")}
        check("project root contains only Stage 1-7 Python modules",
              root_py <= {"config.py", "app.py", "wsgi.py", "extensions.py"},
              ", ".join(sorted(root_py)))
    else:
        skip("no Stage 8+ code yet", "delivered in Stage 8; enforced by verify_stage8.py")

    for gate in ("verify_stage1.py", "verify_stage2.py", "verify_stage3.py",
                 "verify_stage4.py", "verify_stage5.py", "verify_stage6.py"):
        # The top-level gate already executes every historical gate directly.
        # Skipping this duplicated nested re-run keeps the suite linear rather
        # than exponential; standalone runs are completely unaffected.
        if PDS_NESTED_GATES:
            print(f"  SKIP  nested regression {gate} (top-level gate runs it)")
            continue
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / gate)],
            capture_output=True, text=True, timeout=400, cwd=ROOT,
        )
        tail = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
        check(f"{gate} still passes", proc.returncode == 0,
              tail[-1] if tail else "no output")


def main() -> int:
    logging.disable(logging.CRITICAL)  # keep the report readable; errors are asserted, not logged
    print("=" * 78)
    print("STAGE 7 EXIT GATE - Flask application factory, wiring, routes and security")
    print(f"Project root : {ROOT}")
    print("=" * 78)
    check_files_and_sources()
    check_factory()
    check_routes()
    check_security()
    check_model_contract()
    check_real_server()
    check_docs_and_discipline()
    print("\n" + "=" * 78)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        return 1
    print(f"RESULT: PASS - all {checks} checks passed")
    print("Stage 7 exit gate satisfied. You may proceed to Stage 8.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
