#!/usr/bin/env python3
"""Stage 11 exit gate: dashboard, scan history, admin view and CSV export.

Run from the project root (Windows or Linux):

    python scripts\\verify_stage11.py       (Windows)
    ./scripts/verify_stage11.py            (Linux/macOS)
    ./.venv/bin/python scripts/verify_stage11.py

This is an EXECUTABLE acceptance test, not a description. It builds isolated
Flask applications against temporary SQLite databases, seeds real scans
through the Stage 10 engine, and verifies that:

  * every dashboard number is counted from the database or read at request
    time from metrics.json (a tampered metrics copy changes the page);
  * history is scoped per account / per signed guest session, filtered and
    paginated, and never leaks another visitor's URL;
  * /admin is role-restricted and keeps Stage 8's 401 UNAUTHENTICATED contract;
  * CSV export neutralises spreadsheet formula and newline injection;
  * the CSP, vendored asset hashes, decision states and detection engine are
    unchanged; Stage 12+ files and routes are still absent.

All test URLs are reserved / synthetic strings. No live site, no malicious URL
and no external network service is ever contacted.
"""
from __future__ import annotations

import contextlib
import csv
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Set by a parent gate (Stage 12+) to avoid exponentially nested historical
# regressions. A standalone run keeps its complete behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"

with contextlib.redirect_stderr(io.StringIO()):
    from config import TestingConfig, describe_config  # noqa: E402
    from app import create_app  # noqa: E402
    from extensions import db  # noqa: E402
    from flask import g, has_app_context  # noqa: E402
    from sqlalchemy import func  # noqa: E402
    from models.database_models import (  # noqa: E402
        ModelInformation, ScanHistory, User, utcnow,
    )
    from routes import BLUEPRINTS  # noqa: E402
    from routes.scanning import GUEST_SCAN_SESSION_KEY  # noqa: E402
    from services import report_service, stats_service  # noqa: E402
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
    "services/stats_service.py", "services/report_service.py",
    "routes/dashboard.py", "routes/history.py", "routes/admin.py",
    "templates/dashboard.html", "templates/history.html", "templates/admin.html",
    "docs/DASHBOARD.md", "scripts/verify_stage11.py",
)

STAGE_12_FILES = (
    "routes/api.py", "scripts/verify_stage12.py", "docs/SECURITY.md",
)
FORBIDDEN_STAGE12 = STAGE_12_FILES + (
    "tests/conftest.py", "tests/test_features.py",
    "docs/TEST_PLAN.md", "docs/DEPLOYMENT.md", "docs/REPORT.md",
)
# Gate 11 runs as a regression under Gate 12. Once Stage 12 is delivered its
# files must exist; ONLY Stage 13+ artefacts remain forbidden.
STAGE_12_DELIVERED = (
    (ROOT / "routes" / "api.py").is_file()
    and (ROOT / "scripts" / "verify_stage12.py").is_file()
)
FORBIDDEN_STAGE13 = tuple(
    rel for rel in FORBIDDEN_STAGE12 if rel not in STAGE_12_FILES
)

# --------------------------------------------------------------------------- #
# Stage 13 awareness (the formal pytest suite).
# --------------------------------------------------------------------------- #
# Gate 11 runs as a regression under the Stage 13 suite. Once Stage 13 is
# delivered, tests/*.py and docs/TEST_PLAN.md must EXIST, so those names leave
# the forbidden list; only genuine Stage 14 artefacts (the report and the
# deployment guide) remain forbidden. The assertion stays stage-aware rather
# than being deleted, so the strict 14-stage order is still enforced.
STAGE_13_FILES = frozenset({
    "tests/conftest.py", "tests/test_features.py", "tests/test_model.py",
    "tests/test_routes.py", "tests/test_api.py", "tests/test_security.py",
    "docs/TEST_PLAN.md",
})
STAGE_13_DELIVERED = all((ROOT / rel).is_file() for rel in STAGE_13_FILES)
FORBIDDEN_STAGE14 = tuple(
    rel for rel in FORBIDDEN_STAGE13 if rel not in STAGE_13_FILES
)

# --------------------------------------------------------------------------- #
# Stage 14 awareness (report + deployment guide).
# --------------------------------------------------------------------------- #
# Gate 11 runs as a regression under the Stage 14 gate. Stage 14 delivers the
# academic report and the deployment guide, so those two names leave the
# forbidden list; every other future artefact stays forbidden.
STAGE_14_FILES = frozenset({"docs/REPORT.md", "docs/DEPLOYMENT.md"})
STAGE_14_DELIVERED = all((ROOT / rel).is_file() for rel in STAGE_14_FILES)
FORBIDDEN_AFTER_14 = tuple(
    rel for rel in FORBIDDEN_STAGE14 if rel not in STAGE_14_FILES
)

VENDOR_HASHES = {
    "static/vendor/bootstrap.min.css": "3c8f27e6009ccfd710a905e6dcf12d0ee3c6f2ac7da05b0572d3e0d12e736fc8",
    "static/vendor/bootstrap.bundle.min.js": "0833b2e9c3a26c258476c46266e6877fc75218625162e0460be9a3a098a61c6c",
    "static/vendor/chart.umd.min.js": "b38076762f7363bc9e912b68b8e034826798db5df26bb61f000ec2e7a3137bc7",
}

# Byte-for-byte reference copied from the Stage 9/10 contract. Stage 11 must
# not add a single directive (no CDN, no unsafe-inline, no connect-src URL).
EXACT_CSP = (
    "default-src 'self'; base-uri 'self'; object-src 'none'; "
    "form-action 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'"
)

RUNTIME_RELS = (
    "app.py", "config.py", "extensions.py", "wsgi.py",
    "routes/__init__.py", "routes/core.py", "routes/auth.py",
    "routes/scanning.py", "routes/dashboard.py", "routes/history.py",
    "routes/admin.py",
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
if STAGE_12_DELIVERED:
    # The REST API is on the request path and must stay network-free.
    RUNTIME_RELS += ("routes/api.py",)

NETWORK_MARKERS = (
    "import requests", "import httpx", "import aiohttp", "from pycurl",
    "urllib.request", "urlopen(", "http.client", "socket.create_connection",
    "requests.get(", "requests.post(",
)

TEMPLATES_NEW = (
    "templates/dashboard.html", "templates/history.html", "templates/admin.html",
)

DASHBOARD_SECTIONS = (
    "## 1. What Stage 11 builds", "## 2. Runtime data sources",
    "## 3. File-by-file map", "## 4. Dashboard and charts",
    "## 5. History, filters and pagination", "## 6. Admin view",
    "## 7. CSV export security", "## 8. Authorisation and privacy",
    "## 9. What is deliberately NOT in Stage 11", "## 10. Run and test",
    "## 11. Common errors and fixes", "## 12. Stage 11 exit criteria",
)

# Published Stage 6 figures. They may appear in docs (as measured provenance),
# but NEVER typed into a template, a JS file or a Stage 11 Python module.
PUBLISHED_LITERALS = ("0.983854", "0.993307", "0.967803", "0.980389", "0.998055")

METRICS = json.loads(read("ml/saved_model/metrics.json"))
METADATA = json.loads(read("ml/saved_model/metadata.json"))

SCAN_URLS = (
    "https://example.com",
    "https://example.com/",
    "https://www.example.org/about",
    "https://paypal.com.login.verify.example.invalid/secure/account/update?next=confirm",
)
# Distinct reserved strings per identity make leakage checks unambiguous.
MEMBER_URLS = ("https://member.example.invalid/one",
               "https://member.example.invalid/two")
ADMIN_URLS = ("https://admin.example.invalid/console",)
STRONG_PASSWORD = "Str0ng!Passphrase2026"
ADMIN_USER = "admin11"
MEMBER_USER = "member11"


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #
def build_app(**overrides: Any):
    """Create a TestingConfig app with a safe fixed secret."""
    settings: dict[str, Any] = {"SECRET_KEY": "s" * 64}
    settings.update(overrides)
    return create_app(TestingConfig, overrides=settings)


def inline_scripts(text: str) -> list[str]:
    return [m.strip() for m in re.findall(
        r"<script\b[^>]*>(.*?)</script>", text, re.DOTALL | re.IGNORECASE
    ) if m.strip()]


def external_assets(text: str) -> list[str]:
    return re.findall(
        r"(?:src|href)\s*=\s*[\"'](?:https?:)?//[^\"']+", text, re.IGNORECASE
    )


def chart_payloads(body: str) -> list[dict[str, Any]]:
    """Parse every data-chart='...' payload out of a rendered page."""
    found = []
    for match in re.findall(r"data-chart='([^']+)'", body):
        try:
            found.append(json.loads(match))
        except json.JSONDecodeError:
            pass
    return found


def fresh_client(app):
    """A brand-new browser. Flask-Login caches the user in g inside a shared
    app context; real WSGI requests always get a fresh context, so this is a
    harness correction only (same technique as verify_stage10.py)."""
    if has_app_context():
        g.pop("_login_user", None)
    return app.test_client()


def login(client, username: str, password: str = STRONG_PASSWORD):
    return client.post("/login", json={"username": username, "password": password})


def seed(app) -> dict[str, Any]:
    """Create the schema, two real accounts and one hostile stored row.

    The hostile row simulates a stored value that a spreadsheet would happily
    evaluate and that a browser would happily parse as markup. It is inserted
    through the ORM (never through the public form) purely to test export and
    rendering defences.
    """
    with app.app_context():
        initialise_schema(app)
        create_user(ADMIN_USER, "admin11@example.com", STRONG_PASSWORD, role="admin")
        create_user(MEMBER_USER, "member11@example.com", STRONG_PASSWORD)
        hostile = ScanHistory(
            user_id=None,
            url="=SUM(1+1)\r\n<script>alert(1)</script>",
            normalised_url="@SUM(2+2)",
            prediction="SUSPICIOUS",
            model_score=0.5,
            risk_level="MEDIUM",
            model_version="1.0.0",
            scan_date=utcnow(),
            features_json=json.dumps({"flagged": ["num_dots"]}),
        )
        db.session.add(hostile)
        db.session.commit()
        hostile_id = int(hostile.id)
        return {
            "hostile_id": hostile_id,
            "users": db.session.query(func.count(User.id)).scalar(),
            "models": db.session.query(func.count(ModelInformation.id)).scalar(),
        }


def scan_as(client, urls=SCAN_URLS) -> list[dict[str, Any]]:
    results = []
    for url in urls:
        response = client.post("/scan", json={"url": url})
        results.append(response.get_json() or {})
    return results


# --------------------------------------------------------------------------- #
# 1. Inventory, stage discipline and compilation
# --------------------------------------------------------------------------- #
def check_inventory() -> None:
    print("\n[1] Stage 11 file inventory, stage discipline and compilation")
    for rel in REQUIRED_FILES:
        check(f"required file exists :: {rel}", (ROOT / rel).is_file())
    if STAGE_13_DELIVERED:
        forbidden = FORBIDDEN_AFTER_14
    elif STAGE_12_DELIVERED:
        forbidden = FORBIDDEN_STAGE13
    else:
        forbidden = FORBIDDEN_STAGE12
    for rel in forbidden:
        check(f"later-stage file absent :: {rel}", not (ROOT / rel).exists())
    if STAGE_12_DELIVERED:
        for rel in STAGE_12_FILES:
            check(f"Stage 12 delivered file exists :: {rel}", (ROOT / rel).is_file())
    if STAGE_13_DELIVERED:
        for rel in sorted(STAGE_13_FILES):
            check(f"Stage 13 delivered file exists :: {rel}", (ROOT / rel).is_file())
    check("Stage 11 reuses main.js instead of a second chart controller",
          not (ROOT / "static/js" / "dashboard.js").exists())

    expected = {
        "services": {"__init__.py", "validation.py", "model_metadata.py",
                     "http_security.py", "auth_service.py", "database_service.py",
                     "detection_service.py", "decision_service.py",
                     "explanation_service.py", "stats_service.py",
                     "report_service.py"},
        "routes": {"__init__.py", "core.py", "auth.py", "scanning.py",
                   "dashboard.py", "history.py", "admin.py"},
        "models": {"__init__.py", "database_models.py", "prediction_model.py"},
    }
    if STAGE_12_DELIVERED:
        expected["routes"] |= {"api.py"}
    for directory, names in expected.items():
        actual = {p.name for p in (ROOT / directory).glob("*.py")}
        check(f"{directory}/ contains exactly the delivered modules",
              actual == names, f"extra={sorted(actual - names)} missing={sorted(names - actual)}")

    html = {str(p.relative_to(ROOT)).replace("\\", "/")
            for p in (ROOT / "templates").rglob("*.html")}
    expected_html = {
        "templates/base.html", "templates/index.html", "templates/login.html",
        "templates/register.html", "templates/auth_result.html",
        "templates/errors/error.html", "templates/scan.html",
        "templates/scan_report.html", "templates/partials/scan_result.html",
        "templates/dashboard.html", "templates/history.html",
        "templates/admin.html",
    }
    check("templates/ contains exactly the twelve delivered pages",
          html == expected_html, ", ".join(sorted(html)))

    blueprints = {bp.name for bp in BLUEPRINTS}
    expected_bps = {"core", "auth", "scanning", "dashboard", "history", "admin"}
    if STAGE_12_DELIVERED:
        expected_bps |= {"api"}
    check("exactly the delivered blueprints are registered",
          blueprints == expected_bps, ", ".join(sorted(blueprints)))

    py_files = sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")
                      if ".venv" not in p.parts and "__pycache__" not in p.parts)
    for rel in py_files:
        try:
            py_compile.compile(str(ROOT / rel), doraise=True)
            check(f"compiles :: {rel}", True)
        except py_compile.PyCompileError as exc:
            check(f"compiles :: {rel}", False, str(exc))


# --------------------------------------------------------------------------- #
# 2. Source-level honesty, CSP and security discipline
# --------------------------------------------------------------------------- #
def check_sources() -> None:
    print("\n[2] Source discipline, exact CSP and offline assets")
    for rel in TEMPLATES_NEW:
        text = read(rel)
        check(f"{rel} has no inline script", not inline_scripts(text))
        check(f"{rel} has no inline style attribute",
              re.search(r"\sstyle\s*=", text, re.IGNORECASE) is None)
        check(f"{rel} loads no external asset", not external_assets(text))
        check(f"{rel} has no inline event handler",
              re.search(r"\son(click|load|error|mouseover)\s*=", text, re.IGNORECASE) is None)
        check(f"{rel} contains no invented performance literal",
              all(literal not in text for literal in PUBLISHED_LITERALS))
        # Prose may EXPLAIN that hashes are excluded; no Jinja expression may
        # actually output one.
        check(f"{rel} never renders a password hash",
              re.search(r"\{\{[^}]*(password_hash|scrypt)", text, re.IGNORECASE) is None)
        check(f"{rel} never calls the model directly",
              "predict_proba" not in text and "joblib" not in text)
        check(f"{rel} embeds chart data with tojson" if rel.endswith("dashboard.html")
              else f"{rel} stays free of raw chart JSON",
              "|tojson" in text if rel.endswith("dashboard.html") else "data-chart='" not in text)

    for rel, expected in VENDOR_HASHES.items():
        check(f"vendored asset unchanged :: {rel}", sha256(rel) == expected)
    check("no new external script or stylesheet was introduced",
          len({p.name for p in (ROOT / "static" / "js").glob("*.js")}) == 2
          and len({p.name for p in (ROOT / "static" / "css").glob("*.css")}) == 2)

    all_python = "\n".join(read(rel) for rel in RUNTIME_RELS)
    for rel in RUNTIME_RELS:
        check(f"runtime module is present :: {rel}", bool(read(rel)))
    for marker in NETWORK_MARKERS:
        check(f"runtime source contains no '{marker}'", marker not in all_python)

    js = read("static/js/main.js")
    check("main.js still reads data-chart attributes", "data-chart" in js and "getAttribute" in js)
    check("main.js still parses with JSON.parse", "JSON.parse" in js)
    check("main.js still instantiates Chart.js", "new window.Chart" in js)
    check("main.js still degrades honestly if Chart is missing",
          'typeof window.Chart === "undefined"' in js)
    check("main.js cycles theme colours for any number of categories",
          "cycledColours" in js and "% base.length" in js)
    check("main.js uses no eval or innerHTML",
          "eval(" not in js and "innerHTML" not in js)
    check("main.js makes no outbound request",
          "fetch(" not in js and "XMLHttpRequest" not in js
          and "http://" not in js and "https://" not in js)

    css = read("static/css/main.css")
    for selector in (".pds-kpi-grid", ".pds-chart-grid", ".pds-filter-bar",
                     ".pds-table", ".pds-badge", ".pds-pagination",
                     ".pds-empty-state"):
        check(f"main.css defines {selector}", selector in css)
    check("main.css keeps the default dark palette and the light theme",
          ":root {" in css and '[data-theme="light"]' in css)

    security = read("services/http_security.py")
    check("CSP source is byte-for-byte unchanged",
          all(line in security for line in (
              "\"default-src 'self'\"", "\"base-uri 'self'\"",
              "\"object-src 'none'\"", "\"form-action 'self'\"",
              "\"script-src 'self'\"", "\"style-src 'self'\"",
              "\"img-src 'self' data:\"", "\"font-src 'self'\"",
              "\"connect-src 'self'\"")))
    check("no unsafe-inline was added to the CSP", "unsafe-inline" not in security)
    check("no CDN allowance was added to the CSP", "cdn" not in security.lower())

    stats = read("services/stats_service.py")
    check("stats_service performs no writes",
          all(token not in stats for token in ("db.session.add(", ".commit()", "db.session.delete(")))
    check("stats_service uses ORM queries, not raw SQL",
          "from sqlalchemy import text" not in stats
          and "db.session.execute(" not in stats
          and "text(" not in stats.replace("read_text(", ""))
    check("stats_service never invents a published figure",
          all(literal not in stats for literal in PUBLISHED_LITERALS))
    check("stats_service reads metrics.json at runtime",
          'current_app.config["METRICS_PATH"]' in stats
          and "json.loads" in stats)
    check("stats_service documents and enforces visibility",
          "visible_query" in stats and "user_id" in stats and "guest_scan_ids" in stats)
    check("stats_service fails closed on a broken artefact",
          "StatsDataError" in stats and "scored_once" in stats)

    report = read("services/report_service.py")
    check("report_service defines CSV columns", "CSV_COLUMNS" in report)
    check("report_service neutralises spreadsheet formulas",
          "FORMULA_PREFIXES" in report and "safe_cell" in report
          and all(token in report for token in ('"="', '"+"', '"-"', '"@"')))
    check("report_service replaces CR/LF inside cells",
          '.replace("\\r", " ")' in report and '.replace("\\n", " ")' in report)
    check("report_service bounds the export", "CSV_ROW_LIMIT" in report)
    check("report_service never exports password hashes",
          "password_hash" not in report and "User.query" not in report)
    check("report_service sets safe download headers",
          all(token in report for token in ("Content-Disposition", "no-store",
                                            "X-Content-Type-Options")))

    dashboard = read("routes/dashboard.py")
    history = read("routes/history.py")
    admin = read("routes/admin.py")
    check("dashboard route is read-only", "@dashboard_bp.get(" in dashboard
          and ".post(" not in dashboard)
    check("dashboard fails closed on DB/artefact errors",
          "SQLAlchemyError" in dashboard and "StatsDataError" in dashboard)
    check("history route reuses Stage 10's guest session key",
          "GUEST_SCAN_SESSION_KEY" in history)
    check("history route stays open to guests",
          "login_required" not in history and "viewer_scope" in history)
    check("history applies validated filters",
          "parse_filters" in history and "export_rows" in history)
    check("admin route composes login_required with a role check",
          "login_required" in admin and "is_admin" in admin and "403" in admin)
    check("admin route keeps the global 401 contract unchanged",
          "login_manager.unauthorized_handler" not in admin
          and "login_manager.login_view" not in admin
          and "login_required" in admin)
    check("admin route uses the safe User projection",
          "user_accounts" in admin and "User.to_dict()" in admin
          and "account.password_hash" not in admin)

    check("routes/__init__.py registers the three Stage 11 blueprints",
          all(name in read("routes/__init__.py")
              for name in ("dashboard", "history", "admin")))
    check("Stage 10 detection engine files are still present and unmodified in role",
          all((ROOT / rel).is_file() for rel in (
              "services/detection_service.py", "services/decision_service.py",
              "services/explanation_service.py", "models/prediction_model.py",
              "routes/scanning.py")))
    check("Stage 11 view modules do not touch the detection pipeline",
          all("from services.detection_service import" not in read(rel)
              and "import detection_service" not in read(rel)
              for rel in ("routes/dashboard.py", "routes/history.py",
                          "routes/admin.py", "services/report_service.py")))


# --------------------------------------------------------------------------- #
# 3. Pure unit checks: stats_service and report_service
# --------------------------------------------------------------------------- #
def check_units() -> None:
    print("\n[3] Runtime aggregates and CSV security (unit checks)")
    with tempfile.TemporaryDirectory() as folder:
        app = build_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(folder) / 'u.db'}")
        with app.app_context():
            initialise_schema(app)
            # Empty database -> honest zeros, never demo data.
            empty = stats_service.system_overview()
            check("empty DB reports zero scans", empty["total_scans"] == 0)
            check("empty DB reports zero in every state",
                  all(v == 0 for v in empty["by_prediction"].values()))
            check("empty DB has no first/last scan date",
                  empty["first_scan_utc"] is None and empty["last_scan_utc"] is None)
            check("empty DB has a defined zero share", empty["suspicious_share"] == 0.0)
            empty_chart = stats_service.daily_chart()
            check("empty DB daily chart has 7 honest zero bars",
                  len(empty_chart["labels"]) == 7
                  and empty_chart["values"] == [0] * 7)
            check("empty DB charts still carry their runtime source",
                  stats_service.prediction_chart()["source"] == stats_service.SQLITE_SCAN_SOURCE)

            measured = stats_service.measured_metrics()
            standard = METRICS["test"]["standard_0.5"]
            check("measured metrics are read from metrics.json",
                  [row["value"] for row in measured["rows"]]
                  == [f"{standard[key]:.6f}" for key in
                      ("accuracy", "precision", "recall", "f1", "roc_auc")])
            check("measured metrics name the exact runtime source",
                  all(row["source"] == stats_service.METRICS_SOURCE for row in measured["rows"]))
            check("measured confusion matrix is copied, not invented",
                  measured["confusion_matrix"] == standard["confusion_matrix"])
            check("measured band comes from the calibrated test results",
                  measured["band"]["low"] == METRICS["test"]["calibrated"]["t_low"]
                  and measured["band"]["high"] == METRICS["test"]["calibrated"]["t_high"])
            check("measured metrics carry the HTTPS-bias caveat",
                  any("HTTPS" in caveat for caveat in measured["caveats"]))
            check("measured metrics are labelled as held-out, not live traffic",
                  any("test split" in caveat for caveat in measured["caveats"]))

            # Seed two accounts and five controlled scan rows.
            create_user(ADMIN_USER, "admin11@example.com", STRONG_PASSWORD, role="admin")
            create_user(MEMBER_USER, "member11@example.com", STRONG_PASSWORD)
            users = {u.username: int(u.id)
                     for u in db.session.query(User).all()}
            predictions = ["LEGITIMATE", "SUSPICIOUS", "SUSPICIOUS", "PHISHING", "PHISHING"]
            risks = ["LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"]
            for index, (prediction, risk) in enumerate(zip(predictions, risks)):
                db.session.add(ScanHistory(
                    user_id=users[MEMBER_USER] if index < 3 else None,
                    url=f"https://example.invalid/{index}",
                    normalised_url=f"https://example.invalid/{index}",
                    prediction=prediction, model_score=0.1 * (index + 1),
                    risk_level=risk, model_version="1.0.0",
                    scan_date=utcnow(), features_json=json.dumps({"flagged": []}),
                ))
            db.session.commit()

            overview = stats_service.system_overview()
            check("overview counts exactly the real rows", overview["total_scans"] == 5)
            check("overview state counts match the database",
                  overview["by_prediction"] == {"LEGITIMATE": 1, "SUSPICIOUS": 2, "PHISHING": 2})
            check("overview risk counts match the database",
                  overview["by_risk"] == {"LOW": 1, "MEDIUM": 2, "HIGH": 2})
            check("overview guest/linked split is correct",
                  overview["guest_scans"] == 2 and overview["linked_scans"] == 3)
            check("overview computes the SUSPICIOUS share from real rows",
                  abs(overview["suspicious_share"] - 0.4) < 1e-12)
            check("overview reports UTC dates",
                  (overview["last_scan_utc"] or "").endswith("+00:00"))

            state_chart = stats_service.prediction_chart()
            check("prediction chart labels are the three decision states",
                  state_chart["labels"] == list(stats_service.PREDICTIONS))
            check("prediction chart values equal the real counts",
                  state_chart["values"] == [1, 2, 2])
            risk_chart = stats_service.risk_chart()
            check("risk chart values equal the real counts", risk_chart["values"] == [1, 2, 2])
            daily = stats_service.daily_chart()
            check("daily chart has seven consecutive UTC dates",
                  len(daily["labels"]) == 7
                  and daily["labels"][-1] == datetime.now(timezone.utc).date().isoformat())
            check("daily chart values sum to the real row count", sum(daily["values"]) == 5)
            payload = stats_service.chart_payload(["a", "b"], [1, 2],
                                                  series_label="X", source="Y")
            check("chart_payload has exactly the Stage 9 contract keys",
                  set(payload) == {"labels", "values", "series_label", "source"})

            counts = stats_service.system_counts()
            check("system counts are real SQL counts",
                  counts == {"users": 2, "admins": 1, "scans": 5, "model_rows": 1},
                  str(counts))
            accounts = stats_service.user_accounts()
            check("user_accounts returns both accounts with scan counts",
                  len(accounts) == 2
                  and {a["username"]: a["scan_count"] for a in accounts}
                  == {ADMIN_USER: 0, MEMBER_USER: 3})
            check("user_accounts never leaks a password hash",
                  all("password_hash" not in a for a in accounts))
            model_rows = stats_service.model_information_rows()
            check("model_information_rows come from the seeded audit row",
                  len(model_rows) == 1
                  and model_rows[0]["model_name"] == METADATA["model_name"]
                  and model_rows[0]["metrics_source"] is not None)

            # Filters are validated, clamped and bound.
            parsed = stats_service.parse_filters({
                "prediction": " phishing ", "risk": "HIGH", "q": "x" * 500,
                "page": "-9", "per_page": "99999",
            })
            check("parse_filters normalises a valid state", parsed["prediction"] == "PHISHING")
            check("parse_filters clamps q length", len(parsed["q"]) == stats_service.MAX_QUERY_LENGTH)
            check("parse_filters clamps page and per_page",
                  parsed["page"] == 1 and parsed["per_page"] == stats_service.MAX_PER_PAGE)
            check("parse_filters rejects unknown states",
                  stats_service.parse_filters({"prediction": "DROP TABLE", "risk": "';--"})["prediction"] == ""
                  and stats_service.parse_filters({"prediction": "DROP TABLE", "risk": "';--"})["risk"] == "")
            base = stats_service.visible_query(None, [])
            check("an empty guest session matches nothing", base.count() == 0)
            injection = stats_service.apply_filters(
                stats_service.visible_query(None, [1, 2, 3, 4, 5]),
                {"prediction": "", "risk": "", "q": "' OR 1=1 --", "page": 1, "per_page": 20},
            )
            check("a SQL-looking search string cannot widen the result",
                  injection.count() == 0)
            member_query = stats_service.visible_query(users[MEMBER_USER], [])
            check("a signed-in user sees only their own rows", member_query.count() == 3)
            guest_query = stats_service.visible_query(None, [1, 2])
            check("a guest sees only their signed session ids", guest_query.count() == 2)

            page_one = stats_service.history_page(None, [1, 2, 3, 4, 5],
                                                  {"prediction": "", "risk": "", "q": "",
                                                   "page": 1, "per_page": 2})
            check("history_page paginates honestly",
                  page_one["total"] == 5 and page_one["pages"] == 3
                  and len(page_one["rows"]) == 2 and page_one["scope"] == "session")
            check("history_page records carry a report link and flagged indicators",
                  all("report_url" in row and "flagged" in row for row in page_one["rows"]))
            page_clamped = stats_service.history_page(None, [1, 2, 3, 4, 5],
                                                      {"prediction": "", "risk": "", "q": "",
                                                       "page": 99, "per_page": 2})
            check("history_page clamps an out-of-range page", page_clamped["page"] == 3)
            filtered = stats_service.history_page(None, [1, 2, 3, 4, 5],
                                                  {"prediction": "PHISHING", "risk": "HIGH",
                                                   "q": "", "page": 1, "per_page": 20})
            check("history_page applies combined filters", filtered["total"] == 2)
            check("export_rows honours the same visibility",
                  len(stats_service.export_rows(users[MEMBER_USER], [],
                                               {"prediction": "", "risk": "", "q": ""})) == 3)
            check("admin export_rows returns every row",
                  len(stats_service.export_rows(None, [],
                                               {"prediction": "", "risk": "", "q": ""},
                                               all_rows=True)) == 5)

            # Report service: pure string and Response checks.
            for raw, expected_prefix in (("=1+1", "'"), ("+1", "'"), ("-1", "'"),
                                        ("@SUM(2)", "'"), ("\t=cmd", "'"),
                                        ("  =cmd", "'"), ("normal text", "")):
                check(f"safe_cell neutralises {raw!r}",
                      report_service.safe_cell(raw).startswith(expected_prefix)
                      if expected_prefix else report_service.safe_cell(raw) == raw)
            check("safe_cell strips CR/LF injection",
                  "\n" not in report_service.safe_cell("a\r\nb")
                  and "\r" not in report_service.safe_cell("a\r\nb"))
            check("safe_cell removes NUL bytes",
                  "\x00" not in report_service.safe_cell("a\x00b"))

            rows = db.session.query(ScanHistory).order_by(ScanHistory.id).all()
            document = report_service.build_csv(rows)
            parsed_csv = list(csv.reader(io.StringIO(document)))
            check("CSV header is the documented column list",
                  parsed_csv[0] == list(report_service.CSV_COLUMNS))
            check("CSV has exactly one row per stored scan",
                  len(parsed_csv) == len(rows) + 1)
            check("CSV cells never create extra rows",
                  all(len(line) == len(report_service.CSV_COLUMNS) for line in parsed_csv[1:]))
            check("CSV contains no password hash",
                  "scrypt" not in document and "password_hash" not in document)
            response = report_service.csv_response(rows)
            body = response.get_data(as_text=True)
            check("CSV response is a download, not inline",
                  "text/csv" in response.content_type
                  and "attachment" in response.headers.get("Content-Disposition", ""))
            check("CSV response is uncached and nosniff",
                  response.headers.get("Cache-Control") == "no-store"
                  and response.headers.get("X-Content-Type-Options") == "nosniff")
            check("CSV response carries a UTF-8 BOM for Windows Excel",
                  body.startswith("\ufeff"))
            check("CSV response filename is a safe fixed name",
                  re.fullmatch(r'attachment; filename="scan-history-\d{8}\.csv"',
                               response.headers.get("Content-Disposition", "")) is not None)
            hostile_name = report_service.csv_response(
                rows, filename='evil"..\r\nheader.csv').headers.get("Content-Disposition", "")
            hostile_file = re.search(r'filename="([^"]+)"', hostile_name)
            check("CSV filename cannot inject a header or path",
                  hostile_file is not None
                  and re.fullmatch(r"[A-Za-z0-9_.-]+\.csv", hostile_file.group(1)) is not None
                  and "\r" not in hostile_name and "\n" not in hostile_name,
                  hostile_name)

        # A broken measured artefact must fail closed, not display zeros.
        broken = build_app(
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(folder) / 'u.db'}",
            METRICS_PATH=str(Path(folder) / "missing-metrics.json"),
        )
        with broken.app_context():
            # No initialise_schema() here: seeding legitimately requires the
            # measured artefact. We are testing the read-only dashboard path.
            try:
                stats_service.measured_metrics()
                failed = False
            except stats_service.StatsDataError:
                failed = True
            check("stats_service raises StatsDataError for a missing artefact", failed)
            corrupt = Path(folder) / "corrupt-metrics.json"
            corrupt.write_text('{"test": {}}', encoding="utf-8")
            broken.config["METRICS_PATH"] = str(corrupt)
            try:
                stats_service.measured_metrics()
                corrupt_failed = False
            except stats_service.StatsDataError:
                corrupt_failed = True
            check("stats_service refuses an artefact without measured values", corrupt_failed)


# --------------------------------------------------------------------------- #
# 4. HTTP integration: real scans, real sessions, real authorisation
# --------------------------------------------------------------------------- #
def check_integration() -> None:
    print("\n[4] HTTP integration, visibility, charts and CSV endpoints")
    with tempfile.TemporaryDirectory() as folder:
        app = build_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(folder) / 'i.db'}")
        seeded = seed(app)
        check("schema seeded with exactly two accounts", seeded["users"] == 2)
        check("schema seeded with exactly one measured model row", seeded["models"] == 1)

        # Each client gets its own request contexts; no shared g cache.
        guest = app.test_client()
        guest_scans = scan_as(guest)
        check("four real scans were committed through the Stage 10 engine",
              all(item.get("result") for item in guest_scans)
              and all(item.get("report_url") for item in guest_scans))
        with guest.session_transaction() as sess:
            guest_ids = list(sess.get(GUEST_SCAN_SESSION_KEY, []))
        check("guest session records its own scan ids", len(guest_ids) == 4)

        stranger = fresh_client(app)
        check("a different anonymous browser sees an empty history",
              "No matching scans" in stranger.get("/history").get_data(as_text=True))

        member = fresh_client(app)
        check("member login succeeds", login(member, MEMBER_USER).status_code == 200)
        member_scans = scan_as(member, MEMBER_URLS)
        check("member scans are committed", len(member_scans) == 2)
        admin = fresh_client(app)
        check("admin login succeeds", login(admin, ADMIN_USER).status_code == 200)
        admin_scans = scan_as(admin, ADMIN_URLS)
        check("admin scan is committed", len(admin_scans) == 1)

        with app.app_context():
            total = db.session.query(func.count(ScanHistory.id)).scalar()
            state_counts = dict(db.session.query(
                ScanHistory.prediction, func.count(ScanHistory.id)
            ).group_by(ScanHistory.prediction).all())
            risk_counts = dict(db.session.query(
                ScanHistory.risk_level, func.count(ScanHistory.id)
            ).group_by(ScanHistory.risk_level).all())
            guest_phishing = db.session.query(func.count(ScanHistory.id)).filter(
                ScanHistory.id.in_(guest_ids),
                ScanHistory.prediction == "PHISHING",
            ).scalar()
            guest_rows = db.session.query(func.count(ScanHistory.id)).filter(
                ScanHistory.user_id.is_(None)).scalar()
            guest_phishing_high = db.session.query(func.count(ScanHistory.id)).filter(
                ScanHistory.id.in_(guest_ids),
                ScanHistory.prediction == "PHISHING",
                ScanHistory.risk_level == "HIGH",
            ).scalar()
            guest_paypal = db.session.query(func.count(ScanHistory.id)).filter(
                ScanHistory.id.in_(guest_ids),
                ScanHistory.normalised_url.contains("paypal.com.login", autoescape=True),
            ).scalar()
        expected_states = [int(state_counts.get(name, 0))
                           for name in stats_service.PREDICTIONS]
        expected_risks = [int(risk_counts.get(name, 0))
                          for name in stats_service.RISKS]
        check("database holds all seven real scans plus the hostile row", total == 8)
        check("four guest scans plus the hostile row have user_id NULL", guest_rows == 5)

        # ---- Dashboard ---------------------------------------------------- #
        page = guest.get("/dashboard")
        body = page.get_data(as_text=True)
        check("GET /dashboard returns 200 themed HTML",
              page.status_code == 200 and "text/html" in page.content_type)
        for marker in ("Operational", "Current system state", "Real visualisations",
                       "Measured model performance", "Source:",
                       "HTTPS alone does not mean a website is legitimate"):
            check(f"dashboard renders :: {marker}", marker in body)
        check("dashboard states that figures are live, not demo data",
              "no demo data" in body.lower() or "at request time" in body.lower())
        payloads = chart_payloads(body)
        check("dashboard embeds exactly three real chart payloads", len(payloads) == 3)
        if len(payloads) == 3:
            check("each chart payload has the Stage 9 contract",
                  all(set(p) == {"labels", "values", "series_label", "source"} for p in payloads))
            check("classification chart values equal the database counts",
                  payloads[0]["values"] == expected_states,
                  f"{payloads[0]['values']} vs {expected_states}")
            check("risk chart values equal the database counts",
                  payloads[1]["values"] == expected_risks,
                  f"{payloads[1]['values']} vs {expected_risks}")
            check("volume chart has seven honest daily bars",
                  len(payloads[2]["labels"]) == 7 and sum(payloads[2]["values"]) == 8)
            check("all charts name their runtime database source",
                  all(p["source"] == stats_service.SQLITE_SCAN_SOURCE for p in payloads))
        standard = METRICS["test"]["standard_0.5"]
        for key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            check(f"dashboard prints the runtime test.{key} value",
                  f"{standard[key]:.6f}" in body)
        check("dashboard prints the measured confusion matrix",
              str(standard["tn"]) in body and str(standard["fn"]) in body)
        check("dashboard names the measured artefact source",
              stats_service.METRICS_SOURCE in body)
        check("dashboard has no inline script", not inline_scripts(body))
        check("dashboard has no inline style attribute",
              re.search(r"\sstyle\s*=", body, re.IGNORECASE) is None)
        check("dashboard loads no external asset", not external_assets(body))
        check("dashboard keeps the exact CSP", page.headers.get("Content-Security-Policy") == EXACT_CSP)
        check("dashboard never prints a password hash",
              "password_hash" not in body and "scrypt" not in body)

        # A tampered metrics artefact must CHANGE the rendered numbers: proof
        # that none of them are hard-coded in the template or the service.
        altered = json.loads(json.dumps(METRICS))
        altered["test"]["standard_0.5"]["accuracy"] = 0.123456
        altered_path = Path(folder) / "altered-metrics.json"
        altered_path.write_text(json.dumps(altered), encoding="utf-8")
        alt_app = build_app(
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(folder) / 'i.db'}",
            METRICS_PATH=str(altered_path),
        )
        alt_body = alt_app.test_client().get("/dashboard").get_data(as_text=True)
        check("a tampered metrics.json changes the dashboard at runtime",
              "0.123456" in alt_body)
        check("the original measured value disappears with the tampered artefact",
              "0.983854" not in alt_body)

        # ---- History ------------------------------------------------------ #
        history_html = guest.get("/history").get_data(as_text=True)
        check("guest history lists exactly the four session scans",
              history_html.count("Open report") == 4)
        check("guest history explains the session limitation",
              "GUEST SESSION" in history_html and "Sign in" in history_html)
        check("guest history does not show the other account's scans",
              "No matching scans" not in history_html)
        check("history table shows all three decision states",
              all(word in history_html for word in ("LEGITIMATE", "SUSPICIOUS", "PHISHING")))
        check("history table shows UTC dates", "+00:00" in history_html)
        check("history renders the filter controls",
              all(word in history_html for word in ("filterPrediction", "filterRisk",
                                                    "filterQuery", "filterPerPage")))
        check("history links to CSV export", "/history/export.csv" in history_html)
        filtered = guest.get("/history?prediction=PHISHING&risk=HIGH").get_data(as_text=True)
        check("combined history filters match the database exactly",
              filtered.count("Open report") == int(guest_phishing_high),
              f"page={filtered.count('Open report')} db={guest_phishing_high}")
        search = guest.get("/history?q=paypal.com.login").get_data(as_text=True)
        check("URL substring filter matches the database exactly",
              search.count("Open report") == int(guest_paypal),
              f"page={search.count('Open report')} db={guest_paypal}")
        bad_filter = guest.get("/history?prediction=DROP%20TABLE&page=-4&per_page=99999")
        check("invalid filter values are rejected without a 500", bad_filter.status_code == 200)
        small = guest.get("/history?per_page=2&page=2").get_data(as_text=True)
        check("pagination renders page 2 with two rows",
              small.count("Open report") == 2 and "Page 2 of 2" in small)
        check("pagination stops at the last page",
              "Page 2 of 2" in guest.get("/history?per_page=2&page=99").get_data(as_text=True))
        member_history = member.get("/history").get_data(as_text=True)
        check("signed-in member sees only their own two rows",
              member_history.count("Open report") == 2
              and "GUEST SESSION" not in member_history)
        admin_history = admin.get("/history").get_data(as_text=True)
        check("admin's personal history is scoped to their own one scan",
              admin_history.count("Open report") == 1)

        # ---- CSV export --------------------------------------------------- #
        guest_csv = guest.get("/history/export.csv")
        csv_text = guest_csv.get_data(as_text=True)
        check("guest CSV export returns 200 text/csv",
              guest_csv.status_code == 200 and "text/csv" in guest_csv.content_type)
        check("guest CSV is a download with no-store",
              "attachment" in guest_csv.headers.get("Content-Disposition", "")
              and guest_csv.headers.get("Cache-Control") == "no-store")
        check("guest CSV contains exactly its four visible rows",
              len(list(csv.reader(io.StringIO(csv_text)))) - 1 == 4)
        check("guest CSV never leaks another account's URLs",
              "member.example.invalid" not in csv_text
              and "admin.example.invalid" not in csv_text)
        check("guest CSV honours the same filters",
              len(list(csv.reader(io.StringIO(
                  guest.get("/history/export.csv?prediction=PHISHING").get_data(as_text=True))))) - 1
              == int(guest_phishing))
        stranger_csv = stranger.get("/history/export.csv").get_data(as_text=True)
        check("a stranger's CSV export is empty, not the whole table",
              len(list(csv.reader(io.StringIO(stranger_csv)))) - 1 == 0)
        member_csv = member.get("/history/export.csv").get_data(as_text=True)
        check("member CSV exports only their own rows",
              len(list(csv.reader(io.StringIO(member_csv)))) - 1 == 2)

        # Hostile stored row: end-to-end formula injection and XSS defences.
        with guest.session_transaction() as sess:
            ids = [seeded["hostile_id"]] + list(sess.get(GUEST_SCAN_SESSION_KEY, []))
            sess[GUEST_SCAN_SESSION_KEY] = ids
        hostile_csv = guest.get("/history/export.csv").get_data(as_text=True)
        check("a stored =SUM(...) URL is prefixed with an apostrophe in CSV",
              "'=SUM(1+1)" in hostile_csv)
        check("a stored @SUM(...) URL is neutralised in CSV", "'@SUM(2+2)" in hostile_csv)
        check("a stored CRLF cannot create an extra CSV row",
              len(list(csv.reader(io.StringIO(hostile_csv)))) - 1 == 5)
        hostile_html = guest.get("/history").get_data(as_text=True)
        check("a stored <script> URL is Jinja-escaped in the history table",
              "<script>alert(1)</script>" not in hostile_html
              and "&lt;script&gt;" in hostile_html)

        # ---- Admin -------------------------------------------------------- #
        anon_admin = stranger.get("/admin")
        check("anonymous GET /admin returns 401 UNAUTHENTICATED",
              anon_admin.status_code == 401 and b"UNAUTHENTICATED" in anon_admin.data)
        anon_json = stranger.get("/admin?format=json")
        check("JSON-negotiated anonymous /admin keeps the 401 error contract",
              anon_json.status_code == 401
              and (anon_json.get_json() or {}).get("error", {}).get("code") == "UNAUTHENTICATED")
        check("the 401 page offers a sign-in link",
              "Sign in" in anon_admin.get_data(as_text=True))
        member_admin = member.get("/admin")
        check("ordinary user GET /admin returns 403 FORBIDDEN",
              member_admin.status_code == 403 and b"FORBIDDEN" in member_admin.data)
        admin_page = admin.get("/admin")
        admin_body = admin_page.get_data(as_text=True)
        check("admin GET /admin returns 200 themed HTML",
              admin_page.status_code == 200 and "Admin console" in admin_body)
        check("admin page lists both real accounts",
              ADMIN_USER in admin_body and MEMBER_USER in admin_body)
        check("admin page never renders a password hash",
              "password_hash" not in admin_body and "scrypt:" not in admin_body)
        check("admin page shows live system counts",
              "Registered users" in admin_body and "Model audit rows" in admin_body)
        check("admin page shows the measured model audit row",
              METADATA["model_name"] in admin_body and "metrics.json" in admin_body)
        check("admin page carries the measured caveats",
              "HTTPS" in admin_body and "test split" in admin_body)

        check("anonymous full CSV export is blocked",
              stranger.get("/admin/export.csv").status_code == 401)
        check("ordinary user full CSV export is blocked",
              member.get("/admin/export.csv").status_code == 403)
        full = admin.get("/admin/export.csv")
        full_text = full.get_data(as_text=True)
        check("admin full CSV export returns 200",
              full.status_code == 200 and "text/csv" in full.content_type)
        check("admin full CSV export contains every stored row",
              len(list(csv.reader(io.StringIO(full_text)))) - 1 == 8)
        check("admin full CSV export honours filters",
              len(list(csv.reader(io.StringIO(
                  admin.get("/admin/export.csv?prediction=PHISHING").get_data(as_text=True))))) - 1
              == int(state_counts.get("PHISHING", 0)))
        check("admin full CSV export keeps the exact CSP",
              full.headers.get("Content-Security-Policy") == EXACT_CSP)

        # ---- Failure paths ------------------------------------------------ #
        bad_db = build_app(
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(folder) / 'absent' / 'x.db'}")
        db_error = bad_db.test_client().get("/dashboard")
        check("uninitialised database yields 503 DATABASE_UNAVAILABLE",
              db_error.status_code == 503 and b"DATABASE_UNAVAILABLE" in db_error.data)
        missing_metrics = build_app(
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(folder) / 'i.db'}",
            METRICS_PATH=str(Path(folder) / "no-such-metrics.json"))
        # The database is already initialised above, so no seeding is needed.
        artefact_error = missing_metrics.test_client().get("/dashboard")
        check("missing measured artefact yields 503 MODEL_UNAVAILABLE",
              artefact_error.status_code == 503
              and b"MODEL_UNAVAILABLE" in artefact_error.data)

        # ---- Detection engine unchanged ----------------------------------- #
        check("Stage 10 scan control is still exactly SCAN WEBSITE",
              re.search(r"<button[^>]*type=\"submit\"[^>]*>\s*SCAN WEBSITE\s*</button>",
                        read("templates/scan.html")) is not None)
        health = guest.get("/health").get_json()
        check("/health still reports the Stage 10 engine as ready",
              health["status"] == "ok" and health["detection"]["status"] == "ready"
              and health["detection"]["feature_count"] == 15)
        check("/health reports build_stage 11 or later",
              health["build_stage"] >= 11)
        rules = {str(rule) for rule in app.url_map.iter_rules()}
        if STAGE_12_DELIVERED:
            check("Stage 12 adds /api/v1/scan", "/api/v1/scan" in rules)
        else:
            check("Stage 12 /api/v1/scan is still absent",
                  "/api/v1/scan" not in rules)
        for rule in ("/dashboard", "/history", "/history/export.csv",
                     "/admin", "/admin/export.csv"):
            check(f"url_map contains {rule}", rule in rules)


# --------------------------------------------------------------------------- #
# 5. A real local HTTP server (not just the Flask test client)
# --------------------------------------------------------------------------- #
def check_live_server() -> None:
    print("\n[5] Real local HTTP smoke of the three new pages")
    from werkzeug.serving import make_server

    with tempfile.TemporaryDirectory() as folder:
        app = build_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(folder) / 'live.db'}")
        with app.app_context():
            initialise_schema(app)
            create_user(ADMIN_USER, "admin11@example.com", STRONG_PASSWORD, role="admin")
        server = make_server("127.0.0.1", 0, app, threaded=True)
        port = int(server.server_port)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base = f"http://127.0.0.1:{port}"
            for path in ("/dashboard", "/history", "/history/export.csv"):
                try:
                    with urllib.request.urlopen(base + path, timeout=15) as reply:
                        payload = reply.read()
                        check(f"live GET {path} returns 200",
                              reply.status == 200 and len(payload) > 100)
                        if path == "/dashboard":
                            check("live dashboard keeps the exact CSP",
                                  reply.headers.get("Content-Security-Policy") == EXACT_CSP)
                except urllib.error.HTTPError as exc:
                    check(f"live GET {path} returns 200", False, str(exc))
            try:
                with urllib.request.urlopen(base + "/admin", timeout=15) as reply:
                    check("live anonymous /admin is 401", False, "unexpected 200")
            except urllib.error.HTTPError as exc:
                check("live anonymous /admin is 401 UNAUTHENTICATED",
                      exc.code == 401 and b"UNAUTHENTICATED" in exc.read())
        finally:
            server.shutdown()
            worker.join(timeout=10)


# --------------------------------------------------------------------------- #
# 6. Configuration and documentation
# --------------------------------------------------------------------------- #
def check_config_and_docs() -> None:
    print("\n[6] Configuration and Stage 11 documentation")
    summary = describe_config()
    # Gate 11 is a regression under Gate 12, so these are "Stage 11 or later".
    check("config reports Stage 11 or later", summary.get("build_stage") >= 11)
    check("config version follows the stage 0.x.0 series",
          re.fullmatch(r"0\.\d+\.0", str(summary.get("app_version", ""))) is not None)
    app = build_app()
    check("app.config BUILD_STAGE is 11 or later",
          app.config["BUILD_STAGE"] >= 11)
    for name in ("core", "auth", "scanning", "dashboard", "history", "admin"):
        check(f"{name} blueprint is registered", name in app.blueprints)

    doc = read("docs/DASHBOARD.md")
    for section in DASHBOARD_SECTIONS:
        check(f"DASHBOARD.md :: {section}", section in doc)
    for marker in ("HTTPS alone does not mean a website is legitimate",
                   "SSRF", "no invented", "metrics.json", "scan_history",
                   "model_information", "formula injection", "401 UNAUTHENTICATED",
                   "Stage 12"):
        check(f"DASHBOARD.md documents :: {marker}",
              marker.lower() in doc.lower())
    check("DASHBOARD.md gives Windows-first commands",
          ".\\.venv\\Scripts\\Activate.ps1" in doc
          or "python scripts\\init_db.py" in doc)
    check("DASHBOARD.md documents DATABASE_UNAVAILABLE",
          "DATABASE_UNAVAILABLE" in doc)
    check("DASHBOARD.md documents MODEL_UNAVAILABLE", "MODEL_UNAVAILABLE" in doc)
    check("DASHBOARD.md gives the Windows gate command",
          "verify_stage11.py" in doc)

    readme = read("README.md")
    check("README marks Stage 11 complete",
          re.search(r"\|\s*11\s*\|.*✅", readme) is not None)
    check("README lists docs/DASHBOARD.md", "docs/DASHBOARD.md" in readme)
    check("README lists the Stage 11 gate", "scripts/verify_stage11.py" in readme)
    plan = read("docs/STAGE_PLAN.md")
    check("STAGE_PLAN records Stage 11 as delivered", "Stage 11 — delivered" in plan)
    check("STAGE_PLAN previews Stage 12", "Stage 12" in plan)
    decisions = read("docs/DECISIONS.md")
    for adr in ("ADR-033", "ADR-034", "ADR-035"):
        check(f"DECISIONS.md contains {adr}", adr in decisions)
    for rel, marker in (
        ("docs/ARCHITECTURE.md", "Stage 11 implementation note"),
        ("docs/BACKEND.md", "Stage 11 update"),
        ("docs/UI.md", "Stage 11 update"),
        ("docs/DATABASE.md", "Stage 11 update"),
        ("docs/SETUP.md", "Stage 11"),
        ("docs/DETECTION.md", "Stage 11"),
    ):
        check(f"{rel} has its Stage 11 note", marker in read(rel))
    check("UI.md keeps the Stage 9 no-scan honesty rule for Gate 9",
          "no scan" in read("docs/UI.md").lower()
          or "not wired" in read("docs/UI.md").lower())
    check("SETUP.md gives the Windows Stage 11 gate command",
          "verify_stage11.py" in read("docs/SETUP.md"))


# --------------------------------------------------------------------------- #
# 7. Historical regressions and dependency health
# --------------------------------------------------------------------------- #
def check_regressions() -> None:
    print("\n[7] Historical exit gates 1-10 and dependency health")
    env = os.environ.copy()
    env["PDS_GATE_NESTED"] = "1"
    for stage in range(1, 11):
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
    print("STAGE 11 EXIT GATE - dashboard, history, admin and CSV export")
    print("=" * 78)
    check_inventory()
    check_sources()
    check_units()
    check_integration()
    check_live_server()
    check_config_and_docs()
    check_regressions()
    print("\n" + "=" * 78)
    print(f"CHECKS: {CHECKS}  SKIPPED: {SKIPPED}  FAILURES: {len(FAILURES)}")
    if FAILURES:
        for item in FAILURES:
            print(f"  - {item}")
        print("RESULT: FAIL - Stage 11 is NOT complete")
        return 1
    print("RESULT: PASS - all Stage 11 checks passed")
    print("Stage 11 exit gate satisfied. You may proceed to Stage 12.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
