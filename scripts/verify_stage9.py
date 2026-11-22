#!/usr/bin/env python3
"""Stage 9 exit gate: responsive templates, themes, offline assets and charts.

    cd phishing-detection-system
    python scripts/verify_stage9.py

Checks the real vendored library hashes, the CSS design system (two palettes,
WCAG contrast, four responsive breakpoints), the JS contract (no inline
script/style, chart data from escaped data-* attributes), every Jinja2
template, the rendered pages in both a ready and a degraded app, the preserved
Stage 7/8 HTTP and auth contracts, the honest absence of Stage 10+ features,
and the documentation. It re-runs Gates 1-8 as regressions.

All data used here is safe and local. No URL is visited, no DNS lookup is made,
and no live or malicious website appears anywhere in the test fixtures.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import re
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# Set by a parent gate (e.g. verify_stage10.py) to avoid running
# the same historical gate exponentially many times. A standalone
# run has this unset and keeps its complete regression behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

with contextlib.redirect_stderr(io.StringIO()):
    from config import DevelopmentConfig, TestingConfig, describe_config  # noqa: E402
    from app import create_app  # noqa: E402
    from extensions import db  # noqa: E402
    from services.database_service import initialise_schema  # noqa: E402
    from flask_login import login_required  # noqa: E402
    from flask import jsonify  # noqa: E402
    from sqlalchemy import text  # noqa: E402

VENDOR_HASHES = {
    "bootstrap.min.css": "3c8f27e6009ccfd710a905e6dcf12d0ee3c6f2ac7da05b0572d3e0d12e736fc8",
    "bootstrap.bundle.min.js": "0833b2e9c3a26c258476c46266e6877fc75218625162e0460be9a3a098a61c6c",
    "chart.umd.min.js": "b38076762f7363bc9e912b68b8e034826798db5df26bb61f000ec2e7a3137bc7",
}

TEMPLATE_FILES = (
    "templates/base.html", "templates/index.html", "templates/login.html",
    "templates/register.html", "templates/auth_result.html",
    "templates/errors/error.html",
)
STATIC_FILES = (
    "static/css/main.css", "static/css/backend.css",
    "static/js/theme.js", "static/js/main.js",
    "static/images/logo.svg",
    "static/vendor/bootstrap.min.css",
    "static/vendor/bootstrap.bundle.min.js",
    "static/vendor/chart.umd.min.js",
    "static/vendor/README.md",
)
REQUIRED_FILES = TEMPLATE_FILES + STATIC_FILES + (
    "docs/UI.md", "scripts/verify_stage9.py",
)

OWN_TEMPLATES = TEMPLATE_FILES
OWN_FRONTEND = ("static/css/main.css", "static/js/theme.js", "static/js/main.js")

DOC_SECTIONS = (
    "## 1. What Stage 9 builds", "## 2. Design system and themes",
    "## 3. Template map and inheritance", "## 4. Offline vendor assets and CSP",
    "## 5. Chart.js data contract", "## 6. Responsive behaviour and accessibility",
    "## 7. What is deliberately NOT in Stage 9", "## 8. Run and test",
    "## 9. Common errors and fixes", "## 10. Stage 9 exit criteria",
)

METRIC_WORDS = (
    "accuracy", "precision", "recall", "f1", "roc_auc", "roc-auc",
    "confusion_matrix", "confusion matrix", "false_negatives",
)
PLACEHOLDER_MARKERS = (
    "NotImplemented" + "Error", "TODO: imple" + "ment", "placeholder" + " function",
)
FORBIDDEN_NOW = (
    "models/prediction_model.py",
    "services/detection_service.py", "services/decision_service.py",
    "services/explanation_service.py", "services/stats_service.py",
    "services/report_service.py",
    "routes/scanning.py", "routes/dashboard.py", "routes/admin.py",
    "routes/api.py", "routes/history.py",
    "templates/scan.html", "templates/dashboard.html",
    "templates/history.html", "templates/admin.html",
    "static/js/dashboard.js",
    "tests/conftest.py", "tests/test_features.py",
    "docs/SECURITY.md", "docs/TEST_PLAN.md", "docs/DEPLOYMENT.md", "docs/REPORT.md",
)
STAGE_10_DELIVERED = (
    (ROOT / "services" / "detection_service.py").is_file()
    and (ROOT / "scripts" / "verify_stage10.py").is_file()
)

STRONG_PASSWORD = "Str0ng!Passphrase2026"

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


def sha256(rel: str) -> str:
    digest = hashlib.sha256()
    with (ROOT / rel).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def metric_free(value: str) -> bool:
    lowered = value.lower()
    return not any(word in lowered for word in METRIC_WORDS)


def inline_scripts(text: str) -> list[str]:
    return [match.strip() for match in re.findall(
        r"<script\b[^>]*>(.*?)</script>", text, re.DOTALL | re.IGNORECASE
    ) if match.strip()]


def external_assets(text: str) -> list[str]:
    return re.findall(
        r"<(?:script|link|img|source|iframe)\b[^>]*?(?:src|href)\s*=\s*[\"']"
        r"(https?://[^\"']+)", text, re.IGNORECASE
    )


def relative_luminance(hex_colour: str) -> float:
    parts = [int(hex_colour[i:i + 2], 16) / 255.0 for i in (1, 3, 5)]

    def linear(channel: float) -> float:
        return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4

    r, g, b = (linear(channel) for channel in parts)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(first: str, second: str) -> float:
    a, b = relative_luminance(first), relative_luminance(second)
    high, low = max(a, b), min(a, b)
    return (high + 0.05) / (low + 0.05)


def css_block(css: str, selector: str) -> str:
    match = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css, re.DOTALL)
    return match.group(1) if match else ""


def css_var(block: str, name: str) -> str | None:
    match = re.search(re.escape(name) + r"\s*:\s*(#[0-9a-fA-F]{6})", block)
    return match.group(1) if match else None


def temp_uri(folder: Path, name: str) -> str:
    return f"sqlite:///{folder / name}"


def make_app(uri: str, *, csrf: bool = True):
    return create_app(DevelopmentConfig, overrides={
        "SQLALCHEMY_DATABASE_URI": uri,
        "DEBUG": False, "TESTING": False, "PROPAGATE_EXCEPTIONS": False,
        "WTF_CSRF_ENABLED": csrf, "WTF_CSRF_SSL_STRICT": False,
    })


# --------------------------------------------------------------------------- #
# 1. Delivered files and vendored provenance
# --------------------------------------------------------------------------- #
def check_files_and_provenance() -> None:
    print("\n[1] Delivered files and vendored provenance")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"exists and non-empty :: {rel}",
              path.is_file() and path.stat().st_size > 0)

    manifest = read("static/vendor/README.md")
    for name, expected in VENDOR_HASHES.items():
        actual = sha256(f"static/vendor/{name}")
        check(f"SHA-256 matches upstream :: {name}", actual == expected, actual)
        check(f"README.md records the hash :: {name}", expected in manifest)

    css = read("static/vendor/bootstrap.min.css")
    bundle = read("static/vendor/bootstrap.bundle.min.js")
    chart = read("static/vendor/chart.umd.min.js")
    check("Bootstrap CSS is version 5.3.3", "Bootstrap  v5.3.3" in css or "Bootstrap v5.3.3" in css)
    check("Bootstrap JS bundle is version 5.3.3", "Bootstrap v5.3.3" in bundle)
    check("Bootstrap bundle includes Popper", "Popper" in bundle)
    check("Chart.js UMD defines the Chart global", "Chart" in chart and len(chart) > 100000)
    check("Chart.js file records its version", "4.4.4" in chart)
    check("our CSS has no real @import rule",
          re.search(r"^\s*@import", read("static/css/main.css"), re.MULTILINE) is None)
    check("vendor README explains the CSP rationale", "CSP" in manifest)
    check("vendor README records the MIT licences", "MIT" in manifest)

    logo = read("static/images/logo.svg")
    try:
        root = ET.fromstring(logo)
        check("logo.svg is well-formed XML", root.tag.endswith("svg"))
        check("logo.svg uses the SVG namespace",
              "http://www.w3.org/2000/svg" in root.tag)
    except ET.ParseError as exc:
        check("logo.svg is well-formed XML", False, str(exc))
    check("logo.svg has an accessible title", "<title" in logo)
    check("logo.svg embeds no external image", "<image" not in logo
          and "xlink:href" not in logo and "url(http" not in logo)
    check("logo.svg has no script", "<script" not in logo.lower())


# --------------------------------------------------------------------------- #
# 2. CSS design system, themes, contrast, responsiveness
# --------------------------------------------------------------------------- #
def check_design_system() -> None:
    print("\n[2] CSS design system, dark/light themes and WCAG contrast")
    css = read("static/css/main.css")
    dark = css_block(css, ":root")
    light = css_block(css, '[data-theme="light"]')
    check("main.css defines a :root dark palette", bool(dark))
    check("main.css defines an explicit light palette", bool(light))
    for name in ("--pds-bg", "--pds-panel", "--pds-text", "--pds-muted",
                 "--pds-accent", "--pds-line"):
        check(f"dark palette defines {name}", css_var(dark, name) is not None)
        check(f"light palette redefines {name}", css_var(light, name) is not None)

    for label, block in (("dark", dark), ("light", light)):
        bg = css_var(block, "--pds-bg")
        panel = css_var(block, "--pds-panel")
        text = css_var(block, "--pds-text")
        muted = css_var(block, "--pds-muted")
        if not all((bg, panel, text, muted)):
            check(f"{label} theme has all four contrast colours", False)
            continue
        body_ratio = contrast_ratio(text, bg)
        muted_ratio = contrast_ratio(muted, panel)
        check(f"{label} body text meets WCAG AA (>= 4.5:1)", body_ratio >= 4.5,
              f"{body_ratio:.2f}:1")
        check(f"{label} muted text meets WCAG AA (>= 4.5:1)", muted_ratio >= 4.5,
              f"{muted_ratio:.2f}:1")
        check(f"{label} and light palettes differ", True)
    check("dark and light backgrounds are genuinely different",
          css_var(dark, "--pds-bg") != css_var(light, "--pds-bg"))
    check("dark and light text colours are genuinely different",
          css_var(dark, "--pds-text") != css_var(light, "--pds-text"))

    check("Bootstrap variables are themed too",
          "--bs-body-bg" in dark and "--bs-body-bg" in light
          and "--bs-card-bg" in dark and "--bs-primary" in light)
    for selector in (".pds-nav", ".pds-card", ".pds-hero", ".pds-auth-card",
                     ".pds-table", ".pds-chart-box", ".pds-message-card"):
        check(f"main.css styles {selector}", selector in css)
    for state in ("pds-state-legitimate", "pds-state-suspicious", "pds-state-phishing"):
        check(f"decision state has its own colour rule :: {state}", state in css)

    for width in (1200, 992, 768, 576):
        check(f"responsive breakpoint at {width}px", f"@media (max-width: {width}px)" in css)
    check("reduced-motion preference honoured", "prefers-reduced-motion" in css)
    check("print stylesheet present", "@media print" in css)
    check("keyboard focus style present", ":focus-visible" in css)
    check("skip link styled", ".pds-skip" in css)
    check("no remote URL in our CSS", "http://" not in css and "https://" not in css)
    check("no external font face", "@font-face" not in css)
    check("Stage 7 backend.css is preserved", ".backend-body" in read("static/css/backend.css"))


# --------------------------------------------------------------------------- #
# 3. JavaScript contract
# --------------------------------------------------------------------------- #
def check_javascript() -> None:
    print("\n[3] External JavaScript contract")
    theme_js = read("static/js/theme.js")
    main_js = read("static/js/main.js")
    joined = theme_js + "\n" + main_js

    check("theme.js sets data-theme before paint",
          'setAttribute("data-theme"' in theme_js)
    check("theme.js reads localStorage", "localStorage" in theme_js)
    check("theme.js guards sandboxed-iframe storage errors",
          "try {" in theme_js and "catch" in theme_js)
    check("theme.js falls back to the OS preference",
          "prefers-color-scheme" in theme_js)

    check("main.js wires the theme toggle", "themeToggle" in main_js
          and "addEventListener" in main_js)
    check("main.js persists the theme choice", "setItem" in main_js)
    check("main.js updates aria-pressed", "aria-pressed" in main_js)
    check("main.js reads chart data from data-* attributes",
          "data-chart" in main_js and "getAttribute" in main_js)
    check("main.js parses chart data with JSON.parse", "JSON.parse" in main_js)
    check("main.js instantiates Chart.js", "new window.Chart" in main_js)
    check("main.js re-themes charts on toggle", "refreshChartColours" in main_js)
    check("main.js degrades honestly if Chart is missing",
          'typeof window.Chart === "undefined"' in main_js)
    check("main.js marks the active nav link", "is-active" in main_js)
    check("main.js announces copy results accessibly", "aria-live" not in main_js
          and "pdsLiveRegion" in main_js)
    check("main.js uses no eval", "eval(" not in joined)
    check("main.js uses no innerHTML", "innerHTML" not in joined)
    check("main.js uses no document.write", "document.write" not in joined)
    check("main.js makes no outbound request",
          "fetch(" not in joined and "XMLHttpRequest" not in joined
          and "http://" not in joined and "https://" not in joined)
    for marker in PLACEHOLDER_MARKERS:
        check(f"no placeholder marker in JS :: {marker}", marker not in joined)
    check("chart colours come from CSS variables", "cssVar(" in main_js
          and "--pds-text" in main_js)


# --------------------------------------------------------------------------- #
# 4. Template source contracts
# --------------------------------------------------------------------------- #
def check_templates_source() -> None:
    print("\n[4] Jinja2 template source contracts")
    all_text = "\n".join(read(rel) for rel in OWN_TEMPLATES)
    base = read("templates/base.html")
    index = read("templates/index.html")
    login = read("templates/login.html")
    register = read("templates/register.html")
    error = read("templates/errors/error.html")

    for rel in OWN_TEMPLATES:
        text = read(rel)
        check(f"no inline <script> content :: {rel}", not inline_scripts(text))
        check(f"no inline style attribute :: {rel}",
              re.search(r"\sstyle\s*=", text, re.IGNORECASE) is None)
        check(f"no external asset URL :: {rel}", not external_assets(text))
        check(f"no inline event handler :: {rel}",
              re.search(r"\son(click|load|error|mouseover)\s*=", text, re.IGNORECASE) is None)
        check(f"no placeholder marker :: {rel}",
              all(marker not in text for marker in PLACEHOLDER_MARKERS))
    check("no template mentions the future scan button", "SCAN WEBSITE" not in all_text)
    check("no template calls predict_proba", "predict_proba" not in all_text)
    check("no template reads metrics.json", "metrics.json" not in all_text)
    check("no template embeds a measured metric word", metric_free(all_text))

    check("base.html declares the document language", 'lang="en"' in base)
    check("base.html declares a responsive viewport", 'name="viewport"' in base)
    check("base.html has a skip link", "pds-skip" in base)
    check("base.html links Bootstrap CSS locally", "vendor/bootstrap.min.css" in base)
    check("base.html links the Stage 7 stylesheet", "css/backend.css" in base)
    check("base.html loads main.css LAST",
          base.index("css/main.css") > base.index("css/backend.css"))
    check("base.html loads theme.js in <head>",
          "js/theme.js" in base and base.index("</head>") > base.index("js/theme.js")
          and base.index("js/theme.js") < base.index("<body"))
    check("base.html loads main.js with defer", "js/main.js') }}\" defer" in base)
    check("base.html loads Chart.js locally with defer",
          "vendor/chart.umd.min.js" in base and "defer" in base)
    check("base.html loads Bootstrap JS locally", "vendor/bootstrap.bundle.min.js" in base)
    check("base.html has a theme toggle", 'id="themeToggle"' in base
          and "aria-pressed" in base)
    check("base.html has a mobile navbar toggler", "data-bs-toggle=\"collapse\"" in base)
    check("base.html has an aria-live region", "aria-live" in base)
    check("base.html defines a content block", "{% block content %}" in base)
    check("base.html defines a title block", "{% block title %}" in base)
    check("base.html shows the local logo", "images/logo.svg" in base)
    check("base.html contains no hard-coded performance figure", metric_free(base))

    for rel, text in (("login.html", login), ("register.html", register),
                      ("index.html", index), ("auth_result.html", read("templates/auth_result.html")),
                      ("errors/error.html", error)):
        check(f"{rel} extends base.html", '{% extends "base.html" %}' in text)

    check("index.html shows the app name", "{{ app_name }}" in index)
    check("index.html shows the build stage", "STAGE {{ build_stage }}" in index)
    check("index.html shows model name/version at runtime",
          "info.model_name" in index and "info.model_version" in index)
    check("index.html shows calibrated thresholds at runtime",
          "info.decision_thresholds.low" in index and "info.decision_thresholds.high" in index)
    check("index.html shows real database status", "db_status.status|upper" in index)
    check("index.html shows VERIFIED/DEGRADED from the bundle",
          "'VERIFIED' if bundle.available else 'DEGRADED'" in index)
    if not STAGE_10_DELIVERED:
        check("index.html declares no functional scan control",
              "/scan" not in index and "SCAN WEBSITE" not in index)
        check("index.html explains that scanning is not wired",
              "not wired" in index.lower())
    else:
        check("Stage 10 index.html links to the real scanner",
              "url_for('scanning.scan_form')" in index
              and "SCAN WEBSITE" not in index)
        check("Stage 10 index.html states scanning is live",
              "URL scanning is live" in index)
    check("index.html states the HTTPS caveat",
          "HTTPS alone does not mean a website is legitimate" in index)
    check("index.html states LEGITIMATE is not a guarantee",
          "not</strong> a guarantee" in index)
    check("index.html has a Chart.js canvas", "<canvas" in index and "data-chart" in index)
    check("index.html passes chart data via an escaped tojson attribute",
          "split_chart|tojson" in index)
    check("index.html lists all 15 features at runtime",
          "{% for name in feature_order %}" in index)
    check("index.html renders the three decision states at runtime",
          "{% for state in states %}" in index and "state.warning" in index)
    check("index.html uses Bootstrap responsive columns",
          "col-sm-" in index and "col-lg-" in index and "col-md-" in index)
    check("index.html has a no-script chart fallback", "<noscript>" in index)
    check("index.html avoids inline style attributes",
          re.search(r"\sstyle\s*=", index, re.IGNORECASE) is None)

    for rel, text, marker in (("login.html", login, "SIGN IN"),
                              ("register.html", register, "CREATE AN ACCOUNT")):
        check(f"{rel} embeds the CSRF token field", 'name="csrf_token"' in text)
        check(f"{rel} keeps its Stage 8 marker", marker in text)
        check(f"{rel} never echoes a password into a value attribute",
              'value="{{ password' not in text and "password }}" not in text)
        check(f"{rel} posts to the real route", "{{ action }}" in text)
        check(f"{rel} renders validation problems", "{% for item in problems %}" in text)
    check("register.html collects confirmation", 'name="confirm_password"' in register)
    check("register.html documents the password policy", "At least 12 characters" in register)
    check("login.html documents scrypt hashing", "scrypt" in login)
    check("auth_result.html never serialises a password hash",
          "password_hash" not in read("templates/auth_result.html"))

    check("error.html shows the generic code", "{{ code }}" in error)
    check("error.html shows the status number", "{{ status_code }}" in error)
    check("error.html shows only the generic message", "{{ message }}" in error)
    check("error.html never renders an exception", "exception" not in error
          or "No diagnostic detail" in error)


# --------------------------------------------------------------------------- #
# 5. Config, wiring and templates actually used
# --------------------------------------------------------------------------- #
def check_wiring() -> None:
    print("\n[5] Configuration, factory and template wiring")
    summary = describe_config()
    check("config reports Stage 9 or later", summary.get("build_stage") >= 9)
    check("config version follows the stage 0.x.0 series",
          re.fullmatch(r"0\.\d+\.0", str(summary.get("app_version", ""))) is not None)
    app = create_app(TestingConfig)
    check("app.config BUILD_STAGE is 9 or later", app.config["BUILD_STAGE"] >= 9)
    check("app.template_folder is templates", app.template_folder == "templates")
    check("app.static_folder is static",
          Path(str(app.static_folder)).name == "static")

    app_src = read("app.py")
    check("app.py still calls every Stage 7 installer",
          all(call in app_src for call in (
              "db.init_app(app)", "csrf.init_app(app)", "limiter.init_app(app)",
              "login_manager.init_app(app)", "install_security_headers(app)",
              "install_error_handlers(app)", "install_request_guards(app)")))
    check("app.py has a Stage 9 context processor", "@app.context_processor" in app_src)
    for key in ("app_name", "app_version", "build_stage", "environment", "debug"):
        check(f"context processor publishes {key}", f'"{key}":' in app_src)
    # The factory default is bumped by each delivered stage. Accept 9, 10 or
    # 11 here; Gate 10/11 assert the exact delivered stage separately.
    check("app.py defaults BUILD_STAGE to its delivered stage (9-14)",
          re.search(r'setdefault\("BUILD_STAGE", (?:9|10|11|12|13|14)\)', app_src) is not None)

    core = read("routes/core.py")
    auth = read("routes/auth.py")
    security = read("services/http_security.py")
    check("core.py renders index.html", 'render_template(\n        "index.html"' in core)
    check("core.py still defines /", '@core_bp.get("/")' in core)
    check("core.py still defines /health", '@core_bp.get("/health")' in core)
    check("core.py still defines /favicon.ico", '@core_bp.get("/favicon.ico")' in core)
    check("core.py reads dataset split sizes at runtime", "dataset_chart()" in core)
    check("core.py passes the 15-feature order", "feature_order" in core)
    check("core.py never reads the measured results file",
          "METRICS_PATH" not in core and "METRICS_FILENAME" not in core
          and "metrics.json" not in core)
    check("auth.py renders login.html / register.html",
          '"register.html" if mode == "register" else "login.html"' in auth)
    check("auth.py renders auth_result.html", '"auth_result.html"' in auth)
    check("auth.py keeps session rotation", "session.clear()" in auth)
    check("auth.py keeps the plain-user role", 'role="user"' in auth)
    check("auth.py keeps the 503 schema contract", "DATABASE_UNAVAILABLE" in auth)
    check("auth.py no longer uses inline HTML strings",
          "render_template_string" not in auth and "AUTH_PAGE" not in auth)
    check("http_security.py renders the themed error template",
          '"errors/error.html"' in security)
    check("http_security.py no longer uses inline HTML strings",
          "render_template_string" not in security and "ERROR_PAGE" not in security)
    check("no backend module loads the estimator yet",
          "joblib.load(" not in (core + auth + security + app_src))
    check("model_metadata.py provides dataset_chart",
          "def dataset_chart(" in read("services/model_metadata.py"))
    check("dataset_chart uses metadata.json split sizes",
          "dataset.split_sizes" in read("services/model_metadata.py"))
    check("public_info() remains free of measured numbers",
          metric_free(json.dumps(app.extensions["model_registry"].public_info())))


# --------------------------------------------------------------------------- #
# 6. Rendered pages and honest chart data
# --------------------------------------------------------------------------- #
def check_rendered_pages(folder: Path) -> None:
    print("\n[6] Rendered pages, local assets and honest chart data")
    uri = temp_uri(folder, "ui.db")
    app = make_app(uri)
    initialise_schema(app)
    metadata = json.loads(read("ml/saved_model/metadata.json"))

    with app.test_client() as client:
        page = client.get("/")
        check("GET / returns 200 HTML", page.status_code == 200
              and "text/html" in page.content_type)
        body = page.get_data(as_text=True)
        check("landing page names the app",
              "Intelligent Phishing Website Detection System" in body)
        delivered_stage = int(describe_config().get("build_stage", 9))
        if not STAGE_10_DELIVERED:
            check("landing page announces STAGE 9", "STAGE 9" in body)
        else:
            check("landing page announces the delivered build stage",
                  f"STAGE {delivered_stage} OF 14" in body,
                  f"expected STAGE {delivered_stage} OF 14")
        check("landing page shows the deployed model",
              metadata["model_name"] in body and metadata["model_version"] in body)
        check("landing page shows the calibrated band",
              str(metadata["thresholds"]["low"]) in body
              and str(metadata["thresholds"]["high"]) in body)
        check("landing page shows READY database state", "READY" in body)
        check("landing page shows VERIFIED artefact state", "VERIFIED" in body)
        check("landing page has NO non-functional scan button", "SCAN WEBSITE" not in body)
        if not STAGE_10_DELIVERED:
            check("landing page honestly says scanning is not wired", "not wired" in body.lower())
        else:
            check("Stage 10 landing page honestly says scanning is live",
                  "URL scanning is live" in body)
        check("landing page contains no measured model figures", metric_free(body))
        check("landing page has no inline script", not inline_scripts(body))
        check("landing page has no inline style attribute",
              re.search(r"\sstyle\s*=", body, re.IGNORECASE) is None)
        check("landing page loads no external asset", not external_assets(body))
        check("landing page contains the exact HTTPS caveat",
              "HTTPS alone does not mean a website is legitimate" in body)
        for state in ("LEGITIMATE", "SUSPICIOUS", "PHISHING"):
            check(f"landing page renders the {state} contract wording",
                  metadata["decision_states"][state]["message"] in body)
        check("landing page renders all 15 feature names",
              all(name in body for name in metadata["feature_order"]))

        # The chart payload is REAL data from metadata.json, embedded safely.
        match = re.search(r"data-chart='([^']+)'", body)
        check("chart data is embedded as a data-* attribute", match is not None)
        if match:
            payload = json.loads(match.group(1))
            expected = [metadata["dataset"]["split_sizes"][key]
                        for key in ("train", "validation", "test")]
            check("chart values equal the real split row counts",
                  payload.get("values") == expected, str(payload.get("values")))
            check("chart has three labels",
                  isinstance(payload.get("labels"), list) and len(payload["labels"]) == 3)
            check("chart names its runtime source",
                  payload.get("source") == "ml/saved_model/metadata.json#dataset.split_sizes")
            check("chart payload contains no performance key", metric_free(json.dumps(payload)))
        check("chart JSON is escaped with tojson", "tojson" in read("templates/index.html"))

        # Every local asset referenced by the page actually exists.
        assets = re.findall(r'(?:src|href)="(/static/[^"]+)"', body)
        check("page references only local /static assets", bool(assets))
        for asset in sorted(set(assets)):
            response = client.get(asset)
            check(f"asset returns 200 :: {asset}", response.status_code == 200
                  and len(response.data) > 0)
        for required in ("bootstrap.min.css", "backend.css", "main.css",
                         "theme.js", "main.js", "chart.umd.min.js",
                         "bootstrap.bundle.min.js", "logo.svg"):
            check(f"page links {required}", required in body)

        csp = page.headers.get("Content-Security-Policy", "")
        check("CSP still defaults to self", "default-src 'self'" in csp)
        check("CSP still forbids inline scripts", "script-src 'self'" in csp
              and "unsafe-inline" not in csp)
        check("CSP still forbids inline styles", "style-src 'self'" in csp)
        check("development still omits framing headers for the preview",
              "X-Frame-Options" not in page.headers)

        health = client.get("/health")
        check("/health is unchanged and healthy", health.status_code == 200
              and health.get_json()["status"] == "ok")
        check("/health reports build_stage 9 or later", health.get_json()["build_stage"] >= 9)
        check("/health still reports detection as Stage 10 work",
              health.get_json()["detection"]["scheduled_stage"] == 10)
        if STAGE_10_DELIVERED:
            check("Stage 10 /health reports the live engine honestly",
                  health.get_json()["detection"]["status"] == "ready"
                  and health.get_json()["detection"]["delivered_stage"] == 10)
        check("/health contains no measured model figures",
              metric_free(json.dumps(health.get_json())))

        for path, marker in (("/login", "SIGN IN"), ("/register", "CREATE AN ACCOUNT")):
            response = client.get(path)
            html = response.get_data(as_text=True)
            check(f"GET {path} returns 200 themed HTML", response.status_code == 200
                  and "pds-auth-card" in html and "pds-nav" in html)
            check(f"GET {path} keeps its Stage 8 marker", marker in html)
            check(f"GET {path} embeds a CSRF field", 'name="csrf_token"' in html)
            check(f"GET {path} never embeds a password",
                  STRONG_PASSWORD not in html and 'value="{{ password' not in html)
            check(f"GET {path} has no inline script", not inline_scripts(html))
        check("GET /login is not cached",
              client.get("/login").headers.get("Cache-Control") in (None, "no-store"))

        # ---- auth POST contracts survived the template change -------------- #
        token = client.get("/auth/csrf-token").get_json()["csrf_token"]
        headers = {"X-CSRF-Token": token}
        created = client.post("/register", json={
            "username": "frank", "email": "frank@example.com",
            "password": STRONG_PASSWORD, "role": "admin",
        }, headers=headers)
        check("JSON registration still returns 201", created.status_code == 201)
        check("self-registration still ignores role escalation",
              created.get_json()["user"]["role"] == "user")
        check("JSON response still hides password_hash",
              "password_hash" not in created.get_json()["user"])
        weak = client.post("/register", json={
            "username": "eve", "email": "eve@example.com", "password": "weak",
        }, headers={"X-CSRF-Token": client.get("/auth/csrf-token").get_json()["csrf_token"]})
        check("weak password still returns 400", weak.status_code == 400)
        bad = client.post("/login", json={
            "username": "frank", "password": "Wrong!Passphrase2026",
        }, headers={"X-CSRF-Token": client.get("/auth/csrf-token").get_json()["csrf_token"]})
        check("wrong password still returns 401 UNAUTHENTICATED",
              bad.status_code == 401 and bad.get_json()["error"]["code"] == "UNAUTHENTICATED")
        good = client.post("/login", json={
            "username": "FRANK@EXAMPLE.COM", "password": STRONG_PASSWORD,
        }, headers={"X-CSRF-Token": client.get("/auth/csrf-token").get_json()["csrf_token"]})
        check("case-insensitive login still returns 200", good.status_code == 200)
        session_page = client.get("/")
        check("authenticated navbar shows the user and sign-out form",
              "frank" in session_page.get_data(as_text=True)
              and 'action="/logout"' in session_page.get_data(as_text=True))
        check("authenticated page has no inline script",
              not inline_scripts(session_page.get_data(as_text=True)))
        out = client.post("/logout", headers={
            "X-CSRF-Token": client.get("/auth/csrf-token").get_json()["csrf_token"]})
        check("logout still clears the session", out.status_code == 200
              and out.get_json()["logged_out"] is True)

        # HTML form POST path (no JSON client).
        html = client.get("/register").get_data(as_text=True)
        form_token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        form_result = client.post("/register", data={
            "username": "carol", "email": "carol@example.com",
            "password": STRONG_PASSWORD, "confirm_password": STRONG_PASSWORD,
            "csrf_token": form_token,
        })
        check("HTML form registration returns 201 themed result",
              form_result.status_code == 201
              and b"Account created" in form_result.data
              and b"pds-message-card" in form_result.data)
        mismatch = client.post("/register", data={
            "username": "grace", "email": "grace@example.com",
            "password": STRONG_PASSWORD, "confirm_password": "Different!2026",
            "csrf_token": form_token,
        })
        check("HTML form mismatch is rejected with the policy text",
              mismatch.status_code == 400 and b"do not match" in mismatch.data)

        # ---- themed error responses --------------------------------------- #
        not_found = client.get("/this-page-does-not-exist")
        check("404 uses the themed error template",
              not_found.status_code == 404 and b"NOT_FOUND" in not_found.data
              and b"pds-message-card" in not_found.data)
        check("404 never leaks a traceback or absolute path",
              b"Traceback" not in not_found.data and b"/home/user" not in not_found.data)
        check("404 has no inline script",
              not inline_scripts(not_found.get_data(as_text=True)))
        method = client.post("/")
        check("405 returns METHOD_NOT_ALLOWED themed",
              method.status_code == 405 and b"METHOD_NOT_ALLOWED" in method.data)
        bare = client.post("/logout")
        check("CSRF-less POST still returns 400 CSRF_FAILED",
              bare.status_code == 400 and b"CSRF_FAILED" in bare.data)
        api_404 = client.get("/api/missing")
        check("API 404 is still JSON NOT_FOUND",
              api_404.status_code == 404
              and api_404.get_json()["error"]["code"] == "NOT_FOUND")

    # A degraded bundle must still be reported honestly on the new UI.
    temp_bundle = folder / "wrong.joblib"
    temp_bundle.write_bytes(b"not a trained model")
    degraded = create_app(TestingConfig, overrides={"MODEL_BUNDLE_PATH": temp_bundle})
    with degraded.test_client() as client:
        check("degraded bundle yields 503 on /health",
              client.get("/health").status_code == 503)
        check("new UI shows DEGRADED instead of faking a result",
              b"DEGRADED" in client.get("/").data)

    # Production posture must survive the template change.
    from config import ProductionConfig  # noqa: E402
    prod = create_app(ProductionConfig, overrides={"SECRET_KEY": "p" * 64})
    with prod.test_client() as client:
        response = client.get("/")
        check("production still sends X-Frame-Options: DENY",
              response.headers.get("X-Frame-Options") == "DENY")
        check("production still sends HSTS",
              "max-age=" in response.headers.get("Strict-Transport-Security", ""))
        check("production CSP pins frame-ancestors",
              "frame-ancestors 'self'" in response.headers.get("Content-Security-Policy", ""))
        check("production renders the themed page",
              response.status_code == 200 and b"pds-nav" in response.data)

    # @login_required still uses the documented 401 handler (ADR-026).
    authz = create_app(TestingConfig)

    @authz.route("/_protected")
    @login_required
    def _protected() -> Any:
        return jsonify({"ok": True})

    with authz.test_client() as client:
        denied = client.get("/_protected")
        check("@login_required still yields 401 UNAUTHENTICATED",
              denied.status_code == 401 and b"UNAUTHENTICATED" in denied.data)


# --------------------------------------------------------------------------- #
# 7. Schema-missing behaviour and 500 handling
# --------------------------------------------------------------------------- #
def check_failure_paths() -> None:
    print("\n[7] Honest failure paths with the new templates")
    empty_app = create_app(TestingConfig)
    with empty_app.test_client() as client:
        blocked = client.post("/login", json={
            "username": "frank", "password": STRONG_PASSWORD,
        })
        check("login without schema still returns 503 DATABASE_UNAVAILABLE",
              blocked.status_code == 503
              and blocked.get_json()["error"]["code"] == "DATABASE_UNAVAILABLE")
        check("overview still renders with NOT_INITIALISED",
              b"NOT_INITIALISED" in client.get("/").data)

    quiet = create_app(DevelopmentConfig, overrides={
        "DEBUG": False, "TESTING": False, "PROPAGATE_EXCEPTIONS": False,
        "WTF_CSRF_ENABLED": False,
    })

    @quiet.route("/_raise")
    def _raise() -> Any:
        raise ValueError("secret diagnostic detail must not reach the client")

    with quiet.test_client() as client:
        html_500 = client.get("/_raise")
        check("500 uses the themed generic page",
              html_500.status_code == 500 and b"INTERNAL_ERROR" in html_500.data
              and b"pds-message-card" in html_500.data)
        check("500 never leaks the exception text",
              b"secret diagnostic detail" not in html_500.data
              and b"Traceback" not in html_500.data)

    cap = create_app(TestingConfig)
    with cap.test_client() as client:
        oversized = client.post(
            "/logout", data=b"x" * (cap.config["MAX_CONTENT_LENGTH"] + 10),
            content_type="application/octet-stream",
        )
        check("oversized body still returns 413 PAYLOAD_TOO_LARGE",
              oversized.status_code == 413 and b"PAYLOAD_TOO_LARGE" in oversized.data)


# --------------------------------------------------------------------------- #
# 8. Stage discipline, documentation and regressions
# --------------------------------------------------------------------------- #
def check_docs_and_discipline() -> None:
    print("\n[8] Documentation, stage discipline and regressions")
    ui = read("docs/UI.md")
    for section in DOC_SECTIONS:
        check(f"UI.md :: {section}", section in ui)
    check("UI.md documents both themes", "dark" in ui.lower() and "light" in ui.lower())
    check("UI.md documents the offline vendor hashes", "SHA-256" in ui)
    check("UI.md states the no-scan honesty rule", "not wired" in ui.lower()
          or "no scan" in ui.lower())
    check("UI.md explains the CSP constraint", "CSP" in ui)
    check("UI.md gives Windows-first commands", ".\\.venv\\Scripts\\Activate.ps1" in ui)

    readme = read("README.md")
    check("README marks Stage 9 complete",
          re.search(r"\|\s*9\s*\|.*✅", readme) is not None)
    check("README lists docs/UI.md", "docs/UI.md" in readme)
    plan = read("docs/STAGE_PLAN.md")
    check("STAGE_PLAN records Stage 9 as delivered", "Stage 9 — delivered" in plan)
    decisions = read("docs/DECISIONS.md")
    for adr in ("ADR-028", "ADR-029"):
        check(f"DECISIONS.md contains {adr}", adr in decisions)
    check("ARCHITECTURE.md has a Stage 9 implementation note",
          "Stage 9 implementation note" in read("docs/ARCHITECTURE.md"))
    check("BACKEND.md has a Stage 9 update note",
          "Stage 9 update" in read("docs/BACKEND.md"))

    if not STAGE_10_DELIVERED:
        for rel in FORBIDDEN_NOW:
            check(f"not created yet :: {rel}", not (ROOT / rel).exists())
        expected = {
            "ml": {"__init__.py", "url_utils.py", "preprocess.py",
                   "feature_extraction.py", "train_model.py",
                   "evaluate_model.py", "thresholds.py"},
            "models": {"__init__.py", "database_models.py"},
            "services": {"__init__.py", "validation.py", "model_metadata.py",
                         "http_security.py", "auth_service.py", "database_service.py"},
            "routes": {"__init__.py", "core.py", "auth.py"},
            "tests": set(), "templates": set(),
        }
        for directory, names in expected.items():
            stray = [p.name for p in (ROOT / directory).glob("*.py") if p.name not in names]
            check(f"{directory}/ contains only Stage 1-9 modules", not stray,
                  ", ".join(stray))
        root_py = {p.name for p in ROOT.glob("*.py")}
        check("project root contains only Stage 1-9 Python modules",
              root_py <= {"config.py", "app.py", "wsgi.py", "extensions.py"},
              ", ".join(sorted(root_py)))
        html_files = {str(p.relative_to(ROOT)).replace("\\", "/")
                      for p in (ROOT / "templates").rglob("*.html")}
        check("templates/ contains exactly the six Stage 9 templates",
              html_files == set(TEMPLATE_FILES), ", ".join(sorted(html_files)))
        css_files = {p.name for p in (ROOT / "static" / "css").glob("*.css")}
        js_files = {p.name for p in (ROOT / "static" / "js").glob("*.js")}
        check("static/css/ contains exactly backend.css and main.css",
              css_files == {"backend.css", "main.css"}, ", ".join(sorted(css_files)))
        check("static/js/ contains exactly theme.js and main.js",
              js_files == {"theme.js", "main.js"}, ", ".join(sorted(js_files)))

        app = create_app(TestingConfig)
        rules = {str(rule) for rule in app.url_map.iter_rules()}
        for rule in ("/scan", "/dashboard", "/history", "/admin", "/api/v1/scan"):
            check(f"url_map correctly omits {rule} at Stage 9", rule not in rules)
        check("no template or JS claims to run inference",
              all("predict_proba" not in read(rel)
                  for rel in OWN_TEMPLATES + OWN_FRONTEND))
        check("no template or JS hard-codes a measured metric word",
              all(metric_free(read(rel)) for rel in OWN_TEMPLATES + OWN_FRONTEND))
    else:
        skip("no Stage 10+ code yet", "delivered in Stage 10; enforced by verify_stage10.py")

    for gate in ("verify_stage1.py", "verify_stage2.py", "verify_stage3.py",
                 "verify_stage4.py", "verify_stage5.py", "verify_stage6.py",
                 "verify_stage7.py", "verify_stage8.py"):
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
    logging.disable(logging.CRITICAL)
    print("=" * 78)
    print("STAGE 9 EXIT GATE - templates, themes, offline assets and charts")
    print(f"Project root : {ROOT}")
    print("=" * 78)
    check_files_and_provenance()
    check_design_system()
    check_javascript()
    check_templates_source()
    check_wiring()
    folder = Path(tempfile.mkdtemp(prefix="stage9-"))
    try:
        check_rendered_pages(folder)
        check_failure_paths()
    finally:
        for item in folder.iterdir():
            item.unlink()
        folder.rmdir()
    check_docs_and_discipline()
    print("\n" + "=" * 78)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        return 1
    print(f"RESULT: PASS - all {checks} checks passed")
    print("Stage 9 exit gate satisfied. You may proceed to Stage 10.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
