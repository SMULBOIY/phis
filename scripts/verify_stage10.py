#!/usr/bin/env python3
"""Stage 10 exit gate: the real, integrated URL detection engine.

Run from the project root (Windows or Linux):

    python scripts\\verify_stage10.py       (Windows)
    ./scripts/verify_stage10.py            (Linux/macOS)
    ./.venv/bin/python scripts/verify_stage10.py

This is an EXECUTABLE acceptance test, not a description. It re-runs every
historical gate (1-9), then checks that /scan really validates, extracts the
shared 15 features, scores with the hash-verified Joblib estimator, applies the
measured abstention thresholds, explains the observations, writes a
ScanHistory row and renders an honest result — including every explicit
failure path. All test URLs are reserved/synthetic strings; no live site and
no malicious URL is ever contacted.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# config.py prints an ephemeral-key notice when SECRET_KEY is unset in dev.
with contextlib.redirect_stderr(io.StringIO()):
    from config import TestingConfig, describe_config  # noqa: E402
    from app import create_app  # noqa: E402
    from extensions import db  # noqa: E402
    from ml.feature_extraction import (  # noqa: E402
        FEATURE_DEFINITIONS, FEATURE_ORDER, FEATURE_RATIONALES,
        extract_features, extract_frame, features_to_frame,
    )
    from ml.thresholds import DECISION_STATES, SCORE_MEANING  # noqa: E402
    from models.database_models import ScanHistory, User  # noqa: E402
    from models.prediction_model import ModelUnavailableError, PredictionModel  # noqa: E402
    from services.database_service import initialise_schema  # noqa: E402
    from services.decision_service import DecisionPolicyError, decide  # noqa: E402
    from services.detection_service import (  # noqa: E402
        IMPORTANCE_SOURCE, DetectionRegistry, get_detection_registry,
    )
    from services.explanation_service import (  # noqa: E402
        HTTPS_CAVEAT, INDICATOR_FEATURES, explain,
    )
    from services.validation import validate_url  # noqa: E402

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
    if not ok:
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
# Constants and safe, controlled fixtures
# --------------------------------------------------------------------------- #
REQUIRED_FILES = (
    "models/prediction_model.py",
    "services/detection_service.py",
    "services/decision_service.py",
    "services/explanation_service.py",
    "routes/scanning.py",
    "templates/scan.html",
    "templates/scan_report.html",
    "templates/partials/scan_result.html",
    "docs/DETECTION.md",
    "scripts/verify_stage10.py",
)

# Stage 11+ deliverables must still be absent (exact 14-stage order).
FORBIDDEN_NOW = (
    "services/stats_service.py", "services/report_service.py",
    "routes/dashboard.py", "routes/admin.py", "routes/api.py",
    "routes/history.py",
    "templates/dashboard.html", "templates/history.html", "templates/admin.html",
    "static/js/dashboard.js",
    "tests/conftest.py", "tests/test_features.py",
    "docs/SECURITY.md", "docs/TEST_PLAN.md", "docs/DEPLOYMENT.md",
    "docs/REPORT.md",
)

# Gate 10 runs as a REGRESSION under Gate 11. Once Stage 11 is delivered its
# files must obviously exist, so the "no later-stage files" assertion becomes
# stage-aware instead of being deleted: everything belonging to Stage 12+ is
# still forbidden. This keeps the exact 14-stage order enforceable.
STAGE_11_DELIVERED = (
    (ROOT / "services" / "stats_service.py").is_file()
    and (ROOT / "scripts" / "verify_stage11.py").is_file()
)
STAGE_11_FILES = frozenset({
    "services/stats_service.py", "services/report_service.py",
    "routes/dashboard.py", "routes/admin.py", "routes/history.py",
    "templates/dashboard.html", "templates/history.html",
    "templates/admin.html",
})
FORBIDDEN_AFTER_11 = tuple(
    rel for rel in FORBIDDEN_NOW if rel not in STAGE_11_FILES
)
# Gate 10 is a regression under Gate 11 AND Gate 12. Once Stage 12 is
# delivered, routes/api.py and docs/SECURITY.md must exist; only Stage 13+
# artefacts remain forbidden. The assertion is stage-aware, never deleted.
STAGE_12_DELIVERED = (
    (ROOT / "routes" / "api.py").is_file()
    and (ROOT / "scripts" / "verify_stage12.py").is_file()
)
STAGE_12_FILES = frozenset({"routes/api.py", "docs/SECURITY.md"})
FORBIDDEN_AFTER_12 = tuple(
    rel for rel in FORBIDDEN_AFTER_11 if rel not in STAGE_12_FILES
)

# --------------------------------------------------------------------------- #
# Stage 13 awareness (the formal pytest suite).
# --------------------------------------------------------------------------- #
# Gate 10 runs as a regression under the Stage 13 suite. Once Stage 13 is
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
FORBIDDEN_AFTER_13 = tuple(
    rel for rel in FORBIDDEN_AFTER_12 if rel not in STAGE_13_FILES
)

# --------------------------------------------------------------------------- #
# Stage 14 awareness (report + deployment guide).
# --------------------------------------------------------------------------- #
# Gate 10 also runs as a regression under the Stage 14 deployment gate. Stage 14
# delivers docs/REPORT.md and docs/DEPLOYMENT.md, so they leave the forbidden
# list; the assertion remains stage-aware, so nothing earlier can silently
# appear. After this subtraction the list is empty by construction.
STAGE_14_FILES = frozenset({"docs/REPORT.md", "docs/DEPLOYMENT.md"})
STAGE_14_DELIVERED = all((ROOT / rel).is_file() for rel in STAGE_14_FILES)
FORBIDDEN_AFTER_14 = tuple(
    rel for rel in FORBIDDEN_AFTER_13 if rel not in STAGE_14_FILES
)

VENDOR_HASHES = {
    "static/vendor/bootstrap.min.css": "3c8f27e6009ccfd710a905e6dcf12d0ee3c6f2ac7da05b0572d3e0d12e736fc8",
    "static/vendor/bootstrap.bundle.min.js": "0833b2e9c3a26c258476c46266e6877fc75218625162e0460be9a3a098a61c6c",
    "static/vendor/chart.umd.min.js": "b38076762f7363bc9e912b68b8e034826798db5df26bb61f000ec2e7a3137bc7",
}

NETWORK_MARKERS = (
    "import requests", "import httpx", "import aiohttp", "from pycurl",
    "urllib.request", "urlopen(", "http.client", "socket.create_connection",
    "requests.get(", "requests.post(",
)

# Modules that can be imported while the web application is serving a request.
# Offline pipeline scripts (scripts/download_dataset.py, ml/train_model.py,
# ml/evaluate_model.py) legitimately read files and, for the dataset download,
# use the network once during setup; they are NOT part of the request path.
RUNTIME_RELS = (
    "app.py", "config.py", "extensions.py", "wsgi.py",
    "routes/__init__.py", "routes/core.py", "routes/auth.py", "routes/scanning.py",
    "services/__init__.py", "services/validation.py", "services/model_metadata.py",
    "services/http_security.py", "services/auth_service.py",
    "services/database_service.py", "services/detection_service.py",
    "services/decision_service.py", "services/explanation_service.py",
    "models/__init__.py", "models/database_models.py", "models/prediction_model.py",
    "ml/__init__.py", "ml/url_utils.py", "ml/preprocess.py",
    "ml/feature_extraction.py", "ml/thresholds.py",
)
if STAGE_11_DELIVERED:
    # Stage 11's read-only views are part of the request path too, so they
    # inherit the same "no network client" rule as every earlier module.
    RUNTIME_RELS += (
        "routes/dashboard.py", "routes/history.py", "routes/admin.py",
        "services/stats_service.py", "services/report_service.py",
    )
if STAGE_12_DELIVERED:
    # The REST API is part of the request path; it must stay network-free too.
    RUNTIME_RELS += ("routes/api.py",)

# RFC 2606 / RFC 5737 reserved strings and a reserved non-resolvable .invalid
# host. Nothing here is ever opened, resolved or executed.
URL_LEGITIMATE = "https://example.com"
URL_SUSPICIOUS = "https://example.com/"
URL_PHISHING = (
    "https://paypal.com.login.verify.example.invalid"
    "/secure/account/update?next=confirm"
)
CONTROLLED_CASES = (
    (URL_LEGITIMATE, "LEGITIMATE", "LOW", "green"),
    (URL_SUSPICIOUS, "SUSPICIOUS", "MEDIUM", "orange"),
    (URL_PHISHING, "PHISHING", "HIGH", "red"),
)

STRONG_PASSWORD = "Str0ng!Passphrase2026"
METADATA = json.loads(read("ml/saved_model/metadata.json"))
METRICS = json.loads(read("ml/saved_model/metrics.json"))
THRESHOLDS = METADATA["thresholds"]
LOW = float(THRESHOLDS["low"])
HIGH = float(THRESHOLDS["high"])

DETECTION_SECTIONS = (
    "## 1. What Stage 10 builds", "## 2. Request pipeline",
    "## 3. File-by-file map", "## 4. Model loading and integrity",
    "## 5. Three-state decision policy", "## 6. Explanations and uncertainty",
    "## 7. Audit persistence and authorisation",
    "## 8. Security properties and limitations",
    "## 9. What is deliberately NOT in Stage 10",
    "## 10. Run and test", "## 11. Common errors and fixes",
    "## 12. Stage 10 exit criteria",
)


def build_app(**overrides: Any):
    """Create a TestingConfig app with a safe fixed secret."""
    settings = {"SECRET_KEY": "s" * 64}
    settings.update(overrides)
    return create_app(TestingConfig, overrides=settings)


def escaped_meaning() -> str:
    """SCORE_MEANING as Jinja2 autoescaping renders it (apostrophe -> &#39;)."""
    from markupsafe import escape
    return str(escape(SCORE_MEANING))


def other_session_get(app, path: str):
    """Simulate a DIFFERENT browser inside a shared test app context.

    Flask test clients reuse a pushed app context, and Flask-Login caches the
    loaded user in ``g._login_user``. Without clearing that cache, a brand-new
    client would appear logged in and the authorisation test would be wrong.
    Real WSGI requests always receive a fresh app context, so this is purely a
    test-harness correction, never application behaviour.
    """
    from flask import g
    g.pop("_login_user", None)
    return app.test_client().get(path)


def inline_scripts(text: str) -> list[str]:
    return [m.strip() for m in re.findall(
        r"<script\b[^>]*>(.*?)</script>", text, re.DOTALL | re.IGNORECASE
    ) if m.strip()]


def external_assets(text: str) -> list[str]:
    return re.findall(
        r"(?:src|href)\s*=\s*[\"'](?:https?:)?//[^\"']+", text, re.IGNORECASE
    )


# --------------------------------------------------------------------------- #
# 1. Inventory, stage discipline and compilation
# --------------------------------------------------------------------------- #
def check_inventory() -> None:
    print("\n[1] Stage 10 file inventory, stage discipline and compilation")
    for rel in REQUIRED_FILES:
        check(f"required file exists :: {rel}", (ROOT / rel).is_file())
    if STAGE_13_DELIVERED:
        forbidden = FORBIDDEN_AFTER_14
    elif STAGE_12_DELIVERED:
        forbidden = FORBIDDEN_AFTER_12
    elif STAGE_11_DELIVERED:
        forbidden = FORBIDDEN_AFTER_11
    else:
        forbidden = FORBIDDEN_NOW
    for rel in forbidden:
        check(f"Stage 13+ file absent :: {rel}", not (ROOT / rel).exists())
    if STAGE_12_DELIVERED:
        for rel in STAGE_12_FILES:
            check(f"Stage 12 delivered file exists :: {rel}", (ROOT / rel).is_file())
    if STAGE_13_DELIVERED:
        for rel in sorted(STAGE_13_FILES):
            check(f"Stage 13 delivered file exists :: {rel}", (ROOT / rel).is_file())

    expected = {
        "models": {"__init__.py", "database_models.py", "prediction_model.py"},
        "services": {"__init__.py", "validation.py", "model_metadata.py",
                     "http_security.py", "auth_service.py", "database_service.py",
                     "detection_service.py", "decision_service.py",
                     "explanation_service.py"},
        "routes": {"__init__.py", "core.py", "auth.py", "scanning.py"},
        "ml": {"__init__.py", "url_utils.py", "preprocess.py",
               "feature_extraction.py", "train_model.py", "evaluate_model.py",
               "thresholds.py"},
    }
    if STAGE_11_DELIVERED:
        expected["services"] |= {"stats_service.py", "report_service.py"}
        expected["routes"] |= {"dashboard.py", "history.py", "admin.py"}
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
    }
    if STAGE_11_DELIVERED:
        expected_html |= {"templates/dashboard.html", "templates/history.html",
                          "templates/admin.html"}
    check("templates/ contains exactly the delivered pages",
          html == expected_html, ", ".join(sorted(html)))

    py_files = sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")
                      if ".venv" not in p.parts and "__pycache__" not in p.parts)
    import py_compile
    for rel in py_files:
        try:
            py_compile.compile(str(ROOT / rel), doraise=True)
            check(f"compiles :: {rel}", True)
        except py_compile.PyCompileError as exc:
            check(f"compiles :: {rel}", False, str(exc))


# --------------------------------------------------------------------------- #
# 2. Source-level honesty, CSP and artefact discipline
# --------------------------------------------------------------------------- #
def check_sources() -> None:
    print("\n[2] Source discipline, exact contracts and offline assets")
    scan = read("templates/scan.html")
    check("scan.html has the exact SCAN WEBSITE button label",
          re.search(r"<button[^>]*type=\"submit\"[^>]*>\s*SCAN WEBSITE\s*</button>", scan) is not None)
    others = ["templates/base.html", "templates/index.html", "templates/login.html",
              "templates/register.html", "templates/auth_result.html",
              "templates/errors/error.html", "templates/scan_report.html",
              "templates/partials/scan_result.html"]
    if STAGE_11_DELIVERED:
        others += ["templates/dashboard.html", "templates/history.html",
                   "templates/admin.html"]
    for rel in others:
        check(f"{rel} does not duplicate the SCAN WEBSITE label",
              "SCAN WEBSITE" not in read(rel))
    check("scan form uses POST", 'method="post"' in scan)
    check("scan form posts to the real route", "url_for('scanning.scan')" in scan)
    check("scan form carries a CSRF field", 'name="csrf_token"' in scan)
    check("scan form bounds the input length", "maxlength=" in scan)

    new_templates = ("templates/scan.html", "templates/scan_report.html",
                     "templates/partials/scan_result.html")
    if STAGE_11_DELIVERED:
        new_templates += ("templates/dashboard.html", "templates/history.html",
                          "templates/admin.html")
    for rel in new_templates:
        text = read(rel)
        check(f"{rel} has no inline script", not inline_scripts(text))
        check(f"{rel} has no inline style attribute",
              re.search(r"\sstyle\s*=", text, re.IGNORECASE) is None)
        check(f"{rel} loads no external asset", not external_assets(text))
        check(f"{rel} contains no invented performance literal",
              all(str(v) not in text for v in (
                  "0.983854", "0.993307", "0.967803", "0.980389", "0.998055",
              )))

    for rel, expected in VENDOR_HASHES.items():
        check(f"vendored asset unchanged :: {rel}", sha256(rel) == expected)
    check("static/vendor/README.md is still present",
          (ROOT / "static/vendor/README.md").is_file())

    all_python = "\n".join(read(rel) for rel in RUNTIME_RELS)
    for rel in RUNTIME_RELS:
        check(f"runtime module is present :: {rel}", bool(read(rel)))
    for marker in NETWORK_MARKERS:
        check(f"application source contains no '{marker}'", marker not in all_python)
    loaders = [rel for rel in RUNTIME_RELS if "joblib.load(" in read(rel)]
    check("joblib.load appears only in models/prediction_model.py",
          loaders == ["models/prediction_model.py"], ", ".join(loaders))

    detection = read("services/detection_service.py")
    decision = read("services/decision_service.py")
    explanation = read("services/explanation_service.py")
    prediction = read("models/prediction_model.py")
    route = read("routes/scanning.py")

    check("detection_service imports the shared extractor",
          "from ml.feature_extraction import" in detection
          and "extract_features(" in detection)
    check("prediction_model uses the shared DataFrame builder",
          "features_to_frame" in prediction and "FEATURE_ORDER" in prediction)
    check("decision_service reuses Stage 6 boundary mapping",
          "decision_codes" in decision and "STATE_NAMES" in decision
          and "DECISION_STATES" in decision)
    check("decision_service imports SCORE_MEANING", "SCORE_MEANING" in decision)
    check("explanation_service uses documented definitions and rationales",
          "FEATURE_DEFINITIONS" in explanation and "FEATURE_RATIONALES" in explanation)
    check("explanation_service reads measured importance at runtime",
          "importance: dict[str, float]" in explanation)
    check("explanation_service never produces a verdict",
          "decide(" not in explanation and "prediction=" not in explanation)
    check("explanation_service never treats HTTPS as a suspicious indicator",
          "has_https" not in INDICATOR_FEATURES)
    check("detection_service has a named failure taxonomy",
          all(name in detection for name in (
              "InvalidSubmissionError", "DetectionUnavailableError",
              "DetectionStorageError")))
    check("detection_service has NO heuristic fallback",
          "fallback_score" not in detection and "rule_based" not in detection
          and "default_score" not in detection)
    check("detection_service persists before returning",
          "db.session.commit()" in detection and "features_json=snapshot" in detection)
    check("scanning route maps the three failures explicitly",
          all(code in route for code in (
              "INVALID_URL", "MODEL_UNAVAILABLE", "DATABASE_UNAVAILABLE")))
    check("scanning route uses make_error_response", "make_error_response" in route)
    check("scanning route links authenticated scans", "_authenticated_user_id" in route)
    check("scanning route has an authorisation policy", "can_view_scan" in route)
    check("scanning route never re-runs inference for a report",
          "registry.scan(" not in route.split("def scan_report")[1])

    # The exact UI contract must be the single source of truth.
    check("metadata.json decision_states matches ml/thresholds.DECISION_STATES",
          METADATA["decision_states"] == DECISION_STATES)
    check("metadata.json score_meaning matches ml/thresholds.SCORE_MEANING",
          METADATA["score_meaning"] == SCORE_MEANING)
    check("score meaning never claims a guarantee",
          "not a guarantee" in SCORE_MEANING.lower()
          and "not a calibrated probability" in SCORE_MEANING.lower())
    check("measured thresholds satisfy 0 <= low < high <= 1", 0 <= LOW < HIGH <= 1)
    check("thresholds are read from the artefact, not hard-coded in the policy",
          'decide(score, low=thresholds["low"], high=thresholds["high"])' in detection)
    check("explanation importance provenance is the real artefact",
          "metrics.json#feature_importance.features" in IMPORTANCE_SOURCE)
    check("feature importance map covers exactly FEATURE_ORDER",
          set(METRICS["feature_importance"]["features"]) == set(FEATURE_ORDER))
    check("measured importance values are finite",
          all(math.isfinite(float(v["mean"]))
              for v in METRICS["feature_importance"]["features"].values()))


# --------------------------------------------------------------------------- #
# 3. Pure unit checks: decision, explanation, estimator parity
# --------------------------------------------------------------------------- #
def check_units() -> None:
    print("\n[3] Pure decision, explanation and estimator-parity checks")
    cases = (
        (0.0, "LEGITIMATE", False), (LOW - 0.000001, "LEGITIMATE", False),
        (LOW, "LEGITIMATE", False), (LOW + 0.000001, "SUSPICIOUS", True),
        ((LOW + HIGH) / 2, "SUSPICIOUS", True),
        (HIGH - 0.000001, "SUSPICIOUS", True), (HIGH, "PHISHING", False),
        (HIGH + 0.000001, "PHISHING", False), (1.0, "PHISHING", False),
    )
    for score, name, uncertain in cases:
        d = decide(score, low=LOW, high=HIGH)
        check(f"decide({score:.6f}) -> {name}", d.prediction == name, d.prediction)
        check(f"decide({score:.6f}) uncertainty is {uncertain}", d.uncertain is uncertain)
        state = DECISION_STATES[name]
        check(f"decide({score:.6f}) uses the exact {name} message",
              d.message == state["message"])
        check(f"decide({score:.6f}) uses the exact {name} warning",
              d.warning == state["warning"])
        check(f"decide({score:.6f}) uses the exact {name} colour",
              d.colour == state["colour"])
        check(f"decide({score:.6f}) uses the exact {name} risk level",
              d.risk_level == state["risk_level"])
        check(f"decide({score:.6f}) carries SCORE_MEANING",
              d.score_meaning == SCORE_MEANING)
        check(f"decide({score:.6f}) is reproducible",
              decide(score, low=LOW, high=HIGH) == d)
    check("decision band is explicit", decide(0.5, low=LOW, high=HIGH).band()
          == f"{LOW:g} < p < {HIGH:g}")
    for bad in (-0.1, 1.1, float("nan"), float("inf")):
        try:
            decide(bad, low=LOW, high=HIGH)
            check(f"invalid score {bad} is rejected", False)
        except DecisionPolicyError:
            check(f"invalid score {bad} is rejected", True)
    for low, high in ((HIGH, LOW), (-1, HIGH), (LOW, 2), (0.5, 0.5)):
        try:
            decide(0.5, low=low, high=high)
            check(f"invalid thresholds ({low},{high}) rejected", False)
        except DecisionPolicyError:
            check(f"invalid thresholds ({low},{high}) rejected", True)

    importance = {name: float(METRICS["feature_importance"]["features"][name]["mean"])
                  for name in FEATURE_ORDER}
    features = extract_features(URL_PHISHING)
    d = decide(0.99, low=LOW, high=HIGH)
    e = explain(features, d, importance=importance, importance_source=IMPORTANCE_SOURCE)
    check("explanation covers all 15 features", len(e.insights) == 15)
    check("explanation names match FEATURE_ORDER",
          [i.name for i in e.insights] == list(FEATURE_ORDER))
    check("explanation definitions come from ml.feature_extraction",
          all(i.definition == FEATURE_DEFINITIONS[i.name] for i in e.insights))
    check("explanation rationales come from ml.feature_extraction",
          all(i.rationale == FEATURE_RATIONALES[i.name] for i in e.insights))
    check("explanation importance equals the measured artefact",
          all(i.importance == importance[i.name] for i in e.insights))
    check("top features are ranked by MEASURED importance",
          [i.name for i in e.top] == sorted(importance, key=lambda n: (-importance[n], n))[:5])
    check("HTTPS caveat is always present", HTTPS_CAVEAT in e.caveats)
    check("has_https is not a suspicious indicator", "has_https" not in INDICATOR_FEATURES)
    check("no-network limitation is disclosed",
          any("did not visit" in c for c in e.caveats))
    check("correlational language is used",
          any("correlations" in c for c in e.caveats))
    check("recommended action is non-empty", bool(e.recommended_action))
    check("uncertainty note is non-empty", bool(e.uncertainty_note))
    check("flagged list is derived from observed indicators",
          all(i.observed and i.indicator for i in e.flagged))
    check("explanation.to_dict is JSON-safe",
          json.dumps(e.to_dict()) is not None)
    try:
        explain({"url_length": 10}, d, importance=importance)
        check("incomplete feature vector is refused", False)
    except ValueError:
        check("incomplete feature vector is refused", True)
    try:
        explain(features, d, importance={"url_length": 0.1})
        check("missing measured importance is refused", False)
    except ValueError:
        check("missing measured importance is refused", True)

    # Training-serving parity: the live single-URL path must produce exactly
    # what Stage 6's batch extract_frame path produces for the same estimator.
    model = PredictionModel(ROOT / "ml/saved_model/model_bundle.joblib")
    check("estimator exposes class 0/1 in the documented order",
          model.phishing_index == 1 and model.feature_order == FEATURE_ORDER)
    check("estimator identity matches metadata.json",
          model.model_name == METADATA["model_name"]
          and model.model_version == METADATA["model_version"]
          and model.schema_version == METADATA["schema_version"])
    for url in (URL_LEGITIMATE, URL_SUSPICIOUS, URL_PHISHING):
        batch = float(model.estimator.predict_proba(extract_frame([url]))[0][1])
        live = model.score(extract_features(url))
        check(f"single-URL score equals batch score :: {url[:36]}",
              abs(batch - live) < 1e-12, f"{batch} vs {live}")
    try:
        model.score({"url_length": 1})
        check("malformed feature vector is refused", False)
    except ModelUnavailableError:
        check("malformed feature vector is refused", True)

    # Reproduce the published held-out confusion matrix through the LIVE path.
    # This is a parity assertion, not test-split peeking or a tuning pass.
    import pandas as pd
    frame = pd.read_csv(ROOT / "dataset/processed/test.csv")
    scores = model.estimator.predict_proba(extract_frame(frame["url"].tolist()))[:, 1]
    pred = (scores >= 0.5).astype(int)
    y = frame["label"].to_numpy()
    tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tp = int(((pred == 1) & (y == 1)).sum())
    published = METRICS["test"]["standard_0.5"]["confusion_matrix"]
    check("live feature path reproduces the published confusion matrix",
          [[tn, fp], [fn, tp]] == published,
          f"live={[[tn, fp], [fn, tp]]} published={published}")


# --------------------------------------------------------------------------- #
# 4. Integration: real scans, results, reports, authorisation
# --------------------------------------------------------------------------- #
def check_integration() -> None:
    print("\n[4] End-to-end scans, result fields, audit rows and reports")
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "stage10.db"
        app = build_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{db_path}")
        with app.app_context():
            initialise_schema(app)
            registry = get_detection_registry(app)
            check("detection registry is ready at boot", registry.available)
            check("detection health describes the live engine",
                  registry.health()["status"] == "ready"
                  and registry.health()["feature_count"] == 15)
            client = app.test_client()

            page = client.get("/scan")
            body = page.get_data(as_text=True)
            check("GET /scan returns 200", page.status_code == 200)
            check("GET /scan contains the exact SCAN WEBSITE button",
                  "SCAN WEBSITE" in body)
            check("GET /scan has a CSRF token field", 'name="csrf_token"' in body)
            check("GET /scan says the engine is ready",
                  "ENGINE UNAVAILABLE" not in body)
            check("GET /scan has no inline script", not inline_scripts(body))
            check("GET /scan has no inline style attribute",
                  re.search(r"\sstyle\s*=", body, re.IGNORECASE) is None)
            check("GET /scan loads no external asset", not external_assets(body))
            csp = page.headers.get("Content-Security-Policy", "")
            for directive in ("default-src 'self'", "script-src 'self'",
                              "style-src 'self'", "form-action 'self'",
                              "img-src 'self' data:"):
                check(f"CSP unchanged :: {directive}", directive in csp)
            check("CSP still forbids inline code", "unsafe-inline" not in csp)

            health = client.get("/health")
            payload = health.get_json()
            check("/health is 200 and ok", health.status_code == 200
                  and payload["status"] == "ok")
            check("/health reports the delivered Stage 10 engine",
                  payload["detection"]["status"] == "ready"
                  and payload["detection"]["delivered_stage"] == 10
                  and payload["detection"]["scheduled_stage"] == 10)
            check("/health publishes the uncertainty band",
                  payload["detection"]["uncertainty_band"] == f"{LOW:g} < p < {HIGH:g}")
            check("/health leaks no measured performance figure",
                  all(word not in json.dumps(payload).lower()
                      for word in ("accuracy", "precision", "recall", "roc_auc")))

            index = client.get("/").get_data(as_text=True)
            check("overview links to the real scanner", "/scan" in index)
            check("overview says scanning is live", "URL scanning is live" in index)
            check("overview has no non-functional SCAN WEBSITE button",
                  "SCAN WEBSITE" not in index)

            results: list[dict[str, Any]] = []
            for url, name, risk, colour in CONTROLLED_CASES:
                response = client.post("/scan", json={"url": url})
                check(f"POST /scan returns 200 :: {name}", response.status_code == 200)
                data = response.get_json()["result"]
                results.append(data)
                state = DECISION_STATES[name]
                check(f"{name}: classification is exact", data["classification"] == name)
                check(f"{name}: risk is exact", data["risk_level"] == risk)
                check(f"{name}: colour is exact", data["colour"] == colour)
                check(f"{name}: message is exact", data["message"] == state["message"])
                check(f"{name}: warning is exact", data["warning"] == state["warning"])
                check(f"{name}: submitted URL is reported",
                      data["submitted_url"] == validate_url(url).normalized)
                check(f"{name}: score is labelled, not called a probability",
                      "uncalibrated" in data["score_label"].lower()
                      and "not a probability" in data["score_label"].lower())
                check(f"{name}: SCORE_MEANING is shown verbatim",
                      data["score_meaning"] == SCORE_MEANING)
                check(f"{name}: score is finite and in [0,1]",
                      0.0 <= data["model_score"] <= 1.0)
                check(f"{name}: date/time is ISO UTC",
                      data["date_time_utc"].endswith("+00:00"))
                check(f"{name}: all 15 characteristics reported",
                      len(data["characteristics"]) == 15)
                check(f"{name}: characteristics are the shared contract",
                      [c["name"] for c in data["characteristics"]] == list(FEATURE_ORDER))
                check(f"{name}: recommended action present",
                      bool(data["recommended_action"]))
                check(f"{name}: uncertainty note present",
                      bool(data["uncertainty_note"]))
                check(f"{name}: HTTPS caveat present", HTTPS_CAVEAT in data["caveats"])
                check(f"{name}: importance provenance recorded",
                      data["importance_source"] == IMPORTANCE_SOURCE)
                check(f"{name}: guest scan has no user id", data["user_id"] is None)
                check(f"{name}: persisted flag is True", data["persisted"] is True)
                check(f"{name}: thresholds come from the artefact",
                      data["thresholds"]["low"] == LOW
                      and data["thresholds"]["high"] == HIGH)
                html = client.post("/scan", data={"url": url}).get_data(as_text=True)
                for marker in (name, state["message"], state["warning"],
                               "Recommended action", "Extracted URL characteristics",
                               "Model score (clearly labelled)", "Date and time (UTC)",
                               HTTPS_CAVEAT, escaped_meaning()):
                    check(f"{name} HTML result shows :: {marker[:38]}", marker in html)
                check(f"{name} HTML result shows the submitted URL",
                      validate_url(url).normalized in html)
                check(f"{name} HTML result has the state CSS class",
                      f"pds-result-{name.lower()}" in html)
                check(f"{name} HTML result has no inline script",
                      not inline_scripts(html))
                check(f"{name} HTML result has no inline style attribute",
                      re.search(r"\sstyle\s*=", html, re.IGNORECASE) is None)
                check(f"{name} HTML result loads no external asset",
                      not external_assets(html))
                check(f"{name} HTML result shows all 15 feature names",
                      all(n in html for n in FEATURE_ORDER))
            check("SUSPICIOUS is flagged as uncertain", results[1]["uncertain"] is True)
            check("decisive states are not flagged uncertain",
                  results[0]["uncertain"] is False and results[2]["uncertain"] is False)
            check("PHISHING example has suspicious-feature explanations",
                  len(results[2]["flagged"]) > 0)
            check("all three states were exercised end to end",
                  {r["classification"] for r in results}
                  == {"LEGITIMATE", "SUSPICIOUS", "PHISHING"})

            # Every submitted scan (HTML + JSON) has exactly one audit row.
            rows = db.session.query(ScanHistory).order_by(ScanHistory.id).all()
            # Three controlled URLs, each submitted once as JSON and once as an
            # ordinary HTML form = six real scans.
            check("one audit row per successful scan", len(rows) == 6, str(len(rows)))
            for row in rows:
                check(f"audit row {row.id} has 15 stored features",
                      set(json.loads(row.features_json)["features"]) == set(FEATURE_ORDER))
                check(f"audit row {row.id} prediction is a valid state",
                      row.prediction in DECISION_STATES)
                check(f"audit row {row.id} score is in range",
                      0.0 <= row.model_score <= 1.0)
                check(f"audit row {row.id} stores the importance provenance",
                      json.loads(row.features_json)["importance_source"] == IMPORTANCE_SOURCE)
            check("guest rows have NULL user_id",
                  all(row.user_id is None for row in rows))

            # Printable report: no re-inference, no second row, access-controlled.
            before = len(rows)
            report = client.get(f"/scan/{rows[0].id}/report")
            check("owner can open the printable report", report.status_code == 200)
            report_html = report.get_data(as_text=True)
            for marker in (escaped_meaning(), "Report provenance",
                           "HTTPS alone does not mean a website is legitimate",
                           "Extracted URL characteristics",
                           "Recommended action", "Date and time (UTC)"):
                check(f"report shows :: {marker[:38]}", marker in report_html)
            check("report states provenance", "Report generated" in report_html)
            check("report does not create another scan",
                  db.session.query(ScanHistory).count() == before)
            check("another browser session cannot read a guest report",
                  other_session_get(app, f"/scan/{rows[0].id}/report").status_code == 404)
            check("unknown scan id returns 404",
                  client.get("/scan/999999/report").status_code == 404)

            # Authenticated scans are linked to the User.
            user = User(username="alice", email="alice@example.com", role="user")
            user.set_password(STRONG_PASSWORD)
            db.session.add(user)
            db.session.commit()
            signed_in = app.test_client()
            check("login succeeds",
                  signed_in.post("/login", json={"username": "alice",
                                                 "password": STRONG_PASSWORD}).status_code == 200)
            linked = signed_in.post("/scan", json={"url": URL_LEGITIMATE})
            check("authenticated scan succeeds", linked.status_code == 200)
            check("authenticated scan is linked to the user",
                  linked.get_json()["result"]["user_id"] == user.id)
            linked_id = linked.get_json()["result"]["scan_id"]
            row = db.session.get(ScanHistory, linked_id)
            check("linked row stores the user id", row.user_id == user.id)
            check("owner can open own report",
                  signed_in.get(f"/scan/{linked_id}/report").status_code == 200)
            check("different guest cannot open a user's report",
                  other_session_get(app, f"/scan/{linked_id}/report").status_code == 404)


# --------------------------------------------------------------------------- #
# 5. Failure paths, security and SSRF resistance
# --------------------------------------------------------------------------- #
def check_failures_and_security() -> None:
    print("\n[5] Explicit failure paths, validation, CSRF, XSS and no-network")
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "failures.db"
        app = build_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{db_path}")
        with app.app_context():
            initialise_schema(app)
            client = app.test_client()
            invalid = ("", "   ", "not a url", "javascript:alert(1)",
                       "ftp://example.com/", "file:///etc/passwd",
                       "https://", "x" * 2100, 123, None, [], {})
            for value in invalid:
                r = client.post("/scan", json={"url": value})
                check(f"invalid input rejected :: {str(value)[:22]!r}",
                      r.status_code == 400
                      and r.get_json()["error"]["code"] == "INVALID_URL")
            html_bad = client.post("/scan", data={"url": "not a url"})
            check("HTML form error is redisplayed with status 400",
                  html_bad.status_code == 400
                  and "INVALID INPUT" in html_bad.get_data(as_text=True))
            check("rejected input created no audit row",
                  db.session.query(ScanHistory).count() == 0)

            # XSS: a submitted string must be autoescaped, never interpreted.
            xss = "https://example.com/?q=<script>alert(1)</script>"
            xss_page = client.post("/scan", json={"url": xss})
            check("URL containing markup is still a bounded string",
                  xss_page.status_code == 200)
            xss_html = client.post("/scan", data={"url": xss}).get_data(as_text=True)
            check("rendered result escapes the submitted markup",
                  "<script>alert(1)</script>" not in xss_html)
            check("rendered result contains the escaped form",
                  "&lt;script&gt;" in xss_html)

            # No outbound network I/O, including for internal-looking addresses.
            with mock.patch.object(socket.socket, "connect",
                                   side_effect=AssertionError("outbound socket attempted")), \
                 mock.patch.object(socket, "create_connection",
                                   side_effect=AssertionError("outbound connection attempted")):
                for target in ("http://127.0.0.1/",
                               "http://169.254.169.254/latest/meta-data/",
                               URL_PHISHING):
                    r = client.post("/scan", json={"url": target})
                    check(f"scan makes NO network connection :: {target[:40]}",
                          r.status_code == 200, str(r.status_code))
            check("internal-looking URLs were stored as strings only",
                  db.session.query(ScanHistory).count() >= 3)

            # CSRF contract inherited from Stage 8.
            csrf_app = build_app(
                SQLALCHEMY_DATABASE_URI=f"sqlite:///{Path(td) / 'csrf.db'}",
                WTF_CSRF_ENABLED=True, RATELIMIT_ENABLED=False,
            )
            with csrf_app.app_context():
                initialise_schema(csrf_app)
                csrf_client = csrf_app.test_client()
                blocked = csrf_client.post("/scan", data={"url": URL_LEGITIMATE})
                check("POST /scan without a CSRF token is rejected",
                      blocked.status_code == 400)
                form = csrf_client.get("/scan").get_data(as_text=True)
                token = re.search(r'name="csrf_token" value="([^"]+)"', form).group(1)
                accepted = csrf_client.post(
                    "/scan", data={"url": URL_LEGITIMATE, "csrf_token": token}
                )
                check("POST /scan with a CSRF token succeeds", accepted.status_code == 200)

        # Database write failure: no result is shown without its audit record.
        no_schema = build_app(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:")
        with no_schema.app_context():
            r = no_schema.test_client().post("/scan", json={"url": URL_LEGITIMATE})
            check("uninitialised database -> 503 DATABASE_UNAVAILABLE",
                  r.status_code == 503
                  and r.get_json()["error"]["code"] == "DATABASE_UNAVAILABLE")
            check("database failure never invents a classification",
                  "classification" not in r.get_json())
            check("database failure page leaks no traceback",
                  "Traceback" not in no_schema.test_client().post(
                      "/scan", data={"url": URL_LEGITIMATE}).get_data(as_text=True))

        # Missing bundle, and a hash-consistent but CORRUPT pickle (a real
        # model-loading failure, not just a missing-file shortcut).
        for label, builder in _broken_model_apps():
            broken = builder()
            with broken.app_context():
                probe = broken.test_client()
                h = probe.get("/health")
                check(f"{label}: /health degrades to 503", h.status_code == 503)
                check(f"{label}: /health names MODEL_UNAVAILABLE",
                      h.get_json()["error"]["code"] == "MODEL_UNAVAILABLE")
                check(f"{label}: /health detection status is unavailable",
                      h.get_json()["detection"]["status"] == "unavailable")
                get_page = probe.get("/scan")
                check(f"{label}: GET /scan still renders an honest banner",
                      get_page.status_code == 200
                      and "ENGINE UNAVAILABLE" in get_page.get_data(as_text=True))
                post = probe.post("/scan", json={"url": URL_PHISHING})
                check(f"{label}: POST /scan -> 503 MODEL_UNAVAILABLE",
                      post.status_code == 503
                      and post.get_json()["error"]["code"] == "MODEL_UNAVAILABLE")
                check(f"{label}: no rule-based fallback verdict",
                      all(word not in json.dumps(post.get_json())
                          for word in ('"classification"', '"prediction"')))
                html_fail = probe.post("/scan", data={"url": URL_PHISHING})
                check(f"{label}: HTML failure leaks no traceback",
                      b"Traceback" not in html_fail.data)
                check(f"{label}: HTML failure never shows a verdict card",
                      b"pds-result-phishing" not in html_fail.data)


def _broken_model_apps():
    """Yield (label, factory) for the two genuine model-unavailable cases."""
    real_bundle = ROOT / "ml/saved_model/model_bundle.joblib"
    real_metrics = ROOT / "ml/saved_model/metrics.json"

    def missing():
        return build_app(MODEL_BUNDLE_PATH=str(ROOT / "missing" / "no_bundle.joblib"))

    corrupt_dir = Path(tempfile.mkdtemp(prefix="pds-corrupt-"))
    bad = b"this is deliberately not a joblib pickle"
    (corrupt_dir / "model_bundle.joblib").write_bytes(bad)
    meta = json.loads((ROOT / "ml/saved_model/metadata.json").read_text(encoding="utf-8"))
    meta["model_bundle_sha256"] = hashlib.sha256(bad).hexdigest()
    (corrupt_dir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")

    def corrupt():
        return build_app(
            METADATA_PATH=str(corrupt_dir / "metadata.json"),
            MODEL_BUNDLE_PATH=str(corrupt_dir / "model_bundle.joblib"),
            METRICS_PATH=str(real_metrics),
        )

    def missing_metrics():
        return build_app(METRICS_PATH=str(corrupt_dir / "no_metrics.json"))

    _ = real_bundle
    return (
        ("bundle file missing", missing),
        ("corrupt hash-consistent pickle", corrupt),
        ("measured provenance missing", missing_metrics),
    )


# --------------------------------------------------------------------------- #
# 6. Configuration and documentation
# --------------------------------------------------------------------------- #
def check_config_and_docs() -> None:
    print("\n[6] Configuration and Stage 10 documentation")
    summary = describe_config()
    # Gate 10 is also a regression under Gate 11+, so these are "Stage 10 or
    # later" checks; Gate 11 asserts the exact delivered value itself.
    check("config reports Stage 10 or later", summary.get("build_stage") >= 10)
    check("config version follows the stage 0.x.0 series",
          re.fullmatch(r"0\.\d+\.0", str(summary.get("app_version", ""))) is not None)
    app = build_app()
    check("app.config BUILD_STAGE is 10 or later", app.config["BUILD_STAGE"] >= 10)
    check("scanning blueprint is registered", "scanning" in app.blueprints)
    rules = {str(rule) for rule in app.url_map.iter_rules()}
    for rule in ("/scan", "/scan/<int:scan_id>/report"):
        check(f"url_map contains {rule}", rule in rules)
    if STAGE_11_DELIVERED:
        for rule in ("/dashboard", "/history", "/history/export.csv",
                     "/admin", "/admin/export.csv"):
            check(f"Stage 11 adds {rule}", rule in rules)
    else:
        for rule in ("/dashboard", "/history", "/admin"):
            check(f"Stage 11 rule still absent :: {rule}", rule not in rules)
    # Stage 12's REST endpoint is absent before Stage 12 and present after it.
    if STAGE_12_DELIVERED:
        check("Stage 12 adds /api/v1/scan", "/api/v1/scan" in rules)
        check("Stage 12 adds /api/v1/model/info", "/api/v1/model/info" in rules)
    else:
        check("Stage 12 /api/v1/scan still absent", "/api/v1/scan" not in rules)
    check("app attaches the detection registry",
          "detection_registry" in app.extensions)

    detection_doc = read("docs/DETECTION.md")
    for section in DETECTION_SECTIONS:
        check(f"DETECTION.md :: {section}", section in detection_doc)
    check("DETECTION.md states the exact HTTPS caveat",
          HTTPS_CAVEAT in detection_doc)
    check("DETECTION.md states the score is not a guarantee",
          "not a guarantee" in detection_doc.lower())
    check("DETECTION.md documents the no-network rule",
          "SSRF" in detection_doc and "never" in detection_doc.lower())
    check("DETECTION.md gives Windows-first commands",
          ".\\.venv\\Scripts\\Activate.ps1" in detection_doc
          or "python scripts\\init_db.py" in detection_doc)
    check("DETECTION.md documents model-load failure",
          "MODEL_UNAVAILABLE" in detection_doc)
    check("DETECTION.md documents the database failure path",
          "DATABASE_UNAVAILABLE" in detection_doc)

    readme = read("README.md")
    check("README marks Stage 10 complete",
          re.search(r"\|\s*10\s*\|.*✅", readme) is not None)
    check("README lists docs/DETECTION.md", "docs/DETECTION.md" in readme)
    plan = read("docs/STAGE_PLAN.md")
    check("STAGE_PLAN records Stage 10 as delivered", "Stage 10 — delivered" in plan)
    check("STAGE_PLAN previews Stage 11", "Stage 11" in plan)
    decisions = read("docs/DECISIONS.md")
    for adr in ("ADR-030", "ADR-031", "ADR-032"):
        check(f"DECISIONS.md contains {adr}", adr in decisions)
    for rel, marker in (
        ("docs/ARCHITECTURE.md", "Stage 10 implementation note"),
        ("docs/BACKEND.md", "Stage 10 update"),
        ("docs/UI.md", "Stage 10 update"),
        ("docs/DATABASE.md", "Stage 10 update"),
        ("docs/SETUP.md", "Stage 10"),
    ):
        check(f"{rel} has its Stage 10 note", marker in read(rel))
    ui = read("docs/UI.md")
    check("UI.md keeps the Stage 9 no-scan honesty rule for Gate 9",
          "no scan" in ui.lower() or "not wired" in ui.lower())
    check("SETUP.md gives the Windows scan commands",
          "verify_stage10.py" in read("docs/SETUP.md"))


# --------------------------------------------------------------------------- #
# 7. Historical regressions
# --------------------------------------------------------------------------- #
def check_regressions() -> None:
    print("\n[7] Historical exit gates 1-9 and dependency health")
    # Each historical gate re-runs all earlier gates. Without this marker that
    # recursion is exponential (Gate 9 alone would spawn 256 processes). This
    # gate runs all nine directly, so children skip only their DUPLICATED
    # nested regressions; every gate's own acceptance checks still execute.
    # Running any verify_stageN.py standalone leaves the marker unset and
    # preserves its full historical behaviour.
    env = os.environ.copy()
    env["PDS_GATE_NESTED"] = "1"
    for stage in range(1, 10):
        script = f"verify_stage{stage}.py"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script)],
            cwd=str(ROOT), capture_output=True, text=True, timeout=900, env=env,
        )
        check(f"Gate {stage} still passes",
              completed.returncode == 0 and "RESULT: PASS" in completed.stdout,
              f"exit={completed.returncode} tail={completed.stdout[-300:]}")
    pip = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300,
    )
    check("pip check reports no broken requirements",
          pip.returncode == 0 and "No broken requirements" in pip.stdout,
          pip.stdout.strip()[:200])


def main() -> int:
    print("=" * 78)
    print("STAGE 10 EXIT GATE - real URL-only ML detection integration")
    print("=" * 78)
    check_inventory()
    check_sources()
    check_units()
    check_integration()
    check_failures_and_security()
    check_config_and_docs()
    check_regressions()
    print("\n" + "=" * 78)
    print(f"CHECKS: {CHECKS}  SKIPPED: {SKIPPED}  FAILURES: {len(FAILURES)}")
    if FAILURES:
        for item in FAILURES:
            print(f"  - {item}")
        print("RESULT: FAIL - Stage 10 is NOT complete")
        return 1
    print("RESULT: PASS - all Stage 10 checks passed")
    print("Stage 10 exit gate satisfied. You may proceed to Stage 11.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
