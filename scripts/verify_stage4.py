#!/usr/bin/env python3
"""Stage 4 exit gate: feature contract, parity, validation and EDA.

    cd phishing-detection-system
    python scripts/verify_stage4.py

Exits 0 only when all checks pass. Uses safe, controlled URL strings only;
no live or malicious website is contacted and no model is trained.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Set by a parent gate (e.g. verify_stage10.py) to avoid running
# the same historical gate exponentially many times. A standalone
# run has this unset and keeps its complete regression behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.feature_extraction import (  # noqa: E402
    BRAND_TOKENS, FEATURE_DEFINITIONS, FEATURE_ORDER, FEATURE_RATIONALES,
    SHORTENER_DOMAINS, SUSPICIOUS_WORDS, extract_features, extract_frame,
    features_to_frame,
)
from ml.url_utils import normalize_url  # noqa: E402
from services.validation import (  # noqa: E402
    URLValidationError, is_valid_submitted_url, safe_display_url, validate_url,
)

EXPECTED_ORDER = (
    "url_length", "domain_length", "num_dots", "num_hyphens",
    "num_special_chars", "num_digits", "has_ip_address", "has_at_symbol",
    "has_suspicious_pattern", "num_subdomains", "has_https", "is_shortened",
    "num_suspicious_words", "has_unusual_port", "has_encoded_chars",
)

REQUIRED_FILES = (
    "ml/feature_extraction.py",
    "ml/url_utils.py",
    "services/__init__.py",
    "services/validation.py",
    "docs/FEATURES.md",
    "scripts/analyse_features.py",
    "scripts/verify_stage4.py",
    "dataset/processed/feature_summary.json",
    "dataset/processed/feature_summary.csv",
)

REQUIRED_DOC_SECTIONS = (
    "## 1. Purpose and the parity contract",
    "## 2. Feature catalogue",
    "## 3. Worked examples",
    "## 4. Measured feature distributions",
    "### Critical dataset-bias warnings",
    "## 5. What is deliberately NOT a feature",
    "## 6. How to run and test",
    "## 7. Limitations",
)

FORBIDDEN_NOW = (
    "ml/train_model.py", "ml/evaluate_model.py", "ml/thresholds.py",
    "ml/saved_model/model_bundle.joblib", "ml/saved_model/metrics.json",
    "ml/saved_model/metadata.json", "docs/MODEL_CARD.md",
    "models/database_models.py", "models/prediction_model.py",
    "services/detection_service.py", "routes/auth.py", "routes/scanning.py",
    "app.py", "wsgi.py", "instance/phishing.db", "templates/index.html",
)

# Once Stage 5 is delivered, its gate enforces "no later-stage code".
STAGE_5_DELIVERED = (
    (ROOT / "ml" / "train_model.py").is_file()
    and (ROOT / "docs" / "TRAINING.md").is_file()
)
STAGE_6_DELIVERED = (
    (ROOT / "ml" / "saved_model" / "metrics.json").is_file()
    and (ROOT / "docs" / "EVALUATION.md").is_file()
)

failures: list[str] = []
checks = 0


def check(label: str, condition: bool, hint: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -> {hint}" if hint else ""))
        failures.append(label)


def check_files_and_contract() -> None:
    print("\n[1] Files and feature contract")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"file {rel}", path.is_file() and path.stat().st_size > 0, "missing or empty")
    check("FEATURE_ORDER has 15 entries", len(FEATURE_ORDER) == 15)
    check("FEATURE_ORDER matches the architecture contract", FEATURE_ORDER == EXPECTED_ORDER)
    check("FEATURE_ORDER has no duplicates", len(set(FEATURE_ORDER)) == len(FEATURE_ORDER))
    check("FEATURE_DEFINITIONS covers exactly the contract",
          set(FEATURE_DEFINITIONS) == set(FEATURE_ORDER))
    check("FEATURE_RATIONALES covers exactly the contract",
          set(FEATURE_RATIONALES) == set(FEATURE_ORDER))
    check("SUSPICIOUS_WORDS contains all 7 required words",
          set(SUSPICIOUS_WORDS) == {"login", "verify", "update", "secure", "account", "banking", "confirm"})
    check("shortener and brand vocabularies are non-empty static sets",
          len(SHORTENER_DOMAINS) >= 20 and len(BRAND_TOKENS) >= 10)

    doc = (ROOT / "docs/FEATURES.md").read_text(encoding="utf-8")
    for section in REQUIRED_DOC_SECTIONS:
        check(f"FEATURES.md :: {section}", section in doc)
    for name in FEATURE_ORDER:
        check(f"FEATURES.md documents `{name}`", f"`{name}`" in doc)
    check("FEATURES.md warns HTTPS is not proof of legitimacy",
          "HTTPS alone does not mean a website is legitimate" in doc)
    if STAGE_6_DELIVERED:
        check("FEATURES.md points to the Stage 6 measured results",
              "Stage 4 itself trained no model" in doc and "docs/EVALUATION.md" in doc)
    else:
        check("FEATURES.md states no model or metric exists yet",
              "No model has been trained and no performance metric has been measured yet" in doc)

    for rel in ("ml/feature_extraction.py", "ml/url_utils.py", "services/validation.py"):
        source = (ROOT / rel).read_text(encoding="utf-8")
        for forbidden in ("import requests", "import socket", "urllib.request", "http.client"):
            check(f"{rel} has no {forbidden}", forbidden not in source)


def check_controlled_features() -> None:
    print("\n[2] Feature behaviour on controlled URL strings")
    cases: list[tuple[str, dict[str, int]]] = [
        ("https://example.com/", {
            "domain_length": 11, "num_dots": 1, "has_https": 1,
            "has_ip_address": 0, "has_at_symbol": 0, "is_shortened": 0,
            "has_unusual_port": 0, "has_encoded_chars": 0, "num_subdomains": 0,
        }),
        ("http://example.com/", {"has_https": 0}),
        ("http://192.168.1.1/login", {"has_ip_address": 1, "num_subdomains": 0}),
        ("http://user@example.com/", {"has_at_symbol": 1, "num_special_chars": 1}),
        ("https://example.com:8443/a", {"has_unusual_port": 1}),
        ("https://example.com:443/a", {"has_unusual_port": 0}),
        ("http://example.com:80/a", {"has_unusual_port": 0}),
        ("https://bit.ly/abc", {"is_shortened": 1}),
        ("https://example.com/%2Flogin", {"has_encoded_chars": 1}),
        ("https://example.com/login", {"has_encoded_chars": 0}),
        ("https://example.com/login/verify/account/secure/update/banking/confirm",
         {"num_suspicious_words": 7}),
        ("https://a.b.c.example.co.uk//x?y=1?z=2",
         {"has_suspicious_pattern": 1, "num_subdomains": 3}),
        ("https://www.example.com/", {"has_suspicious_pattern": 0, "num_subdomains": 1}),
        ("https://paypal.com.verify.evil.example/login", {"has_suspicious_pattern": 1}),
        ("https://www.paypal.com/", {"has_suspicious_pattern": 0}),
        ("http://exa-mple.com/a-b-c?x=1&y=2", {"num_hyphens": 3, "num_digits": 2}),
    ]
    for url, expected in cases:
        vector = extract_features(url)
        wrong = {key: (vector[key], value) for key, value in expected.items()
                 if vector[key] != value}
        check(f"{url[:52]}", not wrong, f"mismatches {wrong}")

    short = extract_features("https://example.com/")
    long = extract_features("https://example.com/" + "a" * 100)
    check("url_length increases with URL length", long["url_length"] > short["url_length"])
    digits = extract_features("https://example.com/1234567890")
    check("num_digits counts digits", digits["num_digits"] == 10)
    frame = features_to_frame(short)
    check("features_to_frame has the exact contract columns", list(frame.columns) == list(FEATURE_ORDER))
    check("features_to_frame has one row of 15 integers",
          frame.shape == (1, 15) and all(str(dtype).startswith("int") for dtype in frame.dtypes))
    batch = extract_frame([case[0] for case in cases])
    check("extract_frame preserves row count and column order",
          batch.shape == (len(cases), 15) and list(batch.columns) == list(FEATURE_ORDER))
    check("extract_frame has no missing values", not batch.isna().any().any())
    check("all feature values are non-negative integers",
          all(int(v) == v and v >= 0 for row in batch.to_dict(orient="records") for v in row.values()))


def check_validation_and_parity() -> None:
    print("\n[3] Live validation and training-serving parity")
    raw = "  HTTPS://WWW.Example.COM:443/login?next=account  "
    validated = validate_url(raw)
    check("validate_url normalises host and removes default port",
          validated.normalized == "https://www.example.com/login?next=account",
          validated.normalized)
    check("ValidatedURL exposes scheme and host",
          validated.scheme == "https" and validated.host == "www.example.com")
    check("parity: raw input and validated URL give identical features",
          extract_features(raw) == extract_features(validated.normalized))
    check("parity: normalise_url output gives identical features",
          extract_features(raw) == extract_features(normalize_url(raw.strip()) or ""))
    check("extract_features is deterministic",
          extract_features(raw) == extract_features(raw))
    check("normalisation is idempotent at the feature level",
          extract_features(validated.normalized) == extract_features(validate_url(validated.normalized).normalized))
    check("is_valid_submitted_url accepts a good URL", is_valid_submitted_url("https://example.com"))
    check("safe_display_url truncates long strings",
          len(safe_display_url("https://example.com/" + "x" * 300)) == 120)

    bad_inputs = ("", "   ", "ftp://example.com", "javascript:alert(1)", "http://",
                  "http://exa mple.com", "https://example.com:notaport/x", "x" * 2100,
                  None, 123)
    for bad in bad_inputs:
        label = repr(bad)[:28]
        try:
            validate_url(bad)
            accepted = True
        except URLValidationError:
            accepted = False
        check(f"validate_url rejects {label}", not accepted)
        check(f"is_valid_submitted_url rejects {label}", not is_valid_submitted_url(bad))
        try:
            extract_features(bad)
            extracted = True
        except (ValueError, TypeError):
            extracted = False
        check(f"extract_features rejects {label}", not extracted)
    check("over-long input is rejected by the configured limit",
          not is_valid_submitted_url("https://example.com/" + "a" * 3000))
    check("URLValidationError message does not echo user input",
          "evil" not in str(validate_url_error_message("javascript:evil()")))


def validate_url_error_message(raw: str) -> str:
    """Return the validation error text for a bad string (helper for one check)."""
    try:
        validate_url(raw)
        return ""
    except URLValidationError as exc:
        return str(exc)


def check_real_data_and_summary() -> None:
    print("\n[4] Real training data and measured feature summary")
    import pandas as pd

    train = pd.read_csv(ROOT / "dataset" / "processed" / "train.csv")
    sample = train.head(2000)
    frame = extract_frame(sample["url"].tolist())
    check("batch extraction on 2,000 real training URLs", frame.shape == (2000, 15))
    check("real-data features contain no NaN", not frame.isna().any().any())
    check("real-data features are all finite and non-negative",
          bool((frame >= 0).all().all()))
    check("real-data feature columns match contract", list(frame.columns) == list(FEATURE_ORDER))
    for url in sample["url"].head(25):
        check(f"parity on stored training URL {url[:34]}",
              extract_features(url) == extract_features(normalize_url(url) or ""))

    summary = json.loads((ROOT / "dataset" / "processed" / "feature_summary.json").read_text())
    check("feature_summary.json covers 15 features", summary["feature_count"] == 15)
    check("feature_summary.json order matches contract", summary["feature_order"] == list(FEATURE_ORDER))
    check("feature_summary.json used the full training split",
          summary["rows_analysed"] == len(train))
    check("feature_summary.json excluded validation and test",
          summary["splits_read"] == ["train"]
          and set(summary["splits_explicitly_excluded"]) == {"validation", "test"})
    check("feature_summary.json states no model results",
          "no accuracy" in summary["description"].lower() or "Not model performance" in summary["description"])
    check("all summary percentages are within 0-100",
          all(0 <= row[key] <= 100 for row in summary["features"]
              for key in ("overall_present_pct", "legitimate_present_pct", "phishing_present_pct")))
    check("all summary means are finite numbers",
          all(isinstance(row[key], (int, float)) for row in summary["features"]
              for key in ("overall_mean", "legitimate_mean", "phishing_mean")))
    csv = pd.read_csv(ROOT / "dataset" / "processed" / "feature_summary.csv")
    check("feature_summary.csv has one row per feature", len(csv) == 15)
    check("feature_summary.csv feature names match contract", list(csv["feature"]) == list(FEATURE_ORDER))

    # The documented HTTPS bias must be a real measurement, not a typed claim.
    https = next(row for row in summary["features"] if row["feature"] == "has_https")
    doc = (ROOT / "docs/FEATURES.md").read_text(encoding="utf-8")
    check("FEATURES.md records the measured HTTPS bias",
          f"{https['legitimate_present_pct']:.2f}%" in doc
          and f"{https['phishing_present_pct']:.2f}%" in doc)
    check("HTTPS bias is genuinely present in the data",
          https["legitimate_present_pct"] > https["phishing_present_pct"] + 20)


def check_stage_discipline() -> None:
    print("\n[5] Stage discipline and regressions")
    if not STAGE_5_DELIVERED:
        for rel in FORBIDDEN_NOW:
            check(f"not created yet :: {rel}", not (ROOT / rel).exists())
        allowed = {
            "ml": {"__init__.py", "url_utils.py", "preprocess.py", "feature_extraction.py"},
            "services": {"__init__.py", "validation.py"},
            "models": set(), "routes": set(), "tests": set(), "templates": set(),
        }
        for directory, names in allowed.items():
            stray = [p.name for p in (ROOT / directory).glob("*.py") if p.name not in names]
            check(f"{directory}/ contains only Stage 1-4 modules", not stray, ", ".join(stray))
    else:
        print("  SKIP  no Stage 5+ code yet (delivered in Stage 5; enforced by verify_stage5.py)")

    for gate in ("verify_stage1.py", "verify_stage2.py", "verify_stage3.py"):
        # The top-level gate already executes every historical gate directly.
        # Skipping this duplicated nested re-run keeps the suite linear rather
        # than exponential; standalone runs are completely unaffected.
        if PDS_NESTED_GATES:
            print(f"  SKIP  nested regression {gate} (top-level gate runs it)")
            continue
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / gate)],
            capture_output=True, text=True, timeout=300, cwd=ROOT,
        )
        tail = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
        check(f"{gate} still passes", proc.returncode == 0, tail[-1] if tail else "no output")


def main() -> int:
    print("=" * 74)
    print("STAGE 4 EXIT GATE - URL feature extraction")
    print(f"Project root : {ROOT}")
    print("=" * 74)
    check_files_and_contract()
    check_controlled_features()
    check_validation_and_parity()
    check_real_data_and_summary()
    check_stage_discipline()
    print("\n" + "=" * 74)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        return 1
    print(f"RESULT: PASS - all {checks} checks passed")
    print("Stage 4 exit gate satisfied. You may proceed to Stage 5.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
