#!/usr/bin/env python3
"""Stage 2 exit gate: environment, dependency, configuration and wiring tests.

Run from anywhere with the project's virtual-environment Python:

    cd phishing-detection-system
    python scripts/verify_stage2.py

Exit code 0 = all checks passed, 1 = at least one check failed.
No dataset, model, database, Flask application or route is created by this
script; it only verifies that the Stage 2 environment is ready for Stage 3.
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.metadata as metadata
import io
import os
import subprocess
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Set by a parent gate (e.g. verify_stage10.py) to avoid running
# the same historical gate exponentially many times. A standalone
# run has this unset and keeps its complete regression behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REQUIRED_FILES = (
    "requirements.txt",
    "config.py",
    ".env.example",
    ".gitignore",
    "docs/SETUP.md",
    "docs/ENVIRONMENT.md",
    "scripts/verify_stage1.py",
    "scripts/verify_stage2.py",
    "README.md",
)

# Distribution name -> importable module name
MODULE_MAP = {
    "Flask": "flask",
    "Werkzeug": "werkzeug",
    "Jinja2": "jinja2",
    "itsdangerous": "itsdangerous",
    "click": "click",
    "blinker": "blinker",
    "Flask-SQLAlchemy": "flask_sqlalchemy",
    "SQLAlchemy": "sqlalchemy",
    "Flask-WTF": "flask_wtf",
    "WTForms": "wtforms",
    "email-validator": "email_validator",
    "Flask-Login": "flask_login",
    "Flask-Limiter": "flask_limiter",
    "limits": "limits",
    "python-dotenv": "dotenv",
    "numpy": "numpy",
    "pandas": "pandas",
    "scikit-learn": "sklearn",
    "joblib": "joblib",
    "pytest": "pytest",
    "waitress": "waitress",
}

REQUIRED_DIST_NAMES = tuple(MODULE_MAP)

REQUIRED_ENV_KEYS = (
    "APP_ENV", "SECRET_KEY", "RATE_LIMIT_SCAN", "RATE_LIMIT_AUTH",
    "RATE_LIMIT_API", "DECISION_LOW_DEFAULT", "DECISION_HIGH_DEFAULT",
    "MAX_URL_LENGTH", "ADMIN_PASSWORD",
)

# Files that belong to LATER stages and must not exist yet.
FORBIDDEN_NOW = (
    "app.py", "wsgi.py",
    "ml/feature_extraction.py", "ml/preprocess.py", "ml/train_model.py",
    "ml/evaluate_model.py", "ml/thresholds.py",
    "models/database_models.py", "models/prediction_model.py",
    "routes/auth.py", "routes/scanning.py", "routes/api.py",
    "services/detection_service.py", "tests/conftest.py",
    "ml/saved_model/model_bundle.joblib", "ml/saved_model/metrics.json",
    "instance/phishing.db", "templates/index.html",
)

# Stage awareness: once Stage 3 has been delivered, its own gate enforces
# "no later-stage code" and this historical gate stops asserting absence of
# Stage 3 files (otherwise a correct project would fail an old test).
STAGE_3_DELIVERED = (
    (ROOT / "ml" / "preprocess.py").is_file()
    and (ROOT / "docs" / "DATASET.md").is_file()
)

failures: list[str] = []
checks = 0


def skip(label: str, reason: str) -> None:
    """Report a check that no longer applies after a later stage is delivered."""
    print(f"  SKIP  {label} ({reason})")


def check(label: str, condition: bool, hint: str = "") -> None:
    """Record and print one named check."""
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -> {hint}" if hint else ""))
        failures.append(label)


def read(rel: str) -> str:
    path = ROOT / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def quiet_reload(module):
    """Reload config without printing its development-key notice."""
    with contextlib.redirect_stderr(io.StringIO()):
        return importlib.reload(module)


def quiet_load_config():
    """Import and reload config quietly (initial import also prints a notice)."""
    with contextlib.redirect_stderr(io.StringIO()):
        module = importlib.import_module("config")
        return importlib.reload(module)


# --------------------------------------------------------------------------- #
# 1. Runtime and files
# --------------------------------------------------------------------------- #
def check_runtime_and_files() -> None:
    print("\n[1] Runtime and Stage 2 files")
    version = ".".join(str(part) for part in sys.version_info[:3])
    check("Python >= 3.10", sys.version_info >= (3, 10), f"found {version}")
    check("running inside a virtual environment", sys.prefix != sys.base_prefix,
          "activate .venv before running this script")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"file {rel}", path.is_file() and path.stat().st_size > 0, "missing or empty")


# --------------------------------------------------------------------------- #
# 2. Dependency pins and imports
# --------------------------------------------------------------------------- #
def parse_requirements() -> list:
    """Parse requirements.txt into packaging Requirement objects."""
    from packaging.requirements import Requirement

    result = []
    for raw in read("requirements.txt").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            result.append(Requirement(line))
    return result


def check_dependencies() -> None:
    print("\n[2] Pinned dependencies")
    try:
        requirements = parse_requirements()
        check("requirements.txt parses as valid PEP 508", True)
    except Exception as exc:  # noqa: BLE001 - report any parse problem clearly
        check("requirements.txt parses as valid PEP 508", False, str(exc))
        return

    check("every requirement is version-pinned",
          all(len(req.specifier) > 0 for req in requirements),
          "a line has no version specifier")
    found = {req.name for req in requirements}
    for name in REQUIRED_DIST_NAMES:
        check(f"pin present :: {name}", name in found)

    from packaging.version import Version

    for req in requirements:
        if req.marker is not None and not req.marker.evaluate():
            continue
        try:
            installed = metadata.version(req.name)
        except metadata.PackageNotFoundError:
            check(f"installed :: {req.name}", False, "distribution missing")
            continue
        ok = req.specifier.contains(Version(installed), prereleases=True)
        check(f"version {req.name} == {installed}", ok, f"does not satisfy {req.specifier}")

    for dist, module_name in MODULE_MAP.items():
        try:
            importlib.import_module(module_name)
            check(f"import :: {module_name}", True)
        except Exception as exc:  # noqa: BLE001
            check(f"import :: {module_name} ({dist})", False, str(exc))

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "check"],
            capture_output=True, text=True, timeout=120, cwd=ROOT,
        )
        detail = (proc.stdout + proc.stderr).strip().splitlines()
        check("pip check: no broken requirements", proc.returncode == 0,
              detail[-1] if detail else "pip check failed")
    except (OSError, subprocess.TimeoutExpired) as exc:
        check("pip check: no broken requirements", False, str(exc))


# --------------------------------------------------------------------------- #
# 3. Configuration
# --------------------------------------------------------------------------- #
def check_configuration() -> None:
    print("\n[3] Configuration module")
    try:
        config = quiet_load_config()
    except Exception as exc:  # noqa: BLE001
        check("import config", False, str(exc))
        return
    check("import config", True)

    check("BASE_DIR is the project root", config.BASE_DIR == ROOT)
    check("python_version_supported()", config.python_version_supported())
    for name in ("DevelopmentConfig", "TestingConfig", "ProductionConfig"):
        cls = getattr(config, name, None)
        check(f"{name} subclasses BaseConfig",
              isinstance(cls, type) and issubclass(cls, config.BaseConfig))

    check("get_config('dev') resolves", config.get_config("dev") is config.DevelopmentConfig)
    check("get_config('test') resolves", config.get_config("test") is config.TestingConfig)
    check("get_config('prod') resolves", config.get_config("prod") is config.ProductionConfig)
    check("default environment is development", config.get_config() is config.DevelopmentConfig
          or os.environ.get("APP_ENV", "").lower() in {"testing", "test", "production", "prod"})
    try:
        config.get_config("not-a-real-environment")
        check("unknown APP_ENV raises ValueError", False)
    except ValueError:
        check("unknown APP_ENV raises ValueError", True)

    dev = config.DevelopmentConfig
    check("development secret is >= 32 chars", len(dev.SECRET_KEY or "") >= 32)
    check("development key is not a hardcoded constant",
          dev.SECRET_KEY != config.TEST_ONLY_SECRET_KEY)
    check("development debug on, cookies not forced Secure",
          dev.DEBUG and not dev.SESSION_COOKIE_SECURE)

    test = config.TestingConfig
    check("testing uses in-memory SQLite",
          test.SQLALCHEMY_DATABASE_URI == "sqlite:///:memory:")
    check("testing disables CSRF and rate limiting",
          not test.WTF_CSRF_ENABLED and not test.RATELIMIT_ENABLED)

    prod = config.ProductionConfig
    check("production debug off", not prod.DEBUG)
    check("production secure session cookies", prod.SESSION_COOKIE_SECURE)
    check("production CSRF enabled and strict",
          prod.WTF_CSRF_ENABLED and prod.WTF_CSRF_SSL_STRICT)
    check("production HTTPS preferred", prod.PREFERRED_URL_SCHEME == "https")

    # Production must REFUSE to run without a strong secret.
    original_secret = prod.SECRET_KEY
    try:
        prod.SECRET_KEY = ""
        problems = prod.validate()
        check("production validate() flags a missing SECRET_KEY",
              any("SECRET_KEY" in item for item in problems))
        try:
            prod.require_valid()
            check("production require_valid() raises without a secret", False)
        except RuntimeError:
            check("production require_valid() raises without a secret", True)
    finally:
        prod.SECRET_KEY = original_secret
    # Positive case: with a real secret supplied, production must validate cleanly.
    prod.SECRET_KEY = "p" * 64
    try:
        check("production config is valid once a secret exists", not prod.validate(),
              "; ".join(prod.validate()))
    finally:
        prod.SECRET_KEY = original_secret

    # Threshold sanity.
    check("default decision band is ordered",
          0.0 <= config.BaseConfig.DECISION_LOW_DEFAULT
          < config.BaseConfig.DECISION_HIGH_DEFAULT <= 1.0)
    check("decision band matches the documented provisional values",
          (config.BaseConfig.DECISION_LOW_DEFAULT, config.BaseConfig.DECISION_HIGH_DEFAULT)
          == (0.30, 0.70) or "DECISION_LOW_DEFAULT" in os.environ)
    original_band = (dev.DECISION_LOW_DEFAULT, dev.DECISION_HIGH_DEFAULT)
    try:
        dev.DECISION_LOW_DEFAULT, dev.DECISION_HIGH_DEFAULT = 0.9, 0.1
        check("validate() rejects an inverted decision band",
              any("decision thresholds" in item for item in dev.validate()))
    finally:
        dev.DECISION_LOW_DEFAULT, dev.DECISION_HIGH_DEFAULT = original_band

    # Environment overrides work on reload.
    original = os.environ.get("MAX_URL_LENGTH")
    original_rate = os.environ.get("RATE_LIMIT_SCAN")
    try:
        os.environ["MAX_URL_LENGTH"] = "4096"
        os.environ["RATE_LIMIT_SCAN"] = "7 per minute"
        reloaded = quiet_reload(config)
        check("MAX_URL_LENGTH env override honoured", reloaded.BaseConfig.MAX_URL_LENGTH == 4096)
        check("RATE_LIMIT_SCAN env override honoured",
              reloaded.BaseConfig.RATE_LIMIT_SCAN == "7 per minute")
        os.environ["DECISION_LOW_DEFAULT"] = "not-a-number"
        try:
            reloaded._env_float("DECISION_LOW_DEFAULT", 0.30)
            check("invalid numeric env var raises ValueError", False)
        except ValueError:
            check("invalid numeric env var raises ValueError", True)
        finally:
            os.environ.pop("DECISION_LOW_DEFAULT", None)
    finally:
        if original is None:
            os.environ.pop("MAX_URL_LENGTH", None)
        else:
            os.environ["MAX_URL_LENGTH"] = original
        if original_rate is None:
            os.environ.pop("RATE_LIMIT_SCAN", None)
        else:
            os.environ["RATE_LIMIT_SCAN"] = original_rate
        config = quiet_reload(config)
    check("configuration restored after override tests",
          config.BaseConfig.MAX_URL_LENGTH == int(original or 2048)
          and config.BaseConfig.RATE_LIMIT_SCAN == (original_rate or "10 per minute"))

    key1, key2 = config.generate_secret_key(), config.generate_secret_key()
    check("generate_secret_key() returns 64 hex chars", len(key1) == 64 and key1 != key2)

    summary = config.describe_config()
    check("describe_config() masks the secret", summary.get("secret_key") == "<set>")
    check("describe_config() does not leak a raw secret",
          key1 not in repr(summary) and "SECRET_KEY" not in repr(summary))
    check("model artefact paths point inside ml/saved_model",
          config.MODEL_DIR.is_dir()
          and config.BaseConfig.MODEL_BUNDLE_PATH.parent == config.MODEL_DIR)

    # .env.example and .gitignore hygiene.
    example = read(".env.example")
    for key in REQUIRED_ENV_KEYS:
        check(f".env.example :: {key}", f"{key}=" in example)
    import re
    check(".env.example contains no real secret value",
          re.search(r"^SECRET_KEY=[0-9a-fA-F]{32,}", example, re.MULTILINE) is None)
    gitignore = read(".gitignore")
    for token in (".env", ".venv/", "instance/*.db", "ml/saved_model/*.joblib"):
        check(f".gitignore :: {token}", token in gitignore)


# --------------------------------------------------------------------------- #
# 4. Integration wiring of installed libraries
# --------------------------------------------------------------------------- #
def check_wiring() -> None:
    print("\n[4] Dependency wiring smoke test (no files written)")
    # Third-party numeric solvers may emit benign OptimizeWarning notices on the
    # tiny 6-row smoke-test array; they are not failures.
    warnings.simplefilter("ignore")
    try:
        import joblib
        import numpy as np
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import (
            accuracy_score, confusion_matrix, f1_score,
            precision_score, recall_score, roc_auc_score,
        )
        from sklearn.model_selection import train_test_split
        from sklearn.tree import DecisionTreeClassifier

        X = np.array([[1, 0], [2, 1], [9, 8], [8, 9], [1, 1], [9, 9]], dtype=float)
        y = np.array([0, 0, 1, 1, 0, 1])
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.34, random_state=0, stratify=y
        )
        check("train_test_split works", len(X_train) and len(X_test))

        for name, estimator in (
            ("LogisticRegression", LogisticRegression(max_iter=200)),
            ("DecisionTree", DecisionTreeClassifier(random_state=0)),
            ("RandomForest", RandomForestClassifier(n_estimators=5, random_state=0)),
        ):
            estimator.fit(X_train, y_train)
            proba = estimator.predict_proba(X_test)
            check(f"{name} fit + predict_proba", proba.shape[0] == len(X_test) and proba.shape[1] == 2)

        rf = RandomForestClassifier(n_estimators=5, random_state=0).fit(X, y)
        buffer = io.BytesIO()
        joblib.dump(rf, buffer)
        buffer.seek(0)
        restored = joblib.load(buffer)
        check("joblib round-trip preserves predictions",
              np.array_equal(restored.predict(X), rf.predict(X)))

        frame = pd.DataFrame([{"url_length": 42, "num_dots": 2, "has_at_symbol": 1}])
        check("pandas DataFrame keeps declared column order",
              list(frame.columns) == ["url_length", "num_dots", "has_at_symbol"])
        preds = rf.predict(X)
        scores = rf.predict_proba(X)[:, 1]
        check("sklearn metric functions import and compute",
              all(0.0 <= value <= 1.0 for value in (
                  accuracy_score(y, preds), precision_score(y, preds),
                  recall_score(y, preds), f1_score(y, preds),
                  roc_auc_score(y, scores),
              )) and confusion_matrix(y, preds).shape == (2, 2))

        from flask import Flask
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        from flask_login import LoginManager
        from flask_sqlalchemy import SQLAlchemy
        from flask_wtf import CSRFProtect
        from werkzeug.security import check_password_hash, generate_password_hash

        app = Flask("stage2_smoke", static_folder=None)
        app.config.update(
            SECRET_KEY="stage2-smoke-key-" + "x" * 48,
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            TESTING=True,
            WTF_CSRF_ENABLED=True,
        )
        db = SQLAlchemy(app)
        csrf = CSRFProtect(app)
        login_manager = LoginManager(app)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            limiter = Limiter(
                get_remote_address, app=app, default_limits=[],
                storage_uri="memory://", enabled=False,
            )

        @app.get("/__stage2_ping")
        def ping():
            return {"status": "ok"}

        with app.test_client() as client:
            check("Flask test client responds", client.get("/__stage2_ping").status_code == 200)
        check("Flask extensions initialise together",
              all(obj is not None for obj in (db, csrf, login_manager, limiter)))

        password = "correct horse battery staple"
        hashed = generate_password_hash(password)
        check("password hash is not plaintext", password not in hashed and hashed != password)
        check("password verification succeeds / rejects wrong password",
              check_password_hash(hashed, password) and not check_password_hash(hashed, "wrong"))

        import waitress  # noqa: F401
        check("waitress WSGI server imports", True)
    except Exception as exc:  # noqa: BLE001
        check("wiring smoke test completed without exceptions", False, f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# 5. Stage discipline and Stage 1 regression
# --------------------------------------------------------------------------- #
def check_stage_discipline() -> None:
    print("\n[5] Stage discipline and Stage 1 regression")
    if not STAGE_3_DELIVERED:
        for rel in FORBIDDEN_NOW:
            check(f"not created yet :: {rel}", not (ROOT / rel).exists())
        for directory in ("ml", "models", "routes", "services", "tests", "templates"):
            stray = sorted((ROOT / directory).glob("*.py"))
            check(f"{directory}/ has no *.py yet", not stray,
                  ", ".join(path.name for path in stray))
    else:
        skip("no Stage 3+ code yet", "delivered in Stage 3; enforced by verify_stage3.py")

    gate = ROOT / "scripts" / "verify_stage1.py"
    if PDS_NESTED_GATES:
        print("  SKIP  nested Stage 1 regression (top-level gate runs it)")
    else:
        proc = subprocess.run(
            [sys.executable, str(gate)], capture_output=True, text=True,
            timeout=120, cwd=ROOT,
        )
        tail = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
        check("Stage 1 gate still passes", proc.returncode == 0,
              tail[-1] if tail else "no output")


def main() -> int:
    print("=" * 72)
    print("STAGE 2 EXIT GATE - development environment and configuration")
    print(f"Project root : {ROOT}")
    print(f"Interpreter  : {sys.executable}")
    print("=" * 72)

    check_runtime_and_files()
    check_dependencies()
    check_configuration()
    check_wiring()
    check_stage_discipline()

    print("\n" + "=" * 72)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        print("\nSee docs/SETUP.md section 7 (common errors) before moving on.")
        return 1
    print(f"RESULT: PASS - all {checks} checks passed")
    print("Stage 2 exit gate satisfied. You may proceed to Stage 3.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
