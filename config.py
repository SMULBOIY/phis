"""Central configuration for the Intelligent Phishing Website Detection System.

Stage 2 deliverable, extended in Stage 7 with the HTTP frame policy and the
WSGI host/port used by ``wsgi.py``. This module defines configuration ONLY. It
does not create a Flask application, a database, a model or any route. The
application factory that consumes it lives in ``app.py`` (Stage 7).

Design notes for the reader
---------------------------
* Three configuration classes are provided: DevelopmentConfig, TestingConfig
  and ProductionConfig. Flask will consume them with
  ``app.config.from_object(get_config())`` in Stage 7, and pytest will use
  ``TestingConfig`` in Stage 13.
* Secrets are read from environment variables. ``.env`` is loaded at import
  time with ``override=False`` so real environment variables always win.
  No secret value is hard-coded in this file for production use.
* DevelopmentConfig generates an EPHEMERAL random key if none is supplied.
  This keeps local development working while guaranteeing that no insecure
  constant ever ships in the repository. Sessions are invalidated on restart;
  set SECRET_KEY in .env if you want persistent sessions.
* ProductionConfig refuses to validate without a strong SECRET_KEY.
* Nothing here contacts the network, reads a dataset or imports a model.

Usage
-----
    from config import get_config, describe_config
    cfg = get_config()                 # reads APP_ENV
    cfg.require_valid()                # raises RuntimeError on bad config
    print(describe_config(cfg))        # safe, secret-free summary
"""
from __future__ import annotations

import os
import secrets
import sys
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DATASET_RAW_DIR = BASE_DIR / "dataset" / "raw"
DATASET_PROCESSED_DIR = BASE_DIR / "dataset" / "processed"
ML_DIR = BASE_DIR / "ml"
MODEL_DIR = ML_DIR / "saved_model"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DOCS_DIR = BASE_DIR / "docs"

MODEL_BUNDLE_FILENAME = "model_bundle.joblib"
METADATA_FILENAME = "metadata.json"
METRICS_FILENAME = "metrics.json"

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
MIN_PYTHON = (3, 10)
VERIFIED_PYTHON_MAX = (3, 13)
MIN_SECRET_KEY_LENGTH = 32
DEFAULT_SQLITE_URI = f"sqlite:///{INSTANCE_DIR / 'phishing.db'}"
TEST_ONLY_SECRET_KEY = "testing-only-not-a-real-secret-0000000000"


def load_environment(env_file: str | Path | None = None) -> Path:
    """Load a .env file if present. Existing environment variables take priority.

    ``env_file`` is only used by tests that want to point at a temporary file.
    Returns the path that was attempted (useful for diagnostics).
    """
    path = Path(env_file) if env_file is not None else (BASE_DIR / ".env")
    if path.is_file():
        load_dotenv(path, override=False)
    return path


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


def generate_secret_key() -> str:
    """Return a cryptographically random 64-character hexadecimal key."""
    return secrets.token_hex(32)


def _ephemeral_development_key() -> str:
    key = generate_secret_key()
    print(
        "config: SECRET_KEY is not set; generated an ephemeral development key. "
        "Sessions will be invalidated on restart. Add SECRET_KEY to .env to fix this.",
        file=sys.stderr,
    )
    return key


# Environment values are read once per module import. ``importlib.reload``
# re-reads them, which is how scripts/verify_stage2.py tests env overrides.
load_environment()
_ENV_SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
_ENV_DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
_ENV_APP_NAME = os.environ.get("APP_ENV", "").strip()


# --------------------------------------------------------------------------- #
# Configuration classes
# --------------------------------------------------------------------------- #
class BaseConfig:
    """Settings shared by every environment. Never instantiate this directly."""

    APP_NAME = "Intelligent Phishing Website Detection System"
    APP_VERSION = "0.14.0"
    ENV_NAME = "base"
    # Highest stage whose code has been delivered. Bumped by each stage.
    BUILD_STAGE = 14

    # --- secrets and core Flask behaviour ---
    SECRET_KEY: str | None = None
    DEBUG = False
    TESTING = False
    MAX_CONTENT_LENGTH = 64 * 1024          # 64 KB request body cap
    JSON_SORT_KEYS = False
    PREFERRED_URL_SCHEME = "https"

    # --- database ---
    SQLALCHEMY_DATABASE_URI = _ENV_DATABASE_URL or DEFAULT_SQLITE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    # --- detection-engine limits (used from Stage 10 onwards) ---
    MAX_URL_LENGTH = _env_int("MAX_URL_LENGTH", 2048)
    ALLOWED_URL_SCHEMES = ("http", "https")
    FEATURE_SCHEMA_VERSION = "1.0"
    # Provisional, UNMEASURED abstention band. Stage 6 replaces these at runtime
    # with calibrated values read from ml/saved_model/metadata.json.
    DECISION_LOW_DEFAULT = _env_float("DECISION_LOW_DEFAULT", 0.30)
    DECISION_HIGH_DEFAULT = _env_float("DECISION_HIGH_DEFAULT", 0.70)

    # --- model artefact locations ---
    MODEL_DIR = MODEL_DIR
    MODEL_BUNDLE_PATH = MODEL_DIR / MODEL_BUNDLE_FILENAME
    METADATA_PATH = MODEL_DIR / METADATA_FILENAME
    METRICS_PATH = MODEL_DIR / METRICS_FILENAME

    # --- WSGI server binding (Stage 7) ---
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = _env_int("PORT", 5000)

    # --- HTTP framing / clickjacking policy (Stage 7, ADR-025) ---
    # Production refuses to be embedded. Development and testing OMIT both
    # headers because the Arena live preview displays the dev server inside a
    # cross-origin iframe; sending DENY there would produce a blank preview.
    X_FRAME_OPTIONS: str | None = "DENY"
    CSP_FRAME_ANCESTORS: str | None = "'self'"

    # --- CSRF / XSS / session hardening ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # --- rate limiting (Flask-Limiter, Stage 12) ---
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True
    RATE_LIMIT_SCAN = os.environ.get("RATE_LIMIT_SCAN", "10 per minute")
    RATE_LIMIT_AUTH = os.environ.get("RATE_LIMIT_AUTH", "5 per minute")
    RATE_LIMIT_API = os.environ.get("RATE_LIMIT_API", "30 per hour")

    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    @classmethod
    def validate(cls) -> list[str]:
        """Return a list of configuration problems. Empty list means valid."""
        problems: list[str] = []
        key = cls.SECRET_KEY or ""
        if len(key) < MIN_SECRET_KEY_LENGTH:
            problems.append(
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters "
                "(generate one with: python -c \"import secrets; print(secrets.token_hex(32))\")"
            )
        low, high = cls.DECISION_LOW_DEFAULT, cls.DECISION_HIGH_DEFAULT
        if not (0.0 <= low < high <= 1.0):
            problems.append("decision thresholds must satisfy 0 <= DECISION_LOW_DEFAULT < DECISION_HIGH_DEFAULT <= 1")
        if not (64 <= cls.MAX_URL_LENGTH <= 8192):
            problems.append("MAX_URL_LENGTH must be between 64 and 8192")
        if tuple(cls.ALLOWED_URL_SCHEMES) != ("http", "https"):
            problems.append("ALLOWED_URL_SCHEMES must be exactly ('http', 'https')")
        if not cls.SQLALCHEMY_DATABASE_URI:
            problems.append("SQLALCHEMY_DATABASE_URI / DATABASE_URL is empty")
        if cls.ENV_NAME == "production" and cls.DEBUG:
            problems.append("DEBUG must be False in production")
        return problems

    @classmethod
    def require_valid(cls) -> None:
        """Raise RuntimeError if this configuration is not safe to run."""
        problems = cls.validate()
        if problems:
            raise RuntimeError(f"Invalid {cls.ENV_NAME} configuration: " + "; ".join(problems))

    @classmethod
    def describe(cls) -> dict[str, object]:
        """Return a safe, secret-free summary (safe to log or display)."""
        return {
            "environment": cls.ENV_NAME,
            "app_name": cls.APP_NAME,
            "app_version": cls.APP_VERSION,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "secret_key": "<set>" if cls.SECRET_KEY else "<missing>",
            "database": "<configured>" if cls.SQLALCHEMY_DATABASE_URI else "<missing>",
            "debug": cls.DEBUG,
            "testing": cls.TESTING,
            "csrf_enabled": cls.WTF_CSRF_ENABLED,
            "rate_limiting_enabled": cls.RATELIMIT_ENABLED,
            "session_cookie_secure": cls.SESSION_COOKIE_SECURE,
            "build_stage": cls.BUILD_STAGE,
            "frame_policy": cls.X_FRAME_OPTIONS or "<omitted for development preview>",
            "wsgi_bind": f"{cls.HOST}:{cls.PORT}",
            "decision_band": [cls.DECISION_LOW_DEFAULT, cls.DECISION_HIGH_DEFAULT],
            "max_url_length": cls.MAX_URL_LENGTH,
            "model_bundle": str(cls.MODEL_BUNDLE_PATH),
        }


class DevelopmentConfig(BaseConfig):
    """Local development: debug on, HTTP cookies allowed, ephemeral secret."""

    ENV_NAME = "development"
    DEBUG = True
    TESTING = False
    SECRET_KEY = _ENV_SECRET_KEY or _ephemeral_development_key()
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_SSL_STRICT = False
    PREFERRED_URL_SCHEME = "http"
    SQLALCHEMY_ECHO = False
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG")
    # Live preview is a cross-origin iframe; production keeps the strict policy.
    X_FRAME_OPTIONS = None
    CSP_FRAME_ANCESTORS = None


class TestingConfig(BaseConfig):
    """Automated tests: in-memory SQLite, CSRF/rate limiting disabled."""

    ENV_NAME = "testing"
    TESTING = True
    DEBUG = False
    SECRET_KEY = _ENV_SECRET_KEY or TEST_ONLY_SECRET_KEY
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    WTF_CSRF_SSL_STRICT = False
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"
    X_FRAME_OPTIONS = None
    CSP_FRAME_ANCESTORS = None


class ProductionConfig(BaseConfig):
    """Deployment: no debug, secure cookies, secret MUST come from the env."""

    ENV_NAME = "production"
    DEBUG = False
    TESTING = False
    SECRET_KEY = _ENV_SECRET_KEY or None
    SQLALCHEMY_DATABASE_URI = _ENV_DATABASE_URL or DEFAULT_SQLITE_URI
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_SSL_STRICT = True
    PREFERRED_URL_SCHEME = "https"
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")


CONFIG_MAP: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}

_ALIASES = {"dev": "development", "test": "testing", "prod": "production"}


def get_config(name: str | None = None) -> type[BaseConfig]:
    """Return the configuration class for ``name`` (or the APP_ENV variable)."""
    key = (name or _ENV_APP_NAME or "development").strip().lower()
    key = _ALIASES.get(key, key)
    if key not in CONFIG_MAP:
        raise ValueError(
            f"Unknown APP_ENV {key!r}. Choose one of: {', '.join(CONFIG_MAP)}"
        )
    return CONFIG_MAP[key]


def describe_config(config_class: type[BaseConfig] | None = None) -> dict[str, object]:
    """Safe summary of the active configuration, with secrets masked."""
    return (config_class or get_config()).describe()


def python_version_supported() -> bool:
    """True when this interpreter is at least the documented minimum."""
    return sys.version_info[:2] >= MIN_PYTHON


def python_version_verified() -> bool:
    """True when this interpreter is inside the version range we tested."""
    return MIN_PYTHON <= sys.version_info[:2] <= VERIFIED_PYTHON_MAX


__all__ = [
    "BASE_DIR", "INSTANCE_DIR", "DATASET_RAW_DIR", "DATASET_PROCESSED_DIR",
    "ML_DIR", "MODEL_DIR", "TEMPLATES_DIR", "STATIC_DIR", "DOCS_DIR",
    "BaseConfig", "DevelopmentConfig", "TestingConfig", "ProductionConfig",
    "CONFIG_MAP", "get_config", "describe_config", "load_environment",
    "generate_secret_key", "python_version_supported", "python_version_verified",
]
