"""Shared pytest fixtures for the Intelligent Phishing Website Detection System.

Stage 13 deliverable.

Why a conftest at all
---------------------
``app.py`` exposes ``create_app(config_class, overrides=...)`` instead of a
module-level ``app``. That is what makes an isolated test run possible: every
fixture here builds its OWN Flask instance with its OWN SQLite database, so no
test can touch ``instance/phishing.db``, the real model artefact or a colleague's
data. Nothing in this file performs network I/O, and every URL submitted during
the suite is a synthetic, controlled string (``example.com`` /
``example.invalid``) - the brief forbids testing against live malicious sites.

Fixture map
-----------
    app                  TestingConfig app, temp SQLite file, CSRF + limits off
    client               Werkzeug test client bound to ``app``
    clean_database       autouse truncation between tests (seeded rows survive)
    seeded               ids/names of the two seeded accounts
    member_client        a signed-in ordinary user
    admin_client         a signed-in administrator
    login_as / csrf_token_for / api_scan
                         small helper callables
    csrf_app / csrf_client
                         app WITH CSRF enforced (security tests)
    limited_app          app WITH Flask-Limiter enabled and tiny quotas
    production_app       ProductionConfig app (framing, HSTS, secure cookies)
    broken_model_app     app whose bundle file is missing      -> 503 always
    tampered_model_app   app whose bundle hash does not match  -> 503 always
    no_schema_app        app whose tables were never created   -> 503 on write
    raising_app          app with a view that raises, to test the 500 handler

Design rules honoured here
--------------------------
* TestingConfig disables CSRF and rate limiting so ordinary tests stay
  deterministic; the two security fixtures switch them back ON explicitly.
  ``extensions.limits_disabled()`` reads the EFFECTIVE config at request time,
  so a CSRF/limit-enabled app created later in the same process still behaves.
* Passwords are hashed ONCE per session (scrypt is deliberately slow) and the
  resulting hash is reused when seeding, which keeps the suite fast without
  weakening the production hashing contract.
* The Flask-Limiter singleton keeps storage across app factories, so the
  limiting fixture calls ``limiter.reset()`` around each test that uses it.
"""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# config.py prints a warning to stderr when SECRET_KEY is unset; the fixtures
# always supply a fixed test secret, so silence the import-time noise.
with contextlib.redirect_stderr(io.StringIO()):
    from app import create_app
    from config import ProductionConfig, TestingConfig
    from extensions import db, limiter
    from models.database_models import ModelInformation, ScanHistory, User, utcnow
    from services.database_service import initialise_schema
    from werkzeug.security import generate_password_hash

# --------------------------------------------------------------------------- #
# Controlled constants. NO real credential and NO real password is used.
# --------------------------------------------------------------------------- #
TEST_SECRET = "s" * 64
STRONG_PASSWORD = "Str0ng-Passw0rd!2026"
WEAK_PASSWORD = "password1"

ADMIN_USER = "testadmin"
ADMIN_EMAIL = "testadmin@example.com"
MEMBER_USER = "testmember"
MEMBER_EMAIL = "testmember@example.com"
SEEDED_USERNAMES = (ADMIN_USER, MEMBER_USER)

# Synthetic, controlled URLs. None of these is a live malicious website and the
# backend never contacts any of them; they are analysed as strings only.
SAFE_URL = "https://example.com"
BAND_URL = "https://example.com/"
PHISHING_URL = "https://www.example.org/about"
LOOKALIKE_URL = (
    "https://paypal.com.login.verify.example.invalid/secure/account/update?next=confirm"
)


# --------------------------------------------------------------------------- #
# Session-scoped primitives
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def password_hash() -> str:
    """One scrypt hash reused by the seeded accounts (scrypt is intentionally slow)."""
    return generate_password_hash(STRONG_PASSWORD, method="scrypt")


@pytest.fixture(scope="session")
def temp_dir() -> Iterator[Path]:
    """A temporary directory outside the repository for per-suite databases."""
    with tempfile.TemporaryDirectory(prefix="pds-tests-") as folder:
        yield Path(folder)


def _build(config_class: type[Any], database: Path | str, **overrides: Any):
    """Create one isolated app with a fixed secret and its own database."""
    settings: dict[str, Any] = {"SECRET_KEY": TEST_SECRET}
    if isinstance(database, Path):
        settings["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{database}"
    else:
        settings["SQLALCHEMY_DATABASE_URI"] = database
    settings.update(overrides)
    return create_app(config_class, overrides=settings)


def _seed(app, password_hash: str) -> None:
    """Create the schema, the measured audit row and the two test accounts."""
    with app.app_context():
        initialise_schema(app)
        for username, email, role in (
            (ADMIN_USER, ADMIN_EMAIL, "admin"),
            (MEMBER_USER, MEMBER_EMAIL, "user"),
        ):
            if db.session.query(User).filter_by(username=username).first() is None:
                db.session.add(User(
                    username=username,
                    email=email,
                    role=role,
                    active=True,
                    created_at=utcnow(),
                    password_hash=password_hash,
                ))
        db.session.commit()


# --------------------------------------------------------------------------- #
# The main, shared application
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def app(temp_dir: Path, password_hash: str):
    """TestingConfig app: temp SQLite file, CSRF off, rate limiting off."""
    application = _build(TestingConfig, temp_dir / "main.db")
    _seed(application, password_hash)
    return application


@pytest.fixture(autouse=True)
def clean_database(request) -> Iterator[None]:
    """Truncate per-test rows so tests cannot influence each other.

    Autouse, but it only touches the database when the test actually asked for
    ``app`` (or a fixture derived from it), so pure unit tests stay instant.
    The two seeded accounts and the measured ``model_information`` row survive.
    """
    if "app" not in request.fixturenames:
        yield
        return

    app = request.getfixturevalue("app")

    def truncate() -> None:
        with app.app_context():
            db.session.rollback()
            db.session.query(ScanHistory).delete()
            db.session.query(User).filter(
                User.username.notin_(SEEDED_USERNAMES)
            ).delete(synchronize_session=False)
            db.session.commit()

    truncate()
    yield
    truncate()


@pytest.fixture()
def seeded(app) -> dict[str, Any]:
    """Ids of the seeded accounts, read from the database (no hard-coded ids)."""
    with app.app_context():
        admin = db.session.query(User).filter_by(username=ADMIN_USER).one()
        member = db.session.query(User).filter_by(username=MEMBER_USER).one()
        model_rows = db.session.query(ModelInformation).count()
        return {
            "admin_id": admin.id,
            "member_id": member.id,
            "model_rows": model_rows,
            "admin_password": STRONG_PASSWORD,
        }


@pytest.fixture()
def client(app):
    """A fresh Werkzeug test client (a new 'browser', new cookie jar).

    Deliberately NOT used as a context manager: ``with client`` sets
    ``preserve_context=True``, which keeps one app context alive between
    requests and lets Flask-Login's cached ``g._login_user`` bleed across
    simulated browsers. A plain client gives each request a clean context,
    which is what a real visitor gets.
    """
    return app.test_client()


# --------------------------------------------------------------------------- #
# Small helper callables (fixtures, so no extra helper module is needed)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def login_as():
    """Return ``login_as(client, username, password=STRONG_PASSWORD)``."""

    def _login(client, username: str, password: str = STRONG_PASSWORD):
        return client.post(
            "/login", json={"username": username, "password": password}
        )

    return _login


@pytest.fixture()
def csrf_token_for():
    """Return ``csrf_token_for(client)`` -> the signed token for that session."""

    def _token(client) -> str:
        response = client.get("/api/v1/csrf-token")
        assert response.status_code == 200, response.get_data(as_text=True)[:200]
        token = (response.get_json() or {}).get("csrf_token", "")
        assert token, "the API must issue a CSRF token"
        return str(token)

    return _token


@pytest.fixture()
def api_scan():
    """Return ``api_scan(client, url, token=None)`` posting the JSON contract."""

    def _scan(client, url: Any, token: str | None = None):
        headers = {"X-CSRF-Token": token} if token else {}
        return client.post("/api/v1/scan", json={"url": url}, headers=headers)

    return _scan


@pytest.fixture()
def scan_count(app):
    """Return ``scan_count()`` -> rows in scan_history right now."""

    def _count() -> int:
        with app.app_context():
            db.session.expire_all()
            return db.session.query(ScanHistory).count()

    return _count


@pytest.fixture()
def member_client(app, login_as):
    """A client signed in as the ordinary user."""
    from flask import g, has_app_context

    if has_app_context():
        g.pop("_login_user", None)
    test_client = app.test_client()
    response = login_as(test_client, MEMBER_USER)
    assert response.status_code == 200, response.get_data(as_text=True)[:300]
    return test_client


@pytest.fixture()
def admin_client(app, login_as):
    """A client signed in as the administrator."""
    from flask import g, has_app_context

    if has_app_context():
        g.pop("_login_user", None)
    test_client = app.test_client()
    response = login_as(test_client, ADMIN_USER)
    assert response.status_code == 200, response.get_data(as_text=True)[:300]
    return test_client


# --------------------------------------------------------------------------- #
# Derived applications with a deliberately different configuration
# --------------------------------------------------------------------------- #
@pytest.fixture()
def csrf_app(temp_dir: Path, password_hash: str, request):
    """App WITH CSRF enforced and rate limiting still disabled."""
    application = _build(
        TestingConfig, temp_dir / f"csrf-{request.node.name[:24]}.db",
        WTF_CSRF_ENABLED=True, RATELIMIT_ENABLED=False,
    )
    _seed(application, password_hash)
    return application


@pytest.fixture()
def csrf_client(csrf_app):
    """Test client for the CSRF-enforcing app (no preserved context)."""
    return csrf_app.test_client()


@pytest.fixture()
def limited_app(temp_dir: Path, password_hash: str, request):
    """App WITH Flask-Limiter enabled and very small, config-driven quotas."""
    application = _build(
        TestingConfig, temp_dir / f"limits-{request.node.name[:24]}.db",
        RATELIMIT_ENABLED=True,
        WTF_CSRF_ENABLED=False,
        RATE_LIMIT_AUTH="2 per minute",
        RATE_LIMIT_SCAN="3 per minute",
        RATE_LIMIT_API="2 per minute",
    )
    _seed(application, password_hash)
    # The Limiter singleton shares its in-memory storage across app factories.
    with contextlib.suppress(Exception):
        limiter.reset()
    yield application
    with contextlib.suppress(Exception):
        limiter.reset()


@pytest.fixture()
def production_app(temp_dir: Path, password_hash: str):
    """ProductionConfig app: strict framing, HSTS and secure cookies."""
    application = _build(
        ProductionConfig, temp_dir / "production.db", SECRET_KEY=TEST_SECRET
    )
    _seed(application, password_hash)
    return application


@pytest.fixture()
def broken_model_app(temp_dir: Path, password_hash: str):
    """App whose model bundle is missing: detection must fail closed (503)."""
    application = _build(
        TestingConfig, temp_dir / "broken.db",
        MODEL_BUNDLE_PATH=temp_dir / "does-not-exist.joblib",
    )
    _seed(application, password_hash)
    return application


@pytest.fixture()
def tampered_model_app(temp_dir: Path, password_hash: str):
    """App whose bundle bytes no longer match metadata.json's SHA-256."""
    original = ROOT / "ml" / "saved_model" / "model_bundle.joblib"
    tampered = temp_dir / "tampered_bundle.joblib"
    tampered.write_bytes(original.read_bytes() + b"\x00tampered")
    application = _build(
        TestingConfig, temp_dir / "tampered.db", MODEL_BUNDLE_PATH=tampered
    )
    _seed(application, password_hash)
    return application


@pytest.fixture()
def no_schema_app(temp_dir: Path, password_hash: str, request):
    """App whose database file exists but was never initialised."""
    return _build(TestingConfig, temp_dir / f"empty-{request.node.name[:24]}.db")


@pytest.fixture()
def raising_app(temp_dir: Path, password_hash: str):
    """App with an extra route that raises, for the 500 handler contract.

    ``PROPAGATE_EXCEPTIONS`` is forced off so Flask renders the registered 500
    handler instead of re-raising into pytest (the TestingConfig default).
    """
    application = _build(
        TestingConfig, temp_dir / "raising.db", PROPAGATE_EXCEPTIONS=False
    )
    _seed(application, password_hash)

    @application.get("/boom-for-tests")
    def _boom():                      # pragma: no cover - executed by one test
        raise RuntimeError("deliberate failure: /home/user/secret/path")

    return application


# --------------------------------------------------------------------------- #
# Small shared utilities
# --------------------------------------------------------------------------- #
def utc_now() -> datetime:
    """Timezone-aware UTC 'now' used by assertions about stored timestamps."""
    return datetime.now(timezone.utc)
