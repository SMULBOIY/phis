"""Flask application factory for the Intelligent Phishing Website Detection System.

Stage 7 deliverable, extended in Stage 8 with the ORM layer and real
authentication, in Stage 9 with the full Jinja2/CSS/JS interface, in Stage 10
with the live URL-only detection engine, in Stage 11 with the dashboard,
history, admin and CSV export views, and in Stage 12 with the versioned REST
API, per-route rate limits and hardened response headers, and in Stage 13 with
the formal pytest suite under tests/ (no runtime behaviour changed there).
Run it with:

    flask --app app run --host 0.0.0.0 --port 5000     (development)
    python wsgi.py                                     (waitress, production-like)

or build an isolated instance in a test / script:

    from app import create_app
    from config import TestingConfig
    app = create_app(TestingConfig)

What this file does, and why an application FACTORY
---------------------------------------------------
A module-level ``app = Flask(__name__)`` would be created at import time, so
tests could not swap in an in-memory database, disable CSRF or point at a
missing model bundle. ``create_app()`` builds a fresh, self-contained Flask
object every call. That is what makes the Stage 13 tests (including the
"model fails to load" case) possible without touching real data.

Startup sequence (order matters):
    1. select and validate the effective configuration;
    2. bind the four extension singletons from ``extensions.py``;
    3. install security headers, safe error handlers and the request-size guard;
    4. validate the Stage 6 model artefacts and attach a ``ModelRegistry``;
    5. register the blueprints that exist at this stage.

Stage 8 additions
-----------------
* ``models/`` is imported after ``db.init_app`` and ``configure_database(app)``
  installs ``PRAGMA foreign_keys=ON`` on this app's SQLite engine, so
  ``ON DELETE SET NULL`` really preserves guest history.
* The Flask-Login ``user_loader`` now resolves accounts through
  ``services.auth_service.get_user_by_id`` (fail-closed), and ``login_view``
  points at the real ``auth.login`` route. ``/login`` and ``/register`` are
  implemented in ``routes/auth.py``.
* Booting the app still creates NO tables. ``python scripts/init_db.py`` is
  the explicit bootstrap step; account routes return an honest
  ``503 DATABASE_UNAVAILABLE`` until it has been run.

Stage 9 additions
-----------------
* A context processor publishes ``app_name``, ``app_version``,
  ``build_stage``, ``environment`` and ``debug`` to every Jinja2 template.
* All pages now extend ``templates/base.html``; templates, vendored Bootstrap 5
  / Chart.js and the dark/light design system are served as LOCAL static files,
  so the strict CSP (``script-src 'self'``, ``style-src 'self'``) is unchanged.
* ``/`` is now the product overview (it still doubles as system telemetry),
  ``/login`` and ``/register`` use real templates, and error responses use
  ``templates/errors/error.html``.

Stage 10 additions
------------------
* After the Stage 6 metadata and bundle hash have been verified, a
  ``DetectionRegistry`` loads the real Joblib estimator exactly once and reads
  the measured feature importance at runtime. Both are attached to
  ``app.extensions``; ``/health`` reports their status honestly.
* ``routes/scanning.py`` supplies GET/POST ``/scan`` and the printable
  ``/scan/<id>/report``. A scan validates, extracts the shared 15 features,
  scores with ``predict_proba``, applies the measured abstention thresholds,
  explains the observations, and commits a ``ScanHistory`` row before the
  result is displayed. Guests may scan; signed-in scans are linked to a User.
* A missing/corrupt bundle, missing measured provenance or a failed database
  write is an explicit 503. There is NO rule-based fallback and NO result
  without its audit row.

Stage 11 additions
------------------
* ``routes/dashboard.py``, ``routes/history.py`` and ``routes/admin.py`` are
  registered from ``routes/__init__.py``. They are READ-ONLY views over the
  same SQLAlchemy models; the detection pipeline in ``services/detection_service.py``
  is untouched.
* ``services/stats_service.py`` counts real rows and reads the measured
  ``metrics.json`` at request time; ``services/report_service.py`` produces
  CSV with formula-injection and newline neutralisation.
* The global ``401 UNAUTHENTICATED`` handler is deliberately UNCHANGED:
  ``admin_required`` composes ``login_required`` with an explicit role check,
  so Stage 8's security contract still holds.

Stage 12 additions
------------------
* ``routes/api.py`` registers ``api_bp`` with the ``/api/v1`` prefix. It calls
  the SAME ``DetectionRegistry.scan()`` pipeline as the HTML form, so there is
  no second inference path and no unlogged result.
* Per-route, config-driven rate limits are attached to ``POST /scan``,
  ``POST /login``, ``POST /register`` and the API data endpoints. They are
  no-ops when ``RATELIMIT_ENABLED`` is false, so ``TestingConfig`` stays
  deterministic. ``default_limits=[]`` still means no blanket throttle.
* ``install_security_headers`` adds cross-origin isolation and no-store
  hardening; ``install_error_handlers`` adds a 429 handler with ``Retry-After``.
  The CSP directive list is UNCHANGED. ``BUILD_STAGE`` is 13.

Stage 13 additions
------------------
* ``tests/`` gained the formal pytest suite (259 cases) and ``docs/TEST_PLAN.md``
  was written. ``create_app()`` itself is unchanged: the suite is possible
  because this factory already accepts a config class and overrides, which is
  exactly why Stage 7 chose an application factory over a module-level ``app``.
* ``APP_VERSION`` / ``BUILD_STAGE`` are bumped to ``0.13.0`` / ``13`` so
  ``/health`` names the stage whose code is present. No route, model, template,
  schema or header changed.

Stage 14 additions
------------------
* Documentation and deployment only: ``docs/REPORT.md``, ``docs/DEPLOYMENT.md``,
  five UML diagrams under ``docs/diagrams/`` and a rewritten ``README.md``.
  ``APP_VERSION`` / ``BUILD_STAGE`` move to ``0.14.0`` / ``14``; the factory,
  every route, the model bundle, the schema and every response header are
  byte-for-byte what Stage 13 shipped.

Explicitly NOT in Stage 13
--------------------------
* No final report/deployment guide (Stage 14), no new feature and no pipeline
  change. No new tables, columns, migrations, secrets or auth schemes;
  no bearer tokens; no CSP relaxation; no CSRF exemption for API POSTs.
* Measured figures remain read-only from ``metrics.json`` at request time.

The backend performs NO outbound network I/O. It never visits, resolves or
executes a submitted URL, so there is no SSRF surface.
"""
from __future__ import annotations

import logging
from typing import Any, Mapping

from flask import Flask, Response

from config import MIN_SECRET_KEY_LENGTH, BaseConfig, get_config
from extensions import csrf, db, limiter, login_manager
from services.http_security import (
    install_error_handlers, install_request_guards, install_security_headers,
    make_error_response,
)
from services.model_metadata import ModelMetadataError, ModelRegistry

__all__ = ["create_app", "app"]


def _validate_runtime_config(app: Flask) -> None:
    """Validate the EFFECTIVE config, including any test overrides.

    ``config.py`` has ``BaseConfig.validate()`` too, but that inspects class
    attributes. Here we must inspect ``app.config`` because an override (for
    example ``SECRET_KEY`` supplied to ``ProductionConfig`` in a test) changes
    the values that actually govern the running application.
    """
    cfg = app.config
    problems: list[str] = []
    key = cfg.get("SECRET_KEY") or ""
    if len(key) < MIN_SECRET_KEY_LENGTH:
        problems.append(
            f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters"
        )
    low = cfg.get("DECISION_LOW_DEFAULT")
    high = cfg.get("DECISION_HIGH_DEFAULT")
    if not (isinstance(low, (int, float)) and isinstance(high, (int, float))
            and 0.0 <= low < high <= 1.0):
        problems.append("decision defaults must satisfy 0 <= low < high <= 1")
    limit = cfg.get("MAX_URL_LENGTH")
    if not isinstance(limit, int) or not (64 <= limit <= 8192):
        problems.append("MAX_URL_LENGTH must be between 64 and 8192")
    if not cfg.get("SQLALCHEMY_DATABASE_URI"):
        problems.append("SQLALCHEMY_DATABASE_URI is empty")
    if cfg.get("PREFERRED_URL_SCHEME") not in ("http", "https"):
        problems.append("PREFERRED_URL_SCHEME must be http or https")

    production = cfg.get("ENV_NAME") == "production"
    if production and cfg.get("DEBUG"):
        problems.append("DEBUG must be False in production")
    if production and not cfg.get("SESSION_COOKIE_SECURE"):
        problems.append("production requires SESSION_COOKIE_SECURE=True")
    if production and not cfg.get("WTF_CSRF_ENABLED"):
        problems.append("production requires CSRF protection")

    if problems:
        raise RuntimeError(
            f"Invalid {cfg.get('ENV_NAME')} configuration: " + "; ".join(problems)
        )


def _configure_login_manager(app: Flask) -> None:
    """Wire Flask-Login to the Stage 8 ORM-backed account lookup."""
    from services.auth_service import get_user_by_id

    login_manager.session_protection = "strong"
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"

    @login_manager.unauthorized_handler
    def _unauthorized() -> Response:
        # The documented error contract is 401 UNAUTHENTICATED (JSON on /api/*,
        # HTML elsewhere). Stage 11 may add friendly redirects for HTML pages.
        return make_error_response(
            401, "UNAUTHENTICATED", "Authentication is required for this resource."
        )

    @login_manager.user_loader
    def _load_user(user_id: str):
        # get_user_by_id converts, catches ORM errors and refuses inactive or
        # unknown accounts, so a stale/tampered cookie fails closed.
        return get_user_by_id(user_id)


def create_app(
    config_class: type[BaseConfig] | None = None,
    *,
    overrides: Mapping[str, Any] | None = None,
) -> Flask:
    """Create, configure and return one fully wired Flask application.

    Parameters
    ----------
    config_class:
        A ``config.py`` class (``DevelopmentConfig`` / ``TestingConfig`` /
        ``ProductionConfig``). Defaults to ``get_config()`` which reads
        ``APP_ENV``.
    overrides:
        Optional config values applied last. Used by automated tests to inject
        an isolated database, a fixed secret or a deliberately missing model
        artefact without editing any file.

    Raises
    ------
    RuntimeError
        If the effective configuration is unsafe, or if the Stage 6 model
        metadata is missing/inconsistent. Starting with a broken contract is
        refused rather than degraded into a rule-based guess.
    """
    selected = config_class or get_config()
    if not overrides:
        # No overrides: the Stage 2 class validator is authoritative.
        selected.require_valid()

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(selected)
    if overrides:
        app.config.update(dict(overrides))

    # Defaults keep the module usable even if a caller supplies a plain dict of
    # settings. Production is strict; development omits framing restrictions so
    # the cross-origin live-preview iframe can render. See ADR-025.
    is_production = app.config.get("ENV_NAME") == "production"
    app.config.setdefault("X_FRAME_OPTIONS", "DENY" if is_production else None)
    app.config.setdefault(
        "CSP_FRAME_ANCESTORS", "'self'" if is_production else None
    )
    app.config.setdefault("BUILD_STAGE", 14)

    _validate_runtime_config(app)
    app.logger.setLevel(getattr(logging, str(app.config.get("LOG_LEVEL", "INFO")).upper(), logging.INFO))

    # --- extensions -------------------------------------------------------- #
    db.init_app(app)
    # Import the ORM mappings and enable SQLite foreign keys before any query.
    # This registers mappers; it does NOT create tables or a database file.
    from models import configure_database

    configure_database(app)
    csrf.init_app(app)
    limiter.init_app(app)
    _configure_login_manager(app)
    login_manager.init_app(app)

    # --- template globals (Stage 9) ---------------------------------------- #
    # Jinja2 config is already available as ``config``; these five keys are
    # used by base.html on every page. Flask-Login supplies ``current_user``
    # and Flask-WTF supplies ``csrf_token()`` as their own Jinja globals.
    @app.context_processor
    def _template_globals() -> dict[str, Any]:
        return {
            "app_name": app.config["APP_NAME"],
            "app_version": app.config["APP_VERSION"],
            "build_stage": app.config["BUILD_STAGE"],
            "environment": app.config["ENV_NAME"],
            "debug": app.config["DEBUG"],
        }

    # --- HTTP security ----------------------------------------------------- #
    install_security_headers(app)
    install_error_handlers(app)
    install_request_guards(app)

    # --- Stage 6 artefacts -------------------------------------------------- #
    try:
        registry = ModelRegistry(
            app.config["METADATA_PATH"], app.config["MODEL_BUNDLE_PATH"]
        )
    except ModelMetadataError as exc:
        raise RuntimeError(
            f"Cannot start the web application without valid Stage 6 model metadata: {exc}"
        ) from exc
    app.extensions["model_registry"] = registry
    if not registry.bundle_available:
        app.logger.warning("Model bundle unavailable: %s", registry.bundle_detail)

    # --- Stage 10 detection engine ----------------------------------------- #
    # Loaded AFTER the SHA-256 check above. A failure here is recorded on the
    # registry (never raised out of the factory) so /health can report it and
    # /scan can return an explicit 503 instead of a heuristic guess.
    from services.detection_service import get_detection_registry

    detection = get_detection_registry(app)
    if not detection.available:
        app.logger.warning("Detection engine unavailable: %s", detection.error)

    # --- blueprints (imported last to avoid circular imports) -------------- #
    from routes import register_blueprints

    register_blueprints(app)
    app.logger.info(
        "%s v%s | env=%s | model=%s v%s | stage=%s",
        app.config["APP_NAME"], app.config["APP_VERSION"],
        app.config["ENV_NAME"], registry.metadata.model_name,
        registry.metadata.model_version, app.config["BUILD_STAGE"],
    )
    return app


# Vercel and WSGI platforms can discover this module-level Flask application.
app = create_app()
