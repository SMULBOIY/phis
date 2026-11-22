"""Shared Flask extension singletons (Stage 7).

Why this module exists
----------------------
Flask extensions must be created ONCE and bound to an application later with
``init_app(app)``. If ``app.py`` created them inside ``create_app()``, then
``models/database_models.py`` (Stage 8) could not do ``from extensions import
db`` without importing the application factory, which would create a circular
import. Keeping the singletons here is the standard Flask "app factory" pattern:

    extensions.py  ->  creates db / csrf / login_manager / limiter
    app.py         ->  create_app() binds them to a specific Flask instance
    models/*       ->  import db to declare ORM classes
    routes/*       ->  import csrf / limiter / login_manager to protect routes

All four extensions are wired now, but two of them are deliberately given no
work until later stages:

* ``db`` has no ORM models yet (Stage 8), so no table or database file is
  created by starting the app.
* ``limiter`` is initialised with NO default limits. Route-specific limits
  (``/scan``, ``/api/v1/scan``, ``/login``, ``/register``) are applied in
  Stage 12. Wiring it now proved the versions were compatible; that throttle
  is now active, still with ``default_limits=[]`` so static assets and GET
  pages are never blanket-throttled.

Stage 7 does NOT load the estimator. Loading ``model_bundle.joblib``, checking
its feature schema and calling ``predict_proba`` is Stage 10's job
(``models/prediction_model.py``). This stage only reads ``metadata.json`` so
that the application can report which model version it is configured for.
"""
from __future__ import annotations

from flask import current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# --- ORM (Stage 8 declares the models) ------------------------------------- #
db = SQLAlchemy()

# --- CSRF: protects every state-changing POST/PUT/PATCH/DELETE ------------- #
csrf = CSRFProtect()

# --- Session authentication ------------------------------------------------ #
login_manager = LoginManager()
login_manager.session_protection = "strong"
# Stage 8 adds the /login form and switches this to "auth.login". Until then an
# unauthenticated request is answered with an explicit 401, never a redirect to
# a route that does not exist.
login_manager.login_view = None
login_manager.login_message_category = "info"

# --- Rate limiting --------------------------------------------------------- #
# ``key_func`` is required by Flask-Limiter 3.x. ``default_limits=[]`` means no
# blanket throttle; Stage 12 decorates the endpoints that need one.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)

def limits_disabled() -> bool:
    """True when the EFFECTIVE app config turns rate limiting off (Stage 12).

    Flask-Limiter's singleton keeps state across application factories in one
    process. Reading ``RATELIMIT_ENABLED`` from ``current_app`` at request time
    (rather than trusting decoration-time state) makes every app independent,
    so ``TestingConfig`` stays unthrottled even if a test earlier in the same
    process created an app with limits enabled.
    """
    return not bool(current_app.config.get("RATELIMIT_ENABLED", True))


__all__ = ["db", "csrf", "login_manager", "limiter", "limits_disabled"]
