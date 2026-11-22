"""HTTP layer: blueprint registry (Stages 7-12).

Blueprints are the modular boundary of this Flask monolith. Each stage adds a
blueprint to ``BLUEPRINTS`` here WITHOUT changing the detection pipeline:

    Stage 8  -> auth.py gained /login and /register (no new blueprint)
    Stage 9  -> core.py and auth.py now render templates/*.html
    Stage 10 -> scanning.py  (form, result, report)              [DELIVERED]
    Stage 11 -> dashboard.py, history.py, admin.py               [DELIVERED]
    Stage 12 -> api.py       (versioned REST JSON contract)      [DELIVERED]
    Stage 13 -> tests only

``register_blueprints`` is idempotent so a test can call it on an app that
already has a blueprint registered.
"""
from __future__ import annotations

from flask import Flask

from routes.admin import admin_bp
from routes.api import api_bp
from routes.auth import auth_bp
from routes.core import core_bp
from routes.dashboard import dashboard_bp
from routes.history import history_bp
from routes.scanning import scan_bp

BLUEPRINTS = (
    core_bp, auth_bp, scan_bp, dashboard_bp, history_bp, admin_bp, api_bp,
)


def register_blueprints(app: Flask) -> None:
    """Attach every blueprint that belongs to the current stage."""
    for blueprint in BLUEPRINTS:
        if blueprint.name not in app.blueprints:
            app.register_blueprint(blueprint)


__all__ = ["BLUEPRINTS", "register_blueprints"]
