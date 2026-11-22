"""Overview, health and favicon blueprint (Stages 7-10).

Routes
------
    GET /            product overview + live system telemetry (Stage 9 template)
    GET /health      machine-readable health + artefact/schema integrity
    GET /favicon.ico 204, so browsers do not generate a spurious 404

Stage 9 replaced the fixed, inline HTML string with ``templates/index.html``
and a full Jinja2 inheritance layout. The POST/JSON contracts are unchanged,
``/health`` still carries zero measured model results, and no template embeds
an inline script or style (the strict CSP remains ``script-src 'self'``).

Stage 10 wires ``GET/POST /scan`` (in ``routes/scanning.py``) into the status
page: the overview now links to the real scanner, and ``/health`` reports the
detection engine's readiness instead of saying it is future work. The
``detection`` health block is supplied by ``DetectionRegistry.health()``, so
it describes the ACTUAL loaded estimator and measured provenance.

The only chart on the overview shows REAL dataset split row counts read at
runtime from ``metadata.json`` via ``ModelRegistry.dataset_chart()``. Model
performance figures are not read here: the measured evaluation artefacts are
consumed by the Stage 11 dashboard at runtime, never typed into a template.
"""
from __future__ import annotations

from flask import Blueprint, Response, current_app, jsonify, render_template
from werkzeug.wrappers import Response as WerkzeugResponse

from services.database_service import database_status
from services.detection_service import get_detection_registry
from services.model_metadata import get_registry

core_bp = Blueprint("core", __name__)


@core_bp.get("/")
def index() -> str:
    """Render the product overview with live, secret-free telemetry."""
    registry = get_registry()
    chart = registry.dataset_chart()
    meta = registry.metadata
    states = [
        {
            "name": name,
            "css": f"pds-state-{name.lower()}",
            **meta.decision_states[name],
        }
        for name in ("LEGITIMATE", "SUSPICIOUS", "PHISHING")
    ]
    split_rows = [
        {"label": label, "value": f"{value:,}"}
        for label, value in zip(chart["labels"], chart["values"])
    ]
    return render_template(
        "index.html",
        info=registry.public_info(),
        bundle=registry.health(),
        db_status=database_status(),
        detection=get_detection_registry().health(),
        feature_order=meta.feature_order,
        states=states,
        split_chart=chart,
        split_rows=split_rows,
        environment=current_app.config["ENV_NAME"],
        debug=current_app.config["DEBUG"],
    )


@core_bp.get("/health")
def health() -> tuple[Response, int]:
    """Machine-readable health contract.

    HTTP 200 means the app, configuration and model artefact are consistent.
    HTTP 503 ``MODEL_UNAVAILABLE`` means the bundle is missing or its hash
    changed; the app still reports honestly instead of inventing a result.
    ``detection.status`` is independent: a hash-verified bundle can still fail
    to load, in which case POST /scan returns an explicit 503.
    """
    registry = get_registry()
    detection = get_detection_registry()
    cfg = current_app.config
    healthy = registry.bundle_available and detection.available
    payload = {
        "status": "ok" if healthy else "degraded",
        "app": cfg["APP_NAME"],
        "version": cfg["APP_VERSION"],
        "environment": cfg["ENV_NAME"],
        "build_stage": cfg["BUILD_STAGE"],
        "model": registry.public_info(),
        "bundle": registry.health(),
        # Real schema inspection: "ready", "not_initialised" or "error".
        # It reports table names and row counts, never credentials or metrics.
        "database": database_status(),
        # Stage 10: the LIVE engine's own status, never a hard-coded claim.
        "detection": detection.health(),
        "extensions": {
            "sqlalchemy": "sqlalchemy" in current_app.extensions,
            "csrf": cfg["WTF_CSRF_ENABLED"],
            "login_manager": hasattr(current_app, "login_manager"),
            "rate_limiter_enabled": cfg["RATELIMIT_ENABLED"],
        },
    }
    if not healthy:
        payload["error"] = {
            "code": "MODEL_UNAVAILABLE",
            "message": "The detection model is unavailable; no result can be produced.",
        }
    return jsonify(payload), (200 if healthy else 503)


@core_bp.get("/favicon.ico")
def favicon() -> WerkzeugResponse:
    """Avoid a spurious 404 for the browser's automatic icon request."""
    return WerkzeugResponse(status=204)


__all__ = ["core_bp"]
