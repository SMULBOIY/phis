"""Versioned REST API (Stage 12).

Routes (all under ``/api/v1``)
------------------------------
    GET  /api/v1/csrf-token       issue the session CSRF token for API clients
    GET  /api/v1/health           machine-readable readiness (no measured figures)
    GET  /api/v1/model/info       measured model card, states, thresholds, hashes
    POST /api/v1/scan             the documented JSON detection contract
    GET  /api/v1/scans            scoped, filtered, paginated scan history
    GET  /api/v1/scans/<id>       one authorised scan, rebuilt from its audit row

Design rules
------------
* The API calls the SAME ``DetectionRegistry.scan()`` pipeline as the HTML
  form. There is no second inference path, no rule fallback and no unlogged
  result. Every successful scan writes exactly one ``ScanHistory`` row.
* JSON in, JSON out. ``make_error_response`` already negotiates ``/api/*``
  paths as JSON, so every error has the documented ``error.code`` /
  ``error.message`` / ``error.status`` shape and never leaks a traceback.
* CSRF is NOT exempted. A browser-session API client obtains a token from
  ``GET /api/v1/csrf-token`` (or ``/auth/csrf-token``) and sends it in the
  ``X-CSRF-Token`` header. This keeps Stage 8's protection on every state-
  changing request instead of inventing a weaker token scheme.
* Visibility is Stage 10/11's policy: ``can_view_scan`` for one row and
  ``stats_service.visible_query`` for lists. A guest sees only ids in their own
  signed session; an authenticated user sees only their own rows.
* Per-route rate limits are config-driven (``RATE_LIMIT_API`` /
  ``RATE_LIMIT_SCAN``) and are no-ops when ``RATELIMIT_ENABLED`` is false, so
  ``TestingConfig`` remains deterministic. There are no blanket default limits.
* No outbound network I/O: submitted URLs are strings only. No socket, DNS,
  HTTP client, ``urlopen`` or live fetch exists anywhere in this module.
"""
from __future__ import annotations

from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request
from flask_login import current_user
from flask_wtf.csrf import generate_csrf
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, limiter, limits_disabled
from ml.thresholds import SCORE_MEANING
from models.database_models import ScanHistory, iso_utc
from routes.history import viewer_scope
from routes.scanning import _remember_guest_scan, can_view_scan
from services import stats_service
from services.database_service import database_status
from services.detection_service import (
    DetectionResult,
    DetectionStorageError,
    DetectionUnavailableError,
    InvalidSubmissionError,
    get_detection_registry,
)
from services.explanation_service import RECOMMENDED_ACTIONS
from services.http_security import ServiceError
from services.model_metadata import get_registry
from services.stats_service import StatsDataError, flagged_from_json

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

BAND_SOURCE = "ml/saved_model/metadata.json#thresholds"
__all__ = ["api_bp", "API_ROUTES"]

API_ROUTES = (
    "/api/v1/csrf-token",
    "/api/v1/health",
    "/api/v1/model/info",
    "/api/v1/scan",
    "/api/v1/scans",
    "/api/v1/scans/<int:scan_id>",
)


def _viewer_key() -> str:
    """Per-account key for signed-in clients, per-IP key for guests."""
    if current_user.is_authenticated:
        return f"acct:{current_user.get_id()}"
    return f"ip:{request.remote_addr or 'unknown'}"


def _user_id() -> int | None:
    if not current_user.is_authenticated:
        return None
    try:
        return int(current_user.get_id())
    except (TypeError, ValueError):
        return None


def _decision_band() -> dict[str, Any]:
    meta = get_registry().metadata
    return {
        "low": meta.threshold_low,
        "high": meta.threshold_high,
        "source": BAND_SOURCE,
    }


def _contract(result: DetectionResult) -> dict[str, Any]:
    """Project a live DetectionResult into the documented REST field names."""
    return {
        "scan_id": result.scan_id,
        "submitted_url": result.raw_url,
        "normalized_url": result.normalized_url,
        "prediction": result.decision.prediction,
        "model_score": result.score,
        "score_meaning": result.decision.score_meaning,
        "risk_level": result.decision.risk_level,
        "decision_band": {
            "low": result.decision.threshold_low,
            "high": result.decision.threshold_high,
            "source": BAND_SOURCE,
        },
        "flagged_features": [item.name for item in result.explanation.flagged],
        "recommended_action": result.explanation.recommended_action,
        "caveats": list(result.explanation.caveats),
        "scanned_at": iso_utc(result.scan_date),
        "model": {"name": result.model_name, "version": result.model_version},
        "report_url": f"/scan/{result.scan_id}/report",
        "persisted": result.persisted,
    }


def _stored_contract(row: ScanHistory) -> dict[str, Any]:
    """Project an audited row WITHOUT re-running inference or writing anything."""
    meta = get_registry().metadata
    return {
        "scan_id": row.id,
        "submitted_url": row.url,
        "normalized_url": row.normalised_url,
        "prediction": row.prediction,
        "model_score": row.model_score,
        "score_meaning": SCORE_MEANING,
        "risk_level": row.risk_level,
        "decision_band": _decision_band(),
        "flagged_features": flagged_from_json(row.features_json),
        "recommended_action": RECOMMENDED_ACTIONS.get(row.prediction, ""),
        "caveats": [
            "HTTPS alone does not mean a website is legitimate.",
            "Only the URL string was analysed. The server did not visit the "
            "submitted address.",
            "This row was rebuilt from the audit record; no new inference ran.",
        ],
        "scanned_at": iso_utc(row.scan_date),
        "model": {"name": meta.model_name, "version": row.model_version},
        "report_url": f"/scan/{row.id}/report",
        "persisted": True,
    }


# --------------------------------------------------------------------------- #
# Public metadata endpoints (unthrottled: needed by monitoring and CSRF setup)
# --------------------------------------------------------------------------- #
@api_bp.get("/csrf-token")
def csrf_token() -> Response:
    """Issue the session CSRF token that POST /api/v1/scan must echo."""
    return jsonify({
        "status": "ok",
        "csrf_token": generate_csrf(),
        "header_name": "X-CSRF-Token",
    })


@api_bp.get("/health")
def health() -> Response:
    """Readiness only. Deliberately contains NO measured model figures."""
    registry = get_registry()
    return jsonify({
        "status": "ok",
        "app_version": current_app.config["APP_VERSION"],
        "build_stage": current_app.config["BUILD_STAGE"],
        "model": registry.public_info(),
        "bundle": registry.health(),
        "detection": get_detection_registry().health(),
        "database": database_status(),
    })


# --------------------------------------------------------------------------- #
# Measured model card
# --------------------------------------------------------------------------- #
@api_bp.get("/model/info")
@limiter.limit(
    lambda: current_app.config["RATE_LIMIT_API"],
    exempt_when=limits_disabled,
)
def model_info() -> Response | tuple[Response, int]:
    """Return the measured model card read at request time from artefacts."""
    try:
        measured = stats_service.measured_metrics()
    except StatsDataError:
        return _service_failure(
            503, "MODEL_UNAVAILABLE",
            "Measured model artefacts are unavailable; no verified figures "
            "can be returned.",
        )
    meta = get_registry().metadata
    return jsonify({
        "status": "ok",
        "model": {
            "name": meta.model_name,
            "version": meta.model_version,
            "schema_version": meta.schema_version,
            "feature_schema_version": meta.feature_schema_version,
            "feature_count": len(meta.feature_order),
            "feature_order": list(meta.feature_order),
            "generated_at_utc": meta.generated_at_utc,
        },
        "decision_states": meta.decision_states,
        "decision_thresholds": _decision_band(),
        "measured": {
            "rows": measured["rows"],
            "confusion_matrix": measured["confusion_matrix"],
            "decision_boundary": measured["decision_boundary"],
            "band": measured["band"],
            "generated_at_utc": measured["generated_at_utc"],
            "source": measured["source"],
            "band_source": measured["band_source"],
            "caveats": measured["caveats"],
        },
        "bundle": get_registry().health(),
    })


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def _service_failure(status: int, code: str, message: str):
    raise ServiceError(status, code, message)


@api_bp.post("/scan")
@limiter.limit(
    lambda: current_app.config["RATE_LIMIT_SCAN"],
    key_func=_viewer_key, exempt_when=limits_disabled,
)
@limiter.limit(
    lambda: current_app.config["RATE_LIMIT_API"],
    exempt_when=limits_disabled,
)
def scan() -> Response | tuple[Response, int]:
    """Run the one real detection pipeline and return the JSON contract."""
    if not request.is_json:
        return _service_failure(
            400, "BAD_REQUEST",
            "Send a JSON object with a url field and Content-Type application/json.",
        )
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or "url" not in payload:
        return _service_failure(
            400, "BAD_REQUEST", "A JSON object containing a url field is required."
        )
    raw_url = payload["url"]
    if not isinstance(raw_url, str) or not raw_url.strip():
        return _service_failure(
            400, "INVALID_URL", "Enter an http or https URL."
        )

    user_id = _user_id()
    try:
        result = get_detection_registry().scan(raw_url, user_id=user_id)
    except InvalidSubmissionError:
        return _service_failure(
            400, "INVALID_URL", "The submitted URL was rejected by validation."
        )
    except DetectionUnavailableError:
        return _service_failure(
            503, "MODEL_UNAVAILABLE",
            "The detection model is unavailable. No heuristic or rule-based "
            "substitute is used.",
        )
    except DetectionStorageError:
        return _service_failure(
            503, "DATABASE_UNAVAILABLE",
            "The scan could not be saved. Run scripts/init_db.py and try again.",
        )

    if user_id is None:
        _remember_guest_scan(result.scan_id)
    return jsonify({"status": "ok", "scan": _contract(result)}), 200


# --------------------------------------------------------------------------- #
# Scoped history
# --------------------------------------------------------------------------- #
@api_bp.get("/scans")
@limiter.limit(
    lambda: current_app.config["RATE_LIMIT_API"],
    exempt_when=limits_disabled,
)
def scans() -> Response | tuple[Response, int]:
    """List only the caller's own scans, with validated filters and paging."""
    user_id, guest_ids = viewer_scope()
    filters = stats_service.parse_filters(request.args)
    try:
        page = stats_service.history_page(user_id, guest_ids, filters)
    except SQLAlchemyError:
        return _service_failure(
            503, "DATABASE_UNAVAILABLE",
            "The scan database is unavailable. Run scripts/init_db.py.",
        )
    return jsonify({
        "status": "ok",
        "scans": page["rows"],
        "total": page["total"],
        "page": page["page"],
        "pages": page["pages"],
        "per_page": page["per_page"],
        "filters": page["filters"],
        "scope": page["scope"],
        "source": page["source"],
    })


@api_bp.get("/scans/<int:scan_id>")
@limiter.limit(
    lambda: current_app.config["RATE_LIMIT_API"],
    exempt_when=limits_disabled,
)
def scan_detail(scan_id: int) -> Response | tuple[Response, int]:
    """Return one authorised row, rebuilt from the audit record only."""
    user_id = _user_id()
    try:
        row = db.session.get(ScanHistory, scan_id)
    except SQLAlchemyError:
        return _service_failure(
            503, "DATABASE_UNAVAILABLE",
            "The scan database is unavailable. Run scripts/init_db.py.",
        )
    # Missing and unauthorised ids share the same generic 404 (no enumeration).
    if row is None or not can_view_scan(row, user_id):
        return _service_failure(
            404, "NOT_FOUND", "The requested resource was not found."
        )
    return jsonify({"status": "ok", "scan": _stored_contract(row)})
