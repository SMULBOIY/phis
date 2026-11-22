"""URL scan form, result and printable report blueprint (Stage 10).

Routes
------
    GET  /scan                     real form; the exact ``SCAN WEBSITE`` button
    POST /scan                     validate -> extract -> predict -> decide ->
                                   explain -> save -> render result
    GET  /scan/<id>/report         printable report for a scan the caller owns

Contracts preserved from Stages 7-9
-----------------------------------
* CSRFProtect applies to every POST. HTML forms send ``csrf_token``; JSON
  clients send the ``X-CSRF-Token`` header (the Stage 8 contract).
* Errors use ``services.http_security.make_error_response`` so HTML callers get
  the themed error page and JSON callers get the documented JSON shape.
* No inline script/style, no CDN, no measured performance figure is rendered.
* ``/scan`` is public. Guests may scan; authenticated users get their rows
  linked to ``User.id`` via ``current_user``.

Failure mapping (explicit, never silently degraded)
--------------------------------------------------
    InvalidSubmissionError    400 INVALID_URL            (form redisplayed)
    DetectionUnavailableError 503 MODEL_UNAVAILABLE     (no rule fallback)
    DetectionStorageError     503 DATABASE_UNAVAILABLE  (no unlogged result)

The printable report is a display concern only: it rebuilds the decision and
explanation deterministically from the SAVED row and the measured artefacts. It
does NOT re-run inference, does NOT create a second audit row, and does NOT
fetch the URL.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    make_response,
    render_template,
    request,
    session,
)
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, limiter, limits_disabled
from models.database_models import ScanHistory, iso_utc, utcnow
from services.database_service import database_status
from services.decision_service import decide
from services.detection_service import (
    DetectionResult,
    DetectionStorageError,
    DetectionUnavailableError,
    InvalidSubmissionError,
    get_detection_registry,
)
from services.explanation_service import explain
from services.http_security import make_error_response
from services.validation import safe_display_url

scan_bp = Blueprint("scanning", __name__)

GUEST_SCAN_SESSION_KEY = "guest_scan_ids"
GUEST_SCAN_SESSION_LIMIT = 25

__all__ = ["scan_bp", "can_view_scan"]


def _wants_json() -> bool:
    """Mirror the content-negotiation rule used by make_error_response."""
    return (
        request.path.startswith("/api/")
        or request.is_json
        or request.args.get("format") == "json"
    )


def _submitted_url() -> Any:
    """Read the single untrusted field from JSON or a normal HTML form."""
    if request.is_json:
        payload = request.get_json(silent=True)
        return payload.get("url") if isinstance(payload, dict) else None
    return request.form.get("url")


def _authenticated_user_id() -> int | None:
    """Resolve the ORM user id for a logged-in scan, or None for a guest."""
    if not current_user.is_authenticated:
        return None
    try:
        return int(current_user.get_id())
    except (TypeError, ValueError):
        return None


def _remember_guest_scan(scan_id: int) -> None:
    """Let a guest open a printable report for scans made in THIS session."""
    if _authenticated_user_id() is not None:
        return
    recent = [item for item in session.get(GUEST_SCAN_SESSION_KEY, [])
              if isinstance(item, int)]
    recent = [item for item in recent if item != scan_id]
    recent.insert(0, scan_id)
    session[GUEST_SCAN_SESSION_KEY] = recent[:GUEST_SCAN_SESSION_LIMIT]
    session.modified = True


def can_view_scan(row: ScanHistory, user_id: int | None) -> bool:
    """Authorisation policy for a single saved scan.

    A registered user may see only their own rows. A guest row is visible only
    to the browser session that created it (Stage 11 adds the full history UI;
    claiming guest rows after sign-in is out of scope here). This avoids an
    unauthenticated enumeration of other people's submitted URLs.
    """
    if row.user_id is None:
        return row.id in session.get(GUEST_SCAN_SESSION_KEY, [])
    return user_id is not None and row.user_id == user_id


def _form_context(**extra: Any) -> dict[str, Any]:
    """Common template context for the scan form page."""
    registry = get_detection_registry()
    meta = registry.metadata
    context: dict[str, Any] = {
        "engine_ready": registry.available,
        "engine_detail": registry.error,
        "thresholds": meta.thresholds,
        "band": (
            f"{meta.threshold_low:g} < p < {meta.threshold_high:g}"
        ),
        "feature_count": len(meta.feature_order),
        "model_name": meta.model_name,
        "model_version": meta.model_version,
        "max_url_length": current_app.config["MAX_URL_LENGTH"],
        "db_status": database_status(),
        "result": None,
        "form_error": None,
    }
    context.update(extra)
    return context


def _failure(
    status: int, code: str, message: str
) -> Response | tuple[Response, int]:
    """Safe error response; a 400 HTML form error redisplayed in place."""
    if _wants_json() or status != 400:
        return make_error_response(status, code, message)
    # Keep the user on the scan page with a generic, autoescaped message.
    return make_response(
        render_template("scan.html", **_form_context(form_error=message)), 400
    )


@scan_bp.get("/scan")
def scan_form() -> str:
    """Render the real scan form. Never pretends to have a result."""
    return render_template("scan.html", **_form_context())


@scan_bp.post("/scan")
@limiter.limit(
    lambda: current_app.config["RATE_LIMIT_SCAN"],
    exempt_when=limits_disabled,
)
def scan() -> Response | tuple[Response, int] | str:
    """Run the full detection pipeline for one URL and persist the outcome."""
    registry = get_detection_registry()
    raw_url = _submitted_url()
    user_id = _authenticated_user_id()
    try:
        result = registry.scan(raw_url, user_id=user_id)
    except InvalidSubmissionError as exc:
        return _failure(400, "INVALID_URL", str(exc))
    except DetectionUnavailableError as exc:
        return _failure(
            503, "MODEL_UNAVAILABLE",
            f"The detection model is unavailable: {exc}. No heuristic or "
            "rule-based substitute is used.",
        )
    except DetectionStorageError as exc:
        return _failure(
            503, "DATABASE_UNAVAILABLE",
            f"The scan could not be saved: {exc}. Run scripts/init_db.py "
            "and try again.",
        )

    if user_id is None:
        _remember_guest_scan(result.scan_id)

    if _wants_json():
        return jsonify({
            "status": "ok",
            "result": result.to_dict(),
            "report_url": f"/scan/{result.scan_id}/report",
        }), 200
    return render_template("scan.html", **_form_context(result=result))


def _rebuild_result(row: ScanHistory) -> DetectionResult:
    """Recreate a display-only result from the audited row (no re-inference)."""
    registry = get_detection_registry()
    snapshot = json.loads(row.features_json or "{}")
    features = snapshot.get("features") or {}
    thresholds = registry.metadata.thresholds
    decision = decide(row.model_score, low=thresholds["low"], high=thresholds["high"])
    explanation = explain(
        features,
        decision,
        importance=registry.importance,
        importance_source="ml/saved_model/metrics.json#feature_importance.features",
    )
    parts = urlsplit(row.normalised_url)
    return DetectionResult(
        raw_url=row.url,
        normalized_url=row.normalised_url,
        display_url=safe_display_url(row.normalised_url),
        scheme=parts.scheme,
        host=parts.hostname or "",
        features=features,
        score=row.model_score,
        decision=decision,
        explanation=explanation,
        model_name=registry.metadata.model_name,
        model_version=row.model_version,
        scan_date=row.scan_date,
        scan_id=row.id,
        user_id=row.user_id,
        persisted=True,
    )


@scan_bp.get("/scan/<int:scan_id>/report")
def scan_report(scan_id: int) -> Response | tuple[Response, int] | str:
    """Printable, access-controlled report for one previously saved scan."""
    user_id = _authenticated_user_id()
    try:
        row = db.session.get(ScanHistory, scan_id)
    except SQLAlchemyError:
        return make_error_response(
            503, "DATABASE_UNAVAILABLE",
            "The scan database is unavailable. Run scripts/init_db.py.",
        )
    if row is None or not can_view_scan(row, user_id):
        # Deliberately identical for "missing" and "not yours": no enumeration.
        return make_error_response(
            404, "NOT_FOUND", "That scan report is not available."
        )
    return render_template(
        "scan_report.html",
        result=_rebuild_result(row),
        generated_at_utc=iso_utc(utcnow()),
    )
