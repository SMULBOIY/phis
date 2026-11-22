"""Public, read-only operational dashboard (Stage 11).

Routes
------
    GET /dashboard   live aggregates, three real Chart.js charts and the
                     measured held-out model metrics read at request time

Design notes
------------
* The dashboard exposes COUNTS only. No submitted URL from another user is
  ever rendered here; individual rows belong to ``/history`` and are scoped.
* Every chart payload uses the existing Stage 9 ``data-chart`` contract, so no
  new JavaScript file and no inline script is needed; the strict CSP is intact.
* Measured performance figures were deliberately absent from Stage 9. Stage 11
  is the first UI allowed to show them, and only by reading
  ``ml/saved_model/metrics.json`` at runtime with an explicit caveat.
* A missing artefact or an uninitialised schema is an explicit 503, never a
  page of zeros that looks like real data.
"""
from __future__ import annotations

from typing import Any

from flask import Blueprint, render_template
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError

from services import stats_service
from services.http_security import make_error_response

dashboard_bp = Blueprint("dashboard", __name__)

__all__ = ["dashboard_bp"]


@dashboard_bp.get("/dashboard")
def dashboard() -> Any:
    """Render live aggregates. Fail closed if the DB or artefacts are absent."""
    try:
        overview = stats_service.system_overview()
        state_chart = stats_service.prediction_chart()
        risk_chart = stats_service.risk_chart()
        volume_chart = stats_service.daily_chart()
        counts = stats_service.system_counts()
        metrics = stats_service.measured_metrics()
    except stats_service.StatsDataError:
        return make_error_response(
            503, "MODEL_UNAVAILABLE",
            "Measured model artefacts are unavailable; the dashboard cannot "
            "display verified figures.",
        )
    except SQLAlchemyError:
        return make_error_response(
            503, "DATABASE_UNAVAILABLE",
            "The scan database is unavailable. Run scripts/init_db.py.",
        )

    show_admin = bool(
        current_user.is_authenticated
        and getattr(current_user, "is_admin", False)
    )
    return render_template(
        "dashboard.html",
        overview=overview,
        state_chart=state_chart,
        risk_chart=risk_chart,
        volume_chart=volume_chart,
        counts=counts,
        metrics=metrics,
        show_admin=show_admin,
    )
