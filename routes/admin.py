"""Administrator-only view and full CSV export (Stage 11).

Routes
------
    GET /admin              accounts, measured model audit rows, system counts
    GET /admin/export.csv   an explicitly authorised export of ALL scan rows

Authorisation
-------------
``admin_required`` composes Flask-Login's ``login_required`` with an explicit
role check. Anonymous callers receive the SAME ``401 UNAUTHENTICATED`` contract
that Stage 8 established (the custom ``unauthorized_callback`` runs before
``login_view``); ordinary signed-in users receive ``403 FORBIDDEN``. Stage 11
deliberately does NOT change the global 401 handler, so Gate 8's security
contract and ``login_view="auth.login"`` remain exactly as delivered.

``User.to_dict()`` is used for every account row; ``password_hash`` is never
selected, rendered or exported. Admins are created only by
``scripts/create_admin.py`` — registration always forces ``role="user"``.
"""
from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required
from sqlalchemy.exc import SQLAlchemyError

from services import report_service, stats_service
from services.http_security import make_error_response

admin_bp = Blueprint("admin", __name__)

__all__ = ["admin_bp", "admin_required"]


def admin_required(view: Callable[..., Any]) -> Callable[..., Any]:
    """401 for anonymous, 403 for non-admins, otherwise run the view."""
    @wraps(view)
    def _guarded(*args: Any, **kwargs: Any) -> Any:
        if not getattr(current_user, "is_admin", False):
            return make_error_response(
                403, "FORBIDDEN", "Administrator access is required."
            )
        return view(*args, **kwargs)

    return login_required(_guarded)


def _database_error() -> Any:
    return make_error_response(
        503, "DATABASE_UNAVAILABLE",
        "The scan database is unavailable. Run scripts/init_db.py.",
    )


@admin_bp.get("/admin")
@admin_required
def admin() -> Any:
    """Render the admin console with measured, safely projected data."""
    try:
        counts = stats_service.system_counts()
        accounts = stats_service.user_accounts()
        model_rows = stats_service.model_information_rows()
        metrics = stats_service.measured_metrics()
    except stats_service.StatsDataError:
        return make_error_response(
            503, "MODEL_UNAVAILABLE",
            "Measured model artefacts are unavailable; verified figures "
            "cannot be displayed.",
        )
    except SQLAlchemyError:
        return _database_error()
    return render_template(
        "admin.html",
        counts=counts,
        accounts=accounts,
        model_rows=model_rows,
        metrics=metrics,
    )


@admin_bp.get("/admin/export.csv")
@admin_required
def export_all_csv() -> Any:
    """Full export. Only reachable by an authenticated admin."""
    filters = stats_service.parse_filters(request.args)
    try:
        rows = stats_service.export_rows(None, [], filters, all_rows=True)
    except SQLAlchemyError:
        return _database_error()
    return report_service.csv_response(rows, filename="admin-scan-export.csv")
