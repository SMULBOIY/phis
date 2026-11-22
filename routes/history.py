"""Scoped scan history and CSV export (Stage 11).

Routes
------
    GET /history              filters + pagination over visible scans
    GET /history/export.csv   download those same visible rows as CSV

Visibility (identical to Stage 10's printable reports)
------------------------------------------------------
* Signed-in user: only rows whose ``user_id`` equals the account id.
* Guest: only ids recorded in their own signed Flask session (bounded to 25 by
  Stage 10). No unauthenticated enumeration of other people's URLs.
* Admin: use ``/admin/export.csv`` for a full, explicitly authorised export.

These are read-only GET routes, so no CSRF token is required. Filters are
validated and clamped by ``stats_service.parse_filters`` and bound through the
ORM. CSV cells are neutralised by ``services/report_service.py``.
"""
from __future__ import annotations

from typing import Any

from flask import Blueprint, render_template, request, session
from flask_login import current_user
from sqlalchemy.exc import SQLAlchemyError

from routes.scanning import GUEST_SCAN_SESSION_KEY
from services import report_service, stats_service
from services.http_security import make_error_response

history_bp = Blueprint("history", __name__)

__all__ = ["history_bp", "viewer_scope"]


def viewer_scope() -> tuple[int | None, list[int]]:
    """Return (linked user id, guest scan ids) for the current viewer."""
    if current_user.is_authenticated:
        try:
            return int(current_user.get_id()), []
        except (TypeError, ValueError):
            return None, []
    stored = session.get(GUEST_SCAN_SESSION_KEY, [])
    ids = [item for item in stored if isinstance(item, int)]
    return None, ids


def _database_error() -> Any:
    return make_error_response(
        503, "DATABASE_UNAVAILABLE",
        "The scan database is unavailable. Run scripts/init_db.py.",
    )


@history_bp.get("/history")
def history() -> Any:
    """Render a filtered, paginated list of the viewer's own scans."""
    user_id, guest_ids = viewer_scope()
    filters = stats_service.parse_filters(request.args)
    try:
        page = stats_service.history_page(user_id, guest_ids, filters)
    except SQLAlchemyError:
        return _database_error()
    return render_template("history.html", history=page, filters=filters)


@history_bp.get("/history/export.csv")
def export_csv() -> Any:
    """Download the SAME visible rows (all matching filters, bounded)."""
    user_id, guest_ids = viewer_scope()
    filters = stats_service.parse_filters(request.args)
    try:
        rows = stats_service.export_rows(user_id, guest_ids, filters)
    except SQLAlchemyError:
        return _database_error()
    return report_service.csv_response(rows)
