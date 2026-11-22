"""Read-only aggregates for the Stage 11 dashboard, history and admin views.

Academic-integrity rules
------------------------
1. Every number returned here is either counted from ``scan_history`` /
   ``users`` / ``model_information`` at REQUEST TIME, or copied from the
   measured Stage 6 artefact ``ml/saved_model/metrics.json``. No figure is
   typed into this module, and no figure is estimated, rounded up or invented.
2. Empty database -> honest zeros and empty lists, never demo data.
3. Measured model metrics are labelled with their exact source key and with a
   caveat: they describe the held-out PhiUSIIL test split, NOT live traffic.
4. Visibility is shared with Stage 10: a signed-in user sees only their own
   rows; a guest sees only scan ids recorded in their own signed session.
   Nothing here can enumerate another user's submitted URLs.

This module performs no writes, no network I/O and no user-input interpolation
into SQL: filters are bound parameters through the SQLAlchemy ORM.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from flask import current_app
from sqlalchemy import func
from sqlalchemy.orm import Query

from extensions import db
from models.database_models import ModelInformation, ScanHistory, User, iso_utc

PREDICTIONS: tuple[str, ...] = ("LEGITIMATE", "SUSPICIOUS", "PHISHING")
RISKS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH")
DEFAULT_PER_PAGE = 20
MAX_PER_PAGE = 100
CSV_ROW_LIMIT = 5000
DAILY_WINDOW_DAYS = 7
MAX_QUERY_LENGTH = 120

SQLITE_SCAN_SOURCE = "sqlite://instance/phishing.db#scan_history"
METRICS_SOURCE = "ml/saved_model/metrics.json#test.standard_0.5"
CALIBRATED_SOURCE = "ml/saved_model/metrics.json#test.calibrated"


class StatsDataError(RuntimeError):
    """A required measured artefact is missing or inconsistent — fail closed."""


# --------------------------------------------------------------------------- #
# Measured model performance (read at runtime, never hard-coded)
# --------------------------------------------------------------------------- #
def measured_metrics() -> dict[str, Any]:
    """Return the published held-out test figures plus their provenance.

    Stage 9 deliberately showed no performance figures anywhere. Stage 11 is
    the first UI surface allowed to display them, and only by reading the
    generated artefact at request time.
    """
    path = Path(current_app.config["METRICS_PATH"])
    if not path.is_file():
        raise StatsDataError("metrics.json is missing")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        standard = payload["test"]["standard_0.5"]
        calibrated = payload["test"]["calibrated"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise StatsDataError(f"metrics.json is unreadable: {type(exc).__name__}") from exc

    if payload.get("test", {}).get("scored_once") is not True:
        raise StatsDataError("the test split is not marked as scored once")

    rows: list[dict[str, str]] = []
    for label, key in (("Accuracy", "accuracy"), ("Precision", "precision"),
                       ("Recall", "recall"), ("F1 score", "f1"),
                       ("ROC-AUC", "roc_auc")):
        value = standard.get(key)
        if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
            raise StatsDataError(f"metrics.json is missing a measured test.{key}")
        rows.append({
            "label": label,
            "key": key,
            "value": f"{float(value):.6f}",
            "source": METRICS_SOURCE,
        })

    matrix = standard.get("confusion_matrix")
    if (not isinstance(matrix, list) or len(matrix) != 2
            or any(not isinstance(row, list) or len(row) != 2 for row in matrix)):
        raise StatsDataError("metrics.json has no usable confusion matrix")

    band = {
        "low": calibrated.get("t_low"),
        "high": calibrated.get("t_high"),
        "abstention_rate": calibrated.get("abstention_rate"),
        "decisive_count": calibrated.get("decisive_count"),
        "abstained_count": calibrated.get("abstained_count"),
        "recall": calibrated.get("recall"),
        "false_negative_rate": calibrated.get("false_negative_rate"),
    }
    if any(not isinstance(v, (int, float)) for v in band.values()):
        raise StatsDataError("metrics.json has no usable calibrated band figures")

    return {
        "rows": rows,
        "confusion_matrix": matrix,
        "decision_boundary": standard.get("decision_boundary"),
        "band": band,
        "generated_at_utc": payload.get("generated_at_utc"),
        "source": METRICS_SOURCE,
        "band_source": CALIBRATED_SOURCE,
        "caveats": (
            "These are measured results on the held-out 15% test split of the "
            "PhiUSIIL / UCI 967 corpus, not measurements of live traffic.",
            "The corpus has a known HTTPS and URL-length shortcut, so real-world "
            "performance is expected to be lower. HTTPS alone does not mean a "
            "website is legitimate.",
            "Recall and false negatives are prioritised because a missed "
            "phishing site is the costliest error; SUSPICIOUS is an abstention, "
            "not a third trained class.",
        ),
    }


# --------------------------------------------------------------------------- #
# System-wide aggregates (counts only — no submitted URLs exposed here)
# --------------------------------------------------------------------------- #
def _count_by(column: Any, options: Sequence[str]) -> dict[str, int]:
    found = {name: 0 for name in options}
    for value, count in (
        db.session.query(column, func.count(ScanHistory.id))
        .group_by(column).all()
    ):
        if value in found:
            found[value] = int(count)
    return found


def system_overview() -> dict[str, Any]:
    """Count the real audit rows. An empty database returns honest zeros."""
    total = int(db.session.query(func.count(ScanHistory.id)).scalar() or 0)
    by_prediction = _count_by(ScanHistory.prediction, PREDICTIONS)
    by_risk = _count_by(ScanHistory.risk_level, RISKS)
    guests = int(db.session.query(func.count(ScanHistory.id))
                 .filter(ScanHistory.user_id.is_(None)).scalar() or 0)
    first = db.session.query(func.min(ScanHistory.scan_date)).scalar()
    last = db.session.query(func.max(ScanHistory.scan_date)).scalar()
    # A computed RATIO over real rows, clearly labelled as a database share.
    suspicious_share = (by_prediction["SUSPICIOUS"] / total) if total else 0.0
    return {
        "total_scans": total,
        "by_prediction": by_prediction,
        "by_risk": by_risk,
        "guest_scans": guests,
        "linked_scans": total - guests,
        "suspicious_share": suspicious_share,
        "first_scan_utc": iso_utc(first),
        "last_scan_utc": iso_utc(last),
        "source": SQLITE_SCAN_SOURCE,
    }


def system_counts() -> dict[str, int]:
    """Small, secret-free counts for the admin view."""
    return {
        "users": int(db.session.query(func.count(User.id)).scalar() or 0),
        "admins": int(db.session.query(func.count(User.id))
                      .filter(User.role == "admin").scalar() or 0),
        "scans": int(db.session.query(func.count(ScanHistory.id)).scalar() or 0),
        "model_rows": int(db.session.query(func.count(ModelInformation.id)).scalar() or 0),
    }


def chart_payload(
    labels: Sequence[str],
    values: Sequence[int],
    *,
    series_label: str,
    source: str,
) -> dict[str, Any]:
    """Build the exact ``data-chart`` contract consumed by static/js/main.js."""
    return {
        "labels": list(labels),
        "values": [int(value) for value in values],
        "series_label": series_label,
        "source": source,
    }


def prediction_chart() -> dict[str, Any]:
    counts = _count_by(ScanHistory.prediction, PREDICTIONS)
    return chart_payload(PREDICTIONS, [counts[name] for name in PREDICTIONS],
                         series_label="Scan results", source=SQLITE_SCAN_SOURCE)


def risk_chart() -> dict[str, Any]:
    counts = _count_by(ScanHistory.risk_level, RISKS)
    return chart_payload(RISKS, [counts[name] for name in RISKS],
                         series_label="Risk levels", source=SQLITE_SCAN_SOURCE)


def daily_chart(days: int = DAILY_WINDOW_DAYS) -> dict[str, Any]:
    """Real per-day scan counts for the last ``days`` UTC days, zeros included."""
    today = datetime.now(timezone.utc).date()
    labels = [(today - timedelta(days=offset)).isoformat()
              for offset in range(days - 1, -1, -1)]
    counts: dict[str, int] = {label: 0 for label in labels}
    for day, count in (
        db.session.query(func.date(ScanHistory.scan_date),
                         func.count(ScanHistory.id))
        .group_by(func.date(ScanHistory.scan_date)).all()
    ):
        if isinstance(day, str) and day in counts:
            counts[day] = int(count)
    return chart_payload(labels, [counts[label] for label in labels],
                         series_label="Scans per day (UTC)",
                         source=SQLITE_SCAN_SOURCE)


# --------------------------------------------------------------------------- #
# History: visibility, filters, pagination
# --------------------------------------------------------------------------- #
def visible_query(user_id: int | None, guest_scan_ids: Sequence[Any]) -> Query:
    """The SAME visibility rule as Stage 10's printable reports.

    Signed-in users see only rows linked to their account. Guests see only ids
    stored in their own signed Flask session (bounded by Stage 10). An empty
    guest list produces an always-false filter rather than the whole table.
    """
    query = db.session.query(ScanHistory)
    if user_id is not None:
        return query.filter(ScanHistory.user_id == user_id)
    ids = [int(item) for item in guest_scan_ids if isinstance(item, int)]
    return query.filter(ScanHistory.id.in_(ids))


def parse_filters(args: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and clamp user-controlled filters. No raw string reaches SQL."""
    prediction = str(args.get("prediction") or "").strip().upper()
    risk = str(args.get("risk") or "").strip().upper()
    query_text = str(args.get("q") or "").strip()[:MAX_QUERY_LENGTH]

    def positive_int(name: str, default: int, ceiling: int) -> int:
        try:
            value = int(str(args.get(name) or default))
        except (TypeError, ValueError):
            return default
        return max(1, min(value, ceiling))

    return {
        "prediction": prediction if prediction in PREDICTIONS else "",
        "risk": risk if risk in RISKS else "",
        "q": query_text,
        "page": positive_int("page", 1, 100000),
        "per_page": positive_int("per_page", DEFAULT_PER_PAGE, MAX_PER_PAGE),
    }


def apply_filters(query: Query, filters: Mapping[str, Any]) -> Query:
    if filters.get("prediction"):
        query = query.filter(ScanHistory.prediction == filters["prediction"])
    if filters.get("risk"):
        query = query.filter(ScanHistory.risk_level == filters["risk"])
    if filters.get("q"):
        # autoescape neutralises %, _ and the escape character, so a search
        # string can never widen the match or smuggle SQL.
        query = query.filter(
            ScanHistory.normalised_url.contains(filters["q"], autoescape=True)
        )
    return query


def history_page(
    user_id: int | None,
    guest_scan_ids: Sequence[Any],
    filters: Mapping[str, Any],
) -> dict[str, Any]:
    """Return one page of visible scans plus honest pagination metadata."""
    base = apply_filters(visible_query(user_id, guest_scan_ids), filters)
    total = int(base.count())
    per_page = int(filters["per_page"])
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(int(filters["page"]), pages)
    rows = (
        base.order_by(ScanHistory.scan_date.desc(), ScanHistory.id.desc())
        .offset((page - 1) * per_page).limit(per_page).all()
    )
    items = []
    for row in rows:
        record = row.to_dict()
        record["flagged"] = _flagged(row.features_json)
        record["report_url"] = f"/scan/{row.id}/report"
        items.append(record)
    return {
        # "rows" rather than "items": Jinja's dict.items method would otherwise
        # shadow the key when a template writes history.items.
        "rows": items,
        "total": total,
        "page": page,
        "pages": pages,
        "per_page": per_page,
        "filters": dict(filters),
        "scope": "account" if user_id is not None else "session",
        "source": SQLITE_SCAN_SOURCE,
    }


def flagged_from_json(raw_json: str | None) -> list[str]:
    """Read the flagged indicator names from a stored feature snapshot."""
    if not raw_json:
        return []
    try:
        values = json.loads(raw_json).get("flagged", [])
    except (json.JSONDecodeError, AttributeError, TypeError):
        return []
    return [str(name) for name in values][:15]


# Internal shorthand used by history_page(); kept for readability only.
_flagged = flagged_from_json


def export_rows(
    user_id: int | None,
    guest_scan_ids: Sequence[Any],
    filters: Mapping[str, Any],
    *,
    all_rows: bool = False,
) -> list[ScanHistory]:
    """Rows for CSV. Admin-only ``all_rows=True`` bypasses visibility."""
    query = (db.session.query(ScanHistory) if all_rows
             else visible_query(user_id, guest_scan_ids))
    query = apply_filters(query, filters)
    return (query.order_by(ScanHistory.scan_date.desc(), ScanHistory.id.desc())
            .limit(CSV_ROW_LIMIT).all())


# --------------------------------------------------------------------------- #
# Admin-only read models
# --------------------------------------------------------------------------- #
def user_accounts() -> list[dict[str, Any]]:
    """Safe account rows. ``password_hash`` is never selected or returned."""
    counts = dict(
        db.session.query(ScanHistory.user_id, func.count(ScanHistory.id))
        .filter(ScanHistory.user_id.is_not(None))
        .group_by(ScanHistory.user_id).all()
    )
    accounts = []
    for user in db.session.query(User).order_by(User.id).all():
        record = user.to_dict()
        record["scan_count"] = int(counts.get(user.id, 0))
        accounts.append(record)
    return accounts


def model_information_rows() -> list[dict[str, Any]]:
    """The measured audit rows seeded by scripts/init_db.py."""
    return [row.to_dict() for row in
            db.session.query(ModelInformation).order_by(ModelInformation.id).all()]


__all__ = [
    "PREDICTIONS", "RISKS", "DEFAULT_PER_PAGE", "MAX_PER_PAGE",
    "CSV_ROW_LIMIT", "DAILY_WINDOW_DAYS", "MAX_QUERY_LENGTH",
    "SQLITE_SCAN_SOURCE", "METRICS_SOURCE", "CALIBRATED_SOURCE",
    "StatsDataError", "measured_metrics", "system_overview", "system_counts",
    "chart_payload", "prediction_chart", "risk_chart", "daily_chart",
    "visible_query", "parse_filters", "apply_filters", "history_page",
    "flagged_from_json", "export_rows", "user_accounts",
    "model_information_rows",
]
