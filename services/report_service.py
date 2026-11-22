"""CSV export of scan history (Stage 11).

Why a separate module
---------------------
Export is a *presentation* concern, but it handles untrusted strings (the URLs
users submitted), so it needs its own, testable security rules:

* **CSV / spreadsheet formula injection:** a cell beginning with ``=``, ``+``,
  ``-``, ``@``, TAB or CR is prefixed with a single quote so Excel/LibreOffice
  treats it as text. ``csv.writer`` quoting alone does NOT stop this.
* **CR/LF injection:** embedded newlines in a URL are replaced with spaces, so
  one submitted URL can never create extra CSV rows.
* **Bounded output:** at most ``CSV_ROW_LIMIT`` rows; no unbounded query.
* **Safe filename:** a fixed ASCII prefix plus a UTC date. No user input is
  ever interpolated into ``Content-Disposition``.
* **Visibility:** the caller passes only rows from
  ``stats_service.export_rows()``, which applies the same account/session rule
  as Stage 10. This module never queries the database itself.

No network I/O, no writes, no secrets. Password hashes are never a column.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from flask import Response

from services.stats_service import flagged_from_json

CSV_COLUMNS: tuple[str, ...] = (
    "scan_id",
    "scan_date_utc",
    "submitted_url",
    "normalised_url",
    "classification",
    "risk_level",
    "model_score",
    "model_version",
    "linked_user_id",
    "flagged_indicators",
    "report_path",
)

FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")

__all__ = ["CSV_COLUMNS", "FORMULA_PREFIXES", "safe_cell", "build_csv",
           "csv_response"]


def safe_cell(value: Any) -> str:
    """Neutralise formula and newline injection in ONE text cell."""
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    text = text.replace("\x00", "")
    if text and text[0] in FORMULA_PREFIXES:
        return "'" + text
    if text[:1].isspace() and text.lstrip()[:1] in FORMULA_PREFIXES:
        return "'" + text
    return text


def _row(record: Any) -> list[str]:
    """Serialise one ORM ScanHistory row into the documented column order."""
    flagged = flagged_from_json(getattr(record, "features_json", None))
    # Numeric cells are produced from typed values, so they cannot be formulas.
    values: tuple[Any, ...] = (
        int(record.id),
        _date_utc(record.scan_date),
        record.url,
        record.normalised_url,
        record.prediction,
        record.risk_level,
        f"{float(record.model_score):.6f}",
        record.model_version,
        "" if record.user_id is None else int(record.user_id),
        "|".join(flagged),
        f"/scan/{int(record.id)}/report",
    )
    return [safe_cell(value) for value in values]


def _date_utc(value: Any) -> str:
    """Render a SQLite (naive) or aware datetime as ISO-8601 UTC text."""
    if not isinstance(value, datetime):
        return str(value or "")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def build_csv(rows: Iterable[Any]) -> str:
    """Return a complete RFC 4180-style CSV document as a Python string."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(list(CSV_COLUMNS))
    for record in rows:
        writer.writerow(_row(record))
    return buffer.getvalue()


def csv_response(rows: Sequence[Any], *, filename: str | None = None) -> Response:
    """Build a downloadable, non-cacheable UTF-8 CSV Flask response.

    A UTF-8 BOM is prepended to the bytes so Excel on Windows detects the
    encoding correctly; ``build_csv()`` itself stays BOM-free for easy testing.
    """
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    safe_name = filename or f"scan-history-{day}.csv"
    # Defence in depth: never allow a caller-supplied filename to escape.
    safe_name = "".join(char for char in safe_name
                        if char.isalnum() or char in "-_.")
    if not safe_name.endswith(".csv"):
        safe_name += ".csv"
    body = "\ufeff" + build_csv(rows)
    response = Response(body.encode("utf-8"), mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{safe_name}"'
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Length"] = str(len(body.encode("utf-8")))
    return response
