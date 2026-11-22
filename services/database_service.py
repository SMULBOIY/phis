"""Database bootstrap, schema inspection and measured-metric seeding (Stage 8).

This module is the ONLY place that creates tables or writes the
``model_information`` audit row. Keeping it out of ``app.py`` means booting a
Flask application has no schema side effects; ``scripts/init_db.py`` is the
explicit, logged bootstrap step (the standard pattern for a deployed app).

Academic-integrity rule: the five performance numbers stored in
``model_information`` are COPIED from ``ml/saved_model/metrics.json`` at
bootstrap time. No value is typed into code, no value is estimated, and no
Stage 8 page displays them. If ``metrics.json`` is missing or inconsistent,
bootstrapping FAILS instead of inserting nulls or defaults.
"""
from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, current_app, has_app_context
from sqlalchemy import inspect, text

from extensions import db
from models.database_models import ModelInformation, ScanHistory, User, utcnow

TABLE_NAMES = ("users", "scan_history", "model_information")
METRIC_FIELDS = {
    "accuracy": "accuracy",
    "precision": "precision",
    "recall": "recall",
    "f1": "f1_score",
    "roc_auc": "roc_auc",
}


class ModelDataError(RuntimeError):
    """The Stage 6 artefacts cannot supply real, measured model metrics."""


def _context(app: Flask):
    """Reuse the active app context when called from a request."""
    return nullcontext() if has_app_context() else app.app_context()


def _parse_utc(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp from a Stage 5/6 artefact into aware UTC."""
    if not isinstance(value, str) or not value:
        raise ModelDataError("a required artefact timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ModelDataError(f"unparseable artefact timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _measured_values(app: Flask) -> dict[str, Any]:
    """Read the deployed model's measured test metrics and provenance."""
    metadata_path = Path(app.config["METADATA_PATH"])
    metrics_path = Path(app.config["METRICS_PATH"])
    manifest_path = metadata_path.parent / "candidates" / "training_manifest.json"
    for path in (metadata_path, metrics_path, manifest_path):
        if not path.is_file():
            raise ModelDataError(f"required Stage 5/6 artefact is missing: {path.name}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelDataError(f"cannot read Stage 5/6 artefacts: {exc}") from exc

    standard = metrics.get("test", {}).get("standard_0.5", {})
    values: dict[str, Any] = {}
    for source_key, column_name in METRIC_FIELDS.items():
        value = standard.get(source_key)
        if not isinstance(value, (int, float)) or not (0.0 <= float(value) <= 1.0):
            raise ModelDataError(
                f"metrics.json is missing a measured test.{source_key} value"
            )
        values[column_name] = float(value)

    if metrics.get("test", {}).get("scored_once") is not True:
        raise ModelDataError("the test split was not marked as scored once")

    dataset = metadata.get("dataset", {})
    split_hashes = [dataset.get(name) for name in ("train_sha256", "validation_sha256", "test_sha256")]
    if not all(isinstance(item, str) and len(item) == 64 for item in split_hashes):
        raise ModelDataError("metadata.json has no verifiable dataset hashes")
    fingerprint = hashlib.sha256("|".join(split_hashes).encode("ascii")).hexdigest()

    feature_order = metadata.get("feature_order")
    if not isinstance(feature_order, list) or len(feature_order) != 15:
        raise ModelDataError("metadata.json feature_order does not contain 15 features")

    training_date = _parse_utc(
        manifest.get("generated_at_utc") or metadata.get("generated_at_utc")
    )
    values.update({
        "model_name": str(metadata["model_name"]),
        "model_version": str(metadata["model_version"]),
        "training_date": training_date,
        "dataset_fingerprint": fingerprint,
        "feature_count": len(feature_order),
        "metrics_source": "ml/saved_model/metrics.json#test.standard_0.5",
    })
    return values


def seed_model_information() -> dict[str, Any]:
    """Insert or refresh one audit row from measured artefacts. Idempotent."""
    app = current_app._get_current_object()
    values = _measured_values(app)
    row = db.session.query(ModelInformation).filter_by(
        model_name=values["model_name"], model_version=values["model_version"]
    ).one_or_none()
    created = row is None
    if created:
        row = ModelInformation(
            model_name=values["model_name"],
            model_version=values["model_version"],
            created_at=utcnow(),
        )
    for column_name in (*METRIC_FIELDS.values(), "training_date",
                        "dataset_fingerprint", "feature_count", "metrics_source"):
        setattr(row, column_name, values[column_name])
    db.session.add(row)
    db.session.commit()
    return {
        "model_name": row.model_name,
        "model_version": row.model_version,
        "created": created,
        "row_count": db.session.query(ModelInformation).count(),
    }


def initialise_schema(app: Flask, *, drop: bool = False) -> dict[str, Any]:
    """Create all tables and seed measured model information.

    ``drop=True`` is destructive and is exposed only through the explicit
    ``--reset --yes`` flags of ``scripts/init_db.py``.
    """
    with app.app_context():
        if drop:
            db.drop_all()
        db.create_all()
        seeded = seed_model_information()
        return {"tables": sorted(inspect(db.engine).get_table_names()), "seeded": seeded}


def database_status(app: Flask | None = None) -> dict[str, Any]:
    """Return a secret-free, request-safe description of the schema.

    ``/health`` calls this on every request. It reports table names and row
    counts only — never a password hash, a full database URI or a measured
    performance figure. Any failure degrades to ``status='error'`` with just
    the exception CLASS name, so no diagnostic detail reaches the client.
    """
    target = app or current_app._get_current_object()
    try:
        with _context(target):
            engine = db.engine
            tables = sorted(
                name for name in inspect(engine).get_table_names()
                if not name.startswith("sqlite_")
            )
            missing = [name for name in TABLE_NAMES if name not in tables]
            result: dict[str, Any] = {
                "status": "ready" if not missing else "not_initialised",
                "introduced_stage": 8,
                "dialect": engine.dialect.name,
                "tables": tables,
                "missing_tables": missing,
                "counts": {},
                "foreign_keys_enabled": None,
            }
            if not missing:
                result["counts"] = {
                    "users": db.session.query(User).count(),
                    "scans": db.session.query(ScanHistory).count(),
                    "model_information": db.session.query(ModelInformation).count(),
                }
            if engine.dialect.name == "sqlite":
                result["foreign_keys_enabled"] = bool(
                    db.session.execute(text("PRAGMA foreign_keys")).scalar()
                )
            return result
    except Exception as exc:  # noqa: BLE001 - a health probe must never crash
        return {
            "status": "error",
            "introduced_stage": 8,
            "dialect": "unknown",
            "tables": [],
            "missing_tables": list(TABLE_NAMES),
            "counts": {},
            "foreign_keys_enabled": None,
            "detail": type(exc).__name__,
        }


__all__ = [
    "TABLE_NAMES", "METRIC_FIELDS", "ModelDataError",
    "database_status", "initialise_schema", "seed_model_information",
]
