"""SQLAlchemy ORM entities for the phishing detection system (Stage 8).

Three tables, exactly as specified in ``docs/ARCHITECTURE.md`` section 9:

    users (1) ---- (0..*) scan_history      user_id NULLABLE, ON DELETE SET NULL
    model_information                       measured audit record, no invented values

Design rules enforced here
--------------------------
* ``password_hash`` is the ONLY password column. There is no ``password``
  attribute anywhere, plaintext is never stored and ``to_dict()`` never
  serialises the hash.
* Guest scans are first-class: ``ScanHistory.user_id`` is nullable, and
  deleting a user preserves their history because the FK is ``ON DELETE SET
  NULL``. SQLite needs ``PRAGMA foreign_keys=ON`` for that, which
  ``configure_database()`` installs on the application's engine.
* Application-level ``CheckConstraint`` objects constrain role, prediction,
  risk level and model score. SQLite ignores ``VARCHAR(n)`` lengths, so URL
  length is ALSO checked with ``length(url) <= 2048``.
* All queries go through the ORM / bound parameters. No raw SQL string is
  assembled from user input anywhere in this project (SQL-injection defence).
* Timestamps are UTC. SQLite returns them as naive datetimes; ``utc_value()``
  normalises them back to timezone-aware UTC for display and comparison.

Columns reserved for later stages are documented as such and remain NULLABLE;
they are not non-functional code. ``ScanHistory.features_json`` will hold the
15-feature snapshot written by Stage 10.
"""
from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Any

from flask import Flask, has_app_context
from flask_login import UserMixin
from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer,
    String, Text, event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db

PREDICTIONS: tuple[str, ...] = ("LEGITIMATE", "SUSPICIOUS", "PHISHING")
RISK_LEVELS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH")
ROLES: tuple[str, ...] = ("user", "admin")
MAX_STORED_URL_LENGTH = 2048

_TABLENAMES = ("users", "scan_history", "model_information")


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_value(value: datetime | None) -> datetime | None:
    """Normalise a SQLite-returned (naive) datetime back to aware UTC."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def iso_utc(value: datetime | None) -> str | None:
    """Render a datetime as an ISO-8601 UTC string, or ``None``."""
    normalised = utc_value(value)
    return normalised.isoformat() if normalised else None


class User(UserMixin, db.Model):
    """A registered account. Guests scan without one; admins have role='admin'."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, default="user", server_default="user"
    )
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    scans: Mapped[list["ScanHistory"]] = relationship(
        "ScanHistory",
        back_populates="user",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint("role IN ('user', 'admin')", name="ck_users_role"),
        CheckConstraint("length(trim(username)) >= 3", name="ck_users_username_length"),
        CheckConstraint("length(password_hash) >= 20", name="ck_users_password_hash_length"),
        {"sqlite_autoincrement": True},
    )

    @property
    def is_active(self) -> bool:
        """Flask-Login checks this. A disabled account cannot sign in."""
        return bool(self.active)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def set_password(self, password: str) -> None:
        """Store a scrypt hash. Never store, log or echo the plaintext."""
        if not isinstance(password, str) or not password:
            raise ValueError("A non-empty password is required.")
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        """Constant-time verification via Werkzeug."""
        if not isinstance(password, str) or not self.password_hash:
            return False
        try:
            return check_password_hash(self.password_hash, password)
        except (ValueError, TypeError):
            return False

    def to_dict(self) -> dict[str, Any]:
        """Safe public representation — deliberately omits ``password_hash``."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "active": bool(self.active),
            "created_at": iso_utc(self.created_at),
            "last_login_at": iso_utc(self.last_login_at),
        }

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"


class ScanHistory(db.Model):
    """One URL screening result. ``user_id`` is NULL for a guest scan."""

    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    url: Mapped[str] = mapped_column(String(MAX_STORED_URL_LENGTH), nullable=False)
    normalised_url: Mapped[str] = mapped_column(
        String(MAX_STORED_URL_LENGTH), nullable=False
    )
    prediction: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    model_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    # Written by Stage 10's detection service as a JSON snapshot of the 15
    # lexical features plus the flagged indicators used for the explanation.
    features_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped["User | None"] = relationship("User", back_populates="scans")

    __table_args__ = (
        CheckConstraint(
            "prediction IN ('LEGITIMATE', 'SUSPICIOUS', 'PHISHING')",
            name="ck_scan_history_prediction",
        ),
        CheckConstraint(
            "risk_level IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_scan_history_risk_level",
        ),
        CheckConstraint(
            "model_score >= 0.0 AND model_score <= 1.0",
            name="ck_scan_history_score_range",
        ),
        CheckConstraint(
            f"length(url) > 0 AND length(url) <= {MAX_STORED_URL_LENGTH}",
            name="ck_scan_history_url_length",
        ),
        Index("ix_scan_history_user_scan_date", "user_id", "scan_date"),
        {"sqlite_autoincrement": True},
    )

    def to_dict(self) -> dict[str, Any]:
        """Safe public representation. Features are deliberately not echoed raw."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "url": self.url,
            "normalised_url": self.normalised_url,
            "prediction": self.prediction,
            "model_score": self.model_score,
            "risk_level": self.risk_level,
            "model_version": self.model_version,
            "scan_date": iso_utc(self.scan_date),
        }

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"<ScanHistory id={self.id} prediction={self.prediction!r}>"


class ModelInformation(db.Model):
    """Audit record of the DEPLOYED model and its MEASURED test metrics.

    ``scripts/init_db.py`` populates exactly one row per (model_name,
    model_version) by copying values from ``ml/saved_model/metrics.json`` and
    ``metadata.json``. No figure is typed into code, and no Stage 8 page
    displays these numbers — Stage 11's admin dashboard reads them here or
    from ``metrics.json`` at runtime.
    """

    __tablename__ = "model_information"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    training_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    accuracy: Mapped[float | None] = mapped_column(Float, nullable=True)
    precision: Mapped[float | None] = mapped_column(Float, nullable=True)
    recall: Mapped[float | None] = mapped_column(Float, nullable=True)
    f1_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    roc_auc: Mapped[float | None] = mapped_column(Float, nullable=True)
    dataset_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    metrics_source: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    __table_args__ = (
        CheckConstraint(
            "accuracy IS NULL OR (accuracy >= 0.0 AND accuracy <= 1.0)",
            name="ck_model_information_accuracy",
        ),
        CheckConstraint(
            "roc_auc IS NULL OR (roc_auc >= 0.0 AND roc_auc <= 1.0)",
            name="ck_model_information_roc_auc",
        ),
        Index("uq_model_information_version", "model_name", "model_version", unique=True),
        {"sqlite_autoincrement": True},
    )

    def to_dict(self) -> dict[str, Any]:
        """Full audit representation (only used by authenticated admin views)."""
        return {
            "id": self.id,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "training_date": iso_utc(self.training_date),
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "roc_auc": self.roc_auc,
            "dataset_fingerprint": self.dataset_fingerprint,
            "feature_count": self.feature_count,
            "metrics_source": self.metrics_source,
            "created_at": iso_utc(self.created_at),
        }

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"<ModelInformation {self.model_name!r} v{self.model_version!r}>"


def configure_database(app: Flask) -> None:
    """Enable SQLite foreign-key enforcement for this app's engine, once.

    Without ``PRAGMA foreign_keys=ON`` SQLite silently ignores
    ``ON DELETE SET NULL``, which would break the guest-history guarantee.
    Registering the listener on the ENGINE (not the global ``Engine`` class)
    keeps the behaviour scoped to one application instance — important for
    the isolated apps created by the test suite.
    """
    if app.extensions.get("sqlite_fk_configured"):
        return
    context = app.app_context() if not has_app_context() else nullcontext()
    with context:
        engine = db.engine
        if engine.dialect.name == "sqlite":

            @event.listens_for(engine, "connect")
            def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        app.extensions["sqlite_fk_configured"] = True


__all__ = [
    "User", "ScanHistory", "ModelInformation", "configure_database",
    "utcnow", "utc_value", "iso_utc", "PREDICTIONS", "RISK_LEVELS", "ROLES",
    "MAX_STORED_URL_LENGTH",
]
