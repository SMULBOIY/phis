"""End-to-end detection orchestration and audit persistence (Stage 10).

Pipeline (one request, one transaction, no shortcuts)
-----------------------------------------------------
    submitted string
      -> services.validation.validate_url        (bounded, normalised, NO network)
      -> ml.feature_extraction.extract_features (the SAME 15 features as training)
      -> models.prediction_model.PredictionModel.score (hash-verified Joblib estimator)
      -> services.decision_service.decide       (measured thresholds -> 3 states)
      -> services.explanation_service.explain  (measured importance + caveats)
      -> models.database_models.ScanHistory    (guest or user-linked audit row)
      -> routes.scanning.render_template       (result + printable report)

Security properties
-------------------
* The backend NEVER opens, resolves, downloads or executes the submitted URL.
  There is no HTTP client, no DNS lookup and no SSRF surface. Classification is
  purely lexical/statistical. This is also a LIMITATION (no page content).
* Untrusted input is validated once at the boundary; the normalised string is
  what is stored and displayed, and Jinja2 autoescaping renders it.
* A missing, corrupt or tampered model bundle produces ``503 MODEL_UNAVAILABLE``.
  There is NO rule-based fallback, no default verdict and no fabricated score.
* A database write failure rolls back and produces ``503 DATABASE_UNAVAILABLE``.
  A scan result is never shown without its audit record being committed, so the
  history can never silently disagree with what a user was told.
* Guest scans are allowed (``user_id=None``, ``ON DELETE SET NULL``); logged-in
  scans are linked to their ``User``. Nothing here reads performance metrics for
  display: feature importance is measured provenance, not an accuracy claim.

Failure taxonomy (all explicit, none hidden)
-------------------------------------------
    InvalidSubmissionError     -> 400 INVALID_URL
    DetectionUnavailableError  -> 503 MODEL_UNAVAILABLE
    DetectionStorageError      -> 503 DATABASE_UNAVAILABLE
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from flask import Flask, current_app
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from ml.feature_extraction import FEATURE_ORDER, extract_features
from models.database_models import (
    MAX_STORED_URL_LENGTH,
    ScanHistory,
    iso_utc,
    utcnow,
)
from models.prediction_model import ModelUnavailableError, PredictionModel
from services.decision_service import Decision, decide
from services.explanation_service import Explanation, explain
from services.model_metadata import ModelRegistry
from services.validation import URLValidationError, safe_display_url, validate_url

IMPORTANCE_SOURCE = "ml/saved_model/metrics.json#feature_importance.features"

__all__ = [
    "IMPORTANCE_SOURCE", "DetectionError", "InvalidSubmissionError",
    "DetectionUnavailableError", "DetectionStorageError",
    "DetectionResult", "DetectionRegistry", "get_detection_registry",
]


class DetectionError(RuntimeError):
    """Base class for every explicit detection failure."""


class InvalidSubmissionError(DetectionError):
    """The submitted URL failed validation (HTTP 400)."""


class DetectionUnavailableError(DetectionError):
    """The deployed estimator cannot be loaded or used (HTTP 503)."""


class DetectionStorageError(DetectionError):
    """The audit row could not be committed (HTTP 503)."""


@dataclass(frozen=True)
class DetectionResult:
    """One complete, immutable scan result."""

    raw_url: str
    normalized_url: str
    display_url: str
    scheme: str
    host: str
    features: dict[str, int]
    score: float
    decision: Decision
    explanation: Explanation
    model_name: str
    model_version: str
    scan_date: datetime
    scan_id: int
    user_id: int | None
    persisted: bool

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe representation (used by the report and future REST API)."""
        return {
            "scan_id": self.scan_id,
            "submitted_url": self.normalized_url,
            "display_url": self.display_url,
            "scheme": self.scheme,
            "host": self.host,
            "model_score": self.score,
            "score_label": "Model score (uncalibrated estimate, not a probability of maliciousness)",
            "score_meaning": self.decision.score_meaning,
            "classification": self.decision.prediction,
            "risk_level": self.decision.risk_level,
            "colour": self.decision.colour,
            "message": self.decision.message,
            "warning": self.decision.warning,
            "uncertain": self.decision.uncertain,
            "thresholds": {
                "low": self.decision.threshold_low,
                "high": self.decision.threshold_high,
                "band": self.decision.band(),
            },
            "date_time_utc": iso_utc(self.scan_date),
            "model": {"name": self.model_name, "version": self.model_version},
            "characteristics": [item.to_dict() for item in self.explanation.insights],
            "flagged": [item.to_dict() for item in self.explanation.flagged],
            "top_measured_features": [item.to_dict() for item in self.explanation.top],
            "recommended_action": self.explanation.recommended_action,
            "uncertainty_note": self.explanation.uncertainty_note,
            "caveats": list(self.explanation.caveats),
            "importance_source": self.explanation.importance_source,
            "user_id": self.user_id,
            "persisted": self.persisted,
        }


class DetectionRegistry:
    """Application-scoped, fail-closed handle on the live detection engine."""

    def __init__(self, model_registry: ModelRegistry, config: Mapping[str, Any]) -> None:
        self.metadata = model_registry.metadata
        self.max_url_length = int(config["MAX_URL_LENGTH"])
        self.bundle_path = Path(config["MODEL_BUNDLE_PATH"])
        self.metrics_path = Path(config["METRICS_PATH"])
        self.model: PredictionModel | None = None
        self.importance: dict[str, float] = {}
        self.error: str | None = None
        self.bundle_integrity: str = model_registry.bundle_detail

        # Measured permutation importance is provenance for the explanation,
        # not a displayed performance figure. If it is missing, fail closed.
        try:
            self.importance = self._read_importance()
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self.error = (
                "measured feature importance is unavailable "
                f"({type(exc).__name__})"
            )

        if not model_registry.bundle_available:
            self.error = self.error or (
                "the deployed model bundle failed integrity verification"
            )
        elif self.error is None:
            try:
                candidate = PredictionModel(self.bundle_path)
                self._verify_identity(candidate)
                self.model = candidate
            except (ModelUnavailableError, ValueError) as exc:
                self.error = str(exc)

    def _verify_identity(self, model: PredictionModel) -> None:
        """Refuse a valid pickle that is not the artefact metadata describes."""
        if (model.model_name != self.metadata.model_name
                or model.model_version != self.metadata.model_version
                or model.schema_version != self.metadata.schema_version):
            raise ModelUnavailableError(
                "the loaded estimator does not match metadata.json provenance"
            )

    def _read_importance(self) -> dict[str, float]:
        """Read measured mean ROC-AUC decrease per feature (Stage 6 artefact)."""
        if not self.metrics_path.is_file():
            raise FileNotFoundError("metrics.json is missing")
        payload = json.loads(self.metrics_path.read_text(encoding="utf-8"))
        features = payload["feature_importance"]["features"]
        values: dict[str, float] = {}
        for name in FEATURE_ORDER:
            mean = float(features[name]["mean"])
            # A small NEGATIVE mean is a legitimate permutation-importance
            # outcome: shuffling that feature happened to improve ROC-AUC on the
            # sample, i.e. it carried no measurable signal. Keep the measured
            # signed value rather than silently clamping it to zero (which
            # would be inventing a number).
            if not math.isfinite(mean):
                raise ValueError(f"invalid measured importance for {name}")
            values[name] = mean
        return values

    @property
    def available(self) -> bool:
        """True only when BOTH the estimator and measured provenance are ready."""
        return self.model is not None and bool(self.importance) and self.error is None

    def health(self) -> dict[str, Any]:
        """Secret-free, metric-free status for ``/health``."""
        return {
            "status": "ready" if self.available else "unavailable",
            "introduced_stage": 10,
            "scheduled_stage": 10,
            "delivered_stage": 10,
            "engine": "static URL-only machine learning (no outbound requests)",
            "feature_count": len(FEATURE_ORDER),
            "decision_thresholds": self.metadata.thresholds,
            "uncertainty_band": (
                f"{self.metadata.threshold_low:g} < p < "
                f"{self.metadata.threshold_high:g}"
            ),
            "importance_source": IMPORTANCE_SOURCE if self.importance else None,
            "model": self.model.describe() if self.model else None,
            "detail": self.error,
        }

    def scan(self, raw_url: Any, *, user_id: int | None = None) -> DetectionResult:
        """Validate, score, explain and persist ONE submitted URL."""
        if not self.available or self.model is None:
            raise DetectionUnavailableError(self.error or "detection engine unavailable")

        # --- 1. trust boundary -------------------------------------------- #
        try:
            validated = validate_url(raw_url, max_length=self.max_url_length)
        except URLValidationError as exc:
            raise InvalidSubmissionError(str(exc)) from exc
        if (len(validated.raw) > MAX_STORED_URL_LENGTH
                or len(validated.normalized) > MAX_STORED_URL_LENGTH):
            raise InvalidSubmissionError(
                "Invalid URL: the value is too long to store safely."
            )

        # --- 2. the shared feature contract -------------------------------- #
        try:
            features = extract_features(
                validated.normalized, max_length=self.max_url_length
            )
        except ValueError as exc:
            raise InvalidSubmissionError(str(exc)) from exc
        if tuple(features) != tuple(FEATURE_ORDER):
            raise DetectionUnavailableError("live feature contract is inconsistent")

        # --- 3. real ML inference (no rule fallback) ----------------------- #
        try:
            score = self.model.score(features)
        except ModelUnavailableError as exc:
            raise DetectionUnavailableError(str(exc)) from exc

        # --- 4. measured abstention policy --------------------------------- #
        thresholds = self.metadata.thresholds
        decision = decide(score, low=thresholds["low"], high=thresholds["high"])
        explanation = explain(
            features,
            decision,
            importance=self.importance,
            importance_source=IMPORTANCE_SOURCE,
        )

        # --- 5. audit row -------------------------------------------------- #
        scan_date = utcnow()
        snapshot = json.dumps({
            "schema_version": self.metadata.feature_schema_version,
            "features": features,
            "flagged": [item.name for item in explanation.flagged],
            "importance_source": IMPORTANCE_SOURCE,
        }, sort_keys=True)
        row = ScanHistory(
            user_id=user_id,
            url=validated.raw,
            normalised_url=validated.normalized,
            prediction=decision.prediction,
            model_score=score,
            risk_level=decision.risk_level,
            model_version=self.metadata.model_version,
            scan_date=scan_date,
            features_json=snapshot,
        )
        try:
            db.session.add(row)
            db.session.commit()
            scan_id = int(row.id)
        except SQLAlchemyError as exc:
            db.session.rollback()
            raise DetectionStorageError(
                "the scan could not be saved to the audit database"
            ) from exc

        return DetectionResult(
            raw_url=validated.raw,
            normalized_url=validated.normalized,
            display_url=safe_display_url(validated.normalized),
            scheme=validated.scheme,
            host=validated.host,
            features=features,
            score=score,
            decision=decision,
            explanation=explanation,
            model_name=self.metadata.model_name,
            model_version=self.metadata.model_version,
            scan_date=scan_date,
            scan_id=scan_id,
            user_id=user_id,
            persisted=True,
        )


def get_detection_registry(app: Flask | None = None) -> DetectionRegistry:
    """Return (and cache) the detection engine attached to this Flask app."""
    target = app or current_app._get_current_object()
    existing = target.extensions.get("detection_registry")
    if isinstance(existing, DetectionRegistry):
        return existing
    model_registry = target.extensions.get("model_registry")
    if not isinstance(model_registry, ModelRegistry):
        raise DetectionUnavailableError("the application has no model registry")
    registry = DetectionRegistry(model_registry, target.config)
    target.extensions["detection_registry"] = registry
    return registry
