"""Runtime wrapper around the Stage 6 Joblib estimator (Stage 10).

Why this file exists
--------------------
Stage 5 trained three candidates and Stage 6 selected one. The deployed
artefact is ``ml/saved_model/model_bundle.joblib``: a dict containing an
``sklearn.pipeline.Pipeline`` (``StandardScaler`` -> ``LogisticRegression``),
the exact 15-feature order, and provenance. Loading a pickle in a web request
is a privileged operation, so it is isolated here, behind one small class with
an explicit, testable failure mode.

Contract
--------
* The bundle is loaded ONCE, at application start, and only after
  ``services.model_metadata.ModelRegistry`` has verified its SHA-256 against
  ``metadata.json``. A tampered or truncated file is never deserialised.
* ``score()`` takes the SAME ``dict[str, int]`` that
  ``ml.feature_extraction.extract_features`` returns and converts it with
  ``ml.feature_extraction.features_to_frame``. That function builds a pandas
  ``DataFrame`` whose column names are ``FEATURE_ORDER`` - the pipeline was
  fitted with feature names, so passing a bare NumPy array would trigger a
  scikit-learn warning and, worse, could silently rely on positional order.
  Using the shared helper guarantees training-serving parity.
* The returned number is the ``predict_proba`` value for the class encoded as
  ``1`` (phishing) in ``metadata.json.class_labels``. It is **not** a calibrated
  probability and must never be described as a guaranteed probability of
  maliciousness.
* Any missing/corrupt artefact, unsupported class layout or non-finite score
  raises ``ModelUnavailableError``. There is NO rule-based fallback, NO default
  score and NO "best guess". Stage 10's route turns this into an explicit
  ``503 MODEL_UNAVAILABLE``.

This module performs NO network I/O. It never sees a live website; it only
reads a local, hash-verified artefact and multiplies numbers.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Mapping

import joblib

from ml.feature_extraction import FEATURE_ORDER, features_to_frame

__all__ = ["ModelUnavailableError", "PredictionModel"]


class ModelUnavailableError(RuntimeError):
    """The deployed estimator cannot be trusted or cannot produce a score.

    Deliberately distinct from a bad *URL* (400) and a bad *database* (503
    DATABASE_UNAVAILABLE). Callers must surface this as
    ``503 MODEL_UNAVAILABLE`` and must never substitute a heuristic verdict.
    """


class PredictionModel:
    """A validated, read-only handle on the deployed binary classifier."""

    def __init__(self, bundle_path: str | Path) -> None:
        self.bundle_path = Path(bundle_path)
        if not self.bundle_path.is_file():
            raise ModelUnavailableError(
                "the deployed model bundle is missing from disk"
            )

        # joblib.load unpickles Python objects. This happens ONLY after the
        # caller (DetectionRegistry) has verified the file's SHA-256 against
        # metadata.json, so a replaced file never reaches this line.
        try:
            bundle: Any = joblib.load(self.bundle_path)
        except Exception as exc:  # noqa: BLE001 - normalise every unpickle failure
            raise ModelUnavailableError(
                f"the deployed model bundle could not be loaded ({type(exc).__name__})"
            ) from exc

        if not isinstance(bundle, dict):
            raise ModelUnavailableError("the model bundle has an unexpected structure")
        estimator = bundle.get("estimator")
        if estimator is None or not callable(getattr(estimator, "predict_proba", None)):
            raise ModelUnavailableError(
                "the model bundle has no estimator with predict_proba"
            )

        order = bundle.get("feature_order")
        if not isinstance(order, (list, tuple)) or list(order) != list(FEATURE_ORDER):
            raise ModelUnavailableError(
                "the bundle feature order does not match the live FEATURE_ORDER"
            )

        classes = getattr(estimator, "classes_", None)
        if classes is None:
            raise ModelUnavailableError("the estimator has no fitted class labels")
        class_values = [int(value) for value in classes]
        if class_values != [0, 1]:
            raise ModelUnavailableError(
                "the estimator's class encoding is not the documented 0=legitimate/1=phishing"
            )

        self.estimator = estimator
        self.feature_order: tuple[str, ...] = tuple(FEATURE_ORDER)
        self.phishing_index: int = class_values.index(1)
        self.model_name: str = str(bundle.get("model_name", ""))
        self.model_version: str = str(bundle.get("model_version", ""))
        self.schema_version: str = str(bundle.get("schema_version", ""))

    def score(self, features: Mapping[str, int]) -> float:
        """Return the uncalibrated phishing-class score for ONE feature vector."""
        if tuple(features) != self.feature_order:
            raise ModelUnavailableError(
                "the live feature vector does not match the fitted feature order"
            )
        try:
            frame = features_to_frame(dict(features))
            probabilities = self.estimator.predict_proba(frame)
            raw = float(probabilities[0][self.phishing_index])
        except Exception as exc:  # noqa: BLE001 - never leak a scikit-learn traceback
            raise ModelUnavailableError(
                f"the estimator could not score this URL ({type(exc).__name__})"
            ) from exc
        if not math.isfinite(raw) or not 0.0 <= raw <= 1.0:
            raise ModelUnavailableError("the estimator returned an invalid score")
        return raw

    def describe(self) -> dict[str, str]:
        """Secret-free provenance for /health and the printable report."""
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "schema_version": self.schema_version,
            "bundle": self.bundle_path.name,
        }

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (
            f"<PredictionModel {self.model_name!r} v{self.model_version!r} "
            f"features={len(self.feature_order)}>"
        )
