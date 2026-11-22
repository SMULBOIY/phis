"""Read-only access to the Stage 6 model artefacts for the web layer (Stage 7).

Responsibilities
----------------
* Load and validate ``ml/saved_model/metadata.json`` once at application start.
* Verify that ``model_bundle.joblib`` still has the SHA-256 recorded in that
  metadata (a corrupted or swapped artefact is a deployment error).
* Expose a small, **performance-number-free** public description of the model
  for ``/health`` and the backend status page.

Deliberate limits (important for academic integrity)
---------------------------------------------------
* This module does NOT load the estimator, does NOT call ``predict_proba`` and
  does NOT read ``metrics.json``. Loading the estimator is Stage 10; displaying
  measured accuracy/precision/recall/F1/ROC-AUC is Stage 11 and must come from
  ``metrics.json`` at runtime, never from a literal in code.
* Stage 9 added ``dataset_chart()``, which reads the real dataset split ROW
  COUNTS from ``metadata.json`` for a provenance chart. Those are counts of
  training rows, not model results; they are still loaded at runtime.
* If metadata is missing or inconsistent, application startup FAILS LOUDLY.
  There is no "silent fallback" to rules, defaults or an older model.
* If the bundle is missing or its hash differs, the app still boots but reports
  ``degraded`` and ``/health`` returns HTTP 503 ``MODEL_UNAVAILABLE``. A 503 is
  an honest result; a 200 with a rule-based guess would not be.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from flask import current_app

from ml.thresholds import DECISION_STATES, SCORE_MEANING

REQUIRED_METADATA_KEYS = (
    "schema_version", "feature_schema_version", "model_name", "model_version",
    "feature_order", "thresholds", "score_meaning", "decision_states",
    "model_bundle_sha256", "generated_at_utc",
)
EXPECTED_FEATURE_COUNT = 15


class ModelMetadataError(RuntimeError):
    """The Stage 6 artefact contract is broken; refuse to start the web app."""


@dataclass(frozen=True)
class ModelMetadata:
    """Validated, immutable view of ``metadata.json``."""

    model_name: str
    model_version: str
    schema_version: str
    feature_schema_version: str
    feature_order: tuple[str, ...]
    threshold_low: float
    threshold_high: float
    score_meaning: str
    decision_states: dict[str, dict[str, str]]
    bundle_sha256: str
    generated_at_utc: str
    source_path: str

    @property
    def thresholds(self) -> dict[str, float]:
        return {"low": self.threshold_low, "high": self.threshold_high}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_model_metadata(path: str | Path) -> ModelMetadata:
    """Parse and validate a Stage 6 ``metadata.json``.

    Validation is deliberately strict: the web layer must never run against a
    model whose feature order, score wording or decision states have drifted
    away from the modules that will do the inference in Stage 10.
    """
    source = Path(path)
    if not source.is_file():
        raise ModelMetadataError(f"model metadata file is missing: {source}")
    try:
        raw: dict[str, Any] = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelMetadataError(f"cannot read model metadata {source}: {exc}") from exc

    missing = [key for key in REQUIRED_METADATA_KEYS if key not in raw]
    if missing:
        raise ModelMetadataError(f"model metadata is missing keys: {', '.join(missing)}")

    order = raw["feature_order"]
    if not isinstance(order, list) or len(order) != EXPECTED_FEATURE_COUNT \
            or len(set(order)) != len(order) or not all(isinstance(x, str) for x in order):
        raise ModelMetadataError(
            f"feature_order must be {EXPECTED_FEATURE_COUNT} unique strings; got {order!r}"
        )

    thresholds = raw["thresholds"]
    try:
        low = float(thresholds["low"])
        high = float(thresholds["high"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ModelMetadataError(f"invalid calibrated thresholds: {thresholds!r}") from exc
    if not (0.0 <= low < high <= 1.0):
        raise ModelMetadataError(f"calibrated band is not ordered: ({low}, {high})")

    states = raw["decision_states"]
    if not isinstance(states, dict) or set(states) != set(DECISION_STATES):
        raise ModelMetadataError("decision_states do not match ml.thresholds.DECISION_STATES")
    for name, contract in DECISION_STATES.items():
        for field in ("colour", "risk_level", "message", "warning"):
            if states[name].get(field) != contract[field]:
                raise ModelMetadataError(f"decision_states.{name}.{field} differs from the contract")

    if raw["score_meaning"] != SCORE_MEANING:
        raise ModelMetadataError("score_meaning differs from ml.thresholds.SCORE_MEANING")

    bundle_hash = raw["model_bundle_sha256"]
    if not isinstance(bundle_hash, str) or len(bundle_hash) != 64:
        raise ModelMetadataError("model_bundle_sha256 is not a SHA-256 hex digest")

    return ModelMetadata(
        model_name=str(raw["model_name"]),
        model_version=str(raw["model_version"]),
        schema_version=str(raw["schema_version"]),
        feature_schema_version=str(raw["feature_schema_version"]),
        feature_order=tuple(order),
        threshold_low=low,
        threshold_high=high,
        score_meaning=str(raw["score_meaning"]),
        decision_states={k: dict(v) for k, v in states.items()},
        bundle_sha256=bundle_hash,
        generated_at_utc=str(raw["generated_at_utc"]),
        source_path=str(source),
    )


class ModelRegistry:
    """Holds the validated metadata plus the measured integrity of the bundle."""

    def __init__(self, metadata_path: str | Path, bundle_path: str | Path) -> None:
        self.metadata_path = Path(metadata_path)
        self.bundle_path = Path(bundle_path)
        self.metadata = load_model_metadata(self.metadata_path)
        # Stage 9 reads the real dataset split SIZES for a provenance chart.
        # load_model_metadata() has already validated this JSON file, so a
        # second read is safe. No model performance number is read here.
        self._raw: dict[str, Any] = json.loads(
            self.metadata_path.read_text(encoding="utf-8")
        )
        self.bundle_available, self.bundle_detail = self._inspect_bundle()

    def _inspect_bundle(self) -> tuple[bool, str]:
        if not self.bundle_path.is_file():
            return False, f"bundle file is missing: {self.bundle_path.name}"
        actual = _sha256(self.bundle_path)
        if actual != self.metadata.bundle_sha256:
            return False, "bundle SHA-256 does not match metadata.json"
        return True, "bundle SHA-256 matches metadata.json"

    def public_info(self) -> dict[str, Any]:
        """Safe, metric-free description for ``/health`` and the status page."""
        meta = self.metadata
        return {
            "model_name": meta.model_name,
            "model_version": meta.model_version,
            "schema_version": meta.schema_version,
            "feature_schema_version": meta.feature_schema_version,
            "feature_count": len(meta.feature_order),
            "decision_thresholds": {
                "low": meta.threshold_low,
                "high": meta.threshold_high,
                "source": "ml/saved_model/metadata.json (calibrated on the validation split in Stage 6)",
            },
            "decision_states": sorted(meta.decision_states),
            "generated_at_utc": meta.generated_at_utc,
        }

    def dataset_chart(self) -> dict[str, Any]:
        """Real dataset split ROW COUNTS for the Stage 9 provenance chart.

        These are provenance counts from ``metadata.json`` — not model scores,
        not invented data, and not a measured performance figure. The template
        embeds them as an escaped ``data-chart`` JSON payload; Chart.js reads it
        from the DOM, so no inline script is needed under the strict CSP.
        """
        sizes = self._raw.get("dataset", {}).get("split_sizes", {})
        keys = ("train", "validation", "test")
        if not all(isinstance(sizes.get(key), int) and sizes[key] > 0 for key in keys):
            raise ModelMetadataError("metadata.json has no usable dataset split sizes")
        return {
            "labels": ["Train (70%)", "Validation (15%)", "Test (15%)"],
            "values": [sizes[key] for key in keys],
            "series_label": "URL rows",
            "source": "ml/saved_model/metadata.json#dataset.split_sizes",
        }

    def health(self) -> dict[str, Any]:
        """Artefact status. An unavailable bundle is reported, never hidden."""
        return {
            "available": self.bundle_available,
            "bundle_file": self.bundle_path.name,
            "detail": self.bundle_detail,
            "metadata_file": self.metadata_path.name,
        }


def get_registry() -> ModelRegistry:
    """Return the application's ``ModelRegistry`` or raise a clear error."""
    registry = current_app.extensions.get("model_registry")
    if registry is None:
        raise ModelMetadataError("the application has no model registry attached")
    return registry


__all__ = [
    "ModelMetadataError", "ModelMetadata", "ModelRegistry", "load_model_metadata",
    "get_registry", "REQUIRED_METADATA_KEYS", "EXPECTED_FEATURE_COUNT",
]
