"""Model training (Stage 5).

Fits the three estimators required by the brief on the TRAINING SPLIT ONLY and
persists each as a joblib candidate bundle. No model is selected here, and NO
performance metric is computed: evaluation, comparison, threshold calibration
and selection are Stage 6 responsibilities. The held-out splits are never read
by this module.

Pipeline design
---------------
* Logistic Regression: StandardScaler -> LogisticRegression. Scaling is needed
  because count features such as url_length (0..6000) dominate 0/1 flags in an
  L2-regularised linear model.
* Decision Tree: no scaling (trees are invariant to monotone rescaling), with a
  depth cap and a minimum leaf size to control overfitting.
* Random Forest: the same depth/leaf regularisation as the single tree, with a
  bounded ensemble size. Depth capping also bounds the serialised artefact to a
  size a student project can actually version and deploy. It is fitted with
  ``n_jobs=1`` so that ``predict_proba`` is bitwise deterministic; threaded
  accumulation in scikit-learn changes the last floating-point bit between two
  otherwise identical predictions.

Class weights are intentionally left at the default. The dataset is reasonably
balanced (about 43% phishing), and Stage 6 implements the brief's recall
priority through an explicit validation-set threshold constraint. Reweighting
here would distort predict_proba before that calibration step.

Usage
-----
    python -m ml.train_model
    python -m ml.train_model --output-dir ml/saved_model/candidates --seed 42

Everything is deterministic for a given seed, input file and library versions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from ml.feature_extraction import FEATURE_ORDER, extract_frame

ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = "1.0"
MODEL_VERSION = "0.5.0-candidate"
CANDIDATE_NAMES: tuple[str, ...] = ("logistic_regression", "decision_tree", "random_forest")


@dataclass(frozen=True)
class TrainingConfig:
    """Every parameter that can change a trained artefact (recorded in the manifest)."""

    train_path: Path
    output_dir: Path
    seed: int = 42
    n_estimators: int = 100
    max_depth: int = 12
    min_samples_leaf: int = 10
    lr_max_iter: int = 1000

    def public_dict(self) -> dict[str, Any]:
        """JSON-safe representation with paths relative to the project root."""
        data = asdict(self)
        data["train_path"] = str(self.train_path)
        data["output_dir"] = str(self.output_dir)
        return data


@dataclass
class TrainedCandidate:
    """One fitted pipeline plus the measured facts about its training run."""

    name: str
    estimator: Pipeline
    training_seconds: float
    hyperparameters: dict[str, Any]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_pipelines(config: TrainingConfig) -> dict[str, Pipeline]:
    """Construct the three candidate pipelines. Pure: no fitting happens here."""
    return {
        "logistic_regression": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                solver="lbfgs",
                max_iter=config.lr_max_iter,
                random_state=config.seed,
                class_weight=None,
            )),
        ]),
        "decision_tree": Pipeline([
            ("classifier", DecisionTreeClassifier(
                max_depth=config.max_depth,
                min_samples_leaf=config.min_samples_leaf,
                random_state=config.seed,
                class_weight=None,
            )),
        ]),
        "random_forest": Pipeline([
            ("classifier", RandomForestClassifier(
                n_estimators=config.n_estimators,
                max_depth=config.max_depth,
                min_samples_leaf=config.min_samples_leaf,
                random_state=config.seed,
                class_weight=None,
                # Single-threaded prediction gives BITWISE-stable scores.
                # With n_jobs=-1 sklearn accumulates tree votes in a shared
                # array from several threads, so predict_proba varies by about
                # 2.2e-16 between two calls on the same URL. That is harmless
                # numerically but makes repeated scans look inconsistent.
                n_jobs=1,
            )),
        ]),
    }


def hyperparameters_for(name: str, config: TrainingConfig) -> dict[str, Any]:
    """Explicit, human-auditable hyperparameter record (not a raw get_params dump)."""
    common = {"random_state": config.seed, "class_weight": None}
    if name == "logistic_regression":
        return {**common, "steps": ["StandardScaler", "LogisticRegression"],
                "solver": "lbfgs", "max_iter": config.lr_max_iter}
    if name == "decision_tree":
        return {**common, "steps": ["DecisionTreeClassifier"],
                "max_depth": config.max_depth, "min_samples_leaf": config.min_samples_leaf}
    return {**common, "steps": ["RandomForestClassifier"],
            "n_estimators": config.n_estimators, "max_depth": config.max_depth,
            "min_samples_leaf": config.min_samples_leaf, "n_jobs": 1}


def load_training_data(path: Path) -> tuple[pd.DataFrame, pd.Series, dict[str, Any]]:
    """Read the training split and compute the shared Stage 4 feature matrix."""
    if not path.is_file():
        raise FileNotFoundError(f"Training split not found: {path}")
    frame = pd.read_csv(path)
    expected = ["url", "label", "group_id"]
    if list(frame.columns) != expected:
        raise ValueError(f"Unexpected training columns {list(frame.columns)}; expected {expected}")
    if set(frame["label"].unique()) != {0, 1}:
        raise ValueError("Training labels must be exactly {0, 1}")

    print(f"Extracting {len(FEATURE_ORDER)} features for {len(frame):,} training URLs ...")
    features = extract_frame(frame["url"].tolist())
    if list(features.columns) != list(FEATURE_ORDER):
        raise RuntimeError("Feature matrix column order does not match FEATURE_ORDER")
    labels = frame["label"].astype(int)

    facts = {
        "train_file": str(path),
        "train_file_sha256": sha256_file(path),
        "rows": int(len(frame)),
        "legitimate_rows": int((labels == 0).sum()),
        "phishing_rows": int((labels == 1).sum()),
        "phishing_rate": round(float((labels == 1).mean()), 6),
        "feature_count": len(FEATURE_ORDER),
        "feature_order": list(FEATURE_ORDER),
        "splits_used": ["train"],
        "held_out_splits_not_read": True,
    }
    return features, labels, facts


def train_all(
    features: pd.DataFrame, labels: pd.Series, config: TrainingConfig
) -> dict[str, TrainedCandidate]:
    """Fit every candidate and measure (only) wall-clock training time."""
    pipelines = build_pipelines(config)
    trained: dict[str, TrainedCandidate] = {}
    for name, pipeline in pipelines.items():
        print(f"  training {name} ...", flush=True)
        started = time.perf_counter()
        # sklearn 1.6.1 + SciPy emits a benign "Unknown solver options: iprint"
        # notice for lbfgs on some builds. Suppress ONLY that message; real
        # convergence warnings must remain visible.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Unknown solver options")
            pipeline.fit(features, labels)
        elapsed = time.perf_counter() - started

        # Fail fast if a candidate cannot support the decision layer.
        probe = pipeline.predict_proba(features.iloc[:2])
        if probe.shape != (2, 2):
            raise RuntimeError(f"{name} did not return a two-column probability matrix")
        if list(pipeline.classes_) != [0, 1]:
            raise RuntimeError(f"{name} has unexpected class order {list(pipeline.classes_)}")

        trained[name] = TrainedCandidate(
            name=name,
            estimator=pipeline,
            training_seconds=round(elapsed, 3),
            hyperparameters=hyperparameters_for(name, config),
        )
        print(f"    fitted in {elapsed:.2f}s", flush=True)
    return trained


def save_candidates(
    candidates: dict[str, TrainedCandidate],
    config: TrainingConfig,
    facts: dict[str, Any],
) -> dict[str, Any]:
    """Persist three joblib bundles and a complete, honest training manifest."""
    config.output_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    environment = {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit_learn": sklearn.__version__,
        "joblib": joblib.__version__,
    }

    model_records: dict[str, Any] = {}
    for name, candidate in candidates.items():
        target = config.output_dir / f"{name}.joblib"
        payload = {
            "estimator": candidate.estimator,
            "feature_order": list(FEATURE_ORDER),
            "schema_version": SCHEMA_VERSION,
            "model_name": name,
            "model_version": MODEL_VERSION,
            "trained_at_utc": generated_at,
            "random_state": config.seed,
            "hyperparameters": candidate.hyperparameters,
            "training_rows": facts["rows"],
            "training_seconds": candidate.training_seconds,
            "library_versions": environment,
        }
        joblib.dump(payload, target, compress=3)
        model_records[name] = {
            "file": str(target),
            "size_bytes": target.stat().st_size,
            "sha256": sha256_file(target),
            "training_seconds": candidate.training_seconds,
            "hyperparameters": candidate.hyperparameters,
        }

    manifest = {
        "stage": 5,
        "generated_at_utc": generated_at,
        "description": "Three fitted candidate pipelines. No evaluation, selection or threshold calibration performed.",
        "schema_version": SCHEMA_VERSION,
        "model_version": MODEL_VERSION,
        "dataset": facts,
        "config": config.public_dict(),
        "feature_contract": {
            "count": len(FEATURE_ORDER),
            "feature_order": list(FEATURE_ORDER),
            "source": "ml.feature_extraction.FEATURE_ORDER (Stage 4)",
        },
        "models": model_records,
        "environment": environment,
        "evaluation_performed": False,
        "selection_performed": False,
        "metrics_measured": [],
        "next_stage": "Stage 6 measures accuracy, precision, recall, F1, confusion matrix and ROC-AUC, then selects a model.",
    }
    (config.output_dir / "training_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest


def run(config: TrainingConfig) -> dict[str, Any]:
    """Execute training end to end and return the written manifest."""
    features, labels, facts = load_training_data(config.train_path)
    candidates = train_all(features, labels, config)
    return save_candidates(candidates, config, facts)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path,
                        default=ROOT / "dataset" / "processed" / "train.csv",
                        help="Path to the Stage 3 training split.")
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "ml" / "saved_model" / "candidates",
                        help="Directory for candidate joblib bundles and the manifest.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=100,
                        help="Random Forest tree count.")
    parser.add_argument("--max-depth", type=int, default=12,
                        help="Depth cap for the tree-based models.")
    parser.add_argument("--min-samples-leaf", type=int, default=10)
    parser.add_argument("--lr-max-iter", type=int, default=1000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = TrainingConfig(
        train_path=args.train,
        output_dir=args.output_dir,
        seed=args.seed,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_samples_leaf,
        lr_max_iter=args.lr_max_iter,
    )
    manifest = run(config)
    print("\nStage 5 training complete")
    print(f"  training rows        : {manifest['dataset']['rows']:,}")
    print(f"  legitimate / phishing: {manifest['dataset']['legitimate_rows']:,} / "
          f"{manifest['dataset']['phishing_rows']:,}")
    print(f"  features             : {manifest['feature_contract']['count']}")
    for name, record in manifest["models"].items():
        print(f"  {name:<21}: {record['size_bytes']:>10,} bytes, "
              f"{record['training_seconds']:.2f}s")
    print(f"  artefacts            : {config.output_dir}")
    print("\nNo model was selected and NO performance metric was computed.")
    print("Run Stage 6 for measured evaluation on the validation split.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
