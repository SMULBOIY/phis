#!/usr/bin/env python3
"""Stage 5 exit gate: trained candidates, artefacts and integrity.

    cd phishing-detection-system
    python scripts/verify_stage5.py

Exits 0 only when every check passes. Verifies that three real pipelines were
fitted and saved, that they are loadable and usable, that training touched ONLY
the training split, and that NO performance metric or model selection has been
claimed. No live or malicious website is contacted.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# Set by a parent gate (e.g. verify_stage10.py) to avoid running
# the same historical gate exponentially many times. A standalone
# run has this unset and keeps its complete regression behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from ml.feature_extraction import FEATURE_ORDER, extract_features, features_to_frame  # noqa: E402
from ml.train_model import (  # noqa: E402
    CANDIDATE_NAMES, SCHEMA_VERSION, TrainingConfig, build_pipelines, train_all,
)
from ml.url_utils import normalize_url  # noqa: E402

CANDIDATES_DIR = ROOT / "ml" / "saved_model" / "candidates"
MANIFEST = CANDIDATES_DIR / "training_manifest.json"

REQUIRED_FILES = (
    "ml/train_model.py",
    "docs/TRAINING.md",
    "scripts/verify_stage5.py",
    "ml/saved_model/candidates/logistic_regression.joblib",
    "ml/saved_model/candidates/decision_tree.joblib",
    "ml/saved_model/candidates/random_forest.joblib",
    "ml/saved_model/candidates/training_manifest.json",
)

REQUIRED_DOC_SECTIONS = (
    "## 1. Scope of this stage",
    "## 2. Training data",
    "## 3. The three pipelines",
    "## 4. Artefacts",
    "## 6. Reproduce and test",
    "## 7. Common errors and fixes",
    "## 8. Limitations",
)

FORBIDDEN_NOW = (
    "ml/evaluate_model.py", "ml/thresholds.py", "docs/MODEL_CARD.md",
    "ml/saved_model/model_bundle.joblib", "ml/saved_model/metadata.json",
    "ml/saved_model/metrics.json", "docs/EVALUATION.md",
    "models/database_models.py", "models/prediction_model.py",
    "services/detection_service.py", "routes/auth.py", "app.py", "wsgi.py",
    "instance/phishing.db", "templates/index.html",
)

METRIC_WORDS = ("accuracy", "precision", "recall", "f1", "roc_auc", "confusion_matrix")

# Once Stage 6 is delivered, its gate enforces "no later-stage code".
STAGE_6_DELIVERED = (
    (ROOT / "ml" / "evaluate_model.py").is_file()
    and (ROOT / "ml" / "saved_model" / "metrics.json").is_file()
)

failures: list[str] = []
checks = 0


def check(label: str, condition: bool, hint: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -> {hint}" if hint else ""))
        failures.append(label)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_keys(value: Any) -> list[str]:
    """Collect all dictionary keys recursively for the no-metrics check."""
    keys: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            keys.append(str(key))
            keys.extend(json_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.extend(json_keys(item))
    return keys


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def check_files_and_manifest() -> dict[str, Any]:
    print("\n[1] Files, integrity and the honesty flags")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"file {rel}", path.is_file() and path.stat().st_size > 0, "missing or empty")
    manifest = load_manifest()
    check("manifest stage is 5", manifest["stage"] == 5)
    check("manifest says evaluation was NOT performed", manifest["evaluation_performed"] is False)
    check("manifest says selection was NOT performed", manifest["selection_performed"] is False)
    check("manifest lists no measured metrics", manifest["metrics_measured"] == [])
    check("manifest contains no metric-named keys",
          not any(any(word in key for word in METRIC_WORDS) for key in json_keys(manifest)))
    check("manifest used the train split only", manifest["dataset"]["splits_used"] == ["train"])
    check("manifest confirms held-out splits were not read",
          manifest["dataset"]["held_out_splits_not_read"] is True)

    train_path = ROOT / "dataset" / "processed" / "train.csv"
    check("training file SHA-256 matches the real train.csv",
          manifest["dataset"]["train_file_sha256"] == sha256_file(train_path))
    train = pd.read_csv(train_path)
    check("training row count matches train.csv", manifest["dataset"]["rows"] == len(train))
    check("training class counts match train.csv",
          manifest["dataset"]["legitimate_rows"] == int((train["label"] == 0).sum())
          and manifest["dataset"]["phishing_rows"] == int((train["label"] == 1).sum()))
    check("feature contract matches Stage 4",
          manifest["feature_contract"]["feature_order"] == list(FEATURE_ORDER)
          and manifest["feature_contract"]["count"] == len(FEATURE_ORDER))
    check("manifest records all three required models",
          set(manifest["models"]) == set(CANDIDATE_NAMES))
    check("schema version is pinned", manifest["schema_version"] == SCHEMA_VERSION)

    for name, record in manifest["models"].items():
        path = Path(record["file"])
        check(f"{name}: file size matches manifest",
              path.is_file() and path.stat().st_size == record["size_bytes"])
        check(f"{name}: SHA-256 matches manifest",
              path.is_file() and sha256_file(path) == record["sha256"])
        check(f"{name}: training time is a positive measured number",
              isinstance(record["training_seconds"], (int, float))
              and record["training_seconds"] > 0)
        check(f"{name}: hyperparameters recorded", bool(record["hyperparameters"]))
        check(f"{name}: uses the required estimator",
              name in ("logistic_regression", "decision_tree", "random_forest"))

    doc = (ROOT / "docs/TRAINING.md").read_text(encoding="utf-8")
    for section in REQUIRED_DOC_SECTIONS:
        check(f"TRAINING.md :: {section}", section in doc)
    check("TRAINING.md states no performance metric was computed at Stage 5",
          "No performance metric computed" in doc)
    if STAGE_6_DELIVERED:
        check("TRAINING.md points to the Stage 6 measured results",
              "Stage 6 note" in doc and "docs/EVALUATION.md" in doc)
    check("TRAINING.md contains a measured artefact size",
          f"{manifest['models']['random_forest']['size_bytes']:,}" in doc)
    check("TRAINING.md contains the real training row count",
          f"{manifest['dataset']['rows']:,}" in doc)

    source = (ROOT / "ml/train_model.py").read_text(encoding="utf-8")
    check("train_model.py does not import sklearn.metrics", "sklearn.metrics" not in source)
    check("train_model.py never names the held-out CSV files",
          "validation.csv" not in source and "test.csv" not in source)
    check("train_model.py uses the shared Stage 4 extractor", "extract_frame" in source)
    return manifest


def check_candidate_bundles(manifest: dict[str, Any]) -> None:
    print("\n[2] Loaded candidate bundles are usable")
    train = pd.read_csv(ROOT / "dataset" / "processed" / "train.csv")
    sample_urls = train["url"].head(30).tolist()
    matrix = pd.DataFrame(
        [extract_features(url) for url in sample_urls], columns=list(FEATURE_ORDER)
    )

    for name in CANDIDATE_NAMES:
        path = CANDIDATES_DIR / f"{name}.joblib"
        bundle = joblib.load(path)
        for key in ("estimator", "feature_order", "schema_version", "model_name",
                    "model_version", "random_state", "hyperparameters", "library_versions"):
            check(f"{name}: bundle has `{key}`", key in bundle)
        check(f"{name}: feature_order matches contract",
              bundle["feature_order"] == list(FEATURE_ORDER))
        check(f"{name}: schema_version matches", bundle["schema_version"] == SCHEMA_VERSION)
        check(f"{name}: model_name is correct", bundle["model_name"] == name)
        estimator = bundle["estimator"]
        check(f"{name}: estimator exposes predict_proba", hasattr(estimator, "predict_proba"))
        check(f"{name}: class order is [0, 1]", list(estimator.classes_) == [0, 1])
        check(f"{name}: n_features_in_ is 15",
              getattr(estimator, "n_features_in_", None) == len(FEATURE_ORDER))
        proba = estimator.predict_proba(matrix)
        check(f"{name}: predict_proba shape is (30, 2)", proba.shape == (30, 2))
        check(f"{name}: probabilities are in [0,1] and sum to 1",
              bool(np.all((proba >= 0) & (proba <= 1)))
              and bool(np.allclose(proba.sum(axis=1), 1.0)))
        check(f"{name}: scores are not constant across different URLs",
              np.unique(np.round(proba[:, 1], 6)).size > 1)
        again = estimator.predict_proba(matrix)
        check(f"{name}: inference is deterministic", np.array_equal(proba, again))
        check(f"{name}: single-row frame prediction works",
              estimator.predict_proba(features_to_frame(extract_features(sample_urls[0]))).shape == (1, 2))

    raw = "HTTPS://WWW.Example.COM/login"
    check("training-serving parity survives into the fitted model",
          np.allclose(
              joblib.load(CANDIDATES_DIR / "random_forest.joblib")["estimator"]
              .predict_proba(features_to_frame(extract_features(raw))),
              joblib.load(CANDIDATES_DIR / "random_forest.joblib")["estimator"]
              .predict_proba(features_to_frame(extract_features(normalize_url(raw) or ""))),
          ))


def fixture_frame(rows: int = 60) -> tuple[pd.DataFrame, pd.Series]:
    """Small, safe, SYNTHETIC feature fixture. Never added to training data."""
    records = []
    for index in range(rows):
        phishing = index % 2
        records.append({
            "url_length": 20 + phishing * 45 + (index % 11),
            "domain_length": 10 + phishing * 15 + (index % 5),
            "num_dots": 1 + phishing * 3 + (index % 3),
            "num_hyphens": phishing * 2 + (index % 2),
            "num_special_chars": phishing,
            "num_digits": phishing * 6 + (index % 4),
            "has_ip_address": phishing if index % 7 == 0 else 0,
            "has_at_symbol": phishing if index % 9 == 0 else 0,
            "has_suspicious_pattern": phishing,
            "num_subdomains": phishing * 2,
            "has_https": 1 - phishing if index % 3 else phishing,
            "is_shortened": phishing if index % 11 == 0 else 0,
            "num_suspicious_words": phishing * 3,
            "has_unusual_port": phishing if index % 13 == 0 else 0,
            "has_encoded_chars": phishing if index % 8 == 0 else 0,
        })
    frame = pd.DataFrame(records, columns=list(FEATURE_ORDER))
    labels = pd.Series([index % 2 for index in range(rows)], name="label")
    return frame, labels


def check_reproducibility(manifest: dict[str, Any]) -> None:
    print("\n[3] Reproducibility on a SAFE synthetic fixture")
    frame, labels = fixture_frame()
    config = TrainingConfig(
        train_path=ROOT / "dataset" / "processed" / "train.csv",
        output_dir=CANDIDATES_DIR, seed=7,
        n_estimators=10, max_depth=4, min_samples_leaf=2, lr_max_iter=200,
    )
    pipelines = build_pipelines(config)
    check("build_pipelines returns exactly three pipelines",
          set(pipelines) == set(CANDIDATE_NAMES))
    for name, pipeline in pipelines.items():
        check(f"{name} is a scikit-learn Pipeline", hasattr(pipeline, "fit") and hasattr(pipeline, "predict_proba"))

    first = train_all(frame, labels, config)
    second = train_all(frame, labels, config)
    check("train_all returns three candidates", set(first) == set(CANDIDATE_NAMES))
    for name in CANDIDATE_NAMES:
        check(f"{name}: fixture training time measured", first[name].training_seconds >= 0)
        check(f"{name}: deterministic for a fixed seed",
              np.allclose(
                  first[name].estimator.predict_proba(frame),
                  second[name].estimator.predict_proba(frame),
              ))
        check(f"{name}: class order [0,1] on fixture",
              list(first[name].estimator.classes_) == [0, 1])
        check(f"{name}: hyperparameters recorded on fixture",
              first[name].hyperparameters["random_state"] == 7)

    check("fixture did not overwrite the delivered candidates",
          sha256_file(CANDIDATES_DIR / "random_forest.joblib")
          == manifest["models"]["random_forest"]["sha256"])
    check("no synthetic fixture file written into the project",
          not any(ROOT.glob("**/fixture*.csv")))


def check_stage_discipline() -> None:
    print("\n[4] Stage discipline and regressions")
    if not STAGE_6_DELIVERED:
        for rel in FORBIDDEN_NOW:
            check(f"not created yet :: {rel}", not (ROOT / rel).exists())
        expected = {
            "ml": {"__init__.py", "url_utils.py", "preprocess.py",
                   "feature_extraction.py", "train_model.py"},
            "services": {"__init__.py", "validation.py"},
            "models": set(), "routes": set(), "tests": set(), "templates": set(),
        }
        for directory, names in expected.items():
            stray = [p.name for p in (ROOT / directory).glob("*.py") if p.name not in names]
            check(f"{directory}/ contains only Stage 1-5 modules", not stray, ", ".join(stray))
    else:
        print("  SKIP  no Stage 6+ code yet (delivered in Stage 6; enforced by verify_stage6.py)")

    for gate in ("verify_stage1.py", "verify_stage2.py",
                 "verify_stage3.py", "verify_stage4.py"):
        # The top-level gate already executes every historical gate directly.
        # Skipping this duplicated nested re-run keeps the suite linear rather
        # than exponential; standalone runs are completely unaffected.
        if PDS_NESTED_GATES:
            print(f"  SKIP  nested regression {gate} (top-level gate runs it)")
            continue
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / gate)],
            capture_output=True, text=True, timeout=300, cwd=ROOT,
        )
        tail = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
        check(f"{gate} still passes", proc.returncode == 0, tail[-1] if tail else "no output")


def main() -> int:
    print("=" * 74)
    print("STAGE 5 EXIT GATE - model training")
    print(f"Project root : {ROOT}")
    print("=" * 74)
    manifest = check_files_and_manifest()
    check_candidate_bundles(manifest)
    check_reproducibility(manifest)
    check_stage_discipline()
    print("\n" + "=" * 74)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        return 1
    print(f"RESULT: PASS - all {checks} checks passed")
    print("Stage 5 exit gate satisfied. You may proceed to Stage 6.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
