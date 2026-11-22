#!/usr/bin/env python3
"""Stage 6 exit gate: measured metrics, selection, thresholds and artefacts.

    cd phishing-detection-system
    python scripts/verify_stage6.py

The core of this gate is an INDEPENDENT recomputation: it reloads the saved
model and the split CSVs, recomputes accuracy, precision, recall, F1, ROC-AUC,
confusion matrices and the abstention band with its own code, and fails if any
published number disagrees. No performance figure can therefore be hand-typed.
"""
from __future__ import annotations

import hashlib
import json
import math
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
import sklearn  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score, confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score,
)

from ml.feature_extraction import FEATURE_ORDER, extract_frame  # noqa: E402
from ml.thresholds import (  # noqa: E402
    DECISION_STATES, SCORE_MEANING, STATE_ABSTAIN, STATE_LEGITIMATE,
    STATE_PHISHING, ThresholdConfig, decision_codes, evaluate_band,
    grid_search_thresholds,
)
from ml.train_model import CANDIDATE_NAMES, SCHEMA_VERSION  # noqa: E402

SAVED = ROOT / "ml" / "saved_model"
CANDIDATES = SAVED / "candidates"
PROCESSED = ROOT / "dataset" / "processed"

REQUIRED_FILES = (
    "ml/thresholds.py", "ml/evaluate_model.py",
    "ml/saved_model/model_bundle.joblib",
    "ml/saved_model/metadata.json", "ml/saved_model/metrics.json",
    "docs/MODEL_CARD.md", "docs/EVALUATION.md",
    "scripts/verify_stage6.py",
)

CARD_SECTIONS = (
    "## 1. Model details", "## 2. Measured performance",
    "## 3. Decision states", "## 4. Threshold selection",
    "## 5. Feature importance", "## 6. Limitations",
)
EVAL_SECTIONS = (
    "## 1. Evaluation protocol", "## 2. Measured per-model comparison",
    "## 3. Thresholds", "## 4. Selected model — validation results",
    "## 5. Selected model — FINAL held-out test results",
    "## 6. Feature importance", "### 6.1 Measured dataset bias",
    "### 6.2 The abstention trade-off", "## 7. Reproduce", "## 8. Limitations",
)

# Once Stage 7 is delivered, its own gate enforces "no later-stage code" and
# this historical gate stops asserting the absence of Stage 7 files.
STAGE_7_DELIVERED = (
    (ROOT / "app.py").is_file()
    and (ROOT / "wsgi.py").is_file()
    and (ROOT / "scripts" / "verify_stage7.py").is_file()
)

FORBIDDEN_NOW = (
    "app.py", "wsgi.py", "routes/__init__.py", "routes/auth.py",
    "models/database_models.py", "models/prediction_model.py",
    "services/detection_service.py", "templates/index.html",
    "instance/phishing.db", "docs/SECURITY.md",
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


def close(left: Any, right: Any, tolerance: float = 2e-6) -> bool:
    return math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=tolerance)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def independent_metrics(y: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    """Independent implementation of the binary metrics (not ml.evaluate_model's)."""
    predicted = (scores >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, predicted)),
        "precision": float(precision_score(y, predicted, zero_division=0)),
        "recall": float(recall_score(y, predicted, zero_division=0)),
        "f1": float(f1_score(y, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def independent_band(y: np.ndarray, scores: np.ndarray,
                     low: float, high: float) -> dict[str, Any]:
    """Independent implementation of the abstention-band metrics."""
    codes = decision_codes(scores, low, high)
    decisive = codes != STATE_ABSTAIN
    truth = y[decisive]
    predicted = codes[decisive].astype(int)
    tn = int(((predicted == 0) & (truth == 0)).sum())
    fp = int(((predicted == 1) & (truth == 0)).sum())
    fn = int(((predicted == 0) & (truth == 1)).sum())
    tp = int(((predicted == 1) & (truth == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    decisive_count = int(decisive.sum())
    return {
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": (tp + tn) / decisive_count if decisive_count else 0.0,
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "decisive_count": decisive_count,
        "abstained_count": int((~decisive).sum()),
        "abstention_rate": float(1 - decisive.mean()),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "state_counts": {
            "LEGITIMATE": int((codes == STATE_LEGITIMATE).sum()),
            "SUSPICIOUS": int((codes == STATE_ABSTAIN).sum()),
            "PHISHING": int((codes == STATE_PHISHING).sum()),
        },
    }


def split_data(name: str) -> tuple[pd.DataFrame, np.ndarray]:
    frame = pd.read_csv(PROCESSED / f"{name}.csv")
    features = extract_frame(frame["url"].tolist())
    return features, frame["label"].to_numpy(dtype=int)


def check_files_and_contract() -> tuple[dict[str, Any], dict[str, Any]]:
    print("\n[1] Files, metadata contract and exact UI strings")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"file {rel}", path.is_file() and path.stat().st_size > 0, "missing or empty")
    metadata = load_json(SAVED / "metadata.json")
    metrics = load_json(SAVED / "metrics.json")

    for key in ("stage", "schema_version", "model_version", "model_name", "estimator_class",
                "feature_order", "thresholds", "threshold_selection", "score_meaning",
                "decision_states", "model_bundle_sha256", "dataset", "library_versions",
                "limitations"):
        check(f"metadata has `{key}`", key in metadata)
    check("metadata stage is 6", metadata["stage"] == 6)
    check("metadata schema version matches", metadata["schema_version"] == SCHEMA_VERSION)
    check("metadata feature_order matches Stage 4", metadata["feature_order"] == list(FEATURE_ORDER))
    check("metadata class labels are 0=legit / 1=phishing",
          metadata["class_labels"] == {"0": "legitimate", "1": "phishing"})
    check("model_bundle SHA-256 matches file",
          metadata["model_bundle_sha256"] == sha256_file(SAVED / "model_bundle.joblib"))
    check("metadata library versions match installed versions",
          metadata["library_versions"]["sklearn"] == sklearn.__version__)

    low, high = metadata["thresholds"]["low"], metadata["thresholds"]["high"]
    check("T_low < T_high", 0 <= low < high <= 1, f"{low} / {high}")
    check("band gap >= documented minimum",
          high - low >= metadata["threshold_selection"]["constraints"]["min_band_gap"] - 1e-9)
    check("provisional defaults were replaced, not reused as measured values",
          metadata["thresholds"]["provisional_defaults_replaced"] == {"low": 0.30, "high": 0.70})
    check("criterion is documented", "recall" in metadata["threshold_selection"]["criterion"].lower()
          and "F1" in metadata["threshold_selection"]["criterion"])
    check("score wording rejects calibrated-probability claim",
          "not a calibrated probability" in SCORE_MEANING and "not a guarantee" in SCORE_MEANING)
    check("metadata stores the same score wording", metadata["score_meaning"] == SCORE_MEANING)

    states = metadata["decision_states"]
    check("three decision states present", set(states) == {"LEGITIMATE", "PHISHING", "SUSPICIOUS"})
    expected_messages = {
        "LEGITIMATE": "No phishing indicators detected by this model.",
        "PHISHING": "Potential phishing website detected.",
        "SUSPICIOUS": "This website requires further investigation.",
    }
    for name, message in expected_messages.items():
        check(f"{name} message is exact", states[name]["message"] == message)
    check("state colours are green / red / orange",
          states["LEGITIMATE"]["colour"] == "green"
          and states["PHISHING"]["colour"] == "red"
          and states["SUSPICIOUS"]["colour"] == "orange")
    check("risk levels are LOW / HIGH / MEDIUM",
          [states[n]["risk_level"] for n in ("LEGITIMATE", "PHISHING", "SUSPICIOUS")]
          == ["LOW", "HIGH", "MEDIUM"])
    check("LEGITIMATE warning denies a safety guarantee",
          "not a guarantee" in states["LEGITIMATE"]["warning"].lower())
    check("PHISHING warning forbids credentials",
          "passwords" in states["PHISHING"]["warning"].lower())
    check("SUSPICIOUS warning explains abstention",
          "abstaining" in states["SUSPICIOUS"]["warning"].lower())

    for name in ("validation", "test"):
        actual = sha256_file(PROCESSED / f"{name}.csv")
        check(f"{name} split hash matches metadata",
              metadata["dataset"][f"{name}_sha256"] == actual)
    check("train split hash matches Stage 5 manifest",
          metadata["dataset"]["train_sha256"]
          == load_json(CANDIDATES / "training_manifest.json")["dataset"]["train_file_sha256"])
    for name in ("train", "validation", "test"):
        actual_rows = len(pd.read_csv(PROCESSED / f"{name}.csv"))
        check(f"{name} split size matches its CSV",
              metadata["dataset"]["split_sizes"][name] == actual_rows)
    check("limitations disclose the measured HTTPS bias",
          any("MEASURED CONFIRMATION" in item for item in metadata["limitations"]))
    check("limitations recommend an ablation study",
          any("ablation" in item.lower() for item in metadata["limitations"]))
    return metadata, metrics


def check_recomputed_metrics(metadata: dict[str, Any], metrics: dict[str, Any]) -> None:
    print("\n[2] INDEPENDENT recomputation of every published number")
    bundle = joblib.load(SAVED / "model_bundle.joblib")
    for key in ("estimator", "feature_order", "schema_version", "model_name", "model_version"):
        check(f"final bundle has `{key}`", key in bundle)
    check("final bundle feature_order matches contract", bundle["feature_order"] == list(FEATURE_ORDER))
    check("final bundle schema matches", bundle["schema_version"] == SCHEMA_VERSION)
    estimator = bundle["estimator"]
    check("final estimator exposes predict_proba", hasattr(estimator, "predict_proba"))
    check("final estimator class order is [0, 1]", list(estimator.classes_) == [0, 1])
    check("final model name matches metadata", bundle["model_name"] == metadata["model_name"])
    check("final model version matches metadata", bundle["model_version"] == metadata["model_version"])

    low, high = metadata["thresholds"]["low"], metadata["thresholds"]["high"]
    validation_features, validation_y = split_data("validation")
    test_features, test_y = split_data("test")
    validation_scores = estimator.predict_proba(validation_features)[:, 1]
    test_scores = estimator.predict_proba(test_features)[:, 1]

    for split_name, y, scores, standard_key in (
        ("validation", validation_y, validation_scores, "validation"),
        ("test", test_y, test_scores, "test"),
    ):
        measured = independent_metrics(y, scores)
        published = metrics[standard_key]["standard_0.5"]
        for metric in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            check(f"{split_name} {metric} matches recomputation",
                  close(measured[metric], published[metric]),
                  f"{published[metric]} vs {measured[metric]:.6f}")
        check(f"{split_name} confusion matrix matches recomputation",
              measured["confusion_matrix"] == published["confusion_matrix"])
        check(f"{split_name} TN/FP/FN/TP match recomputation",
              all(measured[key] == published[key] for key in ("tn", "fp", "fn", "tp")))
        check(f"{split_name} confusion matrix sums to split size",
              sum(sum(row) for row in published["confusion_matrix"]) == len(y))

        band = independent_band(y, scores, low, high)
        published_band = metrics[standard_key]["calibrated"]
        for metric in ("accuracy", "precision", "recall", "f1", "abstention_rate"):
            check(f"{split_name} calibrated {metric} matches recomputation",
                  close(band[metric], published_band[metric]),
                  f"{published_band[metric]} vs {band[metric]:.6f}")
        check(f"{split_name} calibrated confusion matrix matches",
              band["confusion_matrix"] == published_band["confusion_matrix"])
        check(f"{split_name} decisive + abstained = split size",
              band["decisive_count"] + band["abstained_count"] == len(y))
        check(f"{split_name} state counts match recomputation",
              band["state_counts"] == published_band["state_counts"])

    check("metadata validation abstention rate matches recomputation",
          close(metadata["threshold_selection"]["abstention_rate"],
                metrics["validation"]["calibrated"]["abstention_rate"]))
    check("metadata validation recall matches recomputation",
          close(metadata["threshold_selection"]["recall"],
                metrics["validation"]["calibrated"]["recall"]))
    check("test state counts duplicated field matches calibrated",
          metrics["test"]["state_counts"] == metrics["test"]["calibrated"]["state_counts"])
    check("test split was scored once after selection",
          metrics["test"]["scored_once"] is True
          and metrics["honesty"]["test_split_read_before_selection"] is False)
    check("honesty flag: no hardcoded values", metrics["honesty"]["hardcoded_values"] is False)

    constraints = metadata["threshold_selection"]["constraints"]
    check("chosen validation recall satisfies the documented floor",
          metrics["validation"]["calibrated"]["recall"] >= constraints["recall_min"] - 1e-9)
    check("chosen validation abstention is within the documented cap",
          metrics["validation"]["calibrated"]["abstention_rate"]
          <= constraints["max_abstention_rate"] + 1e-9)
    check("feasible pairs <= total grid pairs",
          0 < metadata["threshold_selection"]["feasible_pairs"]
          <= metadata["threshold_selection"]["total_pairs"])

    print("    ... recomputing per-model validation metrics")
    for name in CANDIDATE_NAMES:
        candidate = joblib.load(CANDIDATES / f"{name}.joblib")
        scores = candidate["estimator"].predict_proba(validation_features)[:, 1]
        measured = independent_metrics(validation_y, scores)
        published = metrics["per_model"][name]["validation"]
        for metric in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            check(f"{name} validation {metric} matches recomputation",
                  close(measured[metric], published[metric]),
                  f"{published[metric]} vs {measured[metric]:.6f}")
        check(f"{name} confusion matrix matches",
              measured["confusion_matrix"] == published["confusion_matrix"])
        report = metrics["per_model"][name]
        check(f"{name} has a measured calibration", report["calibration"] is not None)
        check(f"{name} feasible pair count is sane",
              0 < report["feasible_pairs"] <= report["total_pairs"])
        for metric in ("f1", "recall", "abstention_rate", "fn"):
            check(f"{name} calibration {metric} present", metric in report["calibration"])

    # Independent re-derivation of the documented selection objective.
    eligible = [(name, report) for name, report in metrics["per_model"].items() if report["feasible"]]
    ranked = sorted(eligible, key=lambda pair: (
        -pair[1]["calibration"]["f1"], pair[1]["calibration"]["fn"],
        pair[1]["calibration"]["abstention_rate"],
        -pair[1]["validation"]["roc_auc"], pair[0],
    ))
    check("selection ranking matches the documented objective",
          [name for name, _ in ranked] == [entry["model"] for entry in metrics["selection"]["ranking"]])
    check("selected model is the objective winner",
          metrics["selection"]["selected_model"] == ranked[0][0])
    check("selected model is one of the three required estimators",
          metrics["selection"]["selected_model"] in CANDIDATE_NAMES)
    check("all published metrics lie in [0, 1]",
          all(0 <= report["validation"][metric] <= 1
              for report in metrics["per_model"].values()
              for metric in ("accuracy", "precision", "recall", "f1", "roc_auc")))

    importance = metrics["feature_importance"]
    check("feature importance covers all 15 features",
          set(importance["features"]) == set(FEATURE_ORDER))
    check("feature importance rows are a validation subsample",
          0 < importance["rows"] <= metrics["dataset"]["validation"]["rows"])
    check("bias analysis is measured",
          metrics["bias_analysis"]["has_https_mean_roc_auc_decrease"]
          == importance["features"]["has_https"]["mean"])
    check("bias analysis records the HTTPS shortcut",
          "HTTPS" in metrics["bias_analysis"]["interpretation"]
          or "HTTPS" in " ".join(metadata["limitations"]))


def check_threshold_module() -> None:
    print("\n[3] Threshold calibration module (controlled fixtures)")
    config = ThresholdConfig()
    grid = config.grid()
    check("grid is non-empty and deterministic", len(grid) > 20 and grid == ThresholdConfig().grid())
    check("every grid pair respects the minimum gap",
          all(high - low >= config.min_band_gap - 1e-9 for low, high in grid))
    check("every grid pair is ordered", all(0 < low < high < 1 for low, high in grid))

    low, high = 0.30, 0.70
    scores = np.array([0.0, 0.29, 0.30, 0.50, 0.70, 0.71, 1.0])
    codes = decision_codes(scores, low, high)
    check("decision_codes maps low scores to LEGITIMATE",
          list(codes[:3]) == [STATE_LEGITIMATE] * 3)
    check("decision_codes maps the band to SUSPICIOUS", codes[3] == STATE_ABSTAIN)
    check("decision_codes maps high scores to PHISHING",
          list(codes[4:]) == [STATE_PHISHING] * 3)

    y = np.array([0, 0, 1, 1, 1, 0])
    fixture_scores = np.array([0.0, 0.1, 0.9, 0.95, 0.5, 0.8])
    band = evaluate_band(y, fixture_scores, 0.30, 0.70)
    check("evaluate_band counts decisive rows correctly", band["decisive_count"] == 5)
    check("evaluate_band counts abstained rows correctly", band["abstained_count"] == 1)
    check("evaluate_band confusion [[TN,FP],[FN,TP]] is exact",
          band["tp"] == 2 and band["tn"] == 2 and band["fp"] == 1 and band["fn"] == 0)
    check("evaluate_band recall is 1.0 on this fixture", close(band["recall"], 1.0))
    check("evaluate_band state counts sum to input size",
          sum(band["state_counts"].values()) == len(y))

    clean_y = np.array([0, 0, 0, 1, 1, 1, 1, 1])
    clean_scores = np.array([0.0, 0.05, 0.1, 0.9, 0.92, 0.95, 0.97, 0.99])
    result = grid_search_thresholds(clean_y, clean_scores, config)
    check("grid search returns a feasible band",
          0 < result.feasible_pairs <= result.total_pairs and 0 < result.t_low < result.t_high < 1)
    check("grid search satisfies the recall floor",
          result.metrics["recall"] >= config.recall_min - 1e-9)
    check("grid search respects the abstention cap",
          result.metrics["abstention_rate"] <= config.max_abstention_rate + 1e-9)
    try:
        grid_search_thresholds(np.ones(8, dtype=int), np.zeros(8), config)
        raised = False
    except RuntimeError:
        raised = True
    check("grid search fails loudly when no band is feasible", raised)


def check_docs(metadata: dict[str, Any], metrics: dict[str, Any]) -> None:
    print("\n[4] Generated documentation contains the measured values")
    card = (ROOT / "docs" / "MODEL_CARD.md").read_text(encoding="utf-8")
    evaluation = (ROOT / "docs" / "EVALUATION.md").read_text(encoding="utf-8")
    for section in CARD_SECTIONS:
        check(f"MODEL_CARD.md :: {section}", section in card)
    for section in EVAL_SECTIONS:
        check(f"EVALUATION.md :: {section}", section in evaluation)
    test = metrics["test"]["standard_0.5"]
    for value in (test["accuracy"], test["precision"], test["recall"], test["f1"], test["roc_auc"]):
        check(f"measured test value {value:.6f} appears in EVALUATION.md",
              f"{value:.6f}" in evaluation)
    check("measured test accuracy appears in MODEL_CARD.md",
          f"{test['accuracy']:.6f}" in card)
    check("thresholds appear in EVALUATION.md",
          str(metadata["thresholds"]["low"]) in evaluation
          and str(metadata["thresholds"]["high"]) in evaluation)
    check("abstention rate appears in MODEL_CARD.md",
          f"{metrics['test']['calibrated']['abstention_rate']:.2%}" in card)
    check("HTTPS bias is measured in EVALUATION.md",
          f"{metrics['bias_analysis']['has_https_mean_roc_auc_decrease']:+.6f}" in evaluation
          or f"{metrics['bias_analysis']['has_https_mean_roc_auc_decrease']:.6f}" in evaluation)
    check("both docs state HTTPS is not proof of legitimacy",
          "HTTPS alone does not mean a website is legitimate" in card
          and "HTTPS alone does not mean a website is legitimate" in evaluation)
    check("docs reject calibrated-probability wording",
          "not a calibrated probability" in card)
    check("EVALUATION.md states results are not universal web accuracy",
          "not universal web accuracy" in evaluation or "optimistic" in evaluation.lower())
    check("MODEL_CARD.md cites the dataset", "10.1016/j.cose.2023.103545" in card)


def check_stage_discipline() -> None:
    print("\n[5] Stage discipline and regressions")
    if not STAGE_7_DELIVERED:
        for rel in FORBIDDEN_NOW:
            check(f"not created yet :: {rel}", not (ROOT / rel).exists())
        expected = {
            "ml": {"__init__.py", "url_utils.py", "preprocess.py", "feature_extraction.py",
                   "train_model.py", "evaluate_model.py", "thresholds.py"},
            "services": {"__init__.py", "validation.py"},
            "models": set(), "routes": set(), "tests": set(), "templates": set(),
        }
        for directory, names in expected.items():
            stray = [p.name for p in (ROOT / directory).glob("*.py") if p.name not in names]
            check(f"{directory}/ contains only Stage 1-6 modules", not stray, ", ".join(stray))
    else:
        print("  SKIP  Stage 7 files now exist (enforced by verify_stage7.py)")
    for gate in ("verify_stage1.py", "verify_stage2.py", "verify_stage3.py",
                 "verify_stage4.py", "verify_stage5.py"):
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
    print("=" * 76)
    print("STAGE 6 EXIT GATE - evaluation, selection and threshold calibration")
    print(f"Project root : {ROOT}")
    print("=" * 76)
    metadata, metrics = check_files_and_contract()
    check_recomputed_metrics(metadata, metrics)
    check_threshold_module()
    check_docs(metadata, metrics)
    check_stage_discipline()
    print("\n" + "=" * 76)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        return 1
    print(f"RESULT: PASS - all {checks} checks passed")
    print("Stage 6 exit gate satisfied. You may proceed to Stage 7.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
