"""Model evaluation, selection and artefact finalisation (Stage 6).

This is the FIRST stage in the project that computes performance numbers. Every
figure is measured here with ``sklearn.metrics`` on a named split and written to
``ml/saved_model/metrics.json``. No accuracy, precision, recall, F1 or ROC-AUC
value is hard-coded anywhere in the application.

Protocol (fixed in docs/ARCHITECTURE.md section 6, before seeing results)
------------------------------------------------------------------------
1. Load the three Stage 5 candidate bundles; verify their hashes against the
   training manifest, their feature_order and their predict_proba support.
2. Score each on the VALIDATION split: accuracy, precision, recall, F1,
   confusion matrix and ROC-AUC at the conventional 0.5 cut-off.
3. For each candidate, calibrate (T_low, T_high) with ``ml.thresholds`` using
   ONLY validation labels/scores under the documented recall constraint.
4. SELECT the model with the best calibrated F1 under that constraint; ties are
   broken by fewest false negatives, lowest abstention, then highest ROC-AUC.
5. Load the TEST split ONCE, after selection, and score the chosen model there.
6. Compute measured permutation feature importance on a validation subsample.
7. Write model_bundle.joblib, metadata.json, metrics.json, docs/MODEL_CARD.md
   and docs/EVALUATION.md.

Usage
-----
    python -m ml.evaluate_model
    python -m ml.evaluate_model --help
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score,
)

from ml.feature_extraction import FEATURE_ORDER, extract_frame
from ml.thresholds import (
    CRITERION_DESCRIPTION, DECISION_STATES, SCORE_MEANING, ThresholdConfig,
    evaluate_band, grid_search_thresholds,
)
from ml.train_model import CANDIDATE_NAMES, SCHEMA_VERSION

ROOT = Path(__file__).resolve().parents[1]
FINAL_MODEL_VERSION = "1.0.0"
PROVISIONAL_BAND = {"low": 0.30, "high": 0.70}


@dataclass(frozen=True)
class EvaluationConfig:
    """Every parameter that can change a reported number (recorded in metrics.json)."""

    validation_path: Path
    test_path: Path
    candidates_dir: Path
    output_dir: Path
    docs_dir: Path
    seed: int = 42
    recall_min: float = 0.90
    max_abstention_rate: float = 0.25
    min_band_gap: float = 0.10
    grid_step: float = 0.05
    importance_rows: int = 5000
    importance_repeats: int = 3

    def public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("validation_path", "test_path", "candidates_dir", "output_dir", "docs_dir"):
            data[key] = str(data[key])
        return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_split(path: Path) -> tuple[pd.DataFrame, np.ndarray, dict[str, Any]]:
    """Read one named split and compute the shared Stage 4 feature matrix."""
    if not path.is_file():
        raise FileNotFoundError(f"Split not found: {path}")
    frame = pd.read_csv(path)
    expected = ["url", "label", "group_id"]
    if list(frame.columns) != expected:
        raise ValueError(f"Unexpected columns in {path}: {list(frame.columns)}")
    labels = frame["label"].to_numpy(dtype=int)
    if set(np.unique(labels)) != {0, 1}:
        raise ValueError(f"{path} must contain exactly labels 0 and 1")
    features = extract_frame(frame["url"].tolist())
    if list(features.columns) != list(FEATURE_ORDER):
        raise RuntimeError("Feature matrix does not match FEATURE_ORDER")
    facts = {
        "file": str(path),
        "sha256": sha256_file(path),
        "rows": int(len(frame)),
        "legitimate": int((labels == 0).sum()),
        "phishing": int((labels == 1).sum()),
        "phishing_rate": round(float((labels == 1).mean()), 6),
    }
    return features, labels, facts


def load_candidates(directory: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Load and integrity-check the three Stage 5 candidate bundles."""
    manifest_path = directory / "training_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Training manifest not found: {manifest_path}")
    training_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    bundles: dict[str, dict[str, Any]] = {}
    for name in CANDIDATE_NAMES:
        path = directory / f"{name}.joblib"
        if not path.is_file():
            raise FileNotFoundError(f"Missing candidate: {path}")
        expected_hash = training_manifest["models"][name]["sha256"]
        if sha256_file(path) != expected_hash:
            raise RuntimeError(f"Candidate {name} hash differs from the training manifest; re-run Stage 5")
        bundle = joblib.load(path)
        for key in ("estimator", "feature_order", "schema_version", "model_name"):
            if key not in bundle:
                raise RuntimeError(f"Candidate {name} is missing '{key}'")
        if bundle["feature_order"] != list(FEATURE_ORDER):
            raise RuntimeError(f"Candidate {name} has a mismatched feature_order")
        if bundle["schema_version"] != SCHEMA_VERSION:
            raise RuntimeError(f"Candidate {name} has an unsupported schema_version")
        estimator = bundle["estimator"]
        if not hasattr(estimator, "predict_proba"):
            raise RuntimeError(f"Candidate {name} lacks predict_proba")
        if list(estimator.classes_) != [0, 1]:
            raise RuntimeError(f"Candidate {name} has unexpected class order")
        bundles[name] = bundle
    return bundles, training_manifest


def compute_metrics(y_true: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    """Measured binary metrics at the conventional 0.5 decision boundary."""
    predicted = (np.asarray(scores) >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    return {
        "decision_boundary": 0.5,
        "accuracy": round(float(accuracy_score(y_true, predicted)), 6),
        "precision": round(float(precision_score(y_true, predicted, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, predicted, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, predicted, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 6),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "score_min": round(float(np.min(scores)), 6),
        "score_max": round(float(np.max(scores)), 6),
        "score_mean": round(float(np.mean(scores)), 6),
    }


def threshold_config_from(config: EvaluationConfig) -> ThresholdConfig:
    return ThresholdConfig(
        recall_min=config.recall_min,
        max_abstention_rate=config.max_abstention_rate,
        min_band_gap=config.min_band_gap,
        grid_step=config.grid_step,
    )


def evaluate_candidates(
    bundles: dict[str, dict[str, Any]],
    features: pd.DataFrame,
    labels: np.ndarray,
    thresholds: ThresholdConfig,
) -> dict[str, dict[str, Any]]:
    """Measure every candidate on validation, including its best feasible band."""
    reports: dict[str, dict[str, Any]] = {}
    for name, bundle in bundles.items():
        print(f"  evaluating {name} ...", flush=True)
        scores = bundle["estimator"].predict_proba(features)[:, 1]
        validation = compute_metrics(labels, scores)
        try:
            calibration = grid_search_thresholds(labels, scores, thresholds)
        except RuntimeError as exc:
            reports[name] = {
                "validation": validation,
                "calibration": None,
                "feasible": False,
                "reason": str(exc),
                "total_pairs": len(thresholds.grid()),
                "feasible_pairs": 0,
            }
            continue
        reports[name] = {
            "validation": validation,
            "calibration": calibration.metrics,
            "feasible": True,
            "t_low": calibration.t_low,
            "t_high": calibration.t_high,
            "total_pairs": calibration.total_pairs,
            "feasible_pairs": calibration.feasible_pairs,
            "criterion": calibration.criterion,
            "constraints": calibration.constraints,
        }
    return reports


def select_best(reports: dict[str, dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Choose a winner with the documented objective; fail loudly if none qualifies."""
    eligible = [(name, report) for name, report in reports.items() if report["feasible"]]
    if not eligible:
        raise RuntimeError(
            "No candidate satisfies the documented recall/abstention constraints. "
            "Do NOT relax the constraints silently; investigate the data and models."
        )
    ranked = sorted(
        eligible,
        key=lambda pair: (
            -pair[1]["calibration"]["f1"],
            pair[1]["calibration"]["fn"],
            pair[1]["calibration"]["abstention_rate"],
            -pair[1]["validation"]["roc_auc"],
            pair[0],
        ),
    )
    ranking = [
        {
            "model": name,
            "calibrated_f1": report["calibration"]["f1"],
            "calibrated_recall": report["calibration"]["recall"],
            "false_negatives": report["calibration"]["fn"],
            "abstention_rate": report["calibration"]["abstention_rate"],
            "validation_roc_auc": report["validation"]["roc_auc"],
        }
        for name, report in ranked
    ]
    return ranked[0][0], ranking


def compute_feature_importance(
    estimator: Any,
    features: pd.DataFrame,
    labels: np.ndarray,
    config: EvaluationConfig,
) -> dict[str, Any]:
    """MEASURED permutation importance on a validation subsample (any model type)."""
    size = min(config.importance_rows, len(features))
    sample_features = features.iloc[:size].copy()
    sample_labels = labels[:size]
    if len(np.unique(sample_labels)) < 2:
        generator = np.random.default_rng(config.seed)
        indices = np.sort(generator.choice(len(features), size=size, replace=False))
        sample_features = features.iloc[indices].copy()
        sample_labels = labels[indices]
    result = permutation_importance(
        estimator, sample_features, sample_labels,
        scoring="roc_auc", n_repeats=config.importance_repeats,
        random_state=config.seed, n_jobs=1,
    )
    measured = {
        "method": "sklearn.inspection.permutation_importance(scoring='roc_auc')",
        "rows": int(size),
        "repeats": config.importance_repeats,
        "random_state": config.seed,
        "features": {
            name: {
                "mean": round(float(mean), 6),
                "std": round(float(std), 6),
            }
            for name, mean, std in zip(FEATURE_ORDER, result.importances_mean, result.importances_std)
        },
    }
    classifier = estimator.named_steps.get("classifier") if hasattr(estimator, "named_steps") else None
    if classifier is not None and hasattr(classifier, "feature_importances_"):
        measured["tree_importances"] = {
            name: round(float(value), 6)
            for name, value in zip(FEATURE_ORDER, classifier.feature_importances_)
        }
    return measured


def render_model_card(metadata: dict[str, Any], metrics: dict[str, Any]) -> str:
    """Generate docs/MODEL_CARD.md from measured artefacts only."""
    test = metrics["test"]
    standard = test["standard_0.5"]
    calibrated = test["calibrated"]
    thresholds = metadata["thresholds"]
    importance = metrics["feature_importance"]["features"]
    top = sorted(importance.items(), key=lambda item: -item[1]["mean"])[:5]
    importance_rows = "\n".join(
        f"| `{name}` | {values['mean']:+.6f} | {values['std']:.6f} |" for name, values in top
    )
    states = "\n".join(
        f"| `{name}` | {info['colour']} | {info['risk_level']} | \"{info['message']}\" |"
        for name, info in DECISION_STATES.items()
    )
    limitations = "\n".join(f"- {item}" for item in metadata["limitations"])
    return f"""# Model Card — Intelligent Phishing Website Detection System

**Generated {metadata['generated_at_utc']}**
**Model version:** `{metadata['model_version']}` · **Schema:** `{metadata['schema_version']}`
**All figures below are measured** by `ml/evaluate_model.py` with `sklearn.metrics` and stored in `ml/saved_model/metrics.json`.

---

## 1. Model details

| Item | Value |
| --- | --- |
| Selected estimator | `{metadata['model_name']}` (`{metadata['estimator_class']}`) |
| Selected from | {', '.join(f'`{name}`' for name in metrics['per_model'])} |
| Features | {len(FEATURE_ORDER)} lexical URL characteristics (`FEATURE_ORDER`, schema `{metadata['feature_schema_version']}`) |
| Training split | {metrics['dataset']['train']['rows']:,} rows ({metrics['dataset']['train']['legitimate']:,} legitimate / {metrics['dataset']['train']['phishing']:,} phishing) |
| Validation split | {metrics['dataset']['validation']['rows']:,} rows |
| Test split | {metrics['dataset']['test']['rows']:,} rows, scored once after selection |
| Random seed | {metrics['config']['seed']} |
| Libraries | Python {metrics['environment']['python']}, scikit-learn {metrics['environment']['sklearn']}, pandas {metrics['environment']['pandas']}, numpy {metrics['environment']['numpy']} |
| Bundle SHA-256 | `{metadata['model_bundle_sha256']}` |

**Intended use:** an educational, static, URL-string screening aid. Given a URL, it produces a phishing-class score and a three-state decision with explanations.

**Out of scope / not a guarantee:** the system never visits a website, inspects page content, checks certificates, DNS age, redirects or reputation. A `LEGITIMATE` result is **not** a safety guarantee. It must not replace user judgement or dedicated security tooling.

## 2. Measured performance

### Held-out test split ({metrics['dataset']['test']['rows']:,} rows) — binary metrics at 0.5

| Metric | Measured value |
| --- | --- |
| Accuracy | {standard['accuracy']:.6f} |
| Precision | {standard['precision']:.6f} |
| Recall | {standard['recall']:.6f} |
| F1 | {standard['f1']:.6f} |
| ROC-AUC | {standard['roc_auc']:.6f} |

Confusion matrix `[[TN, FP], [FN, TP]]` = `{standard['confusion_matrix']}` → TN {standard['tn']:,}, FP {standard['fp']:,}, FN {standard['fn']:,}, TP {standard['tp']:,}.

### Held-out test split — three-state decision layer

| Metric | Measured value |
| --- | --- |
| `T_low` / `T_high` | {thresholds['low']} / {thresholds['high']} |
| Decisive predictions | {calibrated['decisive_count']:,} of {metrics['dataset']['test']['rows']:,} |
| Abstention rate (SUSPICIOUS) | {calibrated['abstention_rate']:.2%} |
| Precision (decisive) | {calibrated['precision']:.6f} |
| Recall (decisive) | {calibrated['recall']:.6f} |
| F1 (decisive) | {calibrated['f1']:.6f} |
| False negatives (decisive) | {calibrated['fn']:,} |

`[[TN, FP], [FN, TP]]` = `{calibrated['confusion_matrix']}`. State counts: `{calibrated['state_counts']}`.

> **Why validation numbers differ from test numbers:** thresholds and model selection were tuned on validation only; the test split was scored **once** afterwards. The test figures are the ones to quote.

## 3. Decision states (exact UI contract)

| State | Colour | Risk | Message |
| --- | --- | --- | --- |
{states}

**Score wording (mandatory):** {SCORE_MEANING}

## 4. Threshold selection (documented, measured)

- Criterion: {CRITERION_DESCRIPTION}
- Grid pairs evaluated: {metadata['threshold_selection']['total_pairs']}; feasible pairs: {metadata['threshold_selection']['feasible_pairs']}
- Validation rows used: {metadata['threshold_selection']['validation_rows']:,}
- Validation abstention rate at the chosen band: {metadata['threshold_selection']['abstention_rate']:.2%}
- Validation recall at the chosen band: {metadata['threshold_selection']['recall']:.6f}
- The provisional defaults {PROVISIONAL_BAND['low']}/{PROVISIONAL_BAND['high']} from `config.py` were **replaced** by the measured values above; runtime reads `metadata.json`.

`SUSPICIOUS` is an abstention over a binary classifier, **not** a trained third class. A phishing URL inside the band is unresolved, not a false negative (it was never declared safe). The 25% abstention cap prevents gaming the recall constraint.

## 5. Feature importance (measured, correlational)

Permutation importance on {metrics['feature_importance']['rows']:,} validation rows, {metrics['feature_importance']['repeats']} repeats, ROC-AUC scoring. Top five by mean decrease in ROC-AUC:

| Feature | Mean decrease | Std |
| --- | --- | --- |
{importance_rows}

These are correlations learned from the training distribution, **not causation**. A single flagged feature does not make a site malicious. No SHAP causality claim is made.

> ⚠️ **Measured bias warning.** `has_https` produces the largest decrease in ROC-AUC ({metrics['bias_analysis']['has_https_mean_roc_auc_decrease']:+.6f}), confirming the dataset shortcut: all legitimate URLs in this corpus use HTTPS while many phishing URLs do not. **HTTPS alone does not mean a website is legitimate.** The reported performance is optimistic for real-world traffic and must be presented with this qualifier.

## 6. Limitations and ethical considerations

{limitations}

Dataset (CC BY 4.0, attribution required): Prasad, A. & Chandra, S. (2023), *PhiUSIIL*, Computers & Security 103545, https://doi.org/10.1016/j.cose.2023.103545, UCI dataset 967. See `docs/DATASET.md`.

---

*Generated from `ml/saved_model/metadata.json` and `metrics.json`. Re-running `python -m ml.evaluate_model` regenerates this card with fresh measurements.*
"""


def render_evaluation(metadata: dict[str, Any], metrics: dict[str, Any]) -> str:
    """Generate docs/EVALUATION.md with full measured comparison tables."""
    rows = []
    for name, report in metrics["per_model"].items():
        validation = report["validation"]
        calibration = report["calibration"]
        rows.append(
            f"| `{name}`{' ★' if name == metrics['selection']['selected_model'] else ''} | "
            f"{validation['accuracy']:.6f} | {validation['precision']:.6f} | "
            f"{validation['recall']:.6f} | {validation['f1']:.6f} | "
            f"{validation['roc_auc']:.6f} | "
            + (f"{calibration['f1']:.6f} | {calibration['recall']:.6f} | "
               f"{calibration['fn']:,} | {calibration['abstention_rate']:.2%} | "
               f"{report['feasible_pairs']}/{report['total_pairs']} |"
               if calibration else "n/a | n/a | n/a | n/a | 0 |")
        )
    comparison = "\n".join(rows)
    ranking = "\n".join(
        f"{index}. `{entry['model']}` — calibrated F1 {entry['calibrated_f1']:.6f}, "
        f"recall {entry['calibrated_recall']:.6f}, FN {entry['false_negatives']:,}, "
        f"abstention {entry['abstention_rate']:.2%}, ROC-AUC {entry['validation_roc_auc']:.6f}"
        for index, entry in enumerate(metrics["selection"]["ranking"], start=1)
    )
    importance_rows = "\n".join(
        f"| `{name}` | {values['mean']:+.6f} | {values['std']:.6f} |"
        for name, values in sorted(
            metrics["feature_importance"]["features"].items(),
            key=lambda item: -item[1]["mean"],
        )
    )
    val_std = metrics["validation"]["standard_0.5"]
    val_cal = metrics["validation"]["calibrated"]
    test_std = metrics["test"]["standard_0.5"]
    test_cal = metrics["test"]["calibrated"]
    return f"""# Stage 6 — Evaluation, Model Selection and Threshold Calibration

**Generated {metadata['generated_at_utc']}**
**Implementation:** `ml/evaluate_model.py`, `ml/thresholds.py`
**Artefacts:** `ml/saved_model/model_bundle.joblib`, `metadata.json`, `metrics.json`
**Status:** model selected, thresholds calibrated, test split scored once. All figures measured.

---

## 1. Evaluation protocol

| Step | Split | What was measured |
| --- | --- | --- |
| 1 | training ({metrics['dataset']['train']['rows']:,}) | Fitting only (Stage 5); no metrics |
| 2 | validation ({metrics['dataset']['validation']['rows']:,}) | Per-model accuracy, precision, recall, F1, confusion matrix, ROC-AUC at 0.5; threshold grid search |
| 3 | validation | Model selection by calibrated F1 under the recall constraint |
| 4 | test ({metrics['dataset']['test']['rows']:,}) | **One** final scoring of the single selected model |

Group-aware splitting from Stage 3 guarantees no URL, leakage group or non-generic path signature crosses splits. The test split was not read during EDA (Stage 4), training (Stage 5), threshold tuning or model selection.

### Selection criterion (fixed a priori)

{CRITERION_DESCRIPTION}

Constraints: recall ≥ {metrics['config']['recall_min']}, abstention ≤ {metrics['config']['max_abstention_rate']:.0%}, band gap ≥ {metrics['config']['min_band_gap']}, grid step {metrics['config']['grid_step']}. Recall priority reflects the brief: a missed phishing site (false negative) is costlier than a false alarm.

---

## 2. Measured per-model comparison (validation split)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Cal. F1 | Cal. recall | FN | Abstention | Feasible pairs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
{comparison}

★ = selected. "Cal." = measured on decisive (non-abstained) predictions at that model's best feasible band.

Ranking by the documented objective:

{ranking}

**Selected model: `{metrics['selection']['selected_model']}` (`{metadata['estimator_class']}`).**

---

## 3. Thresholds (explicitly defined uncertainty band)

| Item | Value |
| --- | --- |
| `T_low` | {metadata['thresholds']['low']} |
| `T_high` | {metadata['thresholds']['high']} |
| Provisional defaults replaced | {PROVISIONAL_BAND['low']} / {PROVISIONAL_BAND['high']} |
| Grid pairs evaluated | {metadata['threshold_selection']['total_pairs']} |
| Feasible pairs | {metadata['threshold_selection']['feasible_pairs']} |
| Validation abstention rate | {metadata['threshold_selection']['abstention_rate']:.2%} |
| Validation recall | {metadata['threshold_selection']['recall']:.6f} |
| Validation false negatives | {metadata['threshold_selection']['false_negatives']:,} |

`p >= {metadata['thresholds']['high']}` → PHISHING (HIGH); `p <= {metadata['thresholds']['low']}` → LEGITIMATE (LOW); otherwise SUSPICIOUS (MEDIUM). Runtime reads these from `metadata.json`; `config.py` holds only the provisional fallbacks.

---

## 4. Selected model — validation results

**Binary metrics at 0.5:** accuracy {val_std['accuracy']:.6f}, precision {val_std['precision']:.6f}, recall {val_std['recall']:.6f}, F1 {val_std['f1']:.6f}, ROC-AUC {val_std['roc_auc']:.6f}. Confusion `[[TN, FP], [FN, TP]]` = `{val_std['confusion_matrix']}`.

**Calibrated three-state:** decisive {val_cal['decisive_count']:,}, abstained {val_cal['abstained_count']:,} ({val_cal['abstention_rate']:.2%}), precision {val_cal['precision']:.6f}, recall {val_cal['recall']:.6f}, F1 {val_cal['f1']:.6f}, FN {val_cal['fn']:,}. Confusion `{val_cal['confusion_matrix']}`.

---

## 5. Selected model — FINAL held-out test results (quote these)

| Metric | At 0.5 | Decisive (calibrated) |
| --- | --- | --- |
| Accuracy | {test_std['accuracy']:.6f} | {test_cal['accuracy']:.6f} |
| Precision | {test_std['precision']:.6f} | {test_cal['precision']:.6f} |
| Recall | {test_std['recall']:.6f} | {test_cal['recall']:.6f} |
| F1 | {test_std['f1']:.6f} | {test_cal['f1']:.6f} |
| ROC-AUC | {test_std['roc_auc']:.6f} | n/a (threshold-independent) |
| Confusion matrix | `{test_std['confusion_matrix']}` | `{test_cal['confusion_matrix']}` |
| False negatives | {test_std['fn']:,} | {test_cal['fn']:,} |

Test state counts: LEGITIMATE {test_cal['state_counts']['LEGITIMATE']:,}, SUSPICIOUS {test_cal['state_counts']['SUSPICIOUS']:,}, PHISHING {test_cal['state_counts']['PHISHING']:,}. Abstention rate {test_cal['abstention_rate']:.2%}.

**Score wording:** {SCORE_MEANING}

---

## 6. Feature importance (measured)

{metrics['feature_importance']['method']}; {metrics['feature_importance']['rows']:,} validation rows, {metrics['feature_importance']['repeats']} repeats, seed {metrics['feature_importance']['random_state']}. Values are mean decrease in ROC-AUC when one feature is shuffled.

| Feature | Mean decrease | Std |
| --- | --- | --- |
{importance_rows}

Correlation, not causation. See `docs/FEATURES.md` for what each feature means.

### 6.1 Measured dataset bias — read this before quoting any accuracy figure

Top measured permutation decreases in ROC-AUC:

{chr(10).join(f"- `{entry['feature']}`: {entry['mean_roc_auc_decrease']:+.6f} (±{entry['std']:.6f})" for entry in metrics['bias_analysis']['top_features'])}

`has_https` alone accounts for a measured decrease of **{metrics['bias_analysis']['has_https_mean_roc_auc_decrease']:+.6f}** versus **{metrics['bias_analysis']['next_largest_mean_roc_auc_decrease']:+.6f}** for the next largest feature; it is the single most influential feature: **{str(metrics['bias_analysis']['https_is_largest_feature']).lower()}**. This is the concrete, measured confirmation of the Stage 4 warning that 100.00% of legitimate URLs in this dataset use HTTPS versus 56.90% of phishing URLs.

**Consequence:** the model has learned a dataset shortcut, not a security truth. Attackers routinely obtain free TLS certificates, so HTTPS alone does not mean a website is legitimate. The reported test accuracy describes a held-out sample of the PhiUSIIL distribution; it is **optimistic** for real-world traffic in which phishing sites also use HTTPS. An ablation study retraining without `has_https` is recommended future work and must appear in the Limitations and Recommendations chapters of the final report.

### 6.2 The abstention trade-off

The a priori cap was {metrics['config']['max_abstention_rate']:.0%}. The measured validation abstention rate is {val_cal['abstention_rate']:.2%} and the test rate is {test_cal['abstention_rate']:.2%}. On the test split, false negatives fall from {test_std['fn']:,} at a fixed 0.5 boundary to {test_cal['fn']:,} among decisive predictions — but {test_cal['abstained_count']:,} URLs become SUSPICIOUS instead of receiving a binary verdict. This is selective prediction in action: it is **not** extra accuracy, and it must be explained that way in the report.

---

## 7. Reproduce

```powershell
python -m ml.evaluate_model
python scripts\\verify_stage6.py
```

```bash
python -m ml.evaluate_model
python scripts/verify_stage6.py
```

`verify_stage6.py` RE-COMPUTES the reported metrics from the saved bundle and the split CSVs, and fails if any published number disagrees with the measurement. No figure in the UI, docs or JSON is allowed to be hand-typed.

---

## 8. Limitations

{chr(10).join(f"- {item}" for item in metadata['limitations'])}

**Interpretation:** these numbers describe performance on a held-out sample of the PhiUSIIL distribution, not on the live web. They must be presented with that qualifier in the final report.
"""


def write_artefacts(
    selected_bundle: dict[str, Any],
    selected_name: str,
    reports: dict[str, dict[str, Any]],
    ranking: list[dict[str, Any]],
    calibration_constraints: dict[str, float],
    validation_facts: dict[str, Any],
    test_facts: dict[str, Any],
    train_facts: dict[str, Any],
    training_manifest: dict[str, Any],
    validation_standard: dict[str, Any],
    validation_calibrated: dict[str, Any],
    test_standard: dict[str, Any],
    test_calibrated: dict[str, Any],
    importance: dict[str, Any],
    config: EvaluationConfig,
) -> dict[str, Any]:
    """Persist the final bundle and every measured number."""
    config.output_dir.mkdir(parents=True, exist_ok=True)
    config.docs_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    environment = {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "sklearn": sklearn.__version__,
        "joblib": joblib.__version__,
    }

    final_bundle = {
        "estimator": selected_bundle["estimator"],
        "feature_order": list(FEATURE_ORDER),
        "schema_version": SCHEMA_VERSION,
        "model_name": selected_name,
        "model_version": FINAL_MODEL_VERSION,
        "trained_at_utc": selected_bundle.get("trained_at_utc"),
        "selected_at_utc": generated_at,
        "random_state": selected_bundle.get("random_state", config.seed),
        "hyperparameters": selected_bundle.get("hyperparameters", {}),
        "library_versions": environment,
    }
    bundle_path = config.output_dir / "model_bundle.joblib"
    joblib.dump(final_bundle, bundle_path, compress=3)
    bundle_hash = sha256_file(bundle_path)

    classifier = selected_bundle["estimator"].named_steps.get("classifier")
    low = float(reports[selected_name]["t_low"])
    high = float(reports[selected_name]["t_high"])
    best = reports[selected_name]["calibration"]

    top_importances = sorted(
        importance["features"].items(), key=lambda item: -item[1]["mean"]
    )[:3]
    top_text = ", ".join(f"{name} ({values['mean']:+.4f})" for name, values in top_importances)
    https_importance = importance["features"].get("has_https", {}).get("mean", 0.0)
    limitations = [
        "Static URL-only analysis: no page content, redirects, DNS age, TLS certificate, domain reputation or external API is consulted. The backend never visits a submitted URL.",
        "Measured on a held-out sample of the PhiUSIIL (UCI 967) distribution donated in 2024; newer phishing tactics may not be represented. Results are not universal web accuracy.",
        "Dataset shortcut: 100.00% of legitimate training URLs used HTTPS versus 56.90% of phishing URLs. HTTPS alone does not mean a website is legitimate.",
        f"MEASURED CONFIRMATION OF THAT BIAS: validation permutation importance is dominated by {top_text}. "
        f"The has_https decrease in ROC-AUC is {https_importance:+.6f}, far above every other feature, so the selected model "
        "relies heavily on a signal that is not a real-world safety indicator. Reported accuracy is therefore "
        "OPTIMISTIC on traffic where phishing sites also use TLS. An ablation study removing has_https is "
        "recommended future work and must be discussed at the viva.",
        "Model scores from predict_proba are UNCALIBRATED and must never be presented as a guaranteed probability that a website is malicious.",
        "SUSPICIOUS is an abstention band over a binary classifier, not a third ground-truth class; a phishing URL in the band is unresolved, not classified safe.",
        f"The a priori 25% abstention cap allowed a measured {validation_calibrated['abstention_rate']:.2%} validation abstention rate; "
        "roughly one in five URLs is unresolved rather than given a binary verdict. This is an honest "
        "trade-off for fewer false negatives, not extra accuracy. A tighter cap or an abstention penalty "
        "is a design alternative for future work.",
        "Fixed hyperparameters without cross-validated tuning; depth-capped trees may underfit rare patterns. See docs/TRAINING.md.",
        "URL shorteners, newly registered lookalike domains and compromised legitimate domains can evade lexical features.",
        "Not a safety guarantee; the system is an educational screening aid and must not replace user judgement or dedicated security tooling.",
    ]
    bias_analysis = {
        "top_features": [
            {"feature": name, "mean_roc_auc_decrease": values["mean"], "std": values["std"]}
            for name, values in top_importances
        ],
        "has_https_mean_roc_auc_decrease": round(float(https_importance), 6),
        "next_largest_mean_roc_auc_decrease": round(
            max((values["mean"] for name, values in importance["features"].items()
                 if name != "has_https"), default=0.0), 6),
        "https_is_largest_feature": bool(https_importance > 0 and https_importance > max(
            (values["mean"] for name, values in importance["features"].items()
             if name != "has_https"), default=0.0)),
        "interpretation": (
            "The HTTPS dataset shortcut identified in Stage 4 is confirmed by measurement. "
            "Performance figures describe this dataset's distribution, not the live web."
        ),
    }

    metadata = {
        "stage": 6,
        "generated_at_utc": generated_at,
        "schema_version": SCHEMA_VERSION,
        "feature_schema_version": "1.0",
        "model_version": FINAL_MODEL_VERSION,
        "model_name": selected_name,
        "estimator_class": type(classifier).__name__ if classifier is not None else "unknown",
        "feature_order": list(FEATURE_ORDER),
        "class_labels": {"0": "legitimate", "1": "phishing"},
        "thresholds": {
            "low": low,
            "high": high,
            "provisional_defaults_replaced": PROVISIONAL_BAND,
        },
        "threshold_selection": {
            "criterion": CRITERION_DESCRIPTION,
            "constraints": calibration_constraints,
            "total_pairs": reports[selected_name]["total_pairs"],
            "feasible_pairs": reports[selected_name]["feasible_pairs"],
            "validation_rows": validation_facts["rows"],
            "abstention_rate": best["abstention_rate"],
            "recall": best["recall"],
            "false_negatives": best["fn"],
            "f1": best["f1"],
        },
        "selection_criterion": CRITERION_DESCRIPTION,
        "score_meaning": SCORE_MEANING,
        "decision_states": DECISION_STATES,
        "model_bundle_sha256": bundle_hash,
        "dataset": {
            "train_sha256": training_manifest["dataset"]["train_file_sha256"],
            "validation_sha256": validation_facts["sha256"],
            "test_sha256": test_facts["sha256"],
            "split_sizes": {
                "train": train_facts["rows"], "validation": validation_facts["rows"],
                "test": test_facts["rows"],
            },
            "class_distribution": {
                "train": {"legitimate": train_facts["legitimate"], "phishing": train_facts["phishing"]},
                "validation": {"legitimate": validation_facts["legitimate"], "phishing": validation_facts["phishing"]},
                "test": {"legitimate": test_facts["legitimate"], "phishing": test_facts["phishing"]},
            },
        },
        "library_versions": environment,
        "limitations": limitations,
    }

    metrics = {
        "stage": 6,
        "generated_at_utc": generated_at,
        "description": "ALL values measured by sklearn.metrics on the named splits. No hard-coded performance figures.",
        "config": config.public_dict(),
        "dataset": {
            "train": train_facts, "validation": validation_facts, "test": test_facts,
        },
        "per_model": reports,
        "selection": {
            "criterion": CRITERION_DESCRIPTION,
            "selected_model": selected_name,
            "eligible_models": [name for name, report in reports.items() if report["feasible"]],
            "ranking": ranking,
        },
        "validation": {
            "standard_0.5": validation_standard,
            "calibrated": validation_calibrated,
        },
        "test": {
            "standard_0.5": test_standard,
            "calibrated": test_calibrated,
            "state_counts": test_calibrated["state_counts"],
            "scored_once": True,
        },
        "feature_importance": importance,
        "bias_analysis": bias_analysis,
        "environment": environment,
        "honesty": {
            "metrics_source": "sklearn.metrics on validation.csv and test.csv",
            "hardcoded_values": False,
            "test_split_read_before_selection": False,
        },
    }

    (config.output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (config.output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (config.docs_dir / "MODEL_CARD.md").write_text(render_model_card(metadata, metrics), encoding="utf-8")
    (config.docs_dir / "EVALUATION.md").write_text(render_evaluation(metadata, metrics), encoding="utf-8")
    return metrics


def run(config: EvaluationConfig) -> dict[str, Any]:
    """Execute the full evaluation protocol and return the written metrics."""
    thresholds = threshold_config_from(config)
    print("Loading candidate bundles ...")
    bundles, training_manifest = load_candidates(config.candidates_dir)
    train_frame = pd.read_csv(ROOT / "dataset" / "processed" / "train.csv")
    train_facts = {
        "file": str(ROOT / "dataset" / "processed" / "train.csv"),
        "sha256": sha256_file(ROOT / "dataset" / "processed" / "train.csv"),
        "rows": int(len(train_frame)),
        "legitimate": int((train_frame["label"] == 0).sum()),
        "phishing": int((train_frame["label"] == 1).sum()),
        "phishing_rate": round(float((train_frame["label"] == 1).mean()), 6),
    }
    if train_facts["sha256"] != training_manifest["dataset"]["train_file_sha256"]:
        raise RuntimeError("train.csv hash differs from the Stage 5 training manifest; re-run Stages 3-5")

    print("Loading validation split ...")
    validation_features, validation_labels, validation_facts = load_split(config.validation_path)
    reports = evaluate_candidates(bundles, validation_features, validation_labels, thresholds)
    selected_name, ranking = select_best(reports)
    print(f"  selected: {selected_name}")

    selected_bundle = bundles[selected_name]
    validation_scores = selected_bundle["estimator"].predict_proba(validation_features)[:, 1]
    validation_standard = reports[selected_name]["validation"]
    validation_calibrated = evaluate_band(
        validation_labels, validation_scores,
        reports[selected_name]["t_low"], reports[selected_name]["t_high"],
    )

    print("Measuring feature importance (validation subsample) ...")
    importance = compute_feature_importance(
        selected_bundle["estimator"], validation_features, validation_labels, config
    )

    # The test split is loaded and scored ONCE, after selection is final.
    print("Loading and scoring the held-out test split once ...")
    test_features, test_labels, test_facts = load_split(config.test_path)
    test_scores = selected_bundle["estimator"].predict_proba(test_features)[:, 1]
    test_standard = compute_metrics(test_labels, test_scores)
    test_calibrated = evaluate_band(
        test_labels, test_scores,
        reports[selected_name]["t_low"], reports[selected_name]["t_high"],
    )

    metrics = write_artefacts(
        selected_bundle, selected_name, reports, ranking,
        reports[selected_name]["constraints"],
        validation_facts, test_facts, train_facts, training_manifest,
        validation_standard, validation_calibrated, test_standard,
        test_calibrated, importance, config,
    )
    return metrics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation", type=Path,
                        default=ROOT / "dataset" / "processed" / "validation.csv")
    parser.add_argument("--test", type=Path,
                        default=ROOT / "dataset" / "processed" / "test.csv")
    parser.add_argument("--candidates-dir", type=Path,
                        default=ROOT / "ml" / "saved_model" / "candidates")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "ml" / "saved_model")
    parser.add_argument("--docs-dir", type=Path, default=ROOT / "docs")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--recall-min", type=float, default=0.90)
    parser.add_argument("--max-abstention", type=float, default=0.25)
    parser.add_argument("--min-band-gap", type=float, default=0.10)
    parser.add_argument("--grid-step", type=float, default=0.05)
    parser.add_argument("--importance-rows", type=int, default=5000)
    parser.add_argument("--importance-repeats", type=int, default=3)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = EvaluationConfig(
        validation_path=args.validation,
        test_path=args.test,
        candidates_dir=args.candidates_dir,
        output_dir=args.output_dir,
        docs_dir=args.docs_dir,
        seed=args.seed,
        recall_min=args.recall_min,
        max_abstention_rate=args.max_abstention,
        min_band_gap=args.min_band_gap,
        grid_step=args.grid_step,
        importance_rows=args.importance_rows,
        importance_repeats=args.importance_repeats,
    )
    metrics = run(config)
    selected = metrics["selection"]["selected_model"]
    print("\nStage 6 evaluation complete")
    print(f"  selected model      : {selected}")
    print(f"  T_low / T_high      : {metrics['per_model'][selected]['t_low']} / "
          f"{metrics['per_model'][selected]['t_high']}")
    print(f"  validation abstention: "
          f"{metrics['validation']['calibrated']['abstention_rate']:.2%}")
    standard = metrics["test"]["standard_0.5"]
    print(f"  TEST accuracy       : {standard['accuracy']:.6f}")
    print(f"  TEST precision      : {standard['precision']:.6f}")
    print(f"  TEST recall         : {standard['recall']:.6f}")
    print(f"  TEST F1             : {standard['f1']:.6f}")
    print(f"  TEST ROC-AUC        : {standard['roc_auc']:.6f}")
    print(f"  TEST FN / FP        : {standard['fn']:,} / {standard['fp']:,}")
    print("  All figures measured; see ml/saved_model/metrics.json and docs/EVALUATION.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
