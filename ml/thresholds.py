"""Abstention-band calibration (Stage 6).

The classifier is BINARY. "SUSPICIOUS" is a *selective prediction* decision:
when the phishing score falls in an uncertainty band the system declines to
give a binary verdict. No third class was invented and no label was fabricated.

    p >= T_high  -> PHISHING   (risk HIGH)   "Potential phishing website detected."
    p <= T_low   -> LEGITIMATE (risk LOW)    "No phishing indicators detected by this model."
    T_low < p < T_high -> SUSPICIOUS (MEDIUM) "This website requires further investigation."

Selection criterion (fixed BEFORE looking at results, documented in the ADRs)
---------------------------------------------------------------------------
On the VALIDATION SPLIT ONLY, grid-search (T_low, T_high). A pair is feasible
when ALL of the following hold:

1. ``recall >= 0.90`` on decisive predictions (a missed phishing site is the
   costliest error - the brief's recall priority);
2. ``abstention_rate <= 0.25`` (the band must not become uselessly wide);
3. ``T_high - T_low >= 0.10`` (no degenerate band).

Among feasible pairs, MAXIMISE F1 on decisive predictions; tie-break by fewest
false negatives, then lowest abstention rate, then the threshold values for
determinism. The resulting abstention rate is always reported.

A phishing URL inside the band is SUSPICIOUS, not a false negative: it was not
declared safe. False negatives are counted ONLY over decisive predictions,
which is why the abstention cap exists - without it, abstaining on every hard
case would trivially inflate recall.

This module is pure computation: it never reads a dataset or writes a file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

STATE_ABSTAIN = -1
STATE_LEGITIMATE = 0
STATE_PHISHING = 1

STATE_NAMES: dict[int, str] = {
    STATE_ABSTAIN: "SUSPICIOUS",
    STATE_LEGITIMATE: "LEGITIMATE",
    STATE_PHISHING: "PHISHING",
}

# Required UI contract (architecture section 6.1). Consumed by Stage 10.
DECISION_STATES: dict[str, dict[str, str]] = {
    "LEGITIMATE": {
        "colour": "green",
        "risk_level": "LOW",
        "message": "No phishing indicators detected by this model.",
        "warning": "This result is not a guarantee that the website is safe. The model only analysed the URL string and did not visit the site.",
    },
    "PHISHING": {
        "colour": "red",
        "risk_level": "HIGH",
        "message": "Potential phishing website detected.",
        "warning": "Do not enter passwords, card details, one-time codes or personal information on this website.",
    },
    "SUSPICIOUS": {
        "colour": "orange",
        "risk_level": "MEDIUM",
        "message": "This website requires further investigation.",
        "warning": "The score falls inside the uncertainty band; the model is abstaining. Treat this as unresolved, not as a 50/50 probability. Verify the sender and domain before continuing.",
    },
}

SCORE_MEANING = (
    "Model score: the model's uncalibrated estimate of P(phishing | URL features), "
    "computed by predict_proba on 15 lexical URL features. It is not a calibrated "
    "probability that the website is malicious, and it is not a guarantee."
)

CRITERION_DESCRIPTION = (
    "Validation-split grid search over (T_low, T_high). Feasible: recall >= 0.90 on "
    "decisive predictions, abstention rate <= 0.25, band gap >= 0.10. Objective: "
    "maximise F1 on decisive predictions; tie-break by fewest false negatives, then "
    "lowest abstention rate, then threshold values. Model selection uses the same "
    "objective across candidates, tie-broken by highest validation ROC-AUC."
)


@dataclass(frozen=True)
class ThresholdConfig:
    """All calibration constraints, fixed a priori and recorded in metadata.json."""

    recall_min: float = 0.90
    max_abstention_rate: float = 0.25
    min_band_gap: float = 0.10
    grid_step: float = 0.05
    grid_low_max: float = 0.45
    grid_high_min: float = 0.55
    grid_high_max: float = 0.95

    def grid(self) -> list[tuple[float, float]]:
        """Return the deterministic, ordered list of candidate threshold pairs."""
        lows = [round(value, 2) for value in
                np.arange(self.grid_step, self.grid_low_max + 1e-9, self.grid_step)]
        highs = [round(value, 2) for value in
                 np.arange(self.grid_high_min, self.grid_high_max + 1e-9, self.grid_step)]
        return [(low, high) for low in lows for high in highs
                if high - low >= self.min_band_gap - 1e-9]


@dataclass
class CalibrationResult:
    """Measured outcome of one grid search over the validation split."""

    t_low: float
    t_high: float
    metrics: dict[str, Any]
    total_pairs: int
    feasible_pairs: int
    criterion: str = CRITERION_DESCRIPTION
    constraints: dict[str, float] = field(default_factory=dict)


def decision_codes(scores: np.ndarray, t_low: float, t_high: float) -> np.ndarray:
    """Map phishing scores to decision codes (-1 abstain, 0 legit, 1 phishing)."""
    values = np.asarray(scores, dtype=float)
    return np.where(values >= t_high, STATE_PHISHING,
                    np.where(values <= t_low, STATE_LEGITIMATE, STATE_ABSTAIN))


def evaluate_band(
    y_true: np.ndarray, scores: np.ndarray, t_low: float, t_high: float
) -> dict[str, Any]:
    """Measure a single (T_low, T_high) pair on decisive predictions only."""
    labels = np.asarray(y_true, dtype=int)
    codes = decision_codes(scores, t_low, t_high)
    decisive = codes != STATE_ABSTAIN
    decisive_labels = labels[decisive]
    decisive_pred = codes[decisive].astype(int)

    tp = int(((decisive_pred == 1) & (decisive_labels == 1)).sum())
    fp = int(((decisive_pred == 1) & (decisive_labels == 0)).sum())
    tn = int(((decisive_pred == 0) & (decisive_labels == 0)).sum())
    fn = int(((decisive_pred == 0) & (decisive_labels == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    decisive_count = int(decisive.sum())
    accuracy = (tp + tn) / decisive_count if decisive_count else 0.0
    abstention_rate = float(1.0 - decisive.mean()) if len(codes) else 0.0

    return {
        "t_low": round(float(t_low), 4),
        "t_high": round(float(t_high), 4),
        "decisive_count": decisive_count,
        "abstained_count": int((~decisive).sum()),
        "abstention_rate": round(abstention_rate, 6),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "accuracy": round(accuracy, 6),
        "false_negative_rate": round(1.0 - recall, 6),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "state_counts": {
            "LEGITIMATE": int((codes == STATE_LEGITIMATE).sum()),
            "SUSPICIOUS": int((codes == STATE_ABSTAIN).sum()),
            "PHISHING": int((codes == STATE_PHISHING).sum()),
        },
    }


def grid_search_thresholds(
    y_true: np.ndarray, scores: np.ndarray, config: ThresholdConfig | None = None
) -> CalibrationResult:
    """Select the documented-best feasible band. Raises if none is feasible."""
    cfg = config or ThresholdConfig()
    if not (0 <= cfg.recall_min <= 1 and 0 <= cfg.max_abstention_rate <= 1):
        raise ValueError("Recall floor and abstention cap must be in [0, 1]")
    pairs = cfg.grid()
    feasible: list[dict[str, Any]] = []
    for low, high in pairs:
        measured = evaluate_band(y_true, scores, low, high)
        if measured["recall"] < cfg.recall_min - 1e-12:
            continue
        if measured["abstention_rate"] > cfg.max_abstention_rate + 1e-12:
            continue
        feasible.append(measured)
    if not feasible:
        raise RuntimeError(
            "No (T_low, T_high) pair satisfies the documented constraints "
            f"(recall >= {cfg.recall_min}, abstention <= {cfg.max_abstention_rate}, "
            f"gap >= {cfg.min_band_gap}). Do NOT relax the constraints silently."
        )
    # Maximise F1, then minimise FN, abstention, then stabilise threshold order.
    feasible.sort(key=lambda item: (
        -item["f1"], item["fn"], item["abstention_rate"],
        item["t_low"], -item["t_high"],
    ))
    best = feasible[0]
    return CalibrationResult(
        t_low=best["t_low"],
        t_high=best["t_high"],
        metrics=best,
        total_pairs=len(pairs),
        feasible_pairs=len(feasible),
        constraints={
            "recall_min": cfg.recall_min,
            "max_abstention_rate": cfg.max_abstention_rate,
            "min_band_gap": cfg.min_band_gap,
            "grid_step": cfg.grid_step,
        },
    )


__all__ = [
    "STATE_ABSTAIN", "STATE_LEGITIMATE", "STATE_PHISHING", "STATE_NAMES",
    "DECISION_STATES", "SCORE_MEANING", "CRITERION_DESCRIPTION",
    "ThresholdConfig", "CalibrationResult", "decision_codes",
    "evaluate_band", "grid_search_thresholds",
]
