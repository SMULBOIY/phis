"""Score -> three-state decision policy (Stage 10).

This is the ONLY place where a model score becomes a verdict. It contains no
detection rules, no URL parsing and no feature inspection: the verdict comes
entirely from ``predict_proba`` and the two thresholds that Stage 6 measured on
the validation split and wrote to ``ml/saved_model/metadata.json``.

Why the third state is not a fake class
--------------------------------------
The fitted estimator is binary (0 = legitimate, 1 = phishing). SUSPICIOUS is a
*selective prediction* / abstention decision: when the score falls inside the
uncertainty band the system declines to give a binary verdict. Nothing is
invented, and no third label was trained.

Boundary semantics (identical to Stage 6's calibration, because this module
reuses ``ml.thresholds.decision_codes`` rather than re-implementing it):

    p >= T_high              -> PHISHING    (HIGH)
    p <= T_low               -> LEGITIMATE  (LOW)
    T_low < p < T_high       -> SUSPICIOUS  (MEDIUM, abstaining)

Exact strings, colours, risk levels, messages and warnings come from
``ml.thresholds.DECISION_STATES`` / ``SCORE_MEANING``. The runtime gate asserts
that ``metadata.json`` still agrees with those constants, so prose can never
silently drift from the calibration contract.

Uncertainty is explicit, not decorative: SUSPICIOUS sets ``uncertain=True`` and
carries the abstention warning to the UI. Even decisive states carry
``SCORE_MEANING``, because ``predict_proba`` is an uncalibrated estimate and is
NOT a guaranteed probability that a website is malicious.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ml.thresholds import (
    DECISION_STATES,
    SCORE_MEANING,
    STATE_ABSTAIN,
    STATE_NAMES,
    decision_codes,
)

__all__ = ["Decision", "DecisionPolicyError", "decide"]


class DecisionPolicyError(ValueError):
    """The measured thresholds or the score failed validation."""


@dataclass(frozen=True)
class Decision:
    """One fully described, reproducible decision for one URL."""

    prediction: str
    risk_level: str
    colour: str
    message: str
    warning: str
    score: float
    uncertain: bool
    threshold_low: float
    threshold_high: float
    score_meaning: str

    def band(self) -> str:
        """Human-readable abstention band, e.g. ``0.05 < p < 0.95``."""
        return f"{self.threshold_low:g} < p < {self.threshold_high:g}"

    def to_dict(self) -> dict[str, object]:
        return {
            "prediction": self.prediction,
            "risk_level": self.risk_level,
            "colour": self.colour,
            "message": self.message,
            "warning": self.warning,
            "score": self.score,
            "uncertain": self.uncertain,
            "thresholds": {
                "low": self.threshold_low,
                "high": self.threshold_high,
                "band": self.band(),
            },
            "score_meaning": self.score_meaning,
        }


def decide(
    score: float,
    *,
    low: float,
    high: float,
    states: dict[str, dict[str, str]] | None = None,
    score_meaning: str | None = None,
) -> Decision:
    """Map one validated score to a decision using the measured thresholds.

    Parameters
    ----------
    score:
        The ``predict_proba`` phishing-class score in ``[0, 1]``.
    low, high:
        ``metadata.json.thresholds.low`` / ``.high`` - the values Stage 6
        selected on the validation split. They are never hard-coded here.
    states, score_meaning:
        Overridable only for automated tests; production uses the constants in
        ``ml.thresholds``.
    """
    try:
        p = float(score)
        t_low = float(low)
        t_high = float(high)
    except (TypeError, ValueError) as exc:
        raise DecisionPolicyError("score and thresholds must be numbers") from exc
    if not np.isfinite(p) or not 0.0 <= p <= 1.0:
        raise DecisionPolicyError("score must be a finite value in [0, 1]")
    if not (np.isfinite(t_low) and np.isfinite(t_high)
            and 0.0 <= t_low < t_high <= 1.0):
        raise DecisionPolicyError("thresholds must satisfy 0 <= low < high <= 1")

    contract = DECISION_STATES if states is None else states
    meaning = SCORE_MEANING if score_meaning is None else score_meaning

    # Reuse Stage 6's own mapping so that a boundary case can never disagree
    # with the calibration that produced the published evaluation.
    code = int(decision_codes(np.asarray([p], dtype=float), t_low, t_high)[0])
    name = STATE_NAMES[code]
    if name not in contract:
        raise DecisionPolicyError(f"no UI contract for decision state {name!r}")
    state = contract[name]
    required = ("colour", "risk_level", "message", "warning")
    if any(key not in state for key in required):
        raise DecisionPolicyError(f"incomplete UI contract for {name!r}")

    return Decision(
        prediction=name,
        risk_level=state["risk_level"],
        colour=state["colour"],
        message=state["message"],
        warning=state["warning"],
        score=p,
        uncertain=(code == STATE_ABSTAIN),
        threshold_low=t_low,
        threshold_high=t_high,
        score_meaning=meaning,
    )
