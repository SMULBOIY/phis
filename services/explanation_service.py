"""Human-readable explanation of ONE prediction (Stage 10).

Honesty rules enforced here
---------------------------
1. This module NEVER decides anything. It receives an already-computed
   ``Decision`` and the observed 15 features, and produces descriptions,
   caveats and safety advice. No ``if feature then verdict`` logic exists.
2. Definitions and rationales come from ``ml.feature_extraction`` (the same
   source used for training), so the UI cannot drift from the methodology.
3. Feature ranking comes from MEASURED permutation importance in
   ``ml/saved_model/metrics.json#feature_importance.features`` (mean decrease
   in ROC-AUC on a held-out sample), passed in by ``DetectionRegistry``. No
   importance is invented, guessed or typed into this file.
4. ``HTTPS alone does not mean a website is legitimate`` is always shown. The
   presence of HTTPS is deliberately NOT listed as a suspicious indicator.
5. Correlational language only: a flagged characteristic is an *observation
   associated with* phishing in the training corpus, not proof of maliciousness
   and not an explanation of the model's internal arithmetic. Linear-model
   coefficient attribution would be misleading here because features are
   standardised and strongly correlated.

The module is pure: no Flask, no database, no network, no file I/O. It is safe
to unit-test with a hand-built feature dict.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ml.feature_extraction import (
    FEATURE_DEFINITIONS,
    FEATURE_ORDER,
    FEATURE_RATIONALES,
)
from services.decision_service import Decision

__all__ = [
    "FeatureInsight", "Explanation", "INDICATOR_FEATURES",
    "HTTPS_CAVEAT", "explain",
]

HTTPS_CAVEAT = "HTTPS alone does not mean a website is legitimate."

# Characteristics documented in docs/FEATURES.md as obfuscation/lure signals.
# These are used ONLY to annotate the result page. They are never a verdict and
# never influence ``prediction``. ``has_https`` is intentionally absent.
INDICATOR_FEATURES: frozenset[str] = frozenset({
    "has_ip_address",
    "has_at_symbol",
    "has_suspicious_pattern",
    "is_shortened",
    "num_suspicious_words",
    "has_unusual_port",
    "has_encoded_chars",
})

RECOMMENDED_ACTIONS: dict[str, str] = {
    "LEGITIMATE": (
        "Still check the sender and the domain yourself before signing in. "
        "A low score is not a safety certificate."
    ),
    "SUSPICIOUS": (
        "Do not continue yet. Verify the sender and the real destination "
        "through an independent channel (type the address yourself or use a "
        "bookmark) before entering any details."
    ),
    "PHISHING": (
        "Do not open the link. Do not enter passwords, card numbers, one-time "
        "codes or personal information. Report the message to your mail or "
        "security administrator."
    ),
}

CAVEATS: tuple[str, ...] = (
    HTTPS_CAVEAT,
    "Only the URL string was analysed. The server did not visit, resolve, "
    "download or execute the submitted address, so page content, redirects "
    "and certificates were not checked.",
    "These observations are correlations learned from the PhiUSIIL training "
    "distribution, not proof of cause. A single flagged characteristic does "
    "not make a site malicious, and a clean-looking URL does not make it safe.",
    "The model has known dataset shortcuts (notably HTTPS and URL length). "
    "Small, harmless edits to a URL can change the score noticeably.",
)


@dataclass(frozen=True)
class FeatureInsight:
    """One observed characteristic, its meaning and its measured importance."""

    name: str
    label: str
    value: int
    definition: str
    rationale: str
    importance: float
    observed: bool
    indicator: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "label": self.label,
            "value": self.value,
            "definition": self.definition,
            "rationale": self.rationale,
            "importance": self.importance,
            "observed": self.observed,
            "indicator": self.indicator,
        }


@dataclass(frozen=True)
class Explanation:
    """Everything the result page needs to explain ONE decision."""

    insights: tuple[FeatureInsight, ...]
    flagged: tuple[FeatureInsight, ...]
    top: tuple[FeatureInsight, ...]
    recommended_action: str
    uncertainty_note: str
    caveats: tuple[str, ...] = field(default=CAVEATS)
    importance_source: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "insights": [item.to_dict() for item in self.insights],
            "flagged": [item.to_dict() for item in self.flagged],
            "top": [item.to_dict() for item in self.top],
            "recommended_action": self.recommended_action,
            "uncertainty_note": self.uncertainty_note,
            "caveats": list(self.caveats),
            "importance_source": self.importance_source,
        }


def _label(name: str) -> str:
    """Readable column heading derived from the documented feature name."""
    return name.replace("_", " ").strip().capitalize()


def explain(
    features: dict[str, int],
    decision: Decision,
    *,
    importance: dict[str, float],
    importance_source: str = "",
) -> Explanation:
    """Build a non-causal, fully sourced explanation for one result.

    Parameters
    ----------
    features:
        The exact 15-feature vector that was scored.
    decision:
        The verdict produced by ``services.decision_service.decide``.
    importance:
        Measured mean ROC-AUC decrease per feature, read at runtime from
        ``metrics.json``. Every feature must be present.
    importance_source:
        Provenance string shown on the report, e.g.
        ``ml/saved_model/metrics.json#feature_importance.features``.
    """
    missing = [name for name in FEATURE_ORDER if name not in features]
    if missing:
        raise ValueError(f"cannot explain an incomplete feature vector: {missing}")
    missing_importance = [name for name in FEATURE_ORDER if name not in importance]
    if missing_importance:
        raise ValueError(
            f"measured feature importance is missing for: {missing_importance}"
        )

    insights: list[FeatureInsight] = []
    for name in FEATURE_ORDER:
        value = int(features[name])
        insights.append(FeatureInsight(
            name=name,
            label=_label(name),
            value=value,
            definition=FEATURE_DEFINITIONS[name],
            rationale=FEATURE_RATIONALES[name],
            importance=float(importance[name]),
            observed=(value != 0),
            indicator=(name in INDICATOR_FEATURES),
        ))

    # Rank by MEASURED importance (deterministic tie-break by name), never by
    # an invented weight. This is descriptive, not a contribution score.
    ranked = tuple(sorted(insights, key=lambda item: (-item.importance, item.name)))
    flagged = tuple(
        item for item in ranked if item.indicator and item.observed
    )
    top = ranked[:5]

    if decision.prediction not in RECOMMENDED_ACTIONS:
        raise ValueError(f"no recommended action for {decision.prediction!r}")

    if decision.uncertain:
        note = (
            f"The model is abstaining: the score sits inside the measured "
            f"uncertainty band {decision.band()}. This is NOT a 50/50 "
            f"probability and NOT a verdict. Treat the address as unresolved "
            f"and investigate through an independent channel."
        )
    else:
        note = (
            f"This is a decisive {decision.prediction.lower()} outcome under "
            f"the measured thresholds (low {decision.threshold_low:g}, high "
            f"{decision.threshold_high:g}), but the score is an uncalibrated "
            f"estimate, not certainty. A decisive result can still be wrong."
        )

    return Explanation(
        insights=tuple(insights),
        flagged=flagged,
        top=top,
        recommended_action=RECOMMENDED_ACTIONS[decision.prediction],
        uncertainty_note=note,
        caveats=CAVEATS,
        importance_source=importance_source,
    )
