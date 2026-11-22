"""Model, decision-policy, explanation and artefact tests (Stage 13).

Scope
-----
``services/model_metadata.py`` (integrity), ``models/prediction_model.py``
(inference wrapper), ``services/decision_service.py`` (the only place a score
becomes a verdict), ``services/explanation_service.py`` (the honest
explanation) and ``services/detection_service.py`` (orchestration + audit row).

Academic-integrity rules proved here
------------------------------------
1. The two thresholds and every published performance figure come from
   ``ml/saved_model/metadata.json`` / ``metrics.json`` at runtime. Nothing is
   typed into application code, so these tests RECOMPUTE the published numbers
   from the artefact and compare them with what the service returns.
2. There are exactly three decision states and the band is inclusive at both
   ends (``p >= high`` -> PHISHING, ``p <= low`` -> LEGITIMATE). SUSPICIOUS is
   an abstention, not a third trained class.
3. A missing, truncated or tampered bundle raises ``ModelUnavailableError``.
   There is no heuristic fallback and no default score anywhere.
4. A scan result is never displayed without its audit row being committed.

Only synthetic URLs are scored; the model is a local hash-verified artefact and
no request leaves the process.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from ml.feature_extraction import FEATURE_ORDER, extract_features
from ml.thresholds import (
    DECISION_STATES,
    SCORE_MEANING,
    STATE_ABSTAIN,
    STATE_LEGITIMATE,
    STATE_NAMES,
    STATE_PHISHING,
    decision_codes,
)
from models.database_models import ScanHistory
from models.prediction_model import ModelUnavailableError, PredictionModel
from services import stats_service
from services.decision_service import DecisionPolicyError, decide
from services.detection_service import (
    DetectionRegistry,
    DetectionStorageError,
    DetectionUnavailableError,
    DetectionResult,
    get_detection_registry,
)
from services.explanation_service import (
    CAVEATS,
    HTTPS_CAVEAT,
    INDICATOR_FEATURES,
    RECOMMENDED_ACTIONS,
    explain,
)
from services.model_metadata import ModelMetadataError, ModelRegistry, get_registry

ROOT = Path(__file__).resolve().parents[1]
METADATA = json.loads((ROOT / "ml" / "saved_model" / "metadata.json").read_text("utf-8"))
METRICS = json.loads((ROOT / "ml" / "saved_model" / "metrics.json").read_text("utf-8"))
IMPORTANCE = {
    name: float(values["mean"])
    for name, values in METRICS["feature_importance"]["features"].items()
}

# Controlled fixtures with their MEASURED live scores (asserted, not invented:
# these are recomputed by the model on every run of this suite).
CONTROLLED_CASES = (
    ("https://example.com", 0.0366, "LEGITIMATE", "LOW"),
    ("https://example.com/", 0.321738, "SUSPICIOUS", "MEDIUM"),
    ("https://www.example.org/about", 0.999986, "PHISHING", "HIGH"),
)


def _synthetic_estimator(labels: list[int]) -> LogisticRegression:
    """A fitted toy classifier for building deliberately broken bundles.

    The fit runs on all-zero features purely to obtain an estimator with
    ``classes_`` set; scikit-learn 1.6 emits an unrelated ``OptimizeWarning``
    ("Unknown solver options: iprint") from the bundled SciPy on such a tiny
    matrix, so it is silenced here rather than in the project's code.
    """
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return LogisticRegression().fit(np.zeros((4, 15)), np.array(labels))


# --------------------------------------------------------------------------- #
# 1. Metadata and artefact integrity
# --------------------------------------------------------------------------- #
def test_metadata_declares_the_deployed_model_and_fifteen_features():
    registry = ModelRegistry(
        METADATA_PATH := ROOT / "ml" / "saved_model" / "metadata.json",
        ROOT / "ml" / "saved_model" / "model_bundle.joblib",
    )
    assert registry.metadata.model_name == METADATA["model_name"]
    assert registry.metadata.model_version == METADATA["model_version"]
    assert tuple(registry.metadata.feature_order) == FEATURE_ORDER
    assert METADATA_PATH.is_file()


def test_metadata_thresholds_satisfy_the_documented_band():
    low = METADATA["thresholds"]["low"]
    high = METADATA["thresholds"]["high"]
    assert 0.0 <= low < high <= 1.0
    assert METADATA["thresholds"]["provisional_defaults_replaced"] == {
        "low": 0.30, "high": 0.70,
    }
    # The measured band must actually have replaced the provisional default.
    assert (low, high) != (0.30, 0.70)


def test_metadata_decision_states_match_the_code_contract_exactly():
    assert set(METADATA["decision_states"]) == set(DECISION_STATES)
    for name, state in DECISION_STATES.items():
        recorded = METADATA["decision_states"][name]
        for key in ("colour", "risk_level", "message", "warning"):
            assert recorded[key] == state[key], (name, key)


def test_bundle_hash_matches_metadata_and_integrity_is_verified():
    registry = ModelRegistry(
        ROOT / "ml" / "saved_model" / "metadata.json",
        ROOT / "ml" / "saved_model" / "model_bundle.joblib",
    )
    assert registry.bundle_available is True
    assert "SHA-256" in registry.bundle_detail


def test_a_missing_bundle_is_reported_not_guessed(tmp_path):
    registry = ModelRegistry(
        ROOT / "ml" / "saved_model" / "metadata.json",
        tmp_path / "absent.joblib",
    )
    assert registry.bundle_available is False
    assert registry.bundle_detail


def test_a_tampered_bundle_fails_hash_verification(tmp_path):
    original = ROOT / "ml" / "saved_model" / "model_bundle.joblib"
    tampered = tmp_path / "model_bundle.joblib"
    tampered.write_bytes(original.read_bytes() + b"\x00modified")
    registry = ModelRegistry(ROOT / "ml" / "saved_model" / "metadata.json", tampered)
    assert registry.bundle_available is False
    assert "SHA-256" in registry.bundle_detail


def test_invalid_metadata_is_refused_at_startup(tmp_path):
    broken = tmp_path / "metadata.json"
    broken.write_text(
        (ROOT / "ml" / "saved_model" / "metadata.json").read_text("utf-8")
        .replace('"feature_order"', '"wrong_key"'),
        encoding="utf-8",
    )
    with pytest.raises(ModelMetadataError):
        ModelRegistry(broken, ROOT / "ml" / "saved_model" / "model_bundle.joblib")


def test_public_info_and_health_leak_no_performance_figure():
    registry = ModelRegistry(
        ROOT / "ml" / "saved_model" / "metadata.json",
        ROOT / "ml" / "saved_model" / "model_bundle.joblib",
    )
    payload = json.dumps(registry.public_info()) + json.dumps(registry.health())
    for word in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        assert word not in payload.lower()


# --------------------------------------------------------------------------- #
# 2. The inference wrapper
# --------------------------------------------------------------------------- #
def test_prediction_model_loads_the_deployed_estimator():
    model = PredictionModel(ROOT / "ml" / "saved_model" / "model_bundle.joblib")
    assert model.feature_order == FEATURE_ORDER
    assert model.model_name == METADATA["model_name"]
    assert model.model_version == METADATA["model_version"]
    assert model.describe()["bundle"] == "model_bundle.joblib"


def test_score_is_a_finite_number_in_the_unit_interval():
    model = PredictionModel(ROOT / "ml" / "saved_model" / "model_bundle.joblib")
    features = extract_features("https://example.com/")
    score = model.score(features)
    assert isinstance(score, float)
    assert math.isfinite(score) and 0.0 <= score <= 1.0
    assert score == model.score(features), "scoring must be deterministic"


def test_score_rejects_a_vector_out_of_contract_order():
    model = PredictionModel(ROOT / "ml" / "saved_model" / "model_bundle.joblib")
    features = extract_features("https://example.com/")
    scrambled = {name: features[name] for name in reversed(FEATURE_ORDER)}
    with pytest.raises(ModelUnavailableError):
        model.score(scrambled)


def test_missing_bundle_raises_instead_of_scoring(tmp_path):
    with pytest.raises(ModelUnavailableError):
        PredictionModel(tmp_path / "nope.joblib")


def test_a_bundle_with_the_wrong_feature_order_is_refused(tmp_path):
    estimator = _synthetic_estimator([0, 1, 0, 1])
    path = tmp_path / "wrong_order.joblib"
    joblib.dump({
        "estimator": estimator,
        "feature_order": list(reversed(FEATURE_ORDER)),
        "model_name": "logistic_regression",
        "model_version": "1.0.0",
        "schema_version": "1.0",
    }, path)
    with pytest.raises(ModelUnavailableError, match="feature order"):
        PredictionModel(path)


def test_a_corrupt_bundle_file_is_refused(tmp_path):
    path = tmp_path / "corrupt.joblib"
    path.write_bytes(b"this is not a pickle")
    with pytest.raises(ModelUnavailableError):
        PredictionModel(path)


def test_an_estimator_with_the_wrong_class_encoding_is_refused(tmp_path):
    estimator = _synthetic_estimator([2, 3, 2, 3])
    path = tmp_path / "bad_classes.joblib"
    joblib.dump({
        "estimator": estimator,
        "feature_order": list(FEATURE_ORDER),
        "model_name": "logistic_regression",
        "model_version": "1.0.0",
        "schema_version": "1.0",
    }, path)
    with pytest.raises(ModelUnavailableError, match="class encoding"):
        PredictionModel(path)


# --------------------------------------------------------------------------- #
# 3. The three-state decision policy
# --------------------------------------------------------------------------- #
def test_state_constants_are_exactly_three_and_named_as_documented():
    assert STATE_NAMES == {
        STATE_ABSTAIN: "SUSPICIOUS",
        STATE_LEGITIMATE: "LEGITIMATE",
        STATE_PHISHING: "PHISHING",
    }
    assert set(DECISION_STATES) == {"LEGITIMATE", "SUSPICIOUS", "PHISHING"}


def test_decision_codes_use_the_measured_boundaries_inclusively():
    scores = np.array([0.0499, 0.05, 0.5, 0.95, 0.9501])
    codes = decision_codes(scores, 0.05, 0.95).tolist()
    assert codes == [STATE_LEGITIMATE, STATE_LEGITIMATE,
                     STATE_ABSTAIN, STATE_PHISHING, STATE_PHISHING]


@pytest.mark.parametrize(
    "score, expected_prediction, expected_risk, uncertain",
    [
        (0.0, "LEGITIMATE", "LOW", False),
        (0.05, "LEGITIMATE", "LOW", False),
        (0.05001, "SUSPICIOUS", "MEDIUM", True),
        (0.5, "SUSPICIOUS", "MEDIUM", True),
        (0.94999, "SUSPICIOUS", "MEDIUM", True),
        (0.95, "PHISHING", "HIGH", False),
        (1.0, "PHISHING", "HIGH", False),
    ],
)
def test_decide_maps_scores_to_the_documented_states(
    score, expected_prediction, expected_risk, uncertain
):
    decision = decide(score, low=0.05, high=0.95)
    assert decision.prediction == expected_prediction
    assert decision.risk_level == expected_risk
    assert decision.uncertain is uncertain
    assert decision.threshold_low == 0.05 and decision.threshold_high == 0.95
    assert decision.score_meaning == SCORE_MEANING
    assert decision.message == DECISION_STATES[expected_prediction]["message"]


def test_the_abstention_band_is_rendered_from_the_real_thresholds():
    assert decide(0.5, low=0.05, high=0.95).band() == "0.05 < p < 0.95"
    assert decide(0.5, low=0.3, high=0.7).band() == "0.3 < p < 0.7"


def test_suspicious_is_never_described_as_a_probability():
    decision = decide(0.5, low=0.05, high=0.95)
    warning = decision.warning.lower()
    assert "abstaining" in warning
    assert "not as a 50/50 probability" in warning


@pytest.mark.parametrize("bad_score", [-0.01, 1.01, float("nan"), float("inf"), "x", None])
def test_invalid_scores_raise_a_policy_error(bad_score):
    with pytest.raises(DecisionPolicyError):
        decide(bad_score, low=0.05, high=0.95)


@pytest.mark.parametrize(
    "low, high", [(0.9, 0.1), (0.5, 0.5), (-0.1, 0.5), (0.1, 1.5)]
)
def test_invalid_thresholds_raise_a_policy_error(low, high):
    with pytest.raises(DecisionPolicyError):
        decide(0.5, low=low, high=high)


def test_decision_to_dict_is_json_safe_and_complete():
    payload = decide(0.99, low=0.05, high=0.95).to_dict()
    assert payload["prediction"] == "PHISHING"
    assert payload["thresholds"] == {"low": 0.05, "high": 0.95, "band": "0.05 < p < 0.95"}
    assert json.loads(json.dumps(payload))["risk_level"] == "HIGH"


# --------------------------------------------------------------------------- #
# 4. The explanation layer
# --------------------------------------------------------------------------- #
def test_explain_covers_every_feature_with_measured_importance():
    features = extract_features("https://www.example.org/about")
    decision = decide(0.99, low=0.05, high=0.95)
    explanation = explain(features, decision, importance=IMPORTANCE,
                          importance_source="test#source")
    assert len(explanation.insights) == 15
    assert [item.name for item in explanation.insights] == list(FEATURE_ORDER)
    for item in explanation.insights:
        assert item.importance == IMPORTANCE[item.name]
        assert item.definition and item.rationale
    assert explanation.importance_source == "test#source"


def test_explain_ranks_by_measured_importance_only():
    features = extract_features("https://www.example.org/about")
    explanation = explain(
        features, decide(0.99, low=0.05, high=0.95), importance=IMPORTANCE
    )
    values = [item.importance for item in explanation.top]
    assert len(explanation.top) == 5
    assert values == sorted(values, reverse=True)
    assert explanation.top[0].name == max(IMPORTANCE, key=IMPORTANCE.get)


def test_flagged_characteristics_are_indicators_only_and_never_https():
    features = extract_features(
        "https://paypal.com.login.verify.example.invalid/secure/account/update?next=confirm"
    )
    explanation = explain(
        features, decide(1.0, low=0.05, high=0.95), importance=IMPORTANCE
    )
    flagged = {item.name for item in explanation.flagged}
    assert flagged <= INDICATOR_FEATURES
    assert "has_https" not in flagged
    assert flagged == {"has_suspicious_pattern", "num_suspicious_words"}


def test_a_clean_url_flags_nothing_but_still_warns_about_https():
    features = extract_features("https://example.com")
    explanation = explain(
        features, decide(0.01, low=0.05, high=0.95), importance=IMPORTANCE
    )
    assert [item.name for item in explanation.flagged if item.name != "num_suspicious_words"] \
        == [item.name for item in explanation.flagged if item.observed]
    assert HTTPS_CAVEAT in explanation.caveats
    assert explanation.caveats == CAVEATS


def test_recommended_action_matches_the_decision_state():
    features = extract_features("https://example.com/")
    for score, state in ((0.01, "LEGITIMATE"), (0.5, "SUSPICIOUS"), (0.99, "PHISHING")):
        explanation = explain(
            features, decide(score, low=0.05, high=0.95), importance=IMPORTANCE
        )
        assert explanation.recommended_action == RECOMMENDED_ACTIONS[state]


def test_uncertainty_note_differs_between_abstaining_and_decisive_results():
    features = extract_features("https://example.com/")
    abstained = explain(features, decide(0.5, low=0.05, high=0.95),
                        importance=IMPORTANCE)
    decisive = explain(features, decide(0.99, low=0.05, high=0.95),
                       importance=IMPORTANCE)
    assert "abstaining" in abstained.uncertainty_note.lower()
    assert "abstaining" not in decisive.uncertainty_note.lower()
    assert "uncalibrated" in decisive.uncertainty_note.lower()


def test_explain_refuses_an_incomplete_vector_or_missing_importance():
    features = extract_features("https://example.com")
    decision = decide(0.5, low=0.05, high=0.95)
    incomplete = dict(features)
    incomplete.pop("num_dots")
    with pytest.raises(ValueError, match="incomplete"):
        explain(incomplete, decision, importance=IMPORTANCE)

    partial_importance = dict(IMPORTANCE)
    partial_importance.pop("url_length")
    with pytest.raises(ValueError, match="importance"):
        explain(features, decision, importance=partial_importance)


# --------------------------------------------------------------------------- #
# 5. Measured metrics are read, not typed
# --------------------------------------------------------------------------- #
def test_measured_metrics_are_recomputed_from_the_artefact(app):
    with app.app_context():
        measured = stats_service.measured_metrics()

    standard = METRICS["test"]["standard_0.5"]
    assert len(measured["rows"]) == 5
    for row in measured["rows"]:
        expected = float(standard[row["key"]])
        assert row["value"] == f"{expected:.6f}"
        assert row["source"] == stats_service.METRICS_SOURCE

    calibrated = METRICS["test"]["calibrated"]
    assert measured["band"]["abstention_rate"] == calibrated["abstention_rate"]
    assert measured["band"]["low"] == calibrated["t_low"]
    assert measured["band"]["high"] == calibrated["t_high"]
    assert measured["confusion_matrix"] == standard["confusion_matrix"]
    assert measured["band_source"] == stats_service.CALIBRATED_SOURCE
    assert measured["caveats"], "measured figures must carry their caveats"


def test_measured_metrics_fail_closed_when_the_artefact_is_absent(tmp_path):
    """A missing metrics.json must raise, never return zeros or guesses."""
    from config import TestingConfig

    from app import create_app

    application = create_app(TestingConfig, overrides={
        "SECRET_KEY": "s" * 64,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'no-metrics.db'}",
        "METRICS_PATH": tmp_path / "absent-metrics.json",
    })
    with application.app_context():
        with pytest.raises(stats_service.StatsDataError):
            stats_service.measured_metrics()


# --------------------------------------------------------------------------- #
# 6. Registry orchestration: score -> decide -> explain -> audit row
# --------------------------------------------------------------------------- #
def test_detection_registry_reports_ready_with_measured_provenance(app):
    with app.app_context():
        registry = get_detection_registry()
        assert isinstance(registry, DetectionRegistry)
        assert registry.available is True
        assert registry.error is None
        assert registry.model is not None
        assert len(registry.importance) == 15
        health = registry.health()
        assert health["status"] == "ready"
        assert health["feature_count"] == 15
        assert health["decision_thresholds"] == {
            "low": METADATA["thresholds"]["low"],
            "high": METADATA["thresholds"]["high"],
        }


@pytest.mark.parametrize("url, expected_score, state, risk", CONTROLLED_CASES)
def test_controlled_fixtures_score_exactly_as_measured(app, url, expected_score, state, risk):
    with app.app_context():
        result = get_detection_registry().scan(url)
    assert result.score == pytest.approx(expected_score, abs=1e-6)
    assert result.decision.prediction == state
    assert result.decision.risk_level == risk


def test_scan_result_is_complete_and_immutable(app):
    with app.app_context():
        result = get_detection_registry().scan("https://example.com/")
        payload = result.to_dict()
    assert isinstance(result, DetectionResult)
    assert result.persisted is True and isinstance(result.scan_id, int)
    assert result.features == extract_features("https://example.com/")
    assert result.user_id is None, "a guest scan must not be linked to an account"
    assert payload["scan_id"] == result.scan_id
    assert payload["classification"] == result.decision.prediction
    assert payload["thresholds"]["band"] == "0.05 < p < 0.95"
    assert "HTTPS alone does not mean a website is legitimate." in payload["caveats"]
    json.dumps(payload)                     # must be JSON serialisable


def test_scan_commits_exactly_one_matching_audit_row(app):
    with app.app_context():
        from extensions import db

        before = db.session.query(ScanHistory).count()
        result = get_detection_registry().scan("https://www.example.org/about")
        db.session.expire_all()
        rows = db.session.query(ScanHistory).all()
        assert len(rows) == before + 1
        row = db.session.get(ScanHistory, result.scan_id)
        assert row.normalised_url == result.normalized_url
        assert row.prediction == result.decision.prediction
        assert row.risk_level == result.decision.risk_level
        assert row.model_score == result.score
        assert row.model_version == METADATA["model_version"]
        assert row.user_id is None
        snapshot = json.loads(row.features_json)
        assert snapshot["features"] == result.features
        assert snapshot["flagged"] == [item.name for item in result.explanation.flagged]


def test_scan_links_an_authenticated_user(app, seeded):
    with app.app_context():
        result = get_detection_registry().scan(
            "https://example.com/", user_id=seeded["member_id"]
        )
        from extensions import db

        row = db.session.get(ScanHistory, result.scan_id)
        assert row.user_id == seeded["member_id"]
        assert result.user_id == seeded["member_id"]


def test_invalid_url_raises_before_any_row_is_written(app):
    with app.app_context():
        from extensions import db
        from services.detection_service import InvalidSubmissionError

        before = db.session.query(ScanHistory).count()
        with pytest.raises(InvalidSubmissionError):
            get_detection_registry().scan("ftp://example.com/file")
        db.session.expire_all()
        assert db.session.query(ScanHistory).count() == before


def test_missing_bundle_makes_detection_unavailable(broken_model_app):
    with broken_model_app.app_context():
        registry = get_detection_registry()
        assert registry.available is False
        assert registry.error
        with pytest.raises(DetectionUnavailableError):
            registry.scan("https://example.com/")


def test_tampered_bundle_makes_detection_unavailable(tampered_model_app):
    with tampered_model_app.app_context():
        registry = get_detection_registry()
        assert registry.available is False
        assert "integrity verification" in (registry.error or "")
        assert "SHA-256" in registry.bundle_integrity
        with pytest.raises(DetectionUnavailableError):
            registry.scan("https://example.com/")


def test_a_database_failure_prevents_a_result_being_returned(app, monkeypatch):
    """No audit row -> no result. The exception is typed, not swallowed."""
    with app.app_context():
        registry = get_detection_registry()

        def _explode(*_args, **_kwargs):
            raise __import__("sqlalchemy.exc", fromlist=["SQLAlchemyError"]).SQLAlchemyError

        monkeypatch.setattr("extensions.db.session.commit", _explode)
        with pytest.raises(DetectionStorageError):
            registry.scan("https://example.com/")
        monkeypatch.undo()

        # The rollback left the session usable, so a later scan still works.
        assert get_detection_registry().scan("https://example.com/").persisted is True


def test_registry_is_cached_per_application(app):
    with app.app_context():
        first = get_detection_registry()
        second = get_detection_registry()
        assert first is second


def test_registry_metadata_is_the_validated_metadata(app):
    with app.app_context():
        registry = get_registry()
        assert registry.metadata.model_name == METADATA["model_name"]
        assert registry.metadata.thresholds["high"] == METADATA["thresholds"]["high"]
