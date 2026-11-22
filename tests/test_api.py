"""Versioned REST API tests (Stage 13).

Scope
-----
``routes/api.py`` - the ``/api/v1`` JSON surface delivered in Stage 12.

Contract under test (``docs/ARCHITECTURE.md`` section 11)
---------------------------------------------------------
    POST /api/v1/scan      { "url": "..." }  ->  200 with a fixed field set
    GET  /api/v1/model/info                   ->  model card + measured metrics
    GET  /api/v1/health                       ->  readiness only
    GET  /api/v1/csrf-token                   ->  token for state-changing calls
    GET  /api/v1/scans                        ->  scoped, filtered, paginated
    GET  /api/v1/scans/<id>                   ->  one authorised audit row

Rules proved here
-----------------
* The API calls the SAME ``DetectionRegistry.scan()`` as the HTML form, so one
  URL scores identically on both surfaces (no second inference path).
* Every response is JSON, including errors, and errors always use the
  ``{"error": {"code", "message", "status"}}`` shape with no traceback.
* Measured figures are returned only by ``/model/info``, and they equal what
  ``metrics.json`` contains - the test recomputes them independently.
* Visibility is scoped: a guest sees only ids in their own signed session.
* 503 ``MODEL_UNAVAILABLE`` is returned when the model cannot run; there is no
  rule-based substitute.

Synthetic URLs only; nothing is fetched.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from models.database_models import ScanHistory

ROOT = Path(__file__).resolve().parents[1]
METRICS = json.loads((ROOT / "ml" / "saved_model" / "metrics.json").read_text("utf-8"))
METADATA = json.loads((ROOT / "ml" / "saved_model" / "metadata.json").read_text("utf-8"))

SAFE_URL = "https://example.com/"
PHISHING_URL = "https://www.example.org/about"
BAND_SOURCE = "ml/saved_model/metadata.json#thresholds"

# The fields the architecture document promises for POST /api/v1/scan.
DOCUMENTED_SCAN_FIELDS = {
    "scan_id", "submitted_url", "normalized_url", "prediction", "model_score",
    "score_meaning", "risk_level", "decision_band", "flagged_features",
    "recommended_action", "scanned_at", "model",
}


def _error_code(response) -> str | None:
    payload = response.get_json(silent=True)
    if isinstance(payload, dict):
        return (payload.get("error") or {}).get("code")
    return None


# --------------------------------------------------------------------------- #
# 1. Public metadata endpoints
# --------------------------------------------------------------------------- #
def test_api_health_is_readiness_only(client, app):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["app_version"] == app.config["APP_VERSION"]
    assert payload["build_stage"] == app.config["BUILD_STAGE"]
    assert payload["build_stage"] >= 12, "Stage 12 or later built this app"
    assert payload["detection"]["status"] == "ready"
    serialised = json.dumps(payload).lower()
    for word in ("accuracy", "precision", "recall", "roc_auc", "f1_score"):
        assert word not in serialised, "health must not publish measured figures"


def test_api_csrf_token_endpoint_issues_a_usable_token(client):
    response = client.get("/api/v1/csrf-token")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["header_name"] == "X-CSRF-Token"
    assert len(payload["csrf_token"]) > 20


def test_model_info_returns_the_measured_card(client):
    response = client.get("/api/v1/model/info")
    assert response.status_code == 200
    payload = response.get_json()

    assert payload["status"] == "ok"
    assert payload["model"]["name"] == METADATA["model_name"]
    assert payload["model"]["version"] == METADATA["model_version"]
    assert payload["model"]["feature_count"] == 15
    assert payload["model"]["feature_order"] == METADATA["feature_order"]
    assert payload["decision_states"] == METADATA["decision_states"]
    assert payload["decision_thresholds"] == {
        "low": METADATA["thresholds"]["low"],
        "high": METADATA["thresholds"]["high"],
        "source": BAND_SOURCE,
    }


def test_model_info_metrics_equal_the_artifact_recomputed(client):
    """Independent recomputation: no figure may be typed into the route."""
    measured = client.get("/api/v1/model/info").get_json()["measured"]
    standard = METRICS["test"]["standard_0.5"]
    assert len(measured["rows"]) == 5
    for row in measured["rows"]:
        assert row["value"] == f"{float(standard[row['key']]):.6f}"
    assert measured["confusion_matrix"] == standard["confusion_matrix"]
    assert measured["band"]["abstention_rate"] == METRICS["test"]["calibrated"]["abstention_rate"]
    assert measured["source"] == "ml/saved_model/metrics.json#test.standard_0.5"
    assert len(measured["caveats"]) == 3


def test_model_info_reports_an_unavailable_artifact_as_503(tmp_path):
    from app import create_app
    from config import TestingConfig

    application = create_app(TestingConfig, overrides={
        "SECRET_KEY": "s" * 64,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'no-metrics.db'}",
        "METRICS_PATH": tmp_path / "absent.json",
    })
    with application.test_client() as client:
        response = client.get("/api/v1/model/info")
        assert response.status_code == 503
        assert _error_code(response) == "MODEL_UNAVAILABLE"


# --------------------------------------------------------------------------- #
# 2. POST /api/v1/scan - the documented contract
# --------------------------------------------------------------------------- #
def test_a_valid_scan_returns_the_full_documented_contract(client, api_scan):
    response = api_scan(client, SAFE_URL)
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    payload = response.get_json()
    assert payload["status"] == "ok"
    scan = payload["scan"]

    assert DOCUMENTED_SCAN_FIELDS <= set(scan), DOCUMENTED_SCAN_FIELDS - set(scan)
    assert scan["submitted_url"] == SAFE_URL
    assert scan["normalized_url"] == SAFE_URL
    assert scan["prediction"] in {"LEGITIMATE", "SUSPICIOUS", "PHISHING"}
    assert 0.0 <= scan["model_score"] <= 1.0
    assert scan["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
    assert isinstance(scan["flagged_features"], list)
    assert scan["decision_band"]["source"] == BAND_SOURCE
    assert scan["model"] == {
        "name": METADATA["model_name"], "version": METADATA["model_version"],
    }
    assert scan["scanned_at"].endswith("+00:00"), "timestamps must be UTC"
    assert scan["recommended_action"].strip()
    assert "uncalibrated" in scan["score_meaning"].lower()


def test_the_api_and_the_html_form_score_a_url_identically(client, api_scan):
    """One pipeline, two surfaces - the Stage 12 design rule."""
    api_score = api_scan(client, PHISHING_URL).get_json()["scan"]["model_score"]
    page = client.post("/scan", data={"url": PHISHING_URL})
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert f"{api_score:.6f}"[:8] in body or f"{api_score * 100:.2f}" in body


def test_a_scan_through_the_api_writes_exactly_one_audit_row(
    client, app, api_scan, scan_count
):
    api_scan(client, PHISHING_URL)
    assert scan_count() == 1
    with app.app_context():
        row = ScanHistory.query.one()
        assert row.user_id is None
        assert row.prediction == "PHISHING"
        assert row.normalised_url == PHISHING_URL


def test_an_authenticated_api_scan_is_linked_to_the_account(
    member_client, app, api_scan, seeded
):
    response = api_scan(member_client, SAFE_URL)
    assert response.status_code == 200
    with app.app_context():
        assert ScanHistory.query.one().user_id == seeded["member_id"]


def test_flagged_features_are_indicator_names_not_scores(client, api_scan):
    lookalike = ("https://paypal.com.login.verify.example.invalid"
                 "/secure/account/update?next=confirm")
    scan = api_scan(client, lookalike).get_json()["scan"]
    assert scan["flagged_features"] == [
        "has_suspicious_pattern", "num_suspicious_words",
    ]
    assert "has_https" not in scan["flagged_features"]


# --------------------------------------------------------------------------- #
# 3. POST /api/v1/scan - rejected input
# --------------------------------------------------------------------------- #
def test_a_non_json_body_is_rejected(client):
    response = client.post("/api/v1/scan", data={"url": SAFE_URL})
    assert response.status_code == 400
    assert _error_code(response) == "BAD_REQUEST"


def test_a_missing_url_field_is_rejected(client):
    response = client.post("/api/v1/scan", json={"website": SAFE_URL})
    assert response.status_code == 400
    assert _error_code(response) == "BAD_REQUEST"


def test_a_json_array_is_rejected(client):
    response = client.post("/api/v1/scan", json=[SAFE_URL])
    assert response.status_code == 400
    assert _error_code(response) == "BAD_REQUEST"


@pytest.mark.parametrize("bad_url", ["", "   ", None, 42, ["https://example.com"]])
def test_a_non_string_or_empty_url_is_rejected(client, bad_url):
    response = client.post("/api/v1/scan", json={"url": bad_url})
    assert response.status_code == 400
    assert _error_code(response) in {"INVALID_URL", "BAD_REQUEST"}


@pytest.mark.parametrize(
    "bad_url",
    ["not a url", "ftp://example.com/file", "javascript:alert(1)", "example .com"],
)
def test_an_invalid_url_returns_invalid_url(client, bad_url, scan_count):
    response = client.post("/api/v1/scan", json={"url": bad_url})
    assert response.status_code == 400
    assert _error_code(response) == "INVALID_URL"
    assert scan_count() == 0


def test_the_invalid_url_message_never_echoes_the_input(client):
    payload = "javascript:alert('reflected-xss')"
    body = client.post("/api/v1/scan", json={"url": payload}).get_data(as_text=True)
    assert payload not in body


# --------------------------------------------------------------------------- #
# 4. Scoped history endpoints
# --------------------------------------------------------------------------- #
def test_scans_lists_only_the_callers_session_rows(client, app, api_scan):
    api_scan(client, SAFE_URL)
    api_scan(client, PHISHING_URL)

    payload = client.get("/api/v1/scans").get_json()
    assert payload["status"] == "ok"
    assert payload["scope"] == "session"
    assert payload["total"] == 2
    assert len(payload["scans"]) == 2

    with app.test_client() as stranger:
        other = stranger.get("/api/v1/scans").get_json()
        assert other["total"] == 0
        assert other["scans"] == []


def test_scans_scope_switches_to_the_account_when_signed_in(member_client, api_scan):
    api_scan(member_client, SAFE_URL)
    payload = member_client.get("/api/v1/scans").get_json()
    assert payload["scope"] == "account"
    assert payload["total"] == 1


def test_scans_filters_are_validated_and_applied(client, api_scan):
    api_scan(client, SAFE_URL)
    api_scan(client, PHISHING_URL)
    payload = client.get("/api/v1/scans?prediction=PHISHING").get_json()
    assert payload["total"] == 1
    assert payload["scans"][0]["prediction"] == "PHISHING"
    assert payload["filters"]["prediction"] == "PHISHING"

    ignored = client.get("/api/v1/scans?prediction=NOT_A_STATE").get_json()
    assert ignored["filters"]["prediction"] == ""
    assert ignored["total"] == 2


def test_scans_pagination_is_clamped(client, api_scan):
    for _ in range(3):
        api_scan(client, SAFE_URL)
    payload = client.get("/api/v1/scans?per_page=99999&page=99999").get_json()
    assert payload["per_page"] == 100
    assert payload["page"] == 1
    assert payload["pages"] == 1


def test_a_caller_can_read_their_own_scan_detail(client, api_scan):
    created = api_scan(client, PHISHING_URL).get_json()["scan"]
    response = client.get(f"/api/v1/scans/{created['scan_id']}")
    assert response.status_code == 200
    stored = response.get_json()["scan"]
    assert stored["scan_id"] == created["scan_id"]
    assert stored["prediction"] == created["prediction"]
    assert stored["model_score"] == created["model_score"]
    assert stored["decision_band"]["source"] == BAND_SOURCE


def test_scan_detail_is_404_for_another_visitor(client, app, api_scan):
    created = api_scan(client, SAFE_URL).get_json()["scan"]
    with app.test_client() as stranger:
        response = stranger.get(f"/api/v1/scans/{created['scan_id']}")
    assert response.status_code == 404
    assert _error_code(response) == "NOT_FOUND"


def test_scan_detail_is_404_for_a_missing_id(client):
    response = client.get("/api/v1/scans/999999")
    assert response.status_code == 404
    assert _error_code(response) == "NOT_FOUND"


def test_the_two_404_cases_are_indistinguishable(client, app, api_scan):
    """No enumeration: a forbidden row and a missing row look the same."""
    created = api_scan(client, SAFE_URL).get_json()["scan"]
    with app.test_client() as stranger:
        forbidden = stranger.get(f"/api/v1/scans/{created['scan_id']}")
        missing = stranger.get("/api/v1/scans/999999")
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.get_json() == missing.get_json()


# --------------------------------------------------------------------------- #
# 5. Method, error-shape and content-type discipline
# --------------------------------------------------------------------------- #
def test_unsupported_methods_return_a_json_405(client):
    response = client.get("/api/v1/scan")
    assert response.status_code == 405
    assert response.mimetype == "application/json"
    assert _error_code(response) == "METHOD_NOT_ALLOWED"


def test_api_errors_never_leak_a_traceback_or_path(client):
    body = client.get("/api/v1/scans/999999").get_data(as_text=True)
    assert "Traceback" not in body
    assert "/home/" not in body
    assert "sqlalchemy" not in body.lower()


def test_every_api_error_uses_the_documented_envelope(client):
    for response in (
        client.post("/api/v1/scan", json={"url": "not a url"}),
        client.get("/api/v1/scans/999999"),
        client.get("/api/v1/scan"),
    ):
        payload = response.get_json()
        assert set(payload) == {"error"}
        assert set(payload["error"]) == {"code", "message", "status"}
        assert payload["error"]["status"] == response.status_code
        assert isinstance(payload["error"]["message"], str) and payload["error"]["message"]


def test_api_responses_are_not_cached(client):
    for path in ("/api/v1/health", "/api/v1/scans", "/api/v1/model/info"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers.get("Cache-Control") == "no-store"


def test_a_broken_model_returns_503_on_the_api_too(broken_model_app):
    """A broken model must surface as 503 on the API - never a guess."""
    with broken_model_app.test_client() as client:
        response = client.post("/api/v1/scan", json={"url": SAFE_URL})
        assert response.status_code == 503
        assert _error_code(response) == "MODEL_UNAVAILABLE"
