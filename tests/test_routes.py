"""HTML route, session, history, dashboard and admin tests (Stage 13).

Scope
-----
The browser-facing surface: ``routes/core.py``, ``routes/auth.py``,
``routes/scanning.py``, ``routes/dashboard.py``, ``routes/history.py`` and
``routes/admin.py``, exercised through Flask's test client.

What is proved here
-------------------
* The exact ``SCAN WEBSITE`` control is still present and POSTs the form.
* One scan = one audit row, linked to the account only when signed in.
* A guest can open the report for a scan made in *their own* session, and gets
  an identical generic 404 for anybody else's row (no enumeration).
* History/CSV obey the same visibility rule; the dashboard shows counts read
  from SQL at request time, not demo data.
* ``/admin`` returns 401 for anonymous and 403 for ordinary users, and never
  exposes a password hash.
* Failure paths are explicit: ``503 MODEL_UNAVAILABLE`` without a model and
  ``503 DATABASE_UNAVAILABLE`` without a schema. No result is ever invented.

Only synthetic URLs (``example.com`` / ``example.org``) are submitted.
"""
from __future__ import annotations

import csv
import io
import json
import re

import pytest

from models.database_models import ScanHistory, User
from services.report_service import CSV_COLUMNS

SAFE_URL = "https://example.com/"
PHISHING_URL = "https://www.example.org/about"
STRONG_PASSWORD = "Str0ng-Passw0rd!2026"


# --------------------------------------------------------------------------- #
# 1. Overview, health and favicon
# --------------------------------------------------------------------------- #
def test_overview_page_renders_without_measured_figures(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Intelligent Phishing Website Detection System" in body
    for word in ("accuracy", "precision", "recall", "roc_auc"):
        assert word not in body.lower(), f"the overview must not publish {word}"


def test_health_endpoint_reports_a_ready_engine_and_real_counts(client, app):
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    # The endpoint must report the CONFIGURED version, never a hard-coded one.
    assert payload["version"] == app.config["APP_VERSION"]
    assert re.fullmatch(r"0\.\d+\.\d+", payload["version"])
    assert payload["build_stage"] == app.config["BUILD_STAGE"]
    assert payload["build_stage"] >= 12, "Stage 12 or later built this app"
    assert payload["detection"]["status"] == "ready"
    assert payload["database"]["status"] == "ready"
    assert payload["database"]["foreign_keys_enabled"] is True
    assert set(payload["database"]["tables"]) == {
        "users", "scan_history", "model_information"
    }
    serialised = json.dumps(payload).lower()
    for word in ("accuracy", "precision", "recall", "f1_score", "roc_auc"):
        assert word not in serialised


def test_favicon_returns_no_content_instead_of_404(client):
    assert client.get("/favicon.ico").status_code == 204


def test_unknown_route_returns_the_themed_error_page(client):
    response = client.get("/definitely-not-a-route")
    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert "NOT_FOUND" in body
    assert "Traceback" not in body


def test_unknown_route_returns_json_when_json_is_requested(client):
    response = client.get("/definitely-not-a-route?format=json")
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "NOT_FOUND"


# --------------------------------------------------------------------------- #
# 2. The scan form and result
# --------------------------------------------------------------------------- #
def test_scan_form_keeps_the_exact_primary_control(client):
    response = client.get("/scan")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "SCAN WEBSITE" in body
    assert 'name="url"' in body
    assert 'name="csrf_token"' in body
    assert 'action="/scan"' in body or "action=\"/scan\"" in body


def test_posting_a_url_renders_a_result_and_writes_one_audit_row(
    client, app, scan_count
):
    response = client.post("/scan", data={"url": PHISHING_URL})
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "PHISHING" in body
    assert "SCAN WEBSITE" in body
    assert scan_count() == 1

    with app.app_context():
        row = ScanHistory.query.one()
        assert row.user_id is None, "a guest scan must have user_id NULL"
        assert row.normalised_url == PHISHING_URL
        assert row.prediction == "PHISHING"
        assert 0.99 <= row.model_score <= 1.0
        assert row.model_version == "1.0.0"


def test_the_three_decision_states_are_all_reachable_through_the_form(
    client, app
):
    seen = set()
    for url in ("https://example.com", "https://example.com/", PHISHING_URL):
        assert client.post("/scan", data={"url": url}).status_code == 200
        with app.app_context():
            seen.add(ScanHistory.query.order_by(ScanHistory.id.desc()).first().prediction)
    assert seen == {"LEGITIMATE", "SUSPICIOUS", "PHISHING"}


def test_a_signed_in_scan_is_linked_to_the_account(member_client, app, seeded):
    response = member_client.post("/scan", data={"url": SAFE_URL})
    assert response.status_code == 200
    with app.app_context():
        row = ScanHistory.query.one()
        assert row.user_id == seeded["member_id"]


def test_an_invalid_url_is_rejected_without_writing_a_row(client, scan_count):
    response = client.post("/scan", data={"url": "not a url"})
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "Invalid URL" in body
    assert scan_count() == 0, "a rejected URL must never create an audit row"


def test_a_missing_url_field_is_rejected(client, scan_count):
    assert client.post("/scan", data={}).status_code == 400
    assert scan_count() == 0


def test_a_submitted_url_is_escaped_and_can_never_execute_script(client):
    payload = "https://example.com/<script>alert('xss')</script>"
    response = client.post("/scan", data={"url": payload})
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "<script>alert('xss')</script>" not in body
    assert "&lt;script&gt;" in body


def test_the_result_page_never_presents_the_score_as_a_probability(client):
    response = client.post("/scan", data={"url": SAFE_URL})
    body = response.get_data(as_text=True).lower()
    assert "uncalibrated" in body
    assert "https alone does not mean a website is legitimate" in body


# --------------------------------------------------------------------------- #
# 3. Printable report visibility
# --------------------------------------------------------------------------- #
def test_a_guest_can_open_the_report_for_their_own_scan(client, app):
    client.post("/scan", data={"url": SAFE_URL})
    with app.app_context():
        scan_id = ScanHistory.query.one().id
    response = client.get(f"/scan/{scan_id}/report")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "LEGITIMATE" in body or "SUSPICIOUS" in body
    assert "example.com" in body


def test_another_browser_cannot_open_a_guest_report(client, app):
    client.post("/scan", data={"url": SAFE_URL})
    with app.app_context():
        scan_id = ScanHistory.query.one().id
    with app.test_client() as stranger:
        assert stranger.get(f"/scan/{scan_id}/report").status_code == 404


def test_a_user_cannot_open_another_users_report(member_client, app, seeded):
    """The member's own scan is visible; the admin cannot read it."""
    member_client.post("/scan", data={"url": SAFE_URL})
    with app.app_context():
        scan_id = ScanHistory.query.one().id

    admin = app.test_client()
    assert admin.post("/login", json={
        "username": "testadmin", "password": STRONG_PASSWORD
    }).status_code == 200
    assert admin.get(f"/scan/{scan_id}/report").status_code == 404
    assert member_client.get(f"/scan/{scan_id}/report").status_code == 200


def test_a_missing_report_is_indistinguishable_from_a_forbidden_one(client):
    assert client.get("/scan/999999/report").status_code == 404
    body = client.get("/scan/999999/report").get_data(as_text=True)
    assert "not available" in body.lower()
    assert "Traceback" not in body


# --------------------------------------------------------------------------- #
# 4. History and CSV export
# --------------------------------------------------------------------------- #
def test_history_shows_only_the_callers_own_scans(client, app):
    client.post("/scan", data={"url": SAFE_URL})
    client.post("/scan", data={"url": PHISHING_URL})
    body = client.get("/history").get_data(as_text=True)
    assert "2 matching scans" in body

    with app.test_client() as stranger:
        other = stranger.get("/history").get_data(as_text=True)
        assert "0 matching scans" in other
        assert "example.org" not in other


def test_history_filters_by_prediction_state(client, app):
    client.post("/scan", data={"url": SAFE_URL})
    client.post("/scan", data={"url": PHISHING_URL})
    body = client.get("/history?prediction=PHISHING").get_data(as_text=True)
    assert "1 matching scan" in body
    assert "example.org" in body
    assert "2 matching scans" not in body


def test_history_ignores_an_invalid_filter_value(client):
    response = client.get("/history?prediction=DROP%20TABLE&risk=EVIL&per_page=99999")
    assert response.status_code == 200
    assert "matching scan" in response.get_data(as_text=True)


def test_history_pagination_is_clamped_server_side(client):
    for _ in range(3):
        client.post("/scan", data={"url": SAFE_URL})
    body = client.get("/history?per_page=99999&page=99999").get_data(as_text=True)
    assert "100 per page" in body, "per_page must be clamped to MAX_PER_PAGE"
    assert "page 1 of 1" in body


def test_history_sql_injection_in_the_search_box_is_harmless(client):
    client.post("/scan", data={"url": SAFE_URL})
    for payload in ("%' OR 1=1 --", "'; DROP TABLE scan_history; --", "%"):
        response = client.get("/history", query_string={"q": payload})
        assert response.status_code == 200
    # The table is still there and still holds the row.
    assert "1 matching scan" in client.get("/history").get_data(as_text=True)


def test_csv_export_contains_only_the_callers_rows(client):
    client.post("/scan", data={"url": SAFE_URL})
    response = client.get("/history/export.csv")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]
    assert response.headers["Cache-Control"] == "no-store"

    body = response.get_data(as_text=True)
    assert body.startswith("\ufeff"), "a UTF-8 BOM helps Excel on Windows"
    rows = list(csv.reader(io.StringIO(body.lstrip("\ufeff"))))
    assert rows[0] == list(CSV_COLUMNS)
    assert len(rows) == 2, "header + the caller's single scan"
    assert rows[1][2] == SAFE_URL
    assert "password" not in body.lower()


def test_csv_export_is_empty_but_valid_for_a_visitor_without_scans(client):
    response = client.get("/history/export.csv")
    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(
        response.get_data(as_text=True).lstrip("\ufeff")
    )))
    assert rows == [list(CSV_COLUMNS)]


# --------------------------------------------------------------------------- #
# 5. Dashboard: live counts, measured metrics at runtime
# --------------------------------------------------------------------------- #
def test_dashboard_counts_come_from_the_database(client, app):
    for _ in range(3):
        client.post("/scan", data={"url": SAFE_URL})
    body = client.get("/dashboard").get_data(as_text=True)
    assert 'id="statTotal">3<' in body
    assert "scan_history" in body


def test_dashboard_shows_measured_metrics_with_their_source(client, app):
    from services import stats_service

    with app.app_context():
        measured = stats_service.measured_metrics()
    body = client.get("/dashboard").get_data(as_text=True)
    assert measured["rows"][0]["value"] in body
    assert "metrics.json" in body
    assert "not measurements of live traffic" in body


def test_dashboard_is_public_but_reveals_no_submitted_url(client, app):
    """The dashboard publishes counts, never another visitor's URL."""
    client.post("/scan", data={"url": PHISHING_URL})
    response = client.get("/dashboard")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert PHISHING_URL not in body
    assert "example.org" not in body
    assert 'id="statTotal">1<' in body


# --------------------------------------------------------------------------- #
# 6. Admin area authorisation
# --------------------------------------------------------------------------- #
def test_admin_requires_authentication(client):
    response = client.get("/admin")
    assert response.status_code == 401
    json_response = client.get("/admin?format=json")
    assert json_response.get_json()["error"]["code"] == "UNAUTHENTICATED"


def test_admin_forbids_an_ordinary_signed_in_user(member_client):
    response = member_client.get("/admin")
    assert response.status_code == 403
    assert member_client.get("/admin?format=json").get_json()["error"]["code"] == "FORBIDDEN"


def test_admin_view_renders_for_an_administrator_without_hashes(admin_client, app):
    response = admin_client.get("/admin")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "testadmin" in body
    assert "scrypt:" not in body
    assert "password_hash" not in body


def test_admin_export_is_authorised_only_for_administrators(member_client, admin_client, client):
    assert client.get("/admin/export.csv").status_code == 401
    assert member_client.get("/admin/export.csv").status_code == 403
    response = admin_client.get("/admin/export.csv")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"


def test_admin_export_sees_other_users_rows_but_history_does_not(
    member_client, admin_client, app
):
    member_client.post("/scan", data={"url": SAFE_URL})
    admin_csv = admin_client.get("/admin/export.csv").get_data(as_text=True)
    assert SAFE_URL in admin_csv
    with app.test_client() as stranger:
        assert SAFE_URL not in stranger.get("/history/export.csv").get_data(as_text=True)


# --------------------------------------------------------------------------- #
# 7. Accounts: registration, sign-in, logout, session hygiene
# --------------------------------------------------------------------------- #
def test_registration_creates_an_ordinary_user_and_ignores_a_role_field(
    client, app
):
    response = client.post("/register", json={
        "username": "newcomer",
        "email": "newcomer@example.com",
        "password": STRONG_PASSWORD,
        "confirm_password": STRONG_PASSWORD,
        "role": "admin",                 # privilege escalation attempt
    })
    assert response.status_code == 201
    assert response.get_json()["authenticated"] is False
    with app.app_context():
        user = User.query.filter_by(username="newcomer").one()
        assert user.role == "user", "self-registration must never grant admin"
        assert user.password_hash.startswith("scrypt:")


def test_registration_rejects_a_weak_password_with_safe_details(client, app):
    response = client.post("/register", json={
        "username": "weakuser",
        "email": "weak@example.com",
        "password": "password1",
    })
    assert response.status_code == 400
    payload = response.get_json()["error"]
    assert payload["code"] == "INVALID_REGISTRATION"
    assert any("12 characters" in item for item in payload["details"])
    assert "password1" not in json.dumps(payload)
    with app.app_context():
        assert User.query.filter_by(username="weakuser").first() is None


def test_registration_rejects_a_mismatched_confirmation(client, app):
    response = client.post("/register", json={
        "username": "mismatch",
        "email": "mismatch@example.com",
        "password": STRONG_PASSWORD,
        "confirm_password": STRONG_PASSWORD + "x",
    })
    assert response.status_code == 400
    assert "do not match" in " ".join(response.get_json()["error"]["details"])


def test_registration_does_not_reveal_which_field_is_taken(client, app):
    for username, email in (("testmember", "fresh@example.com"),
                            ("freshname", "testmember@example.com")):
        response = client.post("/register", json={
            "username": username, "email": email,
            "password": STRONG_PASSWORD, "confirm_password": STRONG_PASSWORD,
        })
        assert response.status_code == 400
        assert "already registered" in response.get_json()["error"]["message"]


def test_login_failure_is_generic_for_unknown_and_wrong_credentials(client):
    unknown = client.post("/login", json={"username": "ghost", "password": "whatever"})
    wrong = client.post("/login", json={
        "username": "testmember", "password": "wrong-but-long-enough",
    })
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json() == wrong.get_json()
    assert unknown.get_json()["error"]["code"] == "UNAUTHENTICATED"


def test_login_by_email_also_works(client):
    response = client.post("/login", json={
        "email": "testmember@example.com", "password": STRONG_PASSWORD,
    })
    assert response.status_code == 200
    assert response.get_json()["authenticated"] is True


def test_session_is_cleared_on_login_and_logout(client, app):
    """Session-fixation defence and guest-scan privacy."""
    client.post("/scan", data={"url": SAFE_URL})
    with client.session_transaction() as session:
        assert session.get("guest_scan_ids"), "the guest id must be remembered"

    assert client.post("/login", json={
        "username": "testmember", "password": STRONG_PASSWORD,
    }).status_code == 200
    with client.session_transaction() as session:
        assert not session.get("guest_scan_ids"), "login clears the old session"

    assert client.post("/logout").status_code == 200
    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_session_endpoint_describes_the_real_state(client):
    payload = client.get("/auth/session").get_json()
    assert payload["authenticated"] is False
    assert payload["guest_scans_allowed"] is True
    assert payload["csrf_protection_enabled"] is False   # TestingConfig
    assert payload["login_available"] and payload["register_available"]


def test_account_routes_do_not_echo_the_password(client):
    response = client.post("/login", json={
        "username": "testmember", "password": "SuperSecret-Value-9!",
    })
    assert "SuperSecret-Value-9!" not in response.get_data(as_text=True)


# --------------------------------------------------------------------------- #
# 8. Explicit failure paths (the "no invented result" rule)
# --------------------------------------------------------------------------- #
def test_without_a_model_the_scan_page_reports_unavailability(
    broken_model_app
):
    with broken_model_app.test_client() as client:
        page = client.get("/scan")
        assert page.status_code == 200
        assert "unavailable" in page.get_data(as_text=True).lower()

        response = client.post("/scan", data={"url": SAFE_URL})
        assert response.status_code == 503
        assert "MODEL_UNAVAILABLE" in response.get_data(as_text=True)

        health = client.get("/health")
        assert health.status_code == 503
        assert health.get_json()["error"]["code"] == "MODEL_UNAVAILABLE"


def test_without_a_database_the_scan_fails_closed(no_schema_app):
    with no_schema_app.test_client() as client:
        response = client.post("/scan", data={"url": SAFE_URL})
        assert response.status_code == 503
        assert "DATABASE_UNAVAILABLE" in response.get_data(as_text=True)


def test_account_post_requires_an_initialised_schema(no_schema_app):
    with no_schema_app.test_client() as client:
        response = client.post("/login", json={
            "username": "testmember", "password": STRONG_PASSWORD,
        })
        assert response.status_code == 503
        assert response.get_json()["error"]["code"] == "DATABASE_UNAVAILABLE"


def test_health_reports_an_uninitialised_schema_honestly(no_schema_app):
    with no_schema_app.test_client() as client:
        payload = client.get("/health").get_json()
        assert payload["database"]["status"] == "not_initialised"
        assert payload["database"]["tables"] == []
        assert set(payload["database"]["missing_tables"]) == {
            "users", "scan_history", "model_information"
        }


def test_an_unexpected_error_returns_a_generic_500(raising_app):
    with raising_app.test_client() as client:
        response = client.get("/boom-for-tests")
        body = response.get_data(as_text=True)
        assert response.status_code == 500
        assert "INTERNAL_ERROR" in body
        assert "deliberate failure" not in body
        assert "/home/user" not in body
        assert "Traceback" not in body
