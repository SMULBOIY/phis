# Test Plan — Intelligent Phishing Website Detection System

**Stage 13 deliverable.** The formal `pytest` suite, its fixtures, its coverage
map against the project brief, and the measured result of running it.

| Item | Value |
| --- | --- |
| Exit gate for this stage | `pytest -v` — the full suite |
| Test modules | `tests/conftest.py`, `test_features.py`, `test_model.py`, `test_routes.py`, `test_api.py`, `test_security.py` |
| Test functions | 203 |
| **Test cases (with parametrisation)** | **259** |
| Measured runtime | ~7 s on the verified environment (`docs/ENVIRONMENT.md`) |
| Test data | Synthetic, controlled URL strings only |
| Live malicious sites contacted | **None** |
| Real database touched | **No** — `instance/phishing.db` is never opened by the suite |

> **Why the gate is `pytest` and not a `verify_stage13.py`:** `docs/STAGE_PLAN.md`
> states from Stage 1 that Stages 1–9 have executable `scripts/verify_stageN.py`
> gates and that **Stage 13's gate is the full `pytest` suite**. Stages 10–12
> followed that rule by shipping both a `verify_*.py` gate *and* deferring the
> formal suite to this stage. Adding a thirteenth `verify_*.py` would duplicate
> `pytest` and contradict the published plan, so it is deliberately absent — and
> `scripts/verify_stage12.py` asserts that it never appears.

---

## 1. Purpose and scope

The suite proves the four things an examiner will check first:

1. **Correctness** — the 15-feature contract, the three decision states, the
   REST contract and the routes behave exactly as documented.
2. **Academic integrity** — every published performance figure is *recomputed
   from `ml/saved_model/metrics.json`* inside the test, never trusted from a
   template or a constant. A missing artefact fails closed instead of showing
   zeros.
3. **Security** — CSRF on every state-changing request (including
   `POST /api/v1/scan`), scrypt hashing, Jinja2 autoescaping, the exact CSP,
   session visibility, and **no outbound network I/O whatsoever**.
4. **Honest failure** — when the model or the database is unavailable the system
   returns an explicit `503` and never invents a verdict.

**Out of scope for Stage 13:** no feature was added, no pipeline was changed, no
template was redesigned. This stage is tests plus this document.

---

## 2. How to run the suite

### Windows (PowerShell) — primary

```powershell
# From the project root, with the virtual environment active
.\.venv\Scripts\Activate.ps1

# The whole exit gate
python -m pytest -v

# Quiet summary
python -m pytest -q

# One module
python -m pytest tests\test_security.py -v

# One test by name
python -m pytest tests\test_api.py -k "csrf or 429" -v

# Stop at the first failure (useful while debugging)
python -m pytest -x

# Show the full diff for a failing assertion
python -m pytest -vv
```

### Linux / macOS — secondary

```bash
source .venv/bin/activate
python -m pytest -v
```

### Expected result

```text
259 passed in 7.07s
```

No warnings, no xfails, no skips. If you see a different number, a later stage
has added tests — that is expected; the gate is "the suite is green", not a
frozen count.

### Running the historical gates as regression

`pytest` proves the current stage. The twelve closed gates are re-run separately
(see §8). They are not invoked from inside `pytest` because Gate 12 alone starts
a real HTTP server and re-runs Gates 1–11, which would make the suite slow and
recursive.

---

## 3. Test environment and isolation

Every fixture lives in `tests/conftest.py`. Nothing in it reads the real
database, the real `.env`, or the network.

| Fixture | What it builds | Why it exists |
| --- | --- | --- |
| `app` (session) | `TestingConfig` app on a **temporary SQLite file** outside the repo | Ordinary HTTP tests, with CSRF and rate limiting off for determinism |
| `clean_database` (autouse) | Truncates `scan_history` and non-seeded users around every test that uses `app` | Test-order independence without re-paying scrypt cost |
| `client` | A fresh `app.test_client()` (own cookie jar) | Each test is a different "browser" |
| `seeded` | Ids of the two seeded accounts, read from the database | No hard-coded primary keys |
| `member_client` / `admin_client` | Signed-in clients (`role='user'` / `role='admin'`) | Authorisation tests |
| `csrf_app` / `csrf_client` | App with **`WTF_CSRF_ENABLED=True`** | Proves CSRF is really enforced |
| `limited_app` | App with **`RATELIMIT_ENABLED=True`** and tiny quotas | Proves the 429 contract |
| `production_app` | `ProductionConfig` | Proves `DENY`, `frame-ancestors`, HSTS, secure cookies |
| `broken_model_app` | Bundle path pointing at a missing file | Proves `503 MODEL_UNAVAILABLE` |
| `tampered_model_app` | Bundle bytes modified after hashing | Proves the SHA-256 check fails closed |
| `no_schema_app` | Database file that was never initialised | Proves `503 DATABASE_UNAVAILABLE` |
| `raising_app` | Extra route that raises, `PROPAGATE_EXCEPTIONS=False` | Proves the generic 500 handler |
| `login_as`, `csrf_token_for`, `api_scan`, `scan_count` | Small callables | Readable tests, no helper module |

### Design decisions worth defending

* **`TestingConfig` turns CSRF and rate limiting off.** That is the documented
  purpose of the class (`config.py`). The tests that care switch both back on
  through `csrf_app` and `limited_app`, so the relaxations are *tested*, never
  assumed. `extensions.limits_disabled()` reads the effective config at request
  time, which keeps several differently-configured apps safe in one process.
* **Passwords are hashed once per session.** scrypt is deliberately slow; the
  hash is reused when seeding accounts. The production hashing contract still
  runs (and is asserted) in `test_security.py`.
* **Test clients are never used as context managers.** `with app.test_client()`
  sets `preserve_context=True`, which keeps one Flask application context alive
  between requests. Flask-Login caches `current_user` on `g`, so two simulated
  browsers would silently share one login. A plain client gives each request the
  clean context a real visitor gets. (This was found by the suite itself — see
  §7.)
* **Seeded usernames are never truncated away.** The autouse fixture removes
  only rows a test created, so `admin_client` and `member_client` stay valid in
  any order.

---

## 4. Coverage map against the brief

The brief lists the required test groups and forbids testing against live
malicious websites. Each row below is proven by named tests.

| Brief / architecture requirement | Module | Representative tests |
| --- | --- | --- |
| Unit tests for all 15 features (C21, Stage 4) | `test_features.py` | `test_raw_counts_are_counted_from_the_normalised_string`, `test_ip_address_host_is_flagged_and_has_no_subdomains`, `test_percent_and_legacy_encoded_characters_are_detected`, `test_brand_as_the_real_domain_is_not_flagged` |
| Identical train/live output (parity) | `test_features.py` | `test_a_url_and_its_canonical_form_produce_one_vector`, `test_repeated_extraction_of_equivalent_spellings_agrees`, `test_extract_frame_matches_single_extraction_for_every_row` |
| Only three decision states | `test_model.py` | `test_state_constants_are_exactly_three_and_named_as_documented`, `test_decide_maps_scores_to_the_documented_states` (7 cases), `test_decision_codes_use_the_measured_boundaries_inclusively` |
| Thresholds are measured, not typed | `test_model.py` | `test_metadata_thresholds_satisfy_the_documented_band`, `test_measured_metrics_are_recomputed_from_the_artefact`, `test_model_info_metrics_equal_the_artifact_recomputed` |
| Model loading / integrity failure | `test_model.py`, `test_routes.py`, `test_api.py` | `test_a_missing_bundle_is_reported_not_guessed`, `test_a_tampered_bundle_fails_hash_verification`, `test_without_a_model_the_scan_page_reports_unavailability`, `test_a_broken_model_returns_503_on_the_api_too` |
| End-to-end scan writes an audit row | `test_routes.py`, `test_api.py` | `test_posting_a_url_renders_a_result_and_writes_one_audit_row`, `test_scan_commits_exactly_one_matching_audit_row` |
| Guest scans allowed (`user_id` NULL) | `test_routes.py`, `test_api.py` | `test_a_signed_in_scan_is_linked_to_the_account`, `test_scan_links_an_authenticated_user`, `test_a_scan_through_the_api_writes_exactly_one_audit_row` |
| CRUD / schema / database behaviour (Stage 8) | `test_routes.py`, `test_model.py` | `test_health_endpoint_reports_a_ready_engine_and_real_counts`, `test_health_reports_an_uninitialised_schema_honestly`, `test_account_post_requires_an_initialised_schema` |
| Dashboard equals real SQL counts (C14, Stage 11) | `test_routes.py` | `test_dashboard_counts_come_from_the_database`, `test_dashboard_shows_measured_metrics_with_their_source`, `test_dashboard_is_public_but_reveals_no_submitted_url` |
| Role restrictions | `test_routes.py` | `test_admin_requires_authentication`, `test_admin_forbids_an_ordinary_signed_in_user`, `test_registration_creates_an_ordinary_user_and_ignores_a_role_field` |
| CSV export safety | `test_routes.py` | `test_csv_export_contains_only_the_callers_rows`, `test_admin_export_sees_other_users_rows_but_history_does_not` |
| CSRF everywhere (C9, Stage 12) | `test_security.py` | `test_the_html_scan_form_requires_a_csrf_token`, `test_the_rest_api_post_is_not_exempt_from_csrf`, `test_login_and_register_are_csrf_protected`, `test_no_route_exempts_itself_from_csrf` |
| Rate limiting + 429 contract | `test_security.py` | `test_login_is_throttled_with_the_documented_429_contract`, `test_the_scan_endpoint_has_its_own_quota`, `test_the_api_scan_is_throttled_and_keeps_the_json_shape` |
| Scrypt hashing, no plaintext | `test_security.py` | `test_passwords_are_stored_only_as_scrypt_hashes`, `test_two_accounts_with_the_same_password_get_different_hashes`, `test_the_hash_is_never_included_in_a_response` |
| XSS / CSP / headers | `test_security.py` | `test_every_response_carries_the_exact_csp`, `test_a_reflected_script_in_a_url_is_escaped_on_the_result_page`, `test_a_report_page_escapes_a_stored_url` |
| SSRF prevention (zero outbound calls) | `test_security.py` | `test_a_scan_succeeds_even_when_the_network_layer_is_broken`, `test_internal_targets_are_analysed_as_strings_never_fetched` (5 targets), `test_no_network_library_is_imported_by_the_application` |
| REST API contract and errors | `test_api.py` | `test_a_valid_scan_returns_the_full_documented_contract`, `test_every_api_error_uses_the_documented_envelope`, `test_unsupported_methods_return_a_json_405` |
| Session visibility / no enumeration | `test_api.py`, `test_routes.py` | `test_the_two_404_cases_are_indistinguishable`, `test_another_browser_cannot_open_a_guest_report`, `test_scans_lists_only_the_callers_session_rows` |
| Safe testing (no live malicious sites) | all modules | Every URL is `example.com` / `example.org` / `example.invalid`, or an RFC 5737/2606 reserved address |

---

## 5. Test catalogue by module

### `tests/test_features.py` — 49 functions / 73 cases

1. **Contract** — 15 unique names in `FEATURE_ORDER`; definitions and rationales
   cover it exactly; the shortener/brand/word vocabularies are local.
2. **Shape and determinism** — order preserved, every value an `int`, no NaN or
   infinity, repeated extraction identical, mutating a result cannot poison the
   next call.
3. **`features_to_frame` / `extract_frame`** — column order equals the contract,
   an incomplete vector raises, batch output equals row-by-row extraction.
4. **Parity** — a URL and its canonical form give one vector; four equivalent
   spellings collapse to a single vector; path case is preserved.
5. **Per-feature semantics** — counts, `domain_length` excluding userinfo/port,
   structural punctuation excluded from `num_special_chars`, IP hosts,
   `@` userinfo, HTTPS flag, shorteners, suspicious words (case-insensitive),
   non-default ports, percent and `%uXXXX` encoding, subdomain depth, brand in a
   lookalike host, brand as the real domain, `//` in path, repeated `?`, deep
   chains.
6. **Fail closed** — 13 parametrised invalid inputs, an over-long URL and a
   tightened `max_length` all raise `ValueError`.
7. **URL helpers** — default scheme, idempotence, rejected schemes/hosts,
   preserved userinfo and non-default ports, verbatim path/query/fragment,
   `registrable_domain` (incl. `co.uk` and IPs), `path_signature` masking,
   `url_fingerprint` stability.
8. **Trust boundary** — `ValidatedURL` is frozen and bounded; errors start with
   `Invalid URL` and never echo the submitted string; length limit enforced;
   `safe_display_url` truncates without ever marking anything HTML-safe.
9. **No network** — seven detection modules are scanned for a network client.

### `tests/test_model.py` — 43 functions / 59 cases

1. **Metadata and artefacts** — model name/version/feature order, threshold band,
   decision-state strings agreeing with `ml/thresholds.py`, SHA-256 match,
   missing bundle, tampered bundle, invalid metadata, and `public_info()` /
   `health()` containing no performance figure.
2. **Inference wrapper** — loads the deployed estimator; score finite and
   deterministic; rejects a scrambled vector, a missing file, a wrong feature
   order, a corrupt pickle and a wrong class encoding.
3. **Decision policy** — three state constants, inclusive boundaries, seven
   parametrised score cases, band rendering, "not a 50/50 probability" wording,
   invalid scores and invalid thresholds.
4. **Explanation** — all 15 insights with measured importance, ranking by
   importance only, flagged ⊆ indicators and never `has_https`, the HTTPS caveat
   always present, recommended action per state, uncertainty note for abstention
   vs decisive, refusal of incomplete input.
5. **Measured metrics** — recomputed from `metrics.json`; fail closed when the
   artefact is absent.
6. **Orchestration** — registry readiness, the three controlled fixtures scoring
   as measured, immutable complete result, exactly one matching audit row,
   user linking, invalid input writing nothing, missing/tampered bundle
   unavailable, a database failure converted to `DetectionStorageError`,
   registry caching.

### `tests/test_routes.py` — 46 functions / 46 cases

Overview and health, the exact `SCAN WEBSITE` control, one scan = one row, all
three states reachable through the form, signed-in linking, rejected URLs writing
nothing, reflected-XSS escaping, "uncalibrated" wording, report visibility (own
guest / other browser / other user / missing id), history scoping and filters,
pagination clamping, SQL-injection-shaped search strings, CSV export shape and
scoping, dashboard counts and measured metrics, admin 401/403/200 and hash-free
rendering, admin export authorisation, registration (role escalation, weak
password, mismatch, enumeration-resistant duplicates), login failure
indistinguishability, login by email, session clearing on login/logout, session
endpoint, no password echo, and the four explicit failure paths (no model, no
schema, schema-unready login, generic 500).

### `tests/test_api.py` — 29 functions / 36 cases

`/api/v1/health` (metric-free), `/api/v1/csrf-token`, `/api/v1/model/info`
(including independent metric recomputation and 503 when the artefact is gone),
`POST /api/v1/scan` (full documented field set, UTC timestamp, identical score to
the HTML form, one audit row, user linking, indicator names), rejected input
(7 cases: non-JSON, missing field, array, non-string, empty, four invalid URLs,
no echo), scoped listing and detail (own / foreign / missing / indistinguishable
404), filter validation and pagination clamping, JSON 405, documented error
envelope, `no-store`, and 503 on a broken model.

### `tests/test_security.py` — 36 functions / 45 cases

Exact CSP on six routes, no relaxed directive, hardening headers on success and
error, development framing relaxation vs production `DENY`/HSTS/Secure cookies,
`no-store` on sensitive paths, offline templates (no CDN, no inline
script/style), CSRF (form, API POST, wrong token, login/register, GETs exempt,
no `csrf.exempt` in the source), rate limiting (login, scan, API scan, monitoring
survival, TestingConfig unthrottled, no blanket default), scrypt hashing and
salting, header/body hygiene, escaped XSS on result and report pages, script
tags rejected as usernames, generic 500 in both formats, no secret or database
path in any response, no open redirect, 413 on an oversized body, and the
SSRF proofs (socket layer broken; five internal targets; AST import scan).

---

## 6. What is deliberately **not** tested

| Not tested | Reason |
| --- | --- |
| A live phishing website | Forbidden by the brief and unnecessary: classification is lexical |
| Real-world accuracy on live traffic | Not measurable from this project; `metrics.json` describes the held-out PhiUSIIL test split and says so |
| Multi-process rate limiting | `memory://` storage is documented single-process behaviour (ADR-037); a shared store is future work |
| Browser rendering / CSS pixel layout | Verified manually in Stage 9 (`docs/UI.md`); no headless-browser dependency is added |
| Waitress/gunicorn serving | Stage 14 (`docs/DEPLOYMENT.md`) — the WSGI callable is already exercised in-process |
| Load / performance benchmarking | Out of scope; the brief asks for functional correctness |
| Password-reset email flow | Feature does not exist; the project never sends mail |

---

## 7. Behaviours the suite uncovered (and what they mean)

These were found while writing Stage 13. Items 1–4 are correct product
behaviour; item 5 was a genuine defect in a *historical test gate*. Items 1–2
are the easiest to misread as bugs, so they are documented here.

1. **`with app.test_client()` shares one login between two simulated browsers.**
   It sets `preserve_context=True`, keeping the Flask application context alive,
   and Flask-Login caches `current_user` on `g`. Two "users" then share one
   identity. *Fix in the suite:* plain clients, so every request gets a clean
   context. *Not a product bug* — a real request always has its own context.
2. **Production login needs HTTPS **and** a `Referer`.** `ProductionConfig` keeps
   `WTF_CSRF_SSL_STRICT=True`, so Flask-WTF rejects a token sent over plain HTTP
   and rejects a secure request with no same-origin referrer. The production test
   therefore posts to `https://localhost/login` with a `Referer`, exactly as a
   browser behind TLS would. This is a *feature*: it blocks token replay over
   downgraded connections.
3. **`https://example.com` and `https://example.com/` are different URLs.** The
   trailing slash is part of the path, so the pair legitimately scores
   differently (0.0366 LEGITIMATE vs 0.3217 SUSPICIOUS). Normalisation never
   invents or removes a path — that would be a silent change to what the user
   submitted.
4. **`mailto:a@example.com` is treated as a bare host string,** because it has no
   `://`; it normalises to `http://mailto:a@example.com` with userinfo. Only
   explicit schemes are rejected (`ftp://`, `javascript:`, `data:`, `file://`).
   The tests therefore use `mailto://a@example.com` when the intent is "scheme
   rejected".

5. **A developer `.env` made a Gate 7 check vacuous.** `verify_stage7.py` proves
   that `ProductionConfig` refuses to start without `SECRET_KEY` by calling
   `create_app(ProductionConfig, overrides={})`. Because `overrides={}` is falsy
   the factory validates the class, and `config.py` loads `.env` at import time —
   so on any machine that followed `docs/SETUP.md` step 8, a key was present, the
   exception never fired, and the check failed for the right reason but the
   wrong cause. **Fixed in this stage:** the gate now sets
   `ProductionConfig.SECRET_KEY = None` for the duration of that assertion and
   restores it in a `finally` block, so the result no longer depends on the
   developer's environment. This is a genuine testing bug caught by Stage 13,
   not a product defect.

---

## 8. Regression: the twelve closed gates

Run these after `pytest` to prove earlier stages are still intact. On Windows:

```powershell
python scripts\verify_stage1.py
python scripts\verify_stage2.py
python scripts\verify_stage3.py
python scripts\verify_stage4.py
python scripts\verify_stage5.py
python scripts\verify_stage6.py
python scripts\verify_stage7.py
python scripts\verify_stage8.py
python scripts\verify_stage9.py
python scripts\verify_stage10.py
python scripts\verify_stage11.py
python scripts\verify_stage12.py
```

Each must print `RESULT: PASS`. Gates 10, 11 and 12 were made **Stage 13-aware**
the same way they were made Stage 12-aware: the files this stage delivers
(`tests/*.py`, `docs/TEST_PLAN.md`) moved from their forbidden list to a required
list, while `docs/REPORT.md` and `docs/DEPLOYMENT.md` (Stage 14) remain
forbidden. No assertion was deleted — the strict 14-stage order is still
enforced.

---

## 9. Exit criteria — measured result

| Criterion | Status |
| --- | --- |
| `pytest -v` completes with the full suite green | ✅ `259 passed in 7.07s` |
| Zero skips, zero xfails, zero warnings | ✅ |
| All brief-listed test groups covered | ✅ §4 |
| Controlled, synthetic data only | ✅ no live URL, no network, real database untouched |
| Historical gates 1–12 still pass | ✅ §8 |
| CSRF, hashing, session, rate limit, XSS/CSP, SSRF and API tests present | ✅ `test_security.py` + `test_api.py` |
| No feature, pipeline or template changed | ✅ tests only |

Reproduce with:

```powershell
python -m pytest -q
```

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ModuleNotFoundError: config` | Running from inside `tests/` | Run `python -m pytest` from the project root (conftest puts the root on `sys.path`, but the root must be the working directory) |
| `RuntimeError: Invalid testing configuration` | A fixture override dropped `SECRET_KEY` | Use the fixtures; every one supplies a fixed 64-character test secret |
| `429` appearing in an ordinary test | A test used `limited_app` and the limiter's in-memory storage was not reset | `limited_app` resets it before and after each use; keep rate-limit assertions in `test_security.py` |
| Two clients appear to share a login | A client was created with `with app.test_client()` | Create a plain client (`client = app.test_client()`) |
| `CSRF_FAILED` in a production test | Plain HTTP, or a missing `Referer` | Post to `https://localhost/...` with a same-origin `Referer` |
| A "tampered bundle" test passes locally but not on a fresh clone | The bundle is generated by Stage 6 and is git-ignored | Run `python -m ml.evaluate_model` (or restore `ml/saved_model/model_bundle.joblib`) so the artefact exists |
| `instance/phishing.db` changed | Something bypassed the fixtures | Nothing in `tests/` opens it; check for a stray script |

---

## 11. Traceability for the report

| Report chapter | Evidence from this stage |
| --- | --- |
| Ch. 3 — Design | The contract tests read as executable specification for `FEATURE_ORDER`, the three states and the `/api/v1` field set |
| Ch. 4 — Implementation | §3 documents the isolation strategy; §7 records five findings, including one real gate defect fixed here |
| Ch. 5 — Evaluation | §9 gives the measured gate result; §4 gives the coverage matrix a marker can audit line by line |
