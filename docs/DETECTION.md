# Stage 10 — Detection Engine Integration

**Deliverable:** the real, end-to-end URL classification pipeline. A user can now
paste a URL, press **SCAN WEBSITE**, and receive a model-based result with an
explicit uncertainty statement, an explanation, a recommended action and a
saved audit record.

This document is written for a final-year CS student. It explains *what* was
built, *why* each part exists, where every file lives, and exactly how to run
and test it on Windows first.

---

## 1. What Stage 10 builds

Stages 1–6 produced a measured model, Stages 7–8 produced a secure Flask/SQLite
backend, and Stage 9 produced the responsive SOC-style interface. Stage 10 joins
them. Before Stage 10 there was deliberately **no scan control**, because a
button that cannot produce a real result would be pretending. Stage 10 replaces
that honest banner with a working scanner.

| Capability | Where it lives |
| --- | --- |
| Validate and normalise one URL | `services/validation.py` (Stage 4, reused) |
| Extract the same 15 features used in training | `ml/feature_extraction.py` (Stage 4, reused) |
| Load the hash-verified Joblib estimator once | `models/prediction_model.py` |
| `predict_proba` scoring | `models/prediction_model.py::PredictionModel.score` |
| Three-state decision with measured thresholds | `services/decision_service.py` |
| Measured-importance explanation + caveats | `services/explanation_service.py` |
| Orchestration and audit persistence | `services/detection_service.py` |
| GET/POST `/scan`, printable report | `routes/scanning.py` |
| Form, result, report pages | `templates/scan.html`, `templates/partials/scan_result.html`, `templates/scan_report.html` |
| Styles and print enhancement | `static/css/main.css`, `static/js/main.js` |
| Executable acceptance gate | `scripts/verify_stage10.py` |

**What is new versus Stage 9:** the exact `SCAN WEBSITE` button, `/scan`,
`/scan/<id>/report`, a `detection_registry` on `app.extensions`, a live
`detection` block in `/health`, a "Scan URL" navigation link, and one real
`ScanHistory` row per successful scan.

**What did NOT change:** the strict CSP, the offline vendor assets and their
SHA-256 digests, the Stage 8 authentication/CSRF contracts, the 15-feature
contract, the trained bundle, the measured thresholds and the published
evaluation results. No model was retrained and no threshold was re-tuned.

---

## 2. Request pipeline

```
Browser (POST /scan, CSRF token)
   │
   ├─ 1. services.validation.validate_url(raw, max_length=config.MAX_URL_LENGTH)
   │       bounded string, strip, length cap, http/https only, canonical form.
   │       NO DNS, NO socket, NO HTTP client.
   │
   ├─ 2. ml.feature_extraction.extract_features(validated.normalized)
   │       exactly 15 integers in FEATURE_ORDER; identical code to training.
   │
   ├─ 3. models.prediction_model.PredictionModel.score(features)
   │       features_to_frame() -> pandas DataFrame with named columns
   │       -> StandardScaler -> LogisticRegression.predict_proba()[:, 1].
   │       Loaded once at boot, only after the SHA-256 check.
   │
   ├─ 4. services.decision_service.decide(score, low, high)
   │       low/high come from metadata.json (calibrated on validation split).
   │       p >= high PHISHING | p <= low LEGITIMATE | otherwise SUSPICIOUS.
   │       Reuses ml.thresholds.decision_codes so boundaries cannot drift.
   │
   ├─ 5. services.explanation_service.explain(features, decision, importance)
   │       definitions/rationales from ml.feature_extraction;
   │       measured permutation importance from metrics.json;
   │       caveats, uncertainty note, recommended action.
   │
   ├─ 6. INSERT INTO scan_history (guest user_id NULL, or linked User.id)
   │       COMMIT must succeed before any result is shown.
   │
   └─ 7. render templates/scan.html (HTML) or jsonify(result) (JSON)
```

The printable report (`GET /scan/<id>/report`) **does not re-run steps 2–3**.
It rebuilds the decision and explanation deterministically from the saved row,
so a report can never contradict what the user was originally shown and never
creates a second audit record.

---

## 3. File-by-file map

| File | Responsibility | Notes for the viva |
| --- | --- | --- |
| `models/prediction_model.py` | `PredictionModel`, `ModelUnavailableError` | Verifies the dict bundle, `feature_order`, `classes_ == [0, 1]`, `predict_proba`, finite score. Only file that calls `joblib.load`. |
| `services/decision_service.py` | `Decision`, `decide()` | Pure function. Uses `ml.thresholds.decision_codes`, `STATE_NAMES`, `DECISION_STATES`, `SCORE_MEANING`. No URL parsing, no rules. |
| `services/explanation_service.py` | `Explanation`, `FeatureInsight`, `explain()` | Descriptive only. Never decides. `has_https` is deliberately NOT a suspicious indicator. |
| `services/detection_service.py` | `DetectionRegistry`, `DetectionResult`, `get_detection_registry()` | Reads measured importance at runtime, owns the DB transaction, defines the three failure classes. |
| `routes/scanning.py` | `scan_bp` | Thin HTTP layer: content negotiation, failure mapping, guest-session report authorisation. |
| `templates/scan.html` | Form + result page | Contains the exact `SCAN WEBSITE` label. One shared form; no duplicated HTML. |
| `templates/partials/scan_result.html` | Shared result/report body | Included by both pages; all output is Jinja-autoescaped. |
| `templates/scan_report.html` | Printable report | Report provenance, no inline script. |
| `static/css/main.css` | Result state colours, form, tables | Reuses theme variables; no new hex constants, no `f1`-like metric strings. |
| `static/js/main.js` | `initPrintButtons()` | `window.print()` from an external script, so the CSP stays `script-src 'self'`. |
| `scripts/verify_stage10.py` | Exit gate | Re-runs Gates 1–9 and adds Stage 10 checks. |

`app.py` attaches the `DetectionRegistry` **after** `ModelRegistry` has verified
the bundle hash. `config.py` moves to `APP_VERSION = 0.10.0`, `BUILD_STAGE = 10`.
`routes/core.py` now publishes `detection.health()` in `/health` and passes the
engine status to the overview card.

---

## 4. Model loading and integrity

`ModelRegistry` (Stage 7) verifies that the SHA-256 of
`ml/saved_model/model_bundle.joblib` equals `metadata.json.model_bundle_sha256`.
Only then does `DetectionRegistry` construct `PredictionModel`, which additionally
checks:

* the bundle is a `dict` containing an estimator with `predict_proba`;
* `bundle["feature_order"] == ml.feature_extraction.FEATURE_ORDER`;
* `estimator.classes_ == [0, 1]` (documented `0 = legitimate`, `1 = phishing`);
* the loaded `model_name`, `model_version` and `schema_version` match
  `metadata.json` (a valid pickle from the wrong artefact is refused).

`score()` converts the feature dict with `ml.feature_extraction.features_to_frame`
so the `StandardScaler` receives a **named** pandas `DataFrame`, exactly as it
was fitted. `scripts/verify_stage10.py` proves parity: the single-URL live score
equals the batch `extract_frame` score to 1e-12, and the live path reproduces
the published held-out confusion matrix exactly.

**There is no rule-based fallback.** A missing bundle, a corrupt pickle, a
hash mismatch, missing measured provenance, an unsupported class layout or a
non-finite score sets `DetectionRegistry.error`; `/health` degrades to 503 and
`POST /scan` returns `503 MODEL_UNAVAILABLE`. The gate builds a *hash-consistent
but corrupt* pickle to prove this is a genuine load-failure path, not merely a
missing-file shortcut.

---

## 5. Three-state decision policy

The fitted estimator is **binary**. `SUSPICIOUS` is a selective-prediction
(abstention) decision, not an invented third trained class. The thresholds were
chosen on the **validation split only** in Stage 6 and are read at runtime from
`metadata.json`:

| Condition | Classification | Risk | Colour | Uncertain |
| --- | --- | --- | --- | --- |
| `p >= T_high` | PHISHING | HIGH | red | no |
| `T_low < p < T_high` | SUSPICIOUS | MEDIUM | orange | **yes** |
| `p <= T_low` | LEGITIMATE | LOW | green | no |

The exact messages and warnings are the strings in `ml.thresholds.DECISION_STATES`.
The gate asserts `metadata.json.decision_states == DECISION_STATES` and
`metadata.json.score_meaning == SCORE_MEANING`, so prose cannot silently drift.

**Score wording rule.** The result labels the value *"Model score (clearly
labelled)"* and displays `SCORE_MEANING` verbatim: an **uncalibrated**
`predict_proba` estimate of `P(phishing | URL features)` over 15 lexical URL
features. It is **not a guaranteed probability that the website is
malicious**, and it is **not a guarantee of safety** when low. The SUSPICIOUS
state additionally says the model is abstaining and that this is not a 50/50
probability.

---

## 6. Explanations and uncertainty

The result page shows:

1. **Submitted URL** (normalised, truncated for display, autoescaped) and a copy
   control;
2. **Classification** with the exact message, warning, risk level and contract
   colour;
3. **Model score** with the explicit caveat;
4. **Date/time (UTC)**, model name/version and scan id;
5. **Suspicious-feature explanations** — each observed indicator with its
   documented rationale and definition;
6. **All 15 extracted characteristics**, their values, definitions and
   *measured* permutation importance (mean ROC-AUC decrease, read at runtime
   from `metrics.json#feature_importance.features`). Small negative measured
   values are shown as measured, not clamped to zero;
7. **Recommended action** per state;
8. **Limitations and uncertainty**, including the exact caveat
   *"HTTPS alone does not mean a website is legitimate."*

**Important:** the flagged indicators are *annotations*, not detection rules.
They never influence `prediction`. The explanation module contains no `decide()`
call and no verdict assignment. Its language is correlational — a flagged
characteristic is an observation associated with phishing in this training
corpus, not proof of cause or malicious intent.

**Observed limitation (disclosed, not hidden).** The deployed logistic
regression is dominated by `url_length` and `has_https` — the shortcut Stage 6
already measured and documented. On harmless reserved-domain strings, tiny
edits can move the score a lot: `https://example.com` scores ~0.037
(LEGITIMATE) while adding a single trailing slash (`https://example.com/`)
scores ~0.322 (SUSPICIOUS). This is a real property of the trained model, not a
bug in the integration. It is precisely why the UI abstains, labels the score as
uncalibrated, and never claims certainty. The held-out test metrics remain valid
*for this dataset's distribution*; they are optimistic for real-world traffic.
An ablation study retraining without `has_https` is recommended future work — it
is **not** performed here, because Stage 10 may not re-tune a closed stage.

---

## 7. Audit persistence and authorisation

Every successful scan commits one `ScanHistory` row **before** the result is
rendered: `url`, `normalised_url`, `prediction`, `model_score`, `risk_level`,
`model_version`, `scan_date` (UTC), `user_id`, and a JSON `features_json`
snapshot of the 15 features plus flagged indicators and provenance.

* **Guests** may scan; `user_id` is `NULL` (the Stage 8 `ON DELETE SET NULL`
  foreign key is preserved).
* **Authenticated** scans are linked to `current_user`'s `User.id`.
* A failed `COMMIT` rolls back and returns `503 DATABASE_UNAVAILABLE`. No result
  is shown without its audit row, so history can never silently disagree with
  what a user was told.
* `GET /scan/<id>/report` is access-controlled: a signed-in user may read only
  their own rows; a guest row is readable only by the browser session that
  created it (a bounded list of ids in the signed Flask session). Missing and
  unauthorised ids return the same generic `404`, so reports cannot be
  enumerated.

Claiming guest rows after sign-in, full history listing, dashboards, admin
views and CSV export are **Stage 11** work.

---

## 8. Security properties and limitations

| Property | Implementation |
| --- | --- |
| **No SSRF** | The backend never opens, resolves, downloads or executes a submitted URL. There is no HTTP client, no DNS lookup and no socket call. Classification is purely lexical/statistical. The gate patches `socket.socket.connect` and `socket.create_connection` to raise while scanning `127.0.0.1` and link-local strings, and the scans still succeed. |
| **Input validation** | `validate_url` caps length (2,048), restricts schemes to http/https, rejects malformed hosts/ports, and returns a bounded typed object. Rejection is `400 INVALID_URL` with a generic message that never echoes the raw string. |
| **SQL injection** | SQLAlchemy ORM only; no string-built SQL. |
| **XSS** | Jinja2 autoescaping. The gate submits a URL containing `<script>` and asserts the response contains `&lt;script&gt;`, not live markup. |
| **CSRF** | `CSRFProtect` (Stage 8) applies to `POST /scan`; HTML forms carry `csrf_token`, JSON clients use the `X-CSRF-Token` header. The gate tests both. |
| **CSP** | Unchanged: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; ...`. No inline script/style and no external asset is added. Print is progressive enhancement from `main.js`. |
| **Safe errors** | `make_error_response` gives themed HTML or JSON with generic codes; no traceback or exception detail reaches the client. |
| **Secrets** | No new secret. `SECRET_KEY`, session cookies and scrypt hashing are unchanged from Stage 8. |

**Limitations.** URL-only analysis cannot see page content, redirects, TLS
certificates, DNS reputation or live behaviour. Shorteners are detected from a
maintained static list, not by following them. Per-route rate limiting and a
REST API are deliberately deferred to Stage 12. Rate limiting the form is *not*
claimed as implemented in Stage 10.

---

## 9. What is deliberately NOT in Stage 10

* No dashboard, scan-history listing, admin view or CSV export (Stage 11).
* No per-route rate limits, no `/api/v1/scan`, no `docs/SECURITY.md` (Stage 12).
* No `tests/conftest.py` or full pytest suite (Stage 13). Stage 10's acceptance
  is the executable `scripts/verify_stage10.py`, following the project's
  stage-gate pattern.
* No final report or deployment guide (Stage 14).
* No retraining, threshold re-tuning, ablation study or new metrics.
* No measured accuracy/precision/recall/F1/ROC-AUC figure printed in the UI.
  Those belong to `docs/EVALUATION.md`, `docs/MODEL_CARD.md` and the Stage 11
  admin dashboard, which will read `metrics.json` at runtime.
* No live malicious URL is used in any test. All fixtures are RFC 2606 / RFC
  5737 reserved names and reserved non-resolvable `.invalid` hosts.

---

## 10. Run and test

### Windows (PowerShell, from `phishing-detection-system\`)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
copy .env.example .env
# Set SECRET_KEY in .env to the output of:
python -c "import secrets; print(secrets.token_hex(32))"

python scripts\init_db.py
python scripts\init_db.py --verify-only
python scripts\create_admin.py           # optional
python scripts\verify_stage10.py         # runs Gates 1-10 + pip check

python -m flask --app app run --host 0.0.0.0 --port 5000
```

Then open `http://localhost:5000/scan`, paste `https://example.com/` and press
**SCAN WEBSITE**. `http://localhost:5000/health` should report
`"detection": {"status": "ready", ...}`.

Production-like alternatives: `python wsgi.py` or
`python -m waitress --host 0.0.0.0 --port 5000 --call wsgi:create_application`.

### Linux / macOS

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/init_db.py
python scripts/verify_stage10.py
python -m flask --app app run --host 0.0.0.0 --port 5000
```

### Verify the offline assets (unchanged from Stage 9)

```powershell
Get-FileHash static\vendor\bootstrap.min.css -Algorithm SHA256
Get-FileHash static\vendor\bootstrap.bundle.min.js -Algorithm SHA256
Get-FileHash static\vendor\chart.umd.min.js -Algorithm SHA256
```

---

## 11. Common errors and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `503 MODEL_UNAVAILABLE` on `/scan` and `"status": "unavailable"` in `/health` | Missing/corrupt `model_bundle.joblib`, SHA-256 mismatch, missing `metrics.json`, or a pickle that cannot be loaded. | Re-run `python -m ml.evaluate_model` (Stage 6) to regenerate artefacts, then restart. **Do not** add a heuristic fallback. |
| `503 DATABASE_UNAVAILABLE` | `init_db.py` was not run, or the DB file is unwritable. | `python scripts\init_db.py` then `python scripts\init_db.py --verify-only`. |
| `400 INVALID_URL` | Missing `http://`/`https://`, unsupported scheme, malformed host or > 2,048 characters. | Submit a complete absolute URL. |
| `400` on every `POST /scan` | Missing CSRF token. | HTML: include `{{ csrf_token() }}`. JSON: send `X-CSRF-Token` from `GET /auth/csrf-token`. |
| `404` on a printable report | The report belongs to another session/account, or the browser session was cleared. | Re-open the report from the same browser session, or sign in as the owning user. |
| `ModuleNotFoundError: sklearn` / `joblib` | Running with the system Python instead of the venv. | Activate `.venv` (see §10); verify with `python -c "import sklearn"`. |
| `ImportError: cannot import name 'DetectionRegistry'` | Stale `__pycache__` after a file move. | Delete `__pycache__` folders and re-run. |
| Button appears but nothing happens | JavaScript from a CDN was expected. | There is no CDN: the form is a normal POST and works with JavaScript disabled. |
| Score changes when a trailing slash is added | Known model sensitivity (§6), not an integration bug. | Read the uncertainty note; treat it as an abstention, not a verdict. |

---

## 12. Stage 10 exit criteria

`python scripts\verify_stage10.py` must print `RESULT: PASS` with zero failures.
It verifies:

* all ten Stage 10 files exist, all Stage 11+ files are still absent, and every
  Python module compiles;
* the exact `SCAN WEBSITE` label exists once; templates have no inline script,
  inline style or external asset; vendor hashes and CSP are unchanged;
* no network-client import exists anywhere in the application source;
* `joblib.load` appears only in `models/prediction_model.py`;
* `metadata.json` still agrees with `ml/thresholds.py` for states and score
  meaning; thresholds and feature importance are read from real artefacts;
* `decide()` reproduces all three states, boundaries, exact strings/colours/
  warnings and rejects invalid inputs;
* `explain()` uses documented definitions, measured importance, the HTTPS
  caveat and correlational language, and never decides;
* live single-URL scoring equals batch scoring and reproduces the published
  held-out confusion matrix;
* GET/POST `/scan` (HTML and JSON) report every required field, write one audit
  row each, link authenticated scans, and produce an access-controlled report;
* invalid input, CSRF, XSS escaping, no-network/SSRF, database failure and all
  three model-unavailable cases behave exactly as documented;
* documentation, ADRs and Windows commands are present;
* **Gates 1–9 still pass** and `pip check` is clean.

### Why the gate suite is linear, not exponential

Every historical gate re-runs all earlier gates. Running Gate 10 therefore used
to spawn 512 nested gate processes and took roughly 17 minutes — and Stage 14
would have been worse. Gate 10 now sets `PDS_GATE_NESTED=1` for the nine
historical subprocesses. A child gate that sees that marker skips **only its
duplicated nested regression re-runs**; all of its own acceptance checks still
execute, and the top-level gate runs every historical gate directly anyway.
Running any `verify_stageN.py` **standalone** leaves the marker unset, so its
complete historical behaviour and check count are unchanged. The result is 542
checks in under a minute instead of 17 minutes, with no check weakened or
faked.

Only after that pass may Stage 11 begin.

---

## Stage 11 note (reporting layer only)

Stage 11 does **not** change this pipeline. `services/detection_service.py`,
`decision_service.py`, `explanation_service.py`,
`models/prediction_model.py`, `routes/scanning.py`, the exact
`SCAN WEBSITE` control, the three decision states, the measured thresholds,
`SCORE_MEANING`, the CSP and the no-network/SSRF rule are all unchanged.
`POST /scan` remains the only route that writes a `ScanHistory` row.

What changed is *where the audit trail is read*: `GET /dashboard`,
`GET /history`, `GET /history/export.csv`, `GET /admin` and
`GET /admin/export.csv` are read-only views over the same rows and over the
same measured `metrics.json`. History reuses `can_view_scan`'s authorisation
policy exactly, so the report endpoint and Gate 10's authorisation assertions
stay valid. The dashboard is the first UI allowed to display measured
performance figures, and only as request-time reads with explicit source keys
and caveats; no figure is hard-coded. See `docs/DASHBOARD.md` and
ADR-033/034/035. Rate limiting and the REST API were delivered in Stage 12
without modifying the detection pipeline; see the note below.

## Stage 12 note — the API reuses this pipeline unchanged

Stage 12 delivered `routes/api.py`. `POST /api/v1/scan` calls
`DetectionRegistry.scan()` — the same validation, 15-feature extraction,
`predict_proba`, three-state decision, measured explanation and single
`ScanHistory` write described above. No detection, decision, explanation or
model file was modified; `SCORE_MEANING`, the measured thresholds, the HTTPS
caveat and the honest `503 MODEL_UNAVAILABLE` behaviour are identical. The API
only PROJECTS the result into the field names documented in
`docs/ARCHITECTURE.md` §11; a `GET /api/v1/scans/<id>` rebuilds from the audit
row and never re-runs inference. All URL strings remain pure text: the no-network
/ SSRF rule now covers the REST edge too and Gate 12 proves it with a
socket-patched probe. See `docs/SECURITY.md` and ADR-036.
