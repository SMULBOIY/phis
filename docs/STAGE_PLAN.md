# 14-Stage Development Plan

This is the build order requested in the brief, with a concrete **exit gate** for each stage. A stage is "done" only when its gate passes. Stage N+1 does not start before Stage N's gate is green and you have seen the result.

## Gate discipline

1. Every stage states: what we are building, why it is necessary, complete file contents, where files go, install commands, how to run, how to test, and common errors with fixes.
2. When a file is modified, its **complete** updated content is provided — never a diff fragment that leaves the file ambiguous.
3. No empty stubs, no dead `pass`, no `NotImplementedError`, no "coming soon" route. A feature that does not work yet is **absent**, not simulated.
4. No fabricated dataset rows and no invented accuracy/precision/recall/F1 figures. Metrics appear only after Stage 6 has measured them.
5. Stages 1–9 have executable gates (`scripts/verify_stage1.py` … `verify_stage9.py`); Stage 13's gate is the full `pytest` suite. Each new gate re-runs all previous ones as regression checks.
6. A gate is **stage-aware**: it checks that later-stage files are absent *only while those stages have not been reached*, so historical gates stay green as the project grows.
7. From Stage 6 onward, every published performance number is recomputed independently by the stage gate. No figure may be hand-typed into a template, script or document. Stage 7 additionally verifies that **no** measured metric appears in the backend's source, status page or health response.

## Stage roadmap

| Stage | What we build | Key files created | How to run / test | Exit gate |
| --- | --- | --- | --- | --- |
| **1** | Planning and architecture | `README.md`, `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`, `docs/STAGE_PLAN.md`, `docs/diagrams/*`, `scripts/verify_stage1.py`, `.gitignore`, directory skeleton | `python scripts/verify_stage1.py` | ✅ Passed — 62 checks (56 applicable now), design approved |
| **2** | Environment and installation | `requirements.txt`, `config.py`, `.env.example`, `docs/SETUP.md`, `docs/ENVIRONMENT.md`, `scripts/verify_stage2.py` | `pip install -r requirements.txt`, `pip check`, `python scripts/verify_stage2.py` | ✅ Passed — clean venv, all pins installed, config + wiring tests green |
| **3** | Dataset acquisition and preprocessing | `docs/DATASET.md`, `ml/url_utils.py`, `ml/preprocess.py`, `scripts/download_dataset.py`, `scripts/verify_stage3.py`, `dataset/raw/*`, `dataset/processed/*` | `python -m ml.preprocess`, `python scripts/verify_stage3.py` | ✅ Passed — real cited dataset, measured provenance, leakage-free 70/15/15 split |
| **4** | URL feature extraction | `ml/feature_extraction.py`, `services/validation.py`, `scripts/analyse_features.py`, `scripts/verify_stage4.py`, `docs/FEATURES.md`, `feature_summary.*` | `python scripts/analyse_features.py`, `python scripts/verify_stage4.py` | ✅ Passed — 15 features, parity proven, 181 checks green |
| **5** | Model training | `ml/train_model.py`, `docs/TRAINING.md`, `scripts/verify_stage5.py`, `ml/saved_model/candidates/*.joblib`, `training_manifest.json` | `python -m ml.train_model`, `python scripts/verify_stage5.py` | ✅ Passed — 3 pipelines fitted on train only, 150 checks green |
| **6** | Evaluation and selection | `ml/thresholds.py`, `ml/evaluate_model.py`, `scripts/verify_stage6.py`, `ml/saved_model/{model_bundle.joblib,metadata.json,metrics.json}`, `docs/MODEL_CARD.md`, `docs/EVALUATION.md` | `python -m ml.evaluate_model`, `python scripts/verify_stage6.py` | ✅ Passed — measured metrics, calibrated band, 211 checks incl. independent recomputation |
| **7** | Flask backend | `app.py`, `wsgi.py`, `extensions.py`, `routes/{__init__,core,auth}.py`, `services/{model_metadata,http_security}.py`, `static/css/backend.css`, `docs/BACKEND.md`, `scripts/verify_stage7.py`, `config.py`/`.env.example` extended | `python -m flask --app app run`, `python wsgi.py`, `python scripts/verify_stage7.py` | ✅ Passed — app boots, routes respond, security + failure paths tested |
| 8 | Database integration | `models/{__init__,database_models}.py`, `services/{auth_service,database_service}.py`, `scripts/{init_db,create_admin}.py`, `routes/auth.py` extended with `/login`, `/register`, `docs/DATABASE.md`, `scripts/verify_stage8.py` | `python scripts/init_db.py`, `python scripts/create_admin.py`, `python scripts/verify_stage8.py` | ✅ Passed — DDL, relationships, constraints, CRUD, hashing, auth routes and CLIs tested; Gates 1–7 green |
| **9** | Frontend | `templates/{base,index,login,register,auth_result}.html`, `templates/errors/error.html`, `static/css/main.css`, `static/js/{theme,main}.js`, `static/images/logo.svg`, `static/vendor/*`, `docs/UI.md`, `scripts/verify_stage9.py` | `python -m flask --app app run`, `python scripts/verify_stage9.py` | ✅ Passed — responsive at 4 breakpoints, dark + light WCAG AA themes, offline hash-verified Bootstrap/Chart.js, real dataset chart; Gates 1–8 green |
| 10 | Detection engine integration | `models/prediction_model.py`, `services/detection_service.py`, `decision_service.py`, `explanation_service.py`, `routes/scanning.py`, `templates/scan.html` | Submit safe synthetic URLs through the form | End-to-end scan with model score, three states, feature analysis, DB write, explicit model-failure path |
| **11** | **Dashboard and history** | `services/{stats_service,report_service}.py`, `routes/{dashboard,history,admin}.py`, `templates/{dashboard,history,admin}.html`, `docs/DASHBOARD.md`, `scripts/verify_stage11.py` | `python scripts/verify_stage11.py` | ✅ Passed — KPIs/charts equal real SQL counts, measured metrics read at runtime, scoped filtered history, role-restricted admin, formula-safe CSV export; Gates 1–10 green |
| 12 | Security and REST API | `routes/api.py`, config-driven per-route rate limits, hardening headers and 429 handler, improved `templates/errors/error.html`, `docs/SECURITY.md`, `scripts/verify_stage12.py`, `config.py` / `app.py` / `routes/__init__.py` extended | `python scripts/verify_stage12.py` (executable gate equivalent to `pytest tests/test_security.py tests/test_api.py`; formal pytest suite is Stage 13) | ✅ Passed — RESULT: PASS; six `/api/v1` JSON endpoints share the one detection pipeline, 429 RATE_LIMITED with Retry-After, CSRF/session/scrypt/XSS/CSP/SSRF/API tests green, unchanged Stage 11 reporting layer; Gates 1–11 green |
| **13** | Testing and debugging | `tests/conftest.py`, `test_features.py`, `test_model.py`, `test_routes.py`, `test_api.py`, `test_security.py`, `docs/TEST_PLAN.md` | `pytest -v` | ✅ Passed — `259 passed in ~7 s`, no skips/warnings; feature, model, route, API, security and failure cases covered with synthetic URLs only; no network I/O and the real database untouched; Gates 1–12 green |
| **14** | **Documentation and deployment** ← current | `docs/REPORT.md` (chapters 1–5 + all sections), 5 UML SVGs, final `README.md`, `docs/DEPLOYMENT.md`, `scripts/verify_stage14.py` | `waitress-serve --call wsgi:create_application`, `python scripts/verify_stage14.py` | ✅ Passed — RESULT: PASS (128 checks); report carries only measured figures (every 4+ decimal traced to `metrics.json`/`metadata.json`), diagrams well-formed and offline-safe, production start on waitress with hash-verified bundle and full security headers; Gates 1–12 + `pytest` (259) green |

## Stage 7 — delivered

`create_app()` in `app.py` builds a fresh, isolated Flask application from one of the three Stage 2 config classes. `extensions.py` holds the four shared extension objects so Stage 8's ORM models cannot create a circular import. `wsgi.py` supplies the long-lived object a WSGI server needs. `routes/core.py` serves a backend status page and a JSON health contract; `routes/auth.py` supplies the working session/CSRF surface. `services/http_security.py` adds strict CSP, hardening headers, generic JSON/HTML error responses and a request-size guard. `services/model_metadata.py` validates `metadata.json` and the bundle's SHA-256 against the code's decision-state contract.

Reproduce:

```powershell
python -m flask --app app run --host 0.0.0.0 --port 5000
python -m flask --app app routes
python scripts\verify_stage7.py
```

Key outcomes:

* **The factory is real:** two calls return distinct apps; testing uses in-memory SQLite; production refuses weak secrets; overrides are re-validated against the effective config.
* **Model integrity is explicit:** broken metadata refuses startup; a missing or corrupt bundle gives `503 MODEL_UNAVAILABLE` — never a rule-based guess.
* **No performance figures leak into the backend:** `/`, `/health` and all backend source contain zero measured metric values. Stage 11 will read `metrics.json` at runtime.
* **Security is testable now:** CSRF rejects token-less POSTs, 500 responses never leak exception text, 413 enforces the 64 KB cap, 401 uses the documented code, production sends `X-Frame-Options: DENY` and HSTS.
* **No pretend UI:** there is no `"SCAN WEBSITE"` button, no `/login` form, no templates and no database file. Those are Stages 8–10.

One scope refinement from the earlier preview: `routes/auth.py` **was** created in Stage 7, but only its session/CSRF endpoints. `/login` and `/register` require the `User` ORM entity and `password_hash` column, so they are scheduled for Stage 8 rather than shipped as non-functional stubs. See ADR-024.

Development omits framing headers so the Arena live preview (a cross-origin iframe) can render; production keeps them strict. See ADR-025.

## Stage 8 — delivered

`models/database_models.py` defines `User`, `ScanHistory` and `ModelInformation` with nullable `ScanHistory.user_id`, `ON DELETE SET NULL`, CHECK constraints for role/prediction/risk/score/URL length, all four required indexes (including the composite `(user_id, scan_date)`) and UTC timestamps. `configure_database(app)` enables `PRAGMA foreign_keys=ON` on the app's engine. `services/auth_service.py` owns validation, scrypt hashing, timing-equalised authentication and the fail-closed `user_loader`. `services/database_service.py` owns schema bootstrap, real-time status inspection and idempotent seeding of `model_information` from **measured** `metrics.json` values. `routes/auth.py` now serves working `/login` and `/register` forms (HTML and JSON), rotates the session on login, ignores any client-supplied `role`, and returns `503 DATABASE_UNAVAILABLE` when the schema is absent. `scripts/init_db.py` and `scripts/create_admin.py` make deployment explicit and ship **no default credentials**.

Reproduce:

```powershell
python scripts\init_db.py
python scripts\init_db.py --verify-only
python scripts\create_admin.py            # optional
python -m flask --app app run --host 0.0.0.0 --port 5000
python scripts\verify_stage8.py
```

Key outcomes:

* **The ER design is really enforced:** Gate 8 inspects the emitted SQLite DDL and deletes a user to prove `ON DELETE SET NULL` keeps the scan history. Guest scans persist with `user_id = NULL`.
* **Passwords are never stored in plaintext:** only `scrypt` hashes reach the database; `to_dict()`, responses, logs and the DB file are checked for leaks.
* **No invented statistics:** every `model_information` metric is compared byte-for-byte against `metrics.json`; a missing or inconsistent artefact aborts bootstrap with `ModelDataError`.
* **Authentication is real but honest:** CSRF, session fixation defence, generic failures, weak-password rejection and role-escalation resistance are tested. Per-route rate limiting is deliberately deferred to Stage 12 and documented as such.
* **No pretend UI:** there is still no `"SCAN WEBSITE"` button, no `templates/*.html`, no `/scan` and no Bootstrap/Chart.js. Those are Stages 9–10.

See `docs/DATABASE.md` for the ER diagram, schema, security controls, commands, common errors and exit criteria. See ADR-026 and ADR-027 for the two new decisions.

## Stage 9 — delivered

Six real Jinja2 templates replace every inline HTML string: `base.html` (master layout), `index.html` (product overview + live telemetry), `login.html`, `register.html`, `auth_result.html` and `errors/error.html`. `static/css/main.css` implements the SOC-style design system with `:root` (dark) and `[data-theme="light"]` palettes, Bootstrap variable overrides, WCAG AA contrast and breakpoints at 1200/992/768/576 px. `static/js/theme.js` applies the stored theme before paint; `static/js/main.js` handles the toggle, Chart.js rendering, active navigation and copy feedback. Bootstrap 5.3.3, its Popper bundle and Chart.js 4.4.4 are vendored locally with recorded SHA-256 digests — no CDN, no inline script or style, so the strict CSP is unchanged.

Reproduce:

```powershell
python scripts\init_db.py
python -m flask --app app run --host 0.0.0.0 --port 5000
python scripts\verify_stage9.py
```

Key outcomes:

* **The UI is real, not a mock-up:** every link resolves to a working route, both auth forms still accept HTML and JSON, and all Stage 7/8 error contracts are preserved.
* **Themes are measurable:** the gate computes WCAG contrast for both palettes and asserts ≥ 4.5:1. The toggle is keyboard-accessible with `aria-pressed`.
* **Offline and CSP-safe:** all three vendor hashes are recomputed by the gate; no template contains an inline script, inline style, inline handler or external asset URL.
* **Honest chart:** the sole Chart.js doughnut shows real dataset split row counts read at runtime from `metadata.json` via an escaped `data-chart` attribute. No model result is typed into a template.
* **No pretend UI:** there is still no `/scan` route, no `"SCAN WEBSITE"` button and no dashboard/history/admin templates. The overview says so in a prominent banner.

See `docs/UI.md` for the design system, template map, data contract, responsive/accessibility details, commands, common errors and exit criteria. See ADR-028 and ADR-029 for the two new decisions.

## Stage 10 — delivered

The real detection engine is wired end to end. `models/prediction_model.py`
loads the hash-verified Joblib bundle once; `services/detection_service.py`
orchestrates validation, the shared 15-feature extractor, `predict_proba`,
the measured abstention decision, explanations and one `ScanHistory` commit;
`services/decision_service.py` and `services/explanation_service.py` keep the
policy and the prose separate and pure; `routes/scanning.py` supplies
`GET/POST /scan` and an access-controlled printable report;
`templates/scan.html` carries the exact **`"SCAN WEBSITE"`** button and
`templates/partials/scan_result.html` renders every required result field.

Reproduce:

```powershell
python scripts\init_db.py
python -m flask --app app run --host 0.0.0.0 --port 5000
python scripts\verify_stage10.py
```

Key outcomes:

* **One real pipeline:** validate → normalise → extract → `predict_proba` →
  decide → explain → commit → display. The live single-URL score equals the
  batch training path and reproduces the published held-out confusion matrix.
* **Three exact states:** strings, colours, risk levels and warnings come from
  `ml/thresholds.py`; `SUSPICIOUS` is an explicit abstention with an uncertainty
  threshold. The score is never called a guaranteed probability of maliciousness.
* **Honest explanations:** measured permutation importance from `metrics.json`,
  documented definitions/rationales, the exact HTTPS caveat, correlational
  language and a recommended action. Explanations never decide the verdict.
* **Explicit failures:** `400 INVALID_URL`, `503 MODEL_UNAVAILABLE` (including a
  hash-consistent but corrupt pickle) and `503 DATABASE_UNAVAILABLE`. There is
  no rule fallback and no result without its audit row.
* **Security preserved:** CSRF, strict CSP, offline vendor hashes, Jinja
  autoescaping, ORM-only writes, generic errors. The gate patches
  `socket.socket.connect` to prove no outbound request occurs even for
  loopback/link-local URL strings.
* **Guests and accounts:** guest rows keep `user_id = NULL`; signed-in scans are
  linked to `User.id`; printable reports are access-controlled.

See `docs/DETECTION.md` for the pipeline, file map, model-loading rules,
decision policy, limitations, Windows commands, common errors and exit
criteria. See ADR-030, ADR-031 and ADR-032 for the new decisions.

## Stage 11 — delivered

Aggregates are read **at runtime** from `metrics.json`, `model_information` and
`scan_history`; the history table has validated filters, pagination and a CSV
export; the admin console is role-restricted; the exact CSP, the three decision
states and the entire Stage 10 detection engine are unchanged.

* **Measured-only figures:** the dashboard is the first UI surface allowed to
  show the held-out test metrics, and only by reading
  `ml/saved_model/metrics.json` at request time with the exact source key and
  caveats printed next to each value. Gate 11 renders a deliberately tampered
  copy of the artefact and asserts the page changes — hard-coded statistics are
  impossible.
* **Three real charts:** classification distribution, risk-level mix and a
  seven-day UTC volume chart, all from SQL `GROUP BY`. Days with no scans are
  honest zeros. Stage 9's `data-chart` contract is reused; no new JS file, no
  inline script, no runtime CDN.
* **Scoped history:** the Stage 10 `can_view_scan` policy is reused exactly —
  a signed-in user sees only their own rows, a guest only ids from their signed
  session. A different browser gets an empty table and an empty CSV.
* **Admin:** `admin_required()` composes `login_required` with an explicit role
  check. Anonymous stays `401 UNAUTHENTICATED` (Stage 8 contract), ordinary
  users get `403 FORBIDDEN`, and `User.to_dict()` is the only account projection.
* **CSV security:** spreadsheet formula prefixes (`= + - @`), CR/LF/NUL and
  filename injection are neutralised; exports are bounded, uncached, `nosniff`
  and UTF-8 BOM prefixed for Windows Excel.
* **Failure paths:** `503 DATABASE_UNAVAILABLE` when the schema is absent and
  `503 MODEL_UNAVAILABLE` when the measured artefact is missing or inconsistent;
  never a page of zeros that looks like data.

See `docs/DASHBOARD.md` for the file map, run commands, common errors and exit
criteria. See ADR-033, ADR-034 and ADR-035 for the new decisions.
`scripts/verify_stage11.py` re-runs Gates 1–10 as regressions.

## Stage 12 — delivered

`routes/api.py` registers `api_bp` under `/api/v1` with six JSON endpoints:
`csrf-token`, `health`, `model/info`, `scan`, `scans` and `scans/<id>`. The
scan endpoint calls the SAME `DetectionRegistry.scan()` pipeline as the HTML
form — validation, 15 features, `predict_proba`, the three-state decision,
measured explanations, one `ScanHistory` row — so no second inference path and
no unlogged result exists. The documented field names come from
`docs/ARCHITECTURE.md` §11; `DetectionResult.to_dict()` is deliberately
projected rather than returned verbatim.

Per-route, config-driven limits now protect `POST /login`, `POST /register`,
`POST /scan`, `POST /api/v1/scan` and the API read endpoints
(`RATE_LIMIT_AUTH` / `RATE_LIMIT_SCAN` / `RATE_LIMIT_API`). There is still no
blanket default throttle, and `TestingConfig` disables limits so tests stay
deterministic. A breach returns the generic `429 RATE_LIMITED` JSON/HTML shape
with `Retry-After`. CSRF is NOT exempted for API POSTs: clients fetch a token
from `/api/v1/csrf-token` and echo it in `X-CSRF-Token`.

Stage 12 also adds `Cross-Origin-Opener-Policy`,
`X-Permitted-Cross-Domain-Policies` and `Origin-Agent-Cluster`, applies
`no-store` to scan/history/admin/dashboard/API paths, and gives the 429 error
page a non-diagnostic hint. The CSP directive list, offline vendor hashes,
`SCAN WEBSITE` control, decision states, `SCORE_MEANING`, measured-only
metrics, `401 UNAUTHENTICATED` contract and the whole Stage 11 reporting layer
are unchanged. No bearer tokens, new tables, runtime CDNs or invented figures
were introduced. See `docs/SECURITY.md`, ADR-036/037/038 and
`scripts/verify_stage12.py`, which re-runs Gates 1–11 as regressions.

Reproduce:

```powershell
python scripts\verify_stage12.py       # must print RESULT: PASS
```

## Stage 13 — delivered

The formal suite lives in `tests/`: `conftest.py` plus five modules covering the
feature contract, the model and decision policy, the HTML routes, the `/api/v1`
contract and the security surface. **203 test functions / 259 cases**, all green,
no skips, no warnings, running in about seven seconds.

Reproduce:

```powershell
python -m pytest -v
python -m pytest tests\test_security.py -v
```

What changed, and what deliberately did not:

* **Added:** `tests/conftest.py`, `tests/test_features.py`,
  `tests/test_model.py`, `tests/test_routes.py`, `tests/test_api.py`,
  `tests/test_security.py`, `docs/TEST_PLAN.md`. `APP_VERSION` / `BUILD_STAGE`
  became `0.13.0` / `13`.
* **Unchanged:** every route, service, model, template, header, schema, CSP
  directive, decision state and measured figure. The suite tests the delivered
  system; it does not redesign it.
* **No `scripts/verify_stage13.py`.** Rule 5 of this document has said since
  Stage 1 that *Stage 13's gate is the full `pytest` suite*. A thirteenth shell
  gate would duplicate it, so `scripts/verify_stage12.py` now asserts that the
  file never appears.
* **Gates 10, 11 and 12 became Stage 13-aware:** `tests/*.py` and
  `docs/TEST_PLAN.md` moved from their forbidden lists to a required list, while
  `docs/REPORT.md` and `docs/DEPLOYMENT.md` (Stage 14) stay forbidden.

Notable findings, all documented in `docs/TEST_PLAN.md` §7: `with app.test_client()`
shares one login between simulated browsers (Flask-Login caches `current_user`
on `g`), production login needs HTTPS **and** a same-origin `Referer` because
`WTF_CSRF_SSL_STRICT` is on, and a developer `.env` made Gate 7's
"production refuses to start without `SECRET_KEY`" check vacuous — now fixed
by clearing the class attribute around the assertion.

## Stage 14 — delivered

Stage 14 completes the submission: `docs/REPORT.md` (chapters 1–5, real measured
results and the limitations section), five UML diagrams as offline SVGs, the
final `README.md` pass, `docs/DEPLOYMENT.md` with a clean `waitress` production
start, and `scripts/verify_stage14.py` as the executable exit gate. It adds no
feature and changes no test.

### What Stage 14 delivered

```powershell
.\.venv\Scripts\waitress-serve.exe --call --listen=127.0.0.1:8000 wsgi:create_application
.\.venv\Scripts\python.exe scripts\verify_stage14.py
```

* **Added:** `docs/REPORT.md`, `docs/DEPLOYMENT.md`,
  `docs/diagrams/{use-case,class-diagram,sequence-scan,activity-pipeline,deployment}.svg`,
  `scripts/verify_stage14.py`. `APP_VERSION` / `BUILD_STAGE` became `0.14.0` / `14`.
* **Unchanged:** every route, service, model, template, header, schema, CSP
  directive, decision state, measured figure and test. Route count stays at 22,
  the test module set is untouched, and the six test modules still collect 259 cases.
* **Gates 10, 11 and 12 became Stage 14-aware:** `docs/REPORT.md` and
  `docs/DEPLOYMENT.md` moved from their forbidden lists to required deliverables;
  `scripts/verify_stage13.py` stays forbidden forever (Stage 13's gate is `pytest`).

### What the gate proves, rather than asserts

1. **No fabricated numbers.** Every decimal printed to four or more places in
   `docs/REPORT.md` is matched against the values in `metrics.json` and
   `metadata.json`. 83 decimals are traced to 158 measured values; a hand-typed
   metric would fail the gate. (DOIs in the reference list are excluded.)
2. **The diagrams render offline.** Each SVG is parsed as XML, must declare a
   `viewBox`, contain at least 40 elements, and contain no external reference,
   `<script>`, raster `<image>` or remote font import.
3. **A clean production start.** `waitress-serve --call wsgi:create_application`
   is launched in a real subprocess with `APP_ENV=production` on a free loopback
   port; `/health`, `/api/v1/health`, `/api/v1/model/info` and `/` must answer
   200, the bundle must report a matching SHA-256, the database must be ready,
   the measured thresholds must be served, the production security headers must
   be present, an unauthenticated `POST /api/v1/scan` must still be rejected with
   400, and the process must terminate without a traceback.
4. **Stage discipline.** 22 application routes, 7 blueprints, the same six test
   modules, the same model bundle and thresholds.

### Correction carried into this stage

The Stage 14 review left one substantive finding, now stated in the report rather
than buried: the selected logistic-regression model wins the selection criterion
**while abstaining on 19.80 % of validation rows** (20.07 % on test) — roughly 2.6×
the decision tree's 7.65 %. Its decisive F1 of 0.998337 is therefore conditioned
on answering, not a general accuracy. `docs/REPORT.md` §5.2, §5.3.2, §5.8 and the
limitations section state the trade-off explicitly, and the report never quotes
0.9988 without the abstention rate in the same sentence.

## How to signal the next stage

There is no next stage: the fourteen-stage plan is complete, and every gate is green on the
final tree. Further work (the `has_https` ablation, calibration, content features) would be a
new Stage 15 and would need its own row in this table, its own exit gate and its own ADR — the
same discipline that produced the first fourteen.

## Project status

All fourteen stages are delivered and every gate is green on the final tree:
`pytest` (259 passed) plus twelve script gates (`verify_stage1.py` …
`verify_stage12.py`, `verify_stage14.py`; Stage 13's gate is the pytest suite).
There is no Stage 15.
