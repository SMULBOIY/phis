# Intelligent Phishing Website Detection System Using Machine Learning Techniques

A final-year Computer Science project: a Flask web application that analyses a submitted **URL string** with a trained scikit-learn classifier and reports LEGITIMATE, PHISHING or SUSPICIOUS — with honest uncertainty, explained indicators and a full audit trail.

> **Safety notice:** this system performs **static, lexical URL analysis only**. The backend never visits, resolves or executes a submitted URL (no SSRF surface, no exposure to live malicious sites). A "LEGITIMATE" result is not a guarantee that a website is safe.

## Project status

| Stage | Name | Status |
| --- | --- | --- |
| 1 | Project planning and architecture | ✅ Complete — exit gate passed |
| 2 | Environment setup and installation | ✅ Complete — exit gate passed |
| 3 | Dataset acquisition and preprocessing | ✅ Complete — exit gate passed |
| 4 | URL feature extraction | ✅ Complete — exit gate passed |
| 5 | Model training | ✅ Complete — exit gate passed |
| 6 | Model evaluation and selection | ✅ Complete — exit gate passed |
| 7 | Flask backend | ✅ Complete — exit gate passed |
| 8 | Database integration | ✅ Complete — exit gate passed |
| 9 | Frontend development | ✅ Complete — exit gate passed |
| 10 | Detection engine integration | ✅ Complete — exit gate passed |
| 11 | Dashboard and scan history | ✅ Complete — exit gate passed |
| 12 | Security and REST API | ✅ Complete — exit gate passed |
| 13 | Testing and debugging | ✅ Complete — `pytest`: 259 passed |
| 14 | Documentation and final deployment | ✅ Complete — `RESULT: PASS`, clean production start |

**A model has now been selected, thresholds calibrated and real metrics measured.** All performance numbers live in `ml/saved_model/metrics.json`, `metadata.json`, `docs/EVALUATION.md` and `docs/MODEL_CARD.md` — generated from measurement, never hand-typed. Read those files for figures; quoting them here would create a second copy that could drift.

## Dataset attribution (CC BY 4.0 — required)

> Prasad, A., & Chandra, S. (2023). *PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning*. Computers & Security, 103545. https://doi.org/10.1016/j.cose.2023.103545. Dataset: UCI Machine Learning Repository, dataset 967.

| Document | Contents |
| --- | --- |
| `docs/ARCHITECTURE.md` | Complete system design and communication flows |
| `docs/DECISIONS.md` | ADR-001…044 — why each decision was made |
| `docs/SETUP.md` | Windows-first environment setup |
| `docs/ENVIRONMENT.md` | Measured interpreter and package versions |
| `docs/DATASET.md` | Real dataset provenance, preprocessing and leakage report |
| `docs/FEATURES.md` | All 15 features, measured statistics and bias warnings |
| `docs/TRAINING.md` | Three pipelines, hyperparameters, artefacts, reproducibility |
| **`docs/EVALUATION.md`** | **Measured per-model comparison, selection, thresholds, final test results** |
| **`docs/MODEL_CARD.md`** | **Deployed model, measured performance, limitations, bias disclosure** |
| `docs/BACKEND.md` | Flask factory, extension wiring, HTTP contract, security, run/test commands |
| **`docs/DATABASE.md`** | **Stage 8 ER model, schema, constraints, auth flow, bootstrap, gate** |
| **`docs/UI.md`** | **Stage 9 templates, dark/light themes, offline assets, Chart.js contract** |
| **`docs/DETECTION.md`** | **Stage 10 pipeline, decision policy, failure paths, SSRF rule** |
| **`docs/DASHBOARD.md`** | **Stage 11 dashboard, history, admin, CSV export and security** |
| **`docs/SECURITY.md`** | **Stage 12 REST contract, per-route limits, threat model, SSRF/CSP/CSS hardening** |
| `docs/TEST_PLAN.md` | Stage 13 test strategy, fixture map, coverage matrix, measured results |
| **`docs/REPORT.md`** | **Final academic report — chapters 1–5, measured results, limitations, references** |
| **`docs/DEPLOYMENT.md`** | **Stage 14 deployment guide — install, configure, waitress, TLS proxy, service, runbook, troubleshooting** |
| **`docs/diagrams/`** | **UML: use case, class, sequence, activity, deployment (+ Stage 1 architecture) — offline SVG** |
| **`docs/ACCEPTANCE_REVIEW.md`** | **Final production acceptance review — live campaign, dataset audit, independent metric recomputation and the path/length finding** |
| `docs/STAGE_PLAN.md` | 14-stage roadmap and exit gates |

## Quick start

### First-time setup (Windows / PowerShell)

```powershell
cd phishing-detection-system
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste result into .env as SECRET_KEY
```

Linux / macOS: `source .venv/bin/activate` and `cp` instead of `copy`. Full instructions: `docs/SETUP.md`.

> The `.venv` directory is excluded from this sandbox's persisted snapshot, so a fresh stage may need the three venv commands repeated. That is normal — `requirements.txt` reproduces it exactly.

### Full offline ML pipeline (Stages 3 → 6)

```powershell
python scripts\download_dataset.py --verify-only
python -m ml.preprocess --input dataset\raw\PhiUSIIL_Phishing_URL_Dataset.csv --output-dir dataset\processed --ratios 0.70 0.15 0.15 --seed 42
python scripts\analyse_features.py
python -m ml.train_model
python -m ml.evaluate_model
```

### Initialise the database (Stage 8 — do this once)

```powershell
python scripts\init_db.py                 # creates instance/phishing.db
python scripts\create_admin.py            # optional: prompts for a strong admin password
python scripts\init_db.py --verify-only
```

`init_db.py` creates the three tables and copies the **measured** test metrics
from `metrics.json` into the `model_information` audit row. It creates **no user
account**; there are no default credentials. Full schema, constraints and the
ER diagram are in `docs/DATABASE.md`.

### Run the Flask backend (Stages 7–9)

```powershell
python -m flask --app app run --host 0.0.0.0 --port 5000
```

Then open, in a normal browser tab:

| URL | What you get |
| --- | --- |
| `http://127.0.0.1:5000/` | SOC-style overview, live telemetry, dark/light toggle, dataset chart |
| `http://127.0.0.1:5000/health` | JSON health: model artefact integrity + real schema status |
| `http://127.0.0.1:5000/login` | Styled working sign-in form |
| `http://127.0.0.1:5000/register` | Styled working registration form |
| `http://127.0.0.1:5000/auth/session` | Current session state |

`python wsgi.py` starts the same app with waitress. Full details are in
`docs/BACKEND.md`, `docs/DATABASE.md` and `docs/UI.md`. The live-preview iframe
cannot send `SameSite=Lax` session cookies for subrequests, so test login in its
own tab. Bootstrap 5.3.3 and Chart.js 4.4.4 are vendored in `static/vendor/`
(no CDN, no network needed).

> Stage 9 has **no scan form and no `"SCAN WEBSITE"` button** — those arrive in
> Stage 10. A button that cannot scan would be pretending. The only chart shows
> real dataset split row counts read from `metadata.json` at runtime.

### Verify the current stage

```powershell
python scripts\verify_stage1.py     # historical gate (stage-aware)
python scripts\verify_stage2.py     # historical gate (stage-aware)
python scripts\verify_stage3.py     # historical gate (stage-aware)
python scripts\verify_stage4.py     # historical gate (stage-aware)
python scripts\verify_stage5.py     # historical gate (stage-aware)
python scripts\verify_stage6.py     # historical gate — recomputes ALL metrics
python scripts\verify_stage7.py     # historical gate — boots and exercises the app
python scripts\verify_stage8.py     # historical gate — schema, ORM, auth, CLIs
python scripts\verify_stage9.py     # historical gate — templates, themes, charts
python scripts\verify_stage10.py    # historical gate — real detection pipeline
python scripts\verify_stage11.py    # historical gate — dashboard, history, admin, CSV
python scripts\verify_stage12.py    # historical gate — REST API, rate limits, security
python -m pytest -v                 # Stage 13 gate — the full test suite (259 cases)
python scripts\verify_stage14.py    # CURRENT EXIT GATE — docs integrity + production start
```

All thirteen gate scripts must print `RESULT: PASS`, and `pytest` must report
`259 passed`. Stage 13's published gate is the suite itself, which is why there
is no `scripts/verify_stage13.py` (see `docs/TEST_PLAN.md` §0). `verify_stage8.py` … `verify_stage12.py`
use isolated temporary SQLite databases and never modify your real
`instance/phishing.db`. `verify_stage14.py` launches a real `waitress` process
on a free loopback port, exercises four endpoints, checks the production
headers, and refuses to pass if any figure in `docs/REPORT.md` cannot be traced
to `metrics.json` / `metadata.json`.

## Repository layout

```
phishing-detection-system/
├── app.py                  # create_app() application factory    [STAGE 7+8]
├── wsgi.py                 # production WSGI entry              [STAGE 7]
├── extensions.py           # db / csrf / login_manager / limiter [STAGE 7]
├── config.py               # Dev/Test/Prod configuration [STAGE 2, extended 7+8]
├── requirements.txt        # pinned dependencies          [STAGE 2]
├── .env.example            # documented secret names      [STAGE 2]
├── .gitignore
├── README.md
├── dataset/
│   ├── raw/                # PhiUSIIL CSV + ZIP (gitignored, hash-verified)
│   └── processed/          # train/validation/test + manifest + leakage + feature summary
├── ml/
│   ├── url_utils.py           # canonical network-free URL normaliser [STAGE 3]
│   ├── preprocess.py          # cleaning, dedup, leakage-safe split   [STAGE 3]
│   ├── feature_extraction.py  # THE 15-feature contract              [STAGE 4]
│   ├── train_model.py         # LR / DT / RF pipelines               [STAGE 5]
│   ├── thresholds.py          # abstention-band calibration          [STAGE 6]
│   ├── evaluate_model.py      # measured metrics + selection         [STAGE 6]
│   └── saved_model/
│       ├── candidates/        # 3 fitted .joblib + training_manifest.json [STAGE 5]
│       ├── model_bundle.joblib # DEPLOYED model                      [STAGE 6]
│       ├── metadata.json       # thresholds, states, wording, hashes [STAGE 6]
│       └── metrics.json        # ALL measured performance numbers     [STAGE 6]
├── services/
│   ├── validation.py       # live input boundary, shares normaliser [STAGE 4]
│   ├── model_metadata.py   # metadata.json + bundle hash validation [STAGE 7]
│   ├── http_security.py    # CSP, error handlers, request guard   [STAGE 7]
│   ├── auth_service.py     # password policy, scrypt, lookup     [STAGE 8]
│   ├── database_service.py # schema bootstrap, status, measured seeding [STAGE 8]
│   ├── detection_service.py, decision_service.py, explanation_service.py [STAGE 10]
│   ├── stats_service.py    # live aggregates, filters, measured metrics [STAGE 11]
│   └── report_service.py   # formula-safe CSV export           [STAGE 11]
├── models/
│   ├── __init__.py         # ORM re-exports                      [STAGE 8]
│   ├── database_models.py  # User / ScanHistory / ModelInformation [STAGE 8]
│   └── ...                 # prediction_model.py (Stage 10)
├── routes/
│   ├── __init__.py         # blueprint registry                   [STAGE 7]
│   ├── core.py             # / and /health                       [STAGE 7+8]
│   ├── auth.py             # session, CSRF, /login, /register, /logout [STAGE 7+8]
│   ├── scanning.py         # /scan, /scan/<id>/report          [STAGE 10]
│   └── dashboard.py, history.py, admin.py                       [STAGE 11]
├── templates/              # Jinja2 pages                        [STAGE 9]
│   ├── base.html           # master layout, nav, theme toggle, assets
│   ├── index.html          # overview, telemetry, dataset chart
│   ├── login.html, register.html, auth_result.html
│   ├── scan.html, scan_report.html, partials/scan_result.html  [STAGE 10]
│   ├── dashboard.html, history.html, admin.html                [STAGE 11]
│   └── errors/error.html   # themed 400/404/500 pages
├── static/
│   ├── css/backend.css     # legacy status/error stylesheet     [STAGE 7+8]
│   ├── css/main.css        # dark + light SOC design system     [STAGE 9]
│   ├── js/theme.js         # pre-paint theme bootstrap         [STAGE 9]
│   ├── js/main.js          # toggle, Chart.js, nav, copy, print [STAGE 9-10]
│   ├── images/logo.svg     # self-contained vector logo        [STAGE 9]
│   └── vendor/             # Bootstrap 5.3.3 + Chart.js 4.4.4 (hash-verified)
├── instance/               # phishing.db (created by init_db.py, gitignored)
├── docs/                   # REPORT + DEPLOYMENT, architecture, ADRs, setup, dataset,
│                           # features, training, evaluation, model card, backend,
│                           # database, UI, DETECTION, DASHBOARD, SECURITY, TEST_PLAN
│   └── diagrams/           # architecture + 5 UML diagrams (offline SVG)  [STAGE 1, 14]
├── scripts/                # download_dataset, analyse_features, init_db, create_admin,
│                           # verify_stage1..12 + verify_stage14               [STAGE 1-12, 14]
└── tests/                  # pytest suite — 259 cases (Stage 13)
```

Empty directories contain a `.gitkeep` so they survive `git clone`.

## Academic integrity

- Training data is a **real, cited, hash-verified dataset**. No synthetic training rows exist; synthetic strings/rows are used only in temporary unit-test fixtures and controlled examples.
- Only raw URL text + label are used; the 54 pre-computed columns were discarded because a static scanner cannot compute them.
- One normaliser and one feature extractor are shared by training and inference; `FEATURE_ORDER` is stored inside every model bundle.
- Group-aware splits with measured zero leakage; a 23,675-URL phishing-kit cluster is confined to training.
- Model selection, threshold calibration and final metrics were measured on validation / test respectively. `verify_stage6.py` **independently recomputes every published figure** and fails on mismatch.
- **Measured bias, disclosed not hidden:** `has_https` is the most influential feature (permutation importance), confirming the dataset shortcut. HTTPS alone does not mean a website is legitimate, and the reported accuracy is optimistic for real-world traffic. An ablation study is recommended future work. See `docs/EVALUATION.md` §6.1.
- `SUSPICIOUS` is a documented **abstention band** over a binary classifier, not an invented third class. The measured abstention rate is reported.
- The model score is described as an uncalibrated estimate of `P(phishing | URL features)`, never as a guaranteed probability of maliciousness.
- No performance figure is hard-coded in any template or script: the Stage 11 dashboard and admin console read `metrics.json` / `metadata.json` at request time and label every figure with its source. Gate 11 proves this by rendering a tampered copy of the artefact.

## Scan a URL (Stage 10)

```powershell
python scripts\init_db.py
python -m flask --app app run --host 0.0.0.0 --port 5000
```

Open `http://localhost:5000/scan` and press **SCAN WEBSITE**. Guests may scan;
signed-in scans are linked to their account. The result shows the submitted
URL, classification, a clearly labelled **uncalibrated model score**, risk
level, UTC date/time, all 15 characteristics, suspicious-feature explanations,
uncertainty caveats and a recommended action. The backend **never visits the
submitted URL**. Full details: [`docs/DETECTION.md`](docs/DETECTION.md).

## Dashboard, history and CSV export (Stage 11)

```powershell
python scripts\init_db.py --verify-only
python scripts\verify_stage11.py
python -m flask --app app run --host 0.0.0.0 --port 5000
```

The executable exit gate is `scripts/verify_stage11.py` (Windows:
`python scripts\verify_stage11.py`); it re-runs Gates 1–10 as regressions.

Then open `http://localhost:5000/dashboard` for live KPI cards, three real
Chart.js charts and the **measured** held-out model figures,
`http://localhost:5000/history` for a filtered, paginated audit table, and
`http://localhost:5000/history/export.csv` for a safe CSV download. Create an
administrator with `python scripts\create_admin.py` to open `/admin` and
`/admin/export.csv`.

Every number is counted from `scan_history`, `users` and `model_information`,
or copied from `ml/saved_model/metrics.json` at request time. There are no
demo rows and no hard-coded statistics. History is scoped to the signed-in
account or, for guests, to their own signed session. CSV cells are protected
against spreadsheet formula injection. The CSP, decision states and detection
engine are unchanged; the backend still never visits a submitted URL. Full
details: [`docs/DASHBOARD.md`](docs/DASHBOARD.md).

## REST API, rate limits and security (Stage 12)

```powershell
python scripts\init_db.py --verify-only
python scripts\verify_stage12.py
python -m flask --app app run --host 0.0.0.0 --port 5000
```

The executable exit gate is `scripts/verify_stage12.py` (Windows:
`python scripts\verify_stage12.py`); it re-runs Gates 1–11 as regressions,
uses temporary SQLite databases and prints `RESULT: PASS` only when every
check succeeds.

`routes/api.py` registers six versioned JSON endpoints under `/api/v1`:
`csrf-token`, `health`, `model/info`, `scan`, `scans` and `scans/<id>`. The API
calls **the same** `DetectionRegistry.scan()` pipeline as the HTML form, so
there is no second inference path and every successful scan still writes one
`ScanHistory` row. Per-route, config-driven rate limits (`RATE_LIMIT_SCAN`,
`RATE_LIMIT_AUTH`, `RATE_LIMIT_API`) protect `POST /scan`, `POST /login`,
`POST /register` and the API data endpoints; a breach returns the generic
`429 RATE_LIMITED` JSON/HTML shape with `Retry-After`. CSRF is **not** exempted
for API POSTs — clients fetch a token from `/api/v1/csrf-token` and send it in
`X-CSRF-Token`.

Stage 12 also adds `Cross-Origin-Opener-Policy`,
`X-Permitted-Cross-Domain-Policies` and `Origin-Agent-Cluster`, marks sensitive
responses `no-store` and improves the 429 error page. The **CSP directive list
is byte-for-byte unchanged**, as are the offline vendor hashes, the three
decision states, `SCORE_MEANING`, the Stage 11 reporting layer and the exact
`SCAN WEBSITE` control. No bearer tokens, no new table, no invented figure and
no runtime CDN were introduced. Full threat model, REST contract, Windows-first
commands and troubleshooting: [`docs/SECURITY.md`](docs/SECURITY.md) and ADR-036…038.

## Testing (Stage 13)

```powershell
# The exit gate: the full suite
python -m pytest -v

# Quiet summary / one module / one test
python -m pytest -q
python -m pytest tests\test_security.py -v
python -m pytest -k "csrf or 429" -v
```

**Measured result:** `259 passed in ~7 s`, no skips, no xfails, no warnings.

`tests/` converts the executable gate assertions into 203 test functions across
six modules — `test_features.py` (the 15-feature contract and URL parity),
`test_model.py` (artefact integrity, the three decision states, explanation,
orchestration), `test_routes.py` (forms, sessions, history, dashboard, admin,
explicit failure paths), `test_api.py` (the `/api/v1` contract), and
`test_security.py` (CSP, CSRF, rate limits, hashing, XSS, SSRF). `conftest.py`
builds an isolated application per configuration with a temporary SQLite file.

Nothing in the suite contacts the network, opens `instance/phishing.db`, or uses
a live malicious URL: every input is a reserved `example.com` / `example.invalid`
string. The SSRF proof is behavioural — the socket layer is made unusable and a
scan still succeeds, because the URL is only ever analysed as a string.

Strategy, fixture map, coverage matrix against the brief, the behaviours the
suite uncovered and a troubleshooting table: [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md).

## Report, diagrams and deployment (Stage 14)

```powershell
# the exit gate: documentation integrity + a real production start
.\.venv\Scripts\python.exe scripts\verify_stage14.py    # CURRENT EXIT GATE — docs integrity + production start

# production server (options BEFORE the module spec — waitress parses it positionally)
waitress-serve --call --listen=127.0.0.1:8000 wsgi:create_application
```

| Deliverable | Where |
| --- | --- |
| Academic report (chapters 1–5, measured results, limitations, references) | [`docs/REPORT.md`](docs/REPORT.md) |
| UML diagrams — use case, class, sequence, activity, deployment | [`docs/diagrams/`](docs/diagrams) |
| Deployment guide — install, configure, TLS proxy, service, runbook | [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) |

The report contains **only measured figures**: every number printed to four or
more decimal places is traced back to `ml/saved_model/metrics.json` or
`metadata.json` by the gate, so a hand-typed metric fails the build. Derived
quantities (percentages, counts) are always shown next to the primary figure
they derive from.

Read together with `docs/MODEL_CARD.md`, the honest summary is: on the held-out
PhiUSIIL test split the model reaches **0.9839 accuracy / 0.9981 ROC-AUC** at a
0.5 boundary, and under the deployed three-state policy it **abstains on 20.07 %
of URLs**, reaching **precision 0.9998 / recall 0.9977 / F1 0.9988** on the
remaining 79.93 %. Both figures belong to the same sentence, because **100.00 %
of legitimate URLs in the corpus use HTTPS against 56.90 % of phishing URLs** and
`has_https` is the model's largest feature by permutation importance — so the
numbers are optimistic for live traffic. The system analyses the URL string
only, never visits the site, and a LEGITIMATE verdict is not a guarantee.

> **Known critical limitation (final acceptance review).** In the training corpus
> **0.00 % of legitimate URLs contain a path** (33.59 % of phishing URLs do), so the
> model reads a path or query string as evidence of phishing: appending `/about`
> to a URL the corpus labels legitimate turns a LEGITIMATE verdict into PHISHING.
> On a hand-picked sample of 20 well-known benign URLs, 11 were reported PHISHING.
> The published metrics are correct for the corpus distribution, but the system is
> **an academic demonstration, not a usable real-world screener**. Full evidence and
> the recommended fix (deep links in the negative class, then retrain and re-measure)
> are in [`docs/ACCEPTANCE_REVIEW.md`](docs/ACCEPTANCE_REVIEW.md).

## Commit each stage (optional)

```powershell
git init
git add .
git commit -m "Stage 14: academic report, UML diagrams, deployment guide"
```

---

*Stage 14 of 14 — the project is complete. A measured ML pipeline; a Flask backend with SQLite authentication; a responsive SOC-style interface; a detection engine that classifies URLs with explicit uncertainty; dashboards, scoped history, an admin console and safe exports; a versioned REST API sharing that one pipeline behind config-driven limits; a 259-case offline pytest suite; thirteen executable gates; and now the academic report, the UML models and a documented `waitress` deployment. Every claim in the report traces to an artefact, and the report says plainly where those claims stop being true.*
