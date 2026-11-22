# Stage 11 — Dashboard, Scan History, Admin View and CSV Export

> **Status:** delivered. `scripts/verify_stage11.py` is the executable exit gate;
> Stage 12 does not start until it prints `RESULT: PASS`.
>
> **Safety notice:** Stage 11 is a **read-only reporting layer**. It does not
> visit, resolve or fetch any submitted URL. The no-network / no-SSRF rule from
> Stage 10 is unchanged. **HTTPS alone does not mean a website is legitimate.**

---

## 1. What Stage 11 builds

Stage 11 turns the audit trail created by Stage 10 into four usable views,
without touching the detection engine, the three decision states or the CSP:

| Route | Method | What it does | Who may use it |
| --- | --- | --- | --- |
| `/dashboard` | GET | Live KPI cards, three Chart.js charts and the **measured** held-out model figures | Public (counts only, no URLs) |
| `/history` | GET | Filterable, paginated scan history with report links | Guest (own session) or signed-in user (own account) |
| `/history/export.csv` | GET | CSV of exactly the rows visible to that viewer | Same scope as `/history` |
| `/admin` | GET | Accounts, measured model audit row, system counts and caveats | Admin role only |
| `/admin/export.csv` | GET | Full, explicitly authorised CSV export | Admin role only |

Everything is **read-only**: no Stage 11 module calls `db.session.add()`,
`commit()` or `delete()`, and no new table, column, migration or seed script is
introduced. `POST /scan` remains the only route that writes.

## 2. Runtime data sources

There is **no invented statistic anywhere in Stage 11**. Every displayed value
comes from one of three sources, read at request time:

1. `ml/saved_model/metrics.json` — the measured Stage 6 artefact. The dashboard
   reads `test.standard_0.5` (the five held-out metrics, confusion matrix and
   decision boundary) and `test.calibrated` (abstention band, decisive and
   abstained counts). It refuses to render if `test.scored_once` is not `true`
   or if a measured value is missing or out of range.
2. `sqlite://instance/phishing.db#scan_history` — SQL `COUNT` / `GROUP BY`
   aggregates for the KPI cards, the classification chart, the risk-level
   chart and the seven-day UTC volume chart. An empty database produces honest
   zeros and empty states, never demo rows.
3. `sqlite://instance/phishing.db#model_information` and `#users` — the admin
   console's measured model audit row and safe account projections.

`services/stats_service.py` computes one derived number, the
**SUSPICIOUS share**, as `SUSPICIOUS / total` over real rows; it is labelled
"Computed from real rows in this database" so it cannot be mistaken for a
measured model property.

**Proof, not assertion:** Gate 11 writes a tampered copy of `metrics.json` with
a different accuracy, points `METRICS_PATH` at it, and asserts the rendered
dashboard changes. If any figure were hard-coded, that check fails.

### Honest interpretation

Measured metrics describe the held-out 15% test split of PhiUSIIL / UCI 967 —
**not live traffic**. The corpus has a known HTTPS and URL-length shortcut, so
real-world performance is expected to be lower; recall and false negatives are
prioritised because a missed phishing site is the costliest error;
`SUSPICIOUS` is an abstention band, not a third trained class. Those caveats
are rendered alongside the numbers, not buried in a footnote.

## 3. File-by-file map

| File | Responsibility |
| --- | --- |
| `services/stats_service.py` | `system_overview()`, `system_counts()`, three chart payload builders, `measured_metrics()`, `visible_query()`, `parse_filters()`, `apply_filters()`, `history_page()`, `export_rows()`, `user_accounts()`, `model_information_rows()` |
| `services/report_service.py` | `CSV_COLUMNS`, `safe_cell()`, `build_csv()`, `csv_response()` |
| `routes/dashboard.py` | `GET /dashboard`; 503 on a missing artefact or schema |
| `routes/history.py` | `viewer_scope()`, `GET /history`, `GET /history/export.csv` |
| `routes/admin.py` | `admin_required`, `GET /admin`, `GET /admin/export.csv` |
| `templates/dashboard.html` | KPI grid, three `data-chart` canvases, measured metrics and caveats |
| `templates/history.html` | GET filter form, table, empty state, pagination, guest banner |
| `templates/admin.html` | Accounts, model audit row, live counts, caveats |
| `static/css/main.css` | Added `.pds-kpi-grid`, `.pds-chart-grid`, `.pds-filter-bar`, `.pds-badge-*`, `.pds-pagination`, `.pds-empty-state`; dark/light themes and print rules preserved |
| `static/js/main.js` | `cycledColours()` repeats the three CSS-variable colours for any number of chart bars; no new JS file and no inline script |
| `templates/base.html` | Dashboard / History nav links; Admin link only for an authenticated admin |
| `templates/errors/error.html` | A `Sign in` action on the generic 401 page (status code and error code unchanged) |
| `templates/index.html` | Five new working-endpoint rows |
| `config.py`, `app.py`, `services/__init__.py`, `routes/__init__.py` | `0.11.0` / `BUILD_STAGE = 11`, factory note, blueprint registry |
| `scripts/verify_stage11.py` | The executable exit gate |
| `docs/DASHBOARD.md` | This document |

## 4. Dashboard and charts

Stage 9's `data-chart` contract is reused verbatim, so no new JavaScript file,
no inline script, no inline `style=` attribute, no runtime CDN and no CSP
change were needed. Each payload is produced by `chart_payload()` and contains
exactly `labels`, `values`, `series_label` and `source`:

* **Classification distribution** (bar) — `LEGITIMATE / SUSPICIOUS / PHISHING`
  counts from `scan_history`.
* **Risk-level mix** (doughnut) — `LOW / MEDIUM / HIGH` counts.
* **Scan volume, last 7 UTC days** (bar) — `func.date(scan_date)` group-by,
  padded with zeros for days with no scans. `cycledColours()` gives each bar a
  theme-derived colour.

If Chart.js is unavailable, `main.js` reveals the text fallback inside each
chart box (the real counts, server-rendered), so the page degrades honestly.

Eight KPI cards show total scans, PHISHING alerts, abstentions, SUSPICIOUS
share, guest scans, linked scans, and the first/last UTC scan timestamps. These
are **counts only** — no submitted URL from any user appears on the public
dashboard.

## 5. History, filters and pagination

`GET /history` accepts four validated query parameters:

| Parameter | Values | Behaviour |
| --- | --- | --- |
| `prediction` | `LEGITIMATE`, `SUSPICIOUS`, `PHISHING` (or empty) | Exact state filter; an unknown value is ignored, not interpolated into SQL |
| `risk` | `LOW`, `MEDIUM`, `HIGH` (or empty) | Exact risk filter |
| `q` | free text, max 120 characters | Case-preserving substring search on `normalised_url`, using SQLAlchemy's bound `contains(..., autoescape=True)` so `%`, `_` and the escape character cannot widen a match |
| `page`, `per_page` | positive integers; `per_page` capped at 100 | Page is clamped to the last real page |

Rows are ordered `scan_date DESC, id DESC` and projected via `ScanHistory.to_dict()`
plus `flagged` indicator names and a printable-report path. The empty state says
"No matching scans" and explains that it is a real empty result. The CSV link
carries the current filters.

## 6. Admin view

`admin_required()` composes Flask-Login's `login_required` with an explicit
`current_user.is_admin` check:

* anonymous → the **Stage 8** `401 UNAUTHENTICATED` contract (themed HTML for a
  browser, JSON error shape for `?format=json`);
* ordinary signed-in user → `403 FORBIDDEN`;
* admin → the console.

The global `unauthorized_callback` and `login_view` settings are deliberately
**unchanged**; Stage 11 does not add a content-negotiated redirect that could
weaken a closed stage's security contract. Instead the generic 401 page gains a
`Sign in` link.

Accounts are rendered exclusively through `User.to_dict()` plus a live scan
count. `password_hash` is never selected, rendered or exported; only scrypt
hashes exist in the database and registration always forces `role="user"`.
Administrators are created solely by `scripts/create_admin.py`.

## 7. CSV export security

`services/report_service.py` treats every submitted URL as hostile input:

* **Formula injection:** any cell starting with `=`, `+`, `-`, `@`, TAB, CR (or
  leading whitespace followed by one of these) is prefixed with an apostrophe.
  `csv.writer` quoting alone does **not** stop Excel/LibreOffice from evaluating
  a formula, so `safe_cell()` is applied to every text cell.
* **Newline injection:** CR, LF and NUL are removed so one stored URL can never
  create extra CSV rows or headers.
* **Safe filename:** a fixed ASCII `scan-history-YYYYMMDD.csv` (or
  `admin-scan-export.csv`) with characters outside `[A-Za-z0-9_.-]` stripped.
  No user input reaches `Content-Disposition`.
* **Headers:** `text/csv; charset=utf-8`, `Content-Disposition: attachment`,
  `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and an exact
  `Content-Length`. A UTF-8 BOM is prepended so Windows Excel detects the
  encoding.
* **Bounded and scoped:** at most 5,000 rows, and the caller passes only rows
  from `stats_service.export_rows()`. The admin endpoint is the sole path that
  sets `all_rows=True`.
* **Password hashes are never a column.**

Columns: `scan_id`, `scan_date_utc`, `submitted_url`, `normalised_url`,
`classification`, `risk_level`, `model_score`, `model_version`,
`linked_user_id`, `flagged_indicators`, `report_path`.

Gate 11 inserts a stored row whose URL is `=SUM(1+1)\r\n<script>alert(1)</script>`
through the ORM (not through the public form), then asserts the CSV contains
`'=SUM(1+1)` and still has exactly one row per record, and that the history
table renders `&lt;script&gt;` rather than a live tag.

## 8. Authorisation and privacy

History reuses Stage 10's `can_view_scan` policy *exactly*:

* signed-in user → only rows with `ScanHistory.user_id == current_user.id`;
* guest → only ids recorded in their own signed Flask session (Stage 10 bounds
  that list to 25); an empty list produces an always-false filter, never the
  whole table;
* a different anonymous browser sees an empty history and an empty CSV;
* `/admin/export.csv` is the only full export and requires the admin role.

Guest scans keep `user_id = NULL`. Scans made before signing in are **not**
automatically claimed afterwards; the history page says so plainly. This keeps
Stage 10's authorisation contract intact and avoids an account-takeover surface
in the reporting layer.

All filter values are bound parameters through the ORM. Jinja autoescaping
remains enabled. CSRF is unchanged (GET-only views need no token). The CSP is
byte-for-byte identical to Stage 9/10, and all three vendored SHA-256 hashes
are re-verified by the gate.

## 9. What is deliberately NOT in Stage 11

* No change to `services/detection_service.py`, `decision_service.py`,
  `explanation_service.py`, `models/prediction_model.py` or the three decision
  states, thresholds and uncertainty band.
* No live URL fetching, DNS lookup, socket or HTTP client; the no-network /
  SSRF prohibition holds for every Stage 11 module too.
* No `/api/v1/scan`, no REST JSON contract, no per-route rate limits, no
  security-header changes — those belong to **Stage 12**.
* No `tests/` suite or `docs/TEST_PLAN.md` (Stage 13), no `docs/REPORT.md` or
  `docs/DEPLOYMENT.md` (Stage 14), no `docs/SECURITY.md` (Stage 12).
* No new tables, columns, migrations, seeded demo rows, hard-coded statistics,
  second chart controller (`static/js/dashboard.js`), runtime CDN, inline
  script or inline style.
* No measured figure typed into a template, a JS file or a Stage 11 Python
  module; measured numbers are read from `metrics.json` at runtime.
* No claiming of guest rows after sign-in.

## 10. Run and test

### Windows / PowerShell (first)

```powershell
cd phishing-detection-system
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into .env as SECRET_KEY
python scripts\init_db.py
python scripts\init_db.py --verify-only
python scripts\create_admin.py            # optional: needed to open /admin
python -m flask --app app run --host 0.0.0.0 --port 5000
```

Then open:

```
http://localhost:5000/dashboard
http://localhost:5000/history
http://localhost:5000/history/export.csv
http://localhost:5000/admin                 (after signing in as admin)
```

Run the full gate (it re-runs Gates 1–10 as regressions):

```powershell
python scripts\verify_stage11.py
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
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python scripts/init_db.py
python scripts/verify_stage11.py
python -m flask --app app run --host 0.0.0.0 --port 5000
```

### A safe, offline demonstration

```powershell
python -m flask --app app run --host 0.0.0.0 --port 5000
```

Open `http://localhost:5000/scan` and press **SCAN WEBSITE** two or three times
with reserved strings such as `https://example.com/` or
`https://paypal.com.login.verify.example.invalid/secure/account/update?next=confirm`.
Then reload `/dashboard` and `/history` — the KPI cards, charts and table change
because they count real rows. The backend never visits any address.

## 11. Common errors and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `503 DATABASE_UNAVAILABLE` on `/dashboard`, `/history` or CSV | `instance/phishing.db` was never initialised, or the SQLite path is unreachable | Run `python scripts\init_db.py`; confirm `python scripts\init_db.py --verify-only` prints `ready` with tables `model_information, scan_history, users` |
| `503 MODEL_UNAVAILABLE` on `/dashboard` | `ml/saved_model/metrics.json` is missing, corrupt, or missing `test.scored_once = true` | Regenerate measured artefacts with `python -m ml.evaluate_model`, then restart. **Never** substitute a hard-coded figure — Stage 11 fails closed |
| `/admin` shows `401 UNAUTHENTICATED` | You are anonymous | Use the *Sign in* link on the 401 page and sign in as an administrator |
| `/admin` shows `403 FORBIDDEN` | You signed in as an ordinary user | Create/promote an admin with `python scripts\create_admin.py` (or `--promote`); registration never grants the admin role |
| Empty `/history` after signing in | Guest scans belong to the browser session, not the account; they are not claimed | This is intentional. Scan again while signed in, or stay in the original guest session |
| CSV opens with garbled characters on Windows | The viewer forced a non-UTF-8 code page | A UTF-8 BOM is already included; use Excel's *Data → From Text/CSV* and choose UTF-8 |
| A URL beginning with `=` looks odd in CSV | Deliberate formula-injection protection | The leading apostrophe forces spreadsheet software to treat it as text; it is not part of the stored URL |
| Charts are blank | Chart.js was blocked or disabled | The server-rendered text fallback inside each chart box shows the same real counts; verify `static/vendor/chart.umd.min.js` with `Get-FileHash` |
| `ModuleNotFoundError: flask` / `sklearn` | Virtual environment not active | Run `.\.venv\Scripts\Activate.ps1` (Windows) or `source .venv/bin/activate` (Linux), then `python -m pip check` |
| `verify_stage11.py` reports an old Gate 7/9/10 failure | A historical gate asserted that Stage 11 files/routes must be absent | Those gates are stage-aware: they detect `services/stats_service.py` and `scripts/verify_stage11.py` and switch to checking Stage 12+ absence instead. Do not delete the assertions; rerun the full gate |

Verify the offline vendor assets are untouched:

```powershell
Get-FileHash static\vendor\bootstrap.min.css -Algorithm SHA256
Get-FileHash static\vendor\bootstrap.bundle.min.js -Algorithm SHA256
Get-FileHash static\vendor\chart.umd.min.js -Algorithm SHA256
```

## 12. Stage 11 exit criteria

`python scripts\verify_stage11.py` must print `RESULT: PASS - all Stage 11
checks passed`. It verifies, with real temporary databases and real HTTP
requests:

* the exact file inventory, absence of all Stage 12+ files and routes, and
  compilation of every Python file;
* runtime aggregates against exact SQL counts, honest zeros on an empty
  database, seven-day UTC charts, and measured metrics copied from
  `metrics.json` (including the tampered-artefact proof);
* filter validation, SQL-injection-shaped search strings, pagination clamping
  and per-account / per-session visibility;
* CSV formula/CRLF/filename/NUL defences, safe headers, and no leakage of
  another account's URLs;
* `401 UNAUTHENTICATED` for anonymous `/admin`, `403 FORBIDDEN` for ordinary
  users, and a working admin console with no password hashes;
* `503 DATABASE_UNAVAILABLE` and `503 MODEL_UNAVAILABLE` failure paths;
* Jinja escaping of hostile stored URLs, exact CSP, unchanged vendor hashes,
  no inline script/style, no network client in any runtime module;
* documentation, ADRs and Windows-first commands;
* **Gates 1–10 still pass** and `pip check` is clean.

Only after that pass may Stage 12 (security hardening and the REST API) begin.
`PDS_GATE_NESTED=1` keeps the historical regression chain linear: Gate 11 runs
Gates 1–10 directly, and child gates skip only their duplicated nested
re-runs. Standalone gates keep their full behaviour.

## Stage 12 note — reporting layer untouched

Stage 12 adds the versioned REST API, per-route rate limits and additive
response headers. It does **not** change `services/stats_service.py`,
`services/report_service.py`, `routes/dashboard.py`, `routes/history.py`,
`routes/admin.py` or any of their templates. Every KPI, chart value, measured
figure, filter, CSV rule, `401 UNAUTHENTICATED` / `403 FORBIDDEN` response and
the formula-injection boundary described in this document remain exactly as
Stage 11 delivered them. `GET /api/v1/model/info` uses the same
`stats_service.measured_metrics()` source as the dashboard, and
`GET /api/v1/scans` uses the same `stats_service.history_page()` visibility
policy as `/history`. Gate 12 re-runs Gate 11 as a regression to prove this.
See `docs/SECURITY.md` §4 and ADR-036/038.
