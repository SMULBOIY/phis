# Final Production Acceptance Review

**Scope.** Independent acceptance review of the delivered system (Stage 14 tree, `APP_VERSION`
`0.14.0`, `BUILD_STAGE` `14`). Nothing in this document adds a feature or changes the pipeline: it
records what was executed, what it produced, and what failed.

**Method.** Every functional check below was performed over HTTP against the running application,
exactly as a browser does — real cookies, CSRF tokens scraped from the rendered HTML, real form posts —
not against the test client and not by reading the source. Model figures were recomputed independently
through the serving path (`normalize_url` → `extract_features` → `PredictionModel.score` → `decide`)
rather than read back from `metrics.json`.

**Test data.** All submitted URLs are either reserved/synthetic strings (`example.invalid`,
`192.0.2.0/24`) or public homepages used as *strings only*. The application never fetches, resolves or
executes a submitted URL, and no live malicious URL was contacted at any point.

**Environment.** Python 3.13.16, Flask 3.1.3, scikit-learn 1.6.1, waitress, SQLite. Development
campaign: `wsgi.py` on `127.0.0.1:5000`. Production campaign: `waitress-serve --call
wsgi:create_application` on `127.0.0.1:8097` with `APP_ENV=production`.

---

## 1. Verdict

| Area | Result |
| --- | --- |
| Application engineering (UI, auth, history, dashboard, CSV, report, API, admin) | **PASS** — 93 live HTTP checks, 0 failures |
| Security posture (CSP, CSRF, scoping, escaping, rate limits, headers) | **PASS** |
| Production deployment (waitress, headers, secure cookies, model verification) | **PASS** |
| Measured metrics reproducibility | **PASS** — every headline figure reproduced to ≤ 5 × 10⁻⁷ |
| Dataset integrity and leakage | **PASS** — zero group/URL overlap across splits, hashes match |
| Documentation completeness | **PASS** — 20 documents, 7 957 lines, 0 broken internal links |
| **Model behaviour outside the corpus distribution** | **FAIL (documented)** — see Finding A |
| F1 0.9988 documented as conditional on answering | **PASS** — stated with coverage and abstention rates |

**Overall: accepted as a coursework deliverable, with one material limitation that must be disclosed
to the supervisor: the deployed model is not a usable real-world screener.** Its measured metrics are
honest and reproduce exactly, but those metrics describe a corpus in which *no* legitimate URL contains
a path, so the model treats almost any real webpage as phishing. This is Finding A and is now stated in
`docs/REPORT.md`, `docs/MODEL_CARD.md` and `README.md`.

---

## 2. Functional verification (development campaign)

Command: `./.venv/bin/python <campaign script> http://127.0.0.1:5000 development`.
**93 checks, 0 failures.**

### 2.1 Pages, assets and links

| Check | Result |
| --- | --- |
| `/`, `/scan`, `/login`, `/register`, `/dashboard`, `/history` | 200 |
| `/health`, `/api/v1/health`, `/api/v1/model/info` | 200 |
| `/favicon.ico` | 204 (no content, by design) |
| `/static/css/main.css`, `/static/js/main.js` | 200 |
| `bootstrap.min.css`, `bootstrap.bundle.min.js`, `chart.umd.min.js`, `logo.svg` | 200 |
| Unknown page `/nonexistent-page-xyz` | 404 (themed error page) |
| Every internal `href`/`src` discovered on the six public pages | resolved; 0 broken |
| External (CDN) asset references in the rendered HTML | 0 |

### 2.2 Registration, login, logout, authentication

| Check | Result |
| --- | --- |
| Register a new account | 201/200, account created with the ordinary user role |
| Duplicate username | rejected, 400 `INVALID_REGISTRATION` |
| Weak password (`password`) | rejected, 400 |
| Invalid email domain (`…@example.invalid`) | rejected with a generic message |
| `GET /auth/session` before login | `authenticated: false` |
| Login with correct credentials | accepted; `/auth/session` → `authenticated: true` |
| Login with a wrong password (new session) | rejected; session stays anonymous |
| Logout (CSRF-protected POST) | session cleared; `/auth/session` → `authenticated: false` |
| Re-login | session restored |
| `/admin` as anonymous | 401; as a signed-in non-admin | 403 |
| Session cookie | `HttpOnly`, `SameSite=Lax` (dev), `Secure` added in production |

### 2.3 Classification through the UI

| Expected | URL (safe) | Verdict shown | Score shown |
| --- | --- | --- | --- |
| LEGITIMATE | `https://www.saffronart.com` | **LEGITIMATE** | 0.027039 |
| SUSPICIOUS | `https://www.google.com/` | **SUSPICIOUS** | 0.168339 |
| PHISHING | `http://secure-paypal-login.example.invalid/verify/account/update.php?id=8831` | **PHISHING** | 1.000000 |

- Verdicts were read from `#classificationValue`, not from a page-wide token scan (the result page also
  renders a three-state legend, so a naive "page contains PHISHING" assertion would pass trivially).
- Each result page also showed: the score labelled **uncalibrated**, the measured band `0.05 / 0.95`,
  the sentence *"not a guarantee that the website is safe"*, the statement that the URL was never
  visited, and all 15 features (45 table cells).
- Scan visibility is session-scoped: a copy of the report URL opened in a different session returns
  **404**, and the 404 page does not echo the scan's content.
- One scan was made while signed in: it appears in that account's history and CSV export.

### 2.4 History, dashboard, report, CSV

| Check | Result |
| --- | --- |
| `/history` for the signed-in user | 200, contains the user's rows |
| Filter by verdict (`?prediction=PHISHING`) and search (`?q=…`) | 200, filters applied |
| `/dashboard` | 200; shows measured figures `0.967803`, `0.980389`, `0.983854`, `0.993307`, `0.998055`, and states their source (`metrics.json`) |
| Dashboard band/abstention wording | present |
| Printable report `/scan/<id>/report` | 200 for each of the three states |
| `/history/export.csv` | 200, `text/csv`, `Content-Disposition: attachment`, header `scan_id,scan_date_utc,submitted_url,…,classification,…`, UTF-8 BOM for Excel |
| Anonymous export | 200 but **0 data rows** — guests can only export their own session's scans, no other user's rows appear |

### 2.5 REST API

| Check | Result |
| --- | --- |
| `GET /api/v1/csrf-token` | 200, 91-character token |
| `POST /api/v1/scan` with session + `X-CSRF-Token` | 200, `{"status":"ok","scan":{…}}` |
| Response fields | `prediction` LEGITIMATE, `model_score` 0.027039…, `persisted: true`, `decision_band {low 0.05, high 0.95, source metadata.json}`, `caveats`, `scan_id`, `report_url`, `scanned_at` |
| `POST` without the CSRF header | 400 `CSRF_FAILED` |
| `POST` with an invalid URL | 400 |
| `GET /api/v1/scans` | 200, `{filters, page, pages, per_page, scans[]}` |
| `GET /api/v1/scans/<id>` / unknown id | 200 / clean 404 |
| One pipeline | the API scan wrote one `scan_history` row, identical in shape to the HTML form's |

### 2.6 Administrator role

An administrator was created with the documented CLI, tested, and **removed afterwards** (see §7).

| Check | Result |
| --- | --- |
| `scripts/create_admin.py` | created `acceptance_admin` (id 3, role `admin`), password stored as a scrypt hash only |
| Login as admin | 200; `/auth/session` → `authenticated: true`, role `admin` |
| `GET /admin` | 200; accounts table present, model audit row present (`logistic_regression`), measured figures rendered |
| `GET /admin/export.csv` | 200, `text/csv`, 38 data rows — the role restriction genuinely widens scope |
| Anonymous / non-admin access | 401 / 403 |

### 2.7 Rate limiting (deliberately provoked)

Fourteen CSRF-valid scan posts in one minute produced `statuses [200, 429]`; `/health` stayed 200
throughout, confirming per-route limits without a blanket throttle. Note: *CSRF-invalid* requests are
rejected with 400 **before** the limiter records them, so a rate-limit test must carry a valid token —
an observation about the middleware order, not a defect.

---

## 3. Production verification (`APP_ENV=production`, waitress)

Command: `waitress-serve --call --listen=127.0.0.1:8097 wsgi:create_application`. **11 checks, 0 failures.**

| Check | Observed |
| --- | --- |
| `/health` | 200, `status: ok`, `version 0.14.0`, `build_stage 14`, `environment production` |
| Model bundle | `available: true`, `"bundle SHA-256 matches metadata.json"` |
| Database | `status: ready`, 3 tables, counts returned |
| `Server` header | `waitress` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | `DENY` (absent in development by configuration, present here) |
| `X-Content-Type-Options` | `nosniff` |
| CSP | strict, `default-src 'self' … frame-ancestors 'self'`, no CDN host |
| Session cookie | `session=…; Secure; HttpOnly; Path=/; SameSite=Lax` (full header, not truncated) |
| Consequence | because the cookie is `Secure`, an interactive session **cannot** be established over plain HTTP — TLS termination is mandatory, as `docs/DEPLOYMENT.md` states |

---

## 4. Model verification

### 4.1 Every headline figure recomputed independently

The full test split (35 302 rows) was scored through the serving path and the metrics recomputed from
the predictions. Deltas are floating-point rounding only.

| Metric | Recomputed | `metrics.json` | Δ |
| --- | --- | --- | --- |
| Accuracy @0.5 | 0.983854 | 0.983854 | 4 × 10⁻⁷ |
| Precision @0.5 | 0.993307 | 0.993307 | 3 × 10⁻⁷ |
| Recall @0.5 | 0.967803 | 0.967803 | 3 × 10⁻⁷ |
| F1 @0.5 | 0.980389 | 0.980389 | 5 × 10⁻⁷ |
| ROC-AUC | 0.998055 | 0.998055 | < 10⁻⁶ |
| Confusion matrix @0.5 | [[20484, 96], [474, 14248]] | same | — |
| Decisive / abstained (band 0.05–0.95) | 28 217 / 7 085 | same | — |
| Abstention rate | 0.200697 | 0.200697 | 0 |
| Precision / recall / F1 (decisive) | 0.999848 / 0.997732 / 0.998789 | same | ≤ 5 × 10⁻⁷ |
| State counts | LEGITIMATE 15 018 · SUSPICIOUS 7 085 · PHISHING 13 199 | same | — |

**No train/serve skew.** Scoring 3 000 test rows with the raw URL (training path) and with
`normalize_url` (serving path) produced identical feature matrices (0 of 3 000 rows differed) and
identical predictions. The deployed bundle is the measured one.

### 4.2 Finding A — the model treats "URL contains a path" as evidence of phishing (CRITICAL)

The `has_https` shortcut was already documented (100.00 % of legitimate vs 56.90 % of phishing URLs use
HTTPS). The review found a **second, undocumented artefact that is worse in practice**:

| Property (training split) | Legitimate (n = 93 690) | Phishing (n = 71 054) |
| --- | --- | --- |
| URLs containing a path | **0.00 %** | 33.59 % |
| URLs containing a query string | **0.00 %** | 7.69 % |
| Median / 90th-percentile length | 27 / 34 | 38 / 89 |

Every legitimate URL in the corpus is a bare homepage (`https://www.example.com`), while a third of the
phishing URLs carry a path or query. The fitted linear model therefore learned *path or query ⇒
phishing*, amplified by the large positive `url_length` coefficient. Demonstration on a benign URL that
the corpus itself labels legitimate:

| Submitted URL | Length | Score | Verdict |
| --- | --- | --- | --- |
| `https://www.saffronart.com` | 26 | 0.027039 | LEGITIMATE |
| `https://www.saffronart.com/` | 27 | 0.257606 | SUSPICIOUS |
| `https://www.saffronart.com/about` | 32 | 0.999991 | PHISHING |
| `https://www.saffronart.com/about/team` | 37 | 1.000000 | PHISHING |
| `https://www.saffronart.com/news/2026/press-release` | 50 | 1.000000 | PHISHING |

Adding one trailing slash moves a known-good site out of LEGITIMATE; adding `/about` makes it
"phishing" with near-certainty.

**Illustrative out-of-distribution sample** (20 well-known benign homepages and pages, used as strings
only, hand-picked rather than randomly sampled — so this is a demonstration, not a benchmark):

| Verdict | Count | Examples |
| --- | --- | --- |
| LEGITIMATE | 2 | `https://www.saffronart.com`, `https://www.diariodealmeria.es` — **both are rows of the corpus** |
| SUSPICIOUS | 7 | `https://www.google.com/`, `https://www.amazon.com/`, `https://www.apple.com/` |
| PHISHING | 11 | `https://www.wikipedia.org/wiki/Phishing`, `https://github.com/login`, `https://www.gov.uk/government/organisations`, `https://docs.python.org/3/library/urllib.html` |

**Impact.** The measured metrics are correct but in-distribution only. Deployed against real traffic,
the system would flag an overwhelming share of ordinary pages as PHISHING — a false-positive rate that
makes it unusable as an automatic blocker. The abstention band does not protect against this: these
scores are far outside the band (1.000000), not inside it.

**What this does *not* invalidate.** The engineering claims stand: leak-free splitting, thresholds
selected on validation, a single read of the test split, metric provenance, honesty of the reported
numbers. The defect is in the *dataset representation* (bare-homepage legitimate URLs) and therefore in
what the model can generalise to — exactly the class of problem the report's limitations chapter exists
to disclose.

**Recommendation (not implemented — out of stage scope):** treat path-bearing legitimate URLs as a
required part of the training distribution (crawl or sample deep links for the negative class), then
re-run `ml/train_model.py` and `ml/evaluate_model.py` and re-measure; and run the `has_https` ablation
already listed in `docs/REPORT.md`. Until then, the system must be presented as an *academic
demonstration of the method*, not a deployable screener.

---

## 5. Dataset and leakage audit (independent recomputation)

| Check | Recomputed | Recorded |
| --- | --- | --- |
| Rows in splits | 235 348 | 235 348 |
| train / validation / test | 164 744 / 35 302 / 35 302 | same |
| Class split | 93 690 L / 71 054 P (train); 20 580 / 14 722 (val, test) | same |
| Groups shared between splits | 0 (all three pairs) | 0 |
| Exact URLs shared between splits | 0 (all three pairs) | 0 |
| Duplicate URLs within a split | 0 | — |
| SHA-256 of `train/validation/test.csv` vs `metadata.json` | match, all three | match |
| Labels | binary `{0, 1}` | binary |
| HTTPS share | 100.00 % legitimate, 56.90 % phishing | 100.00 % / 56.90 % |

**Verdict: the split is genuinely leak-free** — grouped by URL signature, checked by group id and by
exact string, with hashes pinned into the model artefact. The corpus itself is biased (Findings A and
the HTTPS shortcut); the *split* is sound.

---

## 6. Documentation and requirements

| Check | Result |
| --- | --- |
| Markdown documents | 20 files (19 in `docs/` + `README.md`), 7 957 lines |
| Internal markdown links | 8 checked, **0 broken** |
| UML/diagram references | all 7 resolve (`architecture.svg/.png`, use case, class, sequence, activity, deployment) |
| Diagram files well-formed and offline-safe | verified by `scripts/verify_stage14.py` (XML, `viewBox`, no external ref, no `<script>`, no raster) |
| Required documents (report, deployment, architecture, ADRs, setup, environment, dataset, features, training, evaluation, model card, backend, database, UI, detection, dashboard, security, test plan, stage plan) | all present |
| Commands quoted in the documents | all project scripts and `python -m` targets exist (`verify_stage13.py` appears only in the text that explains why it deliberately does not exist) |
| Requirements traceability | the 11 functional requirements in `docs/REPORT.md` §3.1.1 map to routes that were exercised in §2 above |
| F1 0.9988 conditional on answering | **PASS** — `docs/REPORT.md` §5.3.2, §5.8 and limitation 4 state 0.998789 over 79.93 % of cases with 20.07 % abstention (test) / 19.80 % (validation); `docs/MODEL_CARD.md` lists the abstention rate directly beside the decisive F1; `README.md` repeats both numbers in one sentence |
| Gates on the delivered tree | `pytest` 259 passed; `verify_stage1…12` and `verify_stage14` all `RESULT: PASS` |

---

## 7. Observations that are *not* defects (verified by design)

1. **`X-Frame-Options` absent in `development`** — set to `DENY` only in production (`config.py`), and
   confirmed present there. Correct for a dev environment.
2. **Anonymous `GET /history/export.csv` returns 200** — guests may export *their own session's* scans;
   the response contained 0 data rows and no other user's data. Scoping verified, not a leak.
3. **CSRF-invalid POSTs return 400 before the rate limiter counts them** — middleware order; documented
   so a future rate-limit test uses a valid token.
4. **`/favicon.ico` returns 204** — intentional (no content).
5. **Production cannot hold a session over plain HTTP** — the cookie is `Secure`; TLS termination is
   required and documented.
6. **`mailto:` normalises to `http://mailto:…`** — a documented boundary of the normaliser, unchanged.
7. **CSV begins with a UTF-8 BOM** — deliberate, so Excel opens UTF-8 URLs correctly.

## 8. Residual risks and what remains unverified

Stated plainly, because an acceptance review that claims total coverage is not credible:

- **No real browser rendering test.** Pages, assets and markup were verified over HTTP (status codes,
  DOM ids, table cells, CSP), not by a browser engine. CSS layout, JS interactivity and the
  dark/light toggle were therefore **not** visually confirmed in this review.
- **No Visual/UI accessibility audit** beyond structural checks; WCAG claims in `docs/UI.md` were not
  re-measured.
- **No load, concurrency or soak testing.** Single-process waitress with in-memory rate limits was
  verified functionally only.
- **No HTTPS reverse proxy was stood up** in this environment; TLS behaviour is asserted from
  configuration plus the `Secure` cookie attribute, not from a live TLS handshake.
- **No real-user usability testing.**
- **Model behaviour under distribution shift is now known to be poor** (Finding A) and was measured
  only illustratively, with a hand-picked sample — not as a benchmark.
- **Email deliverability checks** are disabled (`check_deliverability=False`); no mail is ever sent.

## 9. Data created during this review, and cleanup

The campaign created test accounts and scans in `instance/phishing.db` (a temporary administrator,
two ordinary accounts, and demo scans). They were **removed** afterwards so the delivered database
matches the documented hand-over state: **9 scans, 0 users, 1 `model_information` row** — verified via
`/health` and `python scripts/init_db.py --verify-only` after cleanup.

To reproduce the demonstration data described in the hand-over, run the three scans in §2.3 through
`/scan`; to reset completely, delete `instance/phishing.db` and run `python scripts/init_db.py`.
