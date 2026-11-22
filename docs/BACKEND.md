# Stage 7 — Flask Backend (Application Factory, Wiring and HTTP Security)

**Status:** delivered and gated. `python scripts/verify_stage7.py` must print `RESULT: PASS`.
**Stage rule:** Stage 8 did not start until this gate was green — and it is now also delivered.

> **Stage 8 update (read this first).** This document describes the Stage 7 backend as shipped. Stage 8 (see `docs/DATABASE.md`) has since **added** the three ORM tables, `scripts/init_db.py`, `scripts/create_admin.py`, real `/login` and `/register` routes, scrypt password hashing, an ORM-backed `user_loader`, and a live database-status block in `/` and `/health`. `app.py` now imports `configure_database` and sets `login_manager.login_view = "auth.login"`; `services/http_security.make_error_response()` now also honours `request.is_json` and `?format=json`. `config.py` reports `APP_VERSION=0.8.0` / `BUILD_STAGE=8`. Everything in §7's "not in Stage 7" table rows marked **8** is now implemented; the rows marked **9–14** are still deliberately absent. The Stage 7 gate is stage-aware and remains green.

> **Stage 9 update.** The three inline HTML strings documented below (`INDEX_PAGE` in `routes/core.py`, `AUTH_PAGE`/`RESULT_PAGE` in `routes/auth.py`, `ERROR_PAGE` in `services/http_security.py`) have been **replaced** by real Jinja2 templates: `templates/base.html`, `index.html`, `login.html`, `register.html`, `auth_result.html` and `errors/error.html`. `app.py` now publishes `app_name` / `app_version` / `build_stage` / `environment` / `debug` through a context processor, `config.py` reports `APP_VERSION=0.9.0` / `BUILD_STAGE=9`, and `static/css/main.css` + `static/js/{theme,main}.js` + hash-verified local Bootstrap/Chart.js deliver dark and light responsive themes. The HTTP contract, JSON shapes, status codes, CSP (`script-src 'self'`, no `unsafe-inline`), error handling and model-artefact validation are **unchanged**. The Stage 9 gate checks all of this. See `docs/UI.md` for the frontend design. There is still **no `"SCAN WEBSITE"` button** and no `/scan` route until Stage 10.

---

## 1. What Stage 7 builds

Until now the project was an **offline machine-learning pipeline**: dataset → preprocessing → feature extraction → training → evaluation → `model_bundle.joblib`. Nothing could receive an HTTP request.

Stage 7 builds the **web application core**: a Flask application factory, configuration wiring, four Flask extensions, a blueprint registry, security headers, safe error handling, request-size enforcement, and a read-only connection to the Stage 6 model artefacts. Two routes now respond:

* `GET /` — a backend status/diagnostics page (this is **not** the product landing page);
* `GET /health` — a machine-readable health and artefact-integrity contract.

The auth blueprint also exposes its **session/CSRF surface**, which genuinely works: `GET /auth/session`, `GET /auth/csrf-token`, `POST /logout`.

**Why this stage exists:** a web system needs a single, reproducible entry point before any page, form or database is added. Building the factory first means every later stage (and every automated test) can construct a clean, isolated application with its own configuration — no global state, no "works only on my machine".

---

## 2. Why an application factory

A beginner often writes `app = Flask(__name__)` at the top of `app.py`. That object is created the moment Python imports the file. It is fine for a toy, but it breaks three things this project needs:

1. **Test isolation.** Stage 13 must create an app with an in-memory SQLite database, CSRF disabled and a *deliberately missing* model bundle to test the failure path. With a module-level app you would have to mutate global state between tests.
2. **Multiple configurations.** Development, testing and production need different secrets, cookies, CSRF strictness and rate limiting. A factory accepts a config class and applies it to one fresh object.
3. **Import safety.** `wsgi.py`, the Flask CLI and `pytest` all import the same module; a factory guarantees no side effects (no files, no sockets, no tables) happen at import time.

`create_app(config_class=None, *, overrides=None)` therefore:

1. selects `DevelopmentConfig` / `TestingConfig` / `ProductionConfig` (or `APP_ENV`);
2. calls `config_class.require_valid()` and then re-validates the **effective** `app.config` (so test overrides cannot silently weaken a control);
3. binds `db`, `csrf`, `limiter` and `login_manager`;
4. installs security headers, error handlers and the request-size guard;
5. validates `metadata.json` and verifies the SHA-256 of `model_bundle.joblib`;
6. registers the blueprints that belong to this stage.

If `metadata.json` is missing, malformed or disagrees with the code's decision-state contract, **startup is refused**. If the estimator bundle is missing or its hash changed, the app still boots but `/health` returns **HTTP 503 `MODEL_UNAVAILABLE`**. There is no rule-based fallback and no invented result; a 503 is an honest answer.

---

## 3. File-by-file map

| File | Role |
| --- | --- |
| `app.py` | `create_app()` factory; runtime config validation; startup sequence |
| `wsgi.py` | Long-lived WSGI object (`app` / `application`), `create_application()` for `waitress-serve --call`, and a direct `python wsgi.py` runner |
| `extensions.py` | The four shared extension singletons (`db`, `csrf`, `login_manager`, `limiter`) |
| `routes/__init__.py` | `BLUEPRINTS` registry and idempotent `register_blueprints(app)` |
| `routes/core.py` | `GET /`, `GET /health`, `GET /favicon.ico` |
| `routes/auth.py` | `GET /auth/session`, `GET /auth/csrf-token`, `POST /logout` |
| `services/model_metadata.py` | `ModelMetadata`, `ModelRegistry`, `load_model_metadata()`, `get_registry()`; validates metadata and bundle hash |
| `services/http_security.py` | CSP + hardening headers, `ServiceError`, safe 400/401/403/404/405/413/429/500/503 responses, body-size guard |
| `static/css/backend.css` | Small local stylesheet for the status/error pages (no CDN, no inline styles) |
| `config.py` | Extended with `BUILD_STAGE`, `HOST`, `PORT`, `X_FRAME_OPTIONS`, `CSP_FRAME_ANCESTORS` |
| `.env.example` | Documents `HOST` and `PORT` |
| `scripts/verify_stage7.py` | The exit gate described in §8 |
| `docs/BACKEND.md` | This document |

`extensions.py` exists to avoid a **circular import**. Stage 8's `models/database_models.py` does `from extensions import db`; if `db` lived inside `app.py`, importing the ORM models would import the factory, which imports the models… and Python would fail. This design paid off in Stage 8.

---

## 4. Extension wiring

| Extension | Bound now? | Does work now? | Scheduled completion |
| --- | --- | --- | --- |
| `Flask-SQLAlchemy` (`db`) | Yes | At Stage 7: no ORM classes → no tables. **Stage 8 now declares the three models** | Done in Stage 8 |
| `Flask-WTF` (`CSRFProtect`) | Yes | **Yes** — every state-changing request without a token gets `400 CSRF_FAILED` | Stage 8 forms include the token; Stage 9/10 add AJAX helpers |
| `Flask-Login` | Yes | **Yes** — anonymous sessions, strong session protection, explicit `401 UNAUTHENTICATED` | Stage 8 adds the ORM `user_loader`, `/login`, `/register` (done) |
| `Flask-Limiter` | Yes | Wired with **no** default limits | Stage 12 applies per-route limits to `/scan`, `/api/v1/scan`, `/login`, `/register` |

Two honest design decisions worth explaining at the viva:

* **`login_manager.user_loader` returned `None` at Stage 7.** There was no `User` table, so *no* session identifier could resolve. Returning `None` was fail-closed and correct for a stale cookie. Stage 8 replaced this callback with `services.auth_service.get_user_by_id()`, which converts the id, catches ORM errors and refuses inactive accounts — still fail-closed, now backed by SQLite. Because the Stage 7 `unauthorized_handler` runs **before** `login_view`, the documented 401 contract was kept and `login_view` is declarative only (ADR-026).
* **The limiter has no blanket throttle yet.** Applying "10 per minute" globally would look like security theatre before any endpoint exists, and would make the gate's tests flaky. The object is proven compatible now; real limits arrive with real endpoints.

### Model metadata, not model metrics

`ModelRegistry` reads **only** `metadata.json` and the hash of the bundle. It reports model name, version, schema version, feature count, the calibrated thresholds (`T_low`/`T_high`) and the three state names. It **does not** read `metrics.json`, does not load the estimator with `joblib.load`, and never calls `predict_proba`.

That separation is an academic-integrity rule: measured accuracy, precision, recall, F1 and ROC-AUC are displayed by the Stage 11 dashboard from `metrics.json` at runtime, never typed into a template. Stage 7's status page deliberately contains **no performance number**.

The model score wording is also protected. `load_model_metadata()` compares `metadata.json`'s `score_meaning` and all three `decision_states` (message, warning, colour, risk level) against the single source of truth in `ml/thresholds.py`. Drift is a startup error. The system will never quietly start calling an uncalibrated model score a "guaranteed probability of maliciousness".

---

## 5. HTTP contract at Stage 7

| Method | Path | Response |
| --- | --- | --- |
| `GET` | `/` | 200 HTML backend status page |
| `GET` | `/health` | 200 JSON health; **503** `MODEL_UNAVAILABLE` when the bundle is absent/corrupt |
| `GET` | `/favicon.ico` | 204 |
| `GET` | `/auth/session` | 200 JSON: anonymous state, guest permission, CSRF status, and *which auth routes actually exist* |
| `GET` | `/auth/csrf-token` | 200 JSON token for header `X-CSRF-Token` or form field `csrf_token` |
| `POST` | `/logout` | 200 JSON after clearing the session; 400 `CSRF_FAILED` without a token |
| `GET` | `/static/css/backend.css` | 200 CSS, served locally |

`/health` payload (shape only; values come from `metadata.json`):

```json
{
  "status": "ok",
  "app": "Intelligent Phishing Website Detection System",
  "version": "0.7.0",
  "environment": "testing",
  "build_stage": 7,
  "model": {
    "model_name": "logistic_regression",
    "model_version": "1.0.0",
    "schema_version": "1.0",
    "feature_schema_version": "1.0",
    "feature_count": 15,
    "decision_thresholds": { "low": 0.05, "high": 0.95, "source": "..." },
    "decision_states": ["LEGITIMATE", "PHISHING", "SUSPICIOUS"],
    "generated_at_utc": "..."
  },
  "bundle": { "available": true, "detail": "bundle SHA-256 matches metadata.json", "...": "..." },
  "database":  { "status": "not_initialised", "scheduled_stage": 8 },
  "detection": { "status": "not_wired",       "scheduled_stage": 10 },
  "extensions": { "sqlalchemy": true, "csrf": false, "login_manager": true, "rate_limiter_enabled": false }
}
```

The numbers `0.05` / `0.95` are **decision thresholds measured on the validation split in Stage 6**, not performance statistics. They are read from `metadata.json`, not written into the code.

Error contract (implemented now, consumed by later stages): `400 BAD_REQUEST` / `CSRF_FAILED` / `INVALID_URL`, `401 UNAUTHENTICATED`, `403 FORBIDDEN`, `404 NOT_FOUND`, `405 METHOD_NOT_ALLOWED`, `413 PAYLOAD_TOO_LARGE`, `429 RATE_LIMITED`, `500 INTERNAL_ERROR`, `503 MODEL_UNAVAILABLE`. Errors are JSON for `/api/*` paths and an HTML page otherwise.

---

## 6. Security behaviour

* **Headers on every response:** strict `Content-Security-Policy` (`default-src 'self'`, no `unsafe-inline` scripts, `object-src 'none'`, `form-action 'self'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `X-XSS-Protection: 0`. `Cache-Control: no-store` on `/api/*`, `/auth/*`, `/health` and all errors.
* **Production adds** `X-Frame-Options: DENY`, CSP `frame-ancestors 'self'` and HSTS; secure session cookies and CSRF are mandatory there (validated at startup).
* **Development/test omit the framing headers** so the Arena live preview can embed the dev server in its cross-origin iframe. This is a documented, config-driven development-only relaxation — see ADR-025.
* **Secure errors:** generic messages only. A deliberate `ValueError("secret diagnostic detail…")` produces a 500 whose body contains neither the message nor a traceback; the detail goes to the server log.
* **Input cap:** `MAX_CONTENT_LENGTH = 64 KB` plus an explicit `before_request` check on `Content-Length`, so an oversized body is rejected with 413 even if a view never reads the body.
* **CSRF:** Flask-WTF protects all POST/PUT/PATCH/DELETE. A token is issued by `/auth/csrf-token` and accepted as `X-CSRF-Token` or `csrf_token`.
* **Passwords:** `werkzeug.security.generate_password_hash` (scrypt) is verified available and never stores plaintext. Stage 8 now uses it in `User.set_password()` / `check_password()` and in `authenticate()`.
* **SSRF:** the backend imports no network client, makes no outbound request and never visits or resolves a submitted URL. `verify_stage7.py` asserts this on the source.
* **Secrets:** `SECRET_KEY` comes from the environment/.env; production refuses to boot without ≥32 characters. No real secret is in the repository.

### A note about the live preview and cookies

The Arena preview is a cross-origin iframe. Because `SESSION_COOKIE_SAMESITE = "Lax"`, a browser will not send session cookies for cross-site subrequests inside that frame. The Stage 7 status page and `/health` need no session and work perfectly. Interactive session features (CSRF-protected POSTs, later login) should be verified either with the Flask/Werkzeug test client, `pytest`, or by opening the dev server directly in its own browser tab. This is a browser privacy rule, not an application defect; the gate tests CSRF through Flask's test client where cookies are first-party.

---

## 7. What is deliberately NOT in Stage 7

| Absent | Why | Stage |
| --- | --- | --- |
| `models/database_models.py`, `instance/phishing.db` | ORM entities and table creation | 8 |
| `/login`, `/register`, `password_hash` column | They require the `User` entity. A stub that returns "coming soon" would be pretending | 8 |
| `templates/*.html`, Bootstrap 5, Chart.js, themes | Full responsive SOC-style UI | 9 (delivered — see `docs/UI.md`) |
| `"SCAN WEBSITE"` button, `/scan`, `predict_proba`, report download | Detection integration | 10 |
| Dashboard, history, admin, CSV export | Aggregations over stored scans | 11 |
| Per-route rate limits, REST API | Security hardening and JSON API | 12 |
| `tests/conftest.py`, full `pytest` suite | Testing and debugging | 13 |
| UML chapters, deployment guide, final report | Documentation and deployment | 14 |

In particular: **there is no `"SCAN WEBSITE"` button yet**. Showing the required button before the scan pipeline exists would violate the project rule "do not pretend incomplete functionality works". It arrives in Stage 9/10 with the exact label — and this statement is still true after Stage 8.

Guest scans remain allowed (`guest_scans=guests_yes`); Stage 8's nullable `ScanHistory.user_id` and `ON DELETE SET NULL` implement that requirement in the database. Stage 8 delivered the three rows marked **8** above; the rows marked **9–14** remain deliberately absent.

---

## 8. Run and test

### Windows (PowerShell) — first time

```powershell
cd phishing-detection-system
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # put this in .env as SECRET_KEY
```

### Run the backend

```powershell
# Development server (factory auto-detected by Flask CLI)
python -m flask --app app run --host 0.0.0.0 --port 5000

# Or the production-style WSGI runner
python wsgi.py

# Or through waitress directly
python -m waitress --host 0.0.0.0 --port 5000 --call wsgi:create_application
```

Open `http://127.0.0.1:5000/` and `http://127.0.0.1:5000/health`. To see the routes Flask discovered:

```powershell
python -m flask --app app routes
```

### Production posture (local check, no secret in the repo)

```powershell
$env:APP_ENV="production"
$env:SECRET_KEY=(python -c "import secrets; print(secrets.token_hex(32))")
python -m flask --app app routes
Remove-Item Env:APP_ENV, Env:SECRET_KEY
```

With `APP_ENV=production` and no `SECRET_KEY`, startup **must fail** with `RuntimeError: Invalid production configuration`. That is the security control working.

### Test the stage

```powershell
python scripts\verify_stage7.py
```

The gate builds isolated development, testing, production, missing-bundle and tampered-metadata applications; checks CSRF rejection/acceptance, all error codes, security headers, the 503 path, the 500 leak test, configuration refusals, a real local HTTP server, the Flask CLI, and re-runs Gates 1–6.

All historical gates:

```powershell
python scripts\verify_stage1.py
python scripts\verify_stage2.py
python scripts\verify_stage3.py
python scripts\verify_stage4.py
python scripts\verify_stage5.py
python scripts\verify_stage6.py
python scripts\verify_stage7.py
```

Linux/macOS: replace `.\.venv\Scripts\Activate.ps1` with `source .venv/bin/activate`, `copy` with `cp`, and `\` with `/` in paths.

---

## 9. Common errors and fixes

| Error | Cause | Fix |
| --- | --- | --- |
| `Error: Could not locate a Flask application` | Ran `flask run` without `--app`, or from the wrong directory | `cd phishing-detection-system` then `python -m flask --app app run` |
| `RuntimeError: Invalid production configuration: SECRET_KEY...` | `APP_ENV=production` with an empty/short key | Generate `python -c "import secrets; print(secrets.token_hex(32))"` and set it in `.env` |
| `ModuleNotFoundError: No module named 'flask'` | Wrong interpreter (global Python, or venv was lost from the sandbox snapshot) | `.\.venv\Scripts\Activate.ps1` and `python -m pip install -r requirements.txt` |
| `config: SECRET_KEY is not set; generated an ephemeral development key` | Normal development behaviour | Add `SECRET_KEY` to `.env` if you want sessions to survive a restart |
| `WARNING: Using the in-memory storage for rate limiting` | Normal Flask-Limiter development default | Expected; Stage 12 configures route limits (and a persistent store if needed) |
| `/health` returns 503 `MODEL_UNAVAILABLE` | `model_bundle.joblib` missing or its SHA-256 changed | Re-run `python -m ml.evaluate_model` to regenerate Stage 6 artefacts; never edit the bundle by hand |
| `Cannot start ... without valid Stage 6 model metadata` | `metadata.json` missing, edited or schema drift | Re-run `python -m ml.evaluate_model`; do not patch the JSON manually |
| `400 CSRF_FAILED` on a POST | No `X-CSRF-Token` header / `csrf_token` form field | First call `GET /auth/csrf-token`, then send the token; in tests use `TestingConfig` where CSRF is disabled |
| Blank live preview | A framing header (`X-Frame-Options: DENY` or CSP `frame-ancestors`) blocking the preview iframe | Use `APP_ENV=development` (framing headers are omitted there); keep them enabled in production |
| `AssertionError: The setup method 'route' can no longer be called` | Added a test route to an app that already handled a request | Register all test routes **before** the first `test_client()` call — Flask freezes setup after first request |
| `500` in a test instead of a handled error page | `TESTING=True` or `DEBUG=True` makes Flask propagate exceptions by design | Set `PROPAGATE_EXCEPTIONS=False`, `TESTING=False`, `DEBUG=False` for the error-handler test |
| `Address already in use` on port 5000 | Another server instance is running | Use `--port 5001`, or stop the previous process |

---

## 10. Stage 7 exit criteria

- [x] `create_app()` returns a fresh, isolated, fully wired Flask application.
- [x] Dev / Test / Prod configuration classes validate at startup; production refuses weak secrets.
- [x] All four extensions are bound; no circular imports.
- [x] `GET /` and `GET /health` respond; `/health` reflects `metadata.json` with **zero hard-coded performance figures**.
- [x] Session/CSRF surface works; `POST` without a token is rejected.
- [x] Strict CSP and hardening headers on every response; production adds framing/HSTS protection.
- [x] Generic JSON/HTML errors for 400/401/403/404/405/413/429/500/503; no exception detail leaks.
- [x] Request-body cap enforced before views run.
- [x] Missing/corrupt model artefact gives an explicit 503, never a rule-based guess.
- [x] No outbound network calls, no SSRF surface, no estimator loading, no UI button that cannot work.
- [x] `scripts/verify_stage7.py` passes and re-runs Gates 1–6.

---

*Stage 7 of 14 (historical). Stages 8 and 9 — SQLite/SQLAlchemy authentication, and the responsive Jinja2 frontend — are now delivered; see `docs/DATABASE.md`, `docs/UI.md`, `scripts/verify_stage8.py` and `scripts/verify_stage9.py`. Next: Stage 10 — detection engine integration.*

---

## Stage 10 update

Stage 7's application factory now attaches a second application-scoped object:
`app.extensions["detection_registry"]`, created **after** the Stage 6 bundle
hash is verified. `routes/scanning.py` registers `scan_bp`, adding
`GET/POST /scan` and `GET /scan/<int:scan_id>/report`. `routes/core.py` no
longer reports detection as future work: `/health` publishes the engine's real
`status`, `feature_count`, `decision_thresholds`, `uncertainty_band` and model
provenance, and the overview card reads that status at request time.

Existing contracts are unchanged: `csrf.init_app`, `limiter.init_app`,
`login_manager`, `install_security_headers`, `install_error_handlers`,
`install_request_guards`, the `401 UNAUTHENTICATED` callback, the `MODEL_UNAVAILABLE`
503 health response, and `make_error_response`'s HTML/JSON negotiation.
`POST /scan` accepts both a normal HTML form (`csrf_token` hidden field) and
JSON (`X-CSRF-Token` header), mirroring `/login` and `/register`.

Failure mapping:

| Condition | Response |
| --- | --- |
| Invalid, over-long or unsupported URL | `400 INVALID_URL` (HTML form redisplayed) |
| Bundle/provenance missing or estimator cannot load | `503 MODEL_UNAVAILABLE` |
| `scan_history` write fails | `503 DATABASE_UNAVAILABLE` |
| Report missing or not owned by the caller | `404 NOT_FOUND` |

There is still no `SCAN WEBSITE` button on `/` — the exact label lives only on
the dedicated `/scan` page (ADR-032), which is why the historical "no
non-functional SCAN WEBSITE button" assertions in Gates 7–9 remain valid.
Per-route rate limiting and `/api/v1/scan` remain Stage 12 work.

---

## Stage 11 update

Three blueprints are added from `routes/__init__.py`:

| Blueprint | Routes | Notes |
| --- | --- | --- |
| `dashboard_bp` | `GET /dashboard` | Public; counts only, no submitted URLs |
| `history_bp` | `GET /history`, `GET /history/export.csv` | Scoped to account or signed guest session |
| `admin_bp` | `GET /admin`, `GET /admin/export.csv` | `admin_required`: 401 anonymous, 403 non-admin |

They are **GET-only**: no CSRF token is required, no write is performed, and
no new table or column is introduced. `services/stats_service.py` supplies
request-time aggregates and measured model figures;
`services/report_service.py` supplies the CSV response. `config.py` and the
factory move to `0.11.0` / `BUILD_STAGE = 11`.

All Stage 7–10 contracts are preserved: `csrf.init_app`, `limiter.init_app`,
`login_manager`, `install_security_headers`, `install_error_handlers`,
`install_request_guards`, the `401 UNAUTHENTICATED` callback (now reused by
`admin_required` rather than replaced), `make_error_response`'s HTML/JSON
negotiation, the `503 MODEL_UNAVAILABLE` health path, and the exact
`SCAN WEBSITE` control on `/scan`. The CSP directive list is unchanged and all
three offline vendor hashes are re-verified by Gate 11. No runtime module
imports an HTTP client, DNS helper or socket — the no-network/SSRF rule now
covers Stage 11 too.

New failure mapping:

| Condition | Response |
| --- | --- |
| `scan_history` / `users` schema unavailable on a Stage 11 view | `503 DATABASE_UNAVAILABLE` |
| `metrics.json` missing, unreadable or missing measured values | `503 MODEL_UNAVAILABLE` |
| Anonymous `GET /admin` or `/admin/export.csv` | `401 UNAUTHENTICATED` |
| Ordinary signed-in user `GET /admin` or `/admin/export.csv` | `403 FORBIDDEN` |

Per-route rate limiting and `/api/v1/scan` remain Stage 12 work. See
`docs/DASHBOARD.md` for the full route, filter and CSV contract.

## Stage 12 update — the REST edge and per-route throttles

`v0.12.0` / `BUILD_STAGE = 12` adds a seventh blueprint, `api_bp`, registered
in `routes/__init__.py` with the `/api/v1` prefix. `routes/api.py` exposes six
JSON endpoints (`csrf-token`, `health`, `model/info`, `scan`, `scans`,
`scans/<id>`) and calls the SAME `DetectionRegistry.scan()` as the HTML form.
There is no second inference path, no new table and no `csrf.exempt`: API POSTs
echo the session token in `X-CSRF-Token`.

`config.py` gains `RATELIMIT_HEADERS_ENABLED`; `RATELIMIT_ENABLED`,
`RATE_LIMIT_SCAN`, `RATE_LIMIT_AUTH` and `RATE_LIMIT_API` already existed and
are now actually consumed. `extensions.py` adds `limits_disabled()`, which
reads the EFFECTIVE `current_app.config` at request time so the process-wide
Limiter singleton cannot leak an enabled/disabled state between app factories.
`default_limits=[]` is untouched. `routes/auth.py` (POST `/login`,
`/register`), `routes/scanning.py` (POST `/scan`) and `routes/api.py` carry the
decorators.

`services/http_security.py` adds `Cross-Origin-Opener-Policy`,
`X-Permitted-Cross-Domain-Policies`, `Origin-Agent-Cluster`, `no-store` for the
sensitive prefixes and an `@app.errorhandler(429)` with `Retry-After`. The CSP
directive list is byte-for-byte unchanged, as are the exact error codes, the
401/403/404 contract and the JSON/HTML negotiation via `make_error_response`.
`app.py` documents the new layer and defaults `BUILD_STAGE` to 12;
`services/__init__.py` is `0.12.0`. `templates/errors/error.html` gains a
non-diagnostic 429 hint; `templates/index.html` lists the six new endpoints.

Gate: `python scripts\verify_stage12.py` (Linux: `python scripts/verify_stage12.py`).
It re-runs Gates 1–11. Full threat model and REST contract: `docs/SECURITY.md`;
decisions: ADR-036/037/038.

## Stage 13 update — the suite that now guards this backend

`APP_VERSION` / `BUILD_STAGE` are `0.13.0` / `13`. **No file in this chapter
changed behaviour**: the factory, the seven blueprints, the services, the ORM
models, the headers and the error contract are exactly as Stage 12 left them.
What changed is that every claim above is now executable.

`tests/conftest.py` reuses the Stage 7 application factory rather than a
module-level `app`, which is precisely why Stage 7 chose the factory:

```python
from app import create_app
from config import TestingConfig

app = create_app(TestingConfig, overrides={
    "SECRET_KEY": "s" * 64,
    "SQLALCHEMY_DATABASE_URI": "sqlite:////tmp/isolated.db",
})
```

Each configuration under test gets its own app and its own database:
`TestingConfig` (deterministic), CSRF enabled, rate limiting enabled,
`ProductionConfig`, a missing bundle, a tampered bundle, an uninitialised schema,
and a view that raises to exercise the 500 handler.

Two backend behaviours are worth repeating because tests encode them:
`POST /api/v1/scan` shares the very same `DetectionRegistry.scan()` as the HTML
form (one URL, one score), and a failed audit write still returns
`503 DATABASE_UNAVAILABLE` rather than a displayed result. Run the suite with
`python -m pytest -v`; see `docs/TEST_PLAN.md`.
