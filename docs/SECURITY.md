# Stage 12 — Security Implementation and REST API

> **Status:** delivered. `scripts/verify_stage12.py` is the executable exit
> gate; Stage 13 does not start until it prints `RESULT: PASS`.
>
> **Safety notice:** this system performs **static, lexical URL analysis only**.
> The backend never visits, resolves or executes a submitted URL. There is no
> SSRF surface. **HTTPS alone does not mean a website is legitimate**, and a
> `LEGITIMATE` result is not a guarantee that a site is safe.

---

## 1. What Stage 12 builds

| Deliverable | Files | Effect |
| --- | --- | --- |
| Versioned REST API | `routes/api.py` | Six `/api/v1/*` JSON endpoints |
| Per-route rate limits | `routes/auth.py`, `routes/scanning.py`, `routes/api.py`, `extensions.py` | Config-driven throttles on abuse-prone routes |
| Hardened response headers | `services/http_security.py` | Cross-origin isolation, `no-store` on sensitive paths, 429 `Retry-After` |
| Improved error page | `templates/errors/error.html` | A human-readable 429 hint, generic as before |
| Wiring | `config.py`, `app.py`, `routes/__init__.py`, `services/__init__.py`, `templates/index.html` | `0.12.0` / `BUILD_STAGE = 12`, seven blueprints, endpoint table |
| Documentation + gate | `docs/SECURITY.md`, `scripts/verify_stage12.py` | This document and its executable acceptance test |

**The detection engine is not modified.** `services/detection_service.py`,
`decision_service.py`, `explanation_service.py`,
`models/prediction_model.py`, the three decision states, the measured
abstention thresholds, `SCORE_MEANING` and the strict CSP directive list are
byte-for-byte unchanged. The API calls the same `DetectionRegistry.scan()`
pipeline as the HTML form: one validation, one feature extraction, one
`predict_proba`, one decision, one explanation, one `ScanHistory` row.

There are **no invented statistics** anywhere in Stage 12; measured figures
are read at request time from `ml/saved_model/metrics.json`.

## 2. Threat model and trust boundaries

| # | Threat | Control | Where |
| --- | --- | --- | --- |
| T1 | Credential stuffing / brute-force login | `RATE_LIMIT_AUTH` on POST `/login` and `/register`; generic 401 for unknown user, wrong password and inactive account | `routes/auth.py`, `services/auth_service.py` |
| T2 | Scan/API flooding and model-extraction abuse | `RATE_LIMIT_SCAN` + `RATE_LIMIT_API` on POST `/scan` and `/api/v1/scan` | `routes/scanning.py`, `routes/api.py` |
| T3 | Cross-site request forgery | `CSRFProtect` on every state-changing request; API clients fetch a token from `GET /api/v1/csrf-token` and send `X-CSRF-Token`. **No API route is exempted.** | `extensions.py`, `routes/api.py` |
| T4 | Session fixation / privilege escalation | `session.clear()` before `login_user`; `role` is ignored on registration; `admin_required` role check; strong `session_protection` | `routes/auth.py`, `routes/admin.py`, `app.py` |
| T5 | Password disclosure | scrypt hashes only; `User.to_dict()` omits `password_hash`; no plaintext in logs, API or CSV | `services/auth_service.py` |
| T6 | XSS / injected markup | Jinja autoescaping, `|tojson` for chart payloads, strict `script-src 'self'`, no inline script/style/event handler, offline vendor hashes | `services/http_security.py`, templates |
| T7 | SSRF / live malicious URL fetching | Zero outbound network I/O in any runtime module; URL strings are never opened or resolved | all `routes/*`, `services/*`, `ml/*` |
| T8 | History enumeration | Stage 10/11 visibility reused: own account rows, or own signed guest-session ids; missing and unauthorised ids share one generic 404 | `can_view_scan`, `stats_service.visible_query` |
| T9 | Information disclosure in errors | Generic codes/messages only, JSON on `/api/*`, HTML themed page elsewhere, no traceback or absolute path | `services/http_security.py` |
| T10 | CSV formula injection | Apostrophe prefix + CR/LF/NUL stripping + safe filename | `services/report_service.py` (Stage 11) |
| T11 | Caching of sensitive responses | `Cache-Control: no-store` for `/api/`, `/auth/`, `/health`, `/scan`, `/history`, `/admin`, `/dashboard`, exports, and every 4xx/5xx | `services/http_security.py` |

The trust boundary between "browser session" and "REST client" is deliberately
thin: both are the same signed Flask session. Stage 12 does **not** introduce
bearer tokens, API keys or a second authentication mechanism, because adding
one without key rotation, revocation and audit would weaken the system rather
than harden it.

## 3. Per-route rate limiting

`extensions.py` still creates `Limiter(key_func=get_remote_address,
default_limits=[], storage_uri="memory://")`. **No blanket default limit** is
added: static assets, GET pages and monitoring endpoints are never throttled
globally. Only the abuse-prone routes are decorated.

| Route | Limit key | Config value | Default |
| --- | --- | --- | --- |
| POST `/login`, POST `/register` | per IP, POST only | `RATE_LIMIT_AUTH` | `5 per minute` |
| POST `/scan` | per IP | `RATE_LIMIT_SCAN` | `10 per minute` |
| POST `/api/v1/scan` | per IP (`RATE_LIMIT_API`) **and** per account/IP (`RATE_LIMIT_SCAN`) | both | `30 per hour` / `10 per minute` |
| GET `/api/v1/model/info`, `/api/v1/scans`, `/api/v1/scans/<id>` | per IP | `RATE_LIMIT_API` | `30 per hour` |
| GET `/api/v1/health`, `/api/v1/csrf-token`, `/api/*` errors | unthrottled | — | monitoring/CSRF setup stays reachable |

Each decorator reads the limit **at request time** from `current_app.config`,
so changing `RATE_LIMIT_SCAN` in `.env` (or injecting an override in a test)
takes effect without editing code. `exempt_when=limits_disabled()` makes the
decorators no-ops when `RATELIMIT_ENABLED` is false — `TestingConfig` stays
deterministic even if an earlier app in the same process enabled limits.
`methods=["POST"]` on `/login` and `/register` means rendering the form is
never counted.

On breach, Flask-Limiter raises 429. `install_error_handlers` now has a
dedicated `@app.errorhandler(429)` which:

* returns the documented generic `429 RATE_LIMITED` shape (JSON for `/api/*`
  and JSON clients, themed HTML otherwise);
* sets `Retry-After` (from the limiter's value when available, otherwise 60 s);
* inherits `Cache-Control: no-store` and every security header.

The 429 error page adds a short, non-diagnostic explanation pointing at
`Retry-After` and the three `RATE_LIMIT_*` settings.

## 4. REST API contract

Blueprint `api_bp`, prefix `/api/v1`. **JSON in, JSON out**; errors always have
`error.code`, `error.message` and `error.status`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/csrf-token` | Session CSRF token + `header_name` |
| GET | `/api/v1/health` | Readiness, artefact and schema status (no measured figures) |
| GET | `/api/v1/model/info` | Measured model card, decision states, thresholds, feature order, caveats |
| POST | `/api/v1/scan` | Validate → classify → explain → persist → return the JSON contract |
| GET | `/api/v1/scans` | Scoped, filtered, paginated history |
| GET | `/api/v1/scans/<int:id>` | One authorised row, rebuilt from the audit record (no re-inference) |

`POST /api/v1/scan` request and 200 response (field names are the contract
first documented in `docs/ARCHITECTURE.md` §11):

```json
// request — X-CSRF-Token header required
{ "url": "https://example.com/login?next=account" }

// 200 — illustrative SHAPE only; no number here is a measured result
{
  "status": "ok",
  "scan": {
    "scan_id": 42,
    "submitted_url": "...",
    "normalized_url": "...",
    "prediction": "SUSPICIOUS",
    "model_score": 0.58,
    "score_meaning": "Uncalibrated model estimate ... not a guarantee",
    "risk_level": "MEDIUM",
    "decision_band": { "low": 0.05, "high": 0.95, "source": "ml/saved_model/metadata.json#thresholds" },
    "flagged_features": ["has_at_symbol", "num_suspicious_words"],
    "recommended_action": "...",
    "caveats": ["HTTPS alone does not mean a website is legitimate.", "..."],
    "scanned_at": "2026-11-03T10:15:00+00:00",
    "model": { "name": "...", "version": "..." },
    "report_url": "/scan/42/report",
    "persisted": true
  }
}
```

Error codes: `400 BAD_REQUEST` (non-JSON body, malformed JSON, missing `url`),
`400 INVALID_URL`, `400 CSRF_FAILED`, `401 UNAUTHENTICATED`,
`403 FORBIDDEN`, `404 NOT_FOUND`, `429 RATE_LIMITED`,
`503 MODEL_UNAVAILABLE`, `503 DATABASE_UNAVAILABLE`, `500 INTERNAL_ERROR`.
A 503 is an honest failure, never a rule-based guess disguised as 200.
`GET /api/v1/model/info` returns `503 MODEL_UNAVAILABLE` if the measured
artefact is missing or inconsistent — it never substitutes a typed number.

`GET /api/v1/scans` accepts the same validated `prediction`, `risk`, `q`,
`page` and `per_page` parameters as the HTML history page, and returns
`status`, `scans`, `total`, `page`, `pages`, `per_page`, `filters`, `scope`
and `source`. A different anonymous browser gets `total: 0`.

## 5. CSRF, sessions and password hashing

* `CSRFProtect` covers **every** POST, including `/api/v1/scan`. There is no
  `csrf.exempt` in the codebase. Stage 12 gate asserts a token-less API POST
  is rejected with `400 CSRF_FAILED`.
* `GET /api/v1/csrf-token` and `GET /auth/csrf-token` both call
  `generate_csrf()`; the token is bound to the signed session.
* Login clears the session before `login_user` (session-fixation defence).
  Authentication failures are generic and identical for unknown users, wrong
  passwords and inactive accounts, so accounts cannot be enumerated.
* Registration ignores any caller-supplied `role`; only
  `scripts/create_admin.py` can grant admin. Gate 12 attempts a role-escalation
  registration and asserts the stored role stays `user`.
* Passwords use Werkzeug **scrypt** hashes; `User.to_dict()` never includes
  `password_hash`; no API response, CSV or template exposes it.
* Session cookies are `HttpOnly`, `SameSite=Lax` and `Secure` in production;
  development relaxes `Secure` for HTTP and omits framing headers so the
  cross-origin live preview renders (ADR-025).

## 6. Headers, CSP, XSS and SSRF

Stage 7 already set `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy`, `X-XSS-Protection: 0`, CSP, production HSTS and
production framing. Stage 12 **adds headers, not CSP directives**:

```
Cross-Origin-Opener-Policy: same-origin
X-Permitted-Cross-Domain-Policies: none
Origin-Agent-Cluster: ?1
Cache-Control: no-store        (sensitive prefixes and all 4xx/5xx)
Retry-After: <seconds>         (429 only)
```

The CSP remains byte-for-byte:

```
default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'
```

No new script, stylesheet, inline handler, inline style, runtime CDN or
third-party origin was introduced. The three vendored SHA-256 hashes are
re-verified by the gate. Jinja `|tojson` still escapes chart payloads, and
Jinja autoescaping still escapes submitted URLs.

**SSRF.** No runtime module imports `requests`, `httpx`, `aiohttp`, `pycurl`,
`urllib.request`, `http.client` or `socket.create_connection`. Gate 12 patches
`socket.socket.connect` to raise and then scans loopback, link-local and
reserved `.invalid` URL strings through `POST /api/v1/scan`; the scans must
still succeed because they are pure string operations.

## 7. Error contract and information disclosure

All errors are produced by `make_error_response`. `/api/*` and JSON clients
get JSON; browsers get the themed `errors/error.html`. The page receives only
`status_code`, `code` and `message` — never an exception text, traceback,
stack frame or absolute path. The 500 handler logs the incident server-side.
Missing and unauthorised scan ids share the same generic `404 NOT_FOUND`, so
the API cannot be used to enumerate other users' URLs. `SENSITIVE_PREFIXES`
now covers `/api/`, `/auth/`, `/health`, `/scan`, `/history`, `/admin`,
`/dashboard` and exports, so those responses are never cached.

## 8. What is deliberately NOT in Stage 12

* No change to the detection pipeline, decision states, measured thresholds,
  `SCORE_MEANING`, CSP directives, dataset, model bundle or schema. No new
  table, column, migration, seed script or secret.
* No bearer tokens, API keys, OAuth, JWT or `csrf.exempt` — no second
  authentication mechanism.
* No `tests/` suite or `docs/TEST_PLAN.md` (Stage 13), no `docs/REPORT.md` or
  `docs/DEPLOYMENT.md` (Stage 14).
* No hard-coded measured figures, no invented statistics, no demo rows.
* No blanket rate limit, no throttling of static assets, health checks or
  GET pages, no external rate-limit store (memory only, documented as a
  single-process limitation).
* No new template, JS or CSS file; no change to the Stage 11 dashboard,
  history, admin or CSV views.

## 9. Run and test

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
python scripts\verify_stage12.py           # must print RESULT: PASS
python -m flask --app app run --host 0.0.0.0 --port 5000
```

Try the API (PowerShell 7+ / curl):

```powershell
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$token = (Invoke-RestMethod -Uri http://localhost:5000/api/v1/csrf-token -WebSession $session).csrf_token
Invoke-RestMethod -Method Post -Uri http://localhost:5000/api/v1/scan `
  -WebSession $session -ContentType "application/json" `
  -Headers @{ "X-CSRF-Token" = $token } `
  -Body '{"url":"https://example.com/"}'
Invoke-RestMethod -Uri http://localhost:5000/api/v1/model/info -WebSession $session
Invoke-RestMethod -Uri http://localhost:5000/api/v1/scans -WebSession $session
```

Linux/macOS: use `source .venv/bin/activate`, `/` separators and
`python scripts/verify_stage12.py`. A cookie jar is required so the CSRF token
and session stay together (`curl -c cookies.txt -b cookies.txt`).

### Safe, offline demonstration

Reserved strings only: `https://example.com`, `https://example.com/`,
`https://paypal.com.login.verify.example.invalid/secure/account/update?next=confirm`.
The backend never visits any address. Repeat a POST quickly to observe
`429 RATE_LIMITED` and `Retry-After`, then wait for the window to reset.

## 10. Common errors and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `400 CSRF_FAILED` on `POST /api/v1/scan` | Missing/expired `X-CSRF-Token`, or the cookie jar was lost | `GET /api/v1/csrf-token` first and keep the same session/cookies |
| `400 BAD_REQUEST` on the API | Body is form data, malformed JSON or has no `url` field | Send `Content-Type: application/json` with `{"url":"..."}` |
| `400 INVALID_URL` | URL rejected by the shared validator | Use a bounded `http`/`https` URL string; no rule fallback exists |
| `429 RATE_LIMITED` | A per-route quota was reached | Wait `Retry-After` seconds; tune `RATE_LIMIT_SCAN` / `RATE_LIMIT_AUTH` / `RATE_LIMIT_API` in `.env` |
| `503 MODEL_UNAVAILABLE` | Bundle or `metrics.json` missing/corrupt | `python -m ml.evaluate_model` to regenerate measured artefacts; never add a heuristic guess |
| `503 DATABASE_UNAVAILABLE` | Schema not created | `python scripts\init_db.py`; confirm `--verify-only` says `ready` |
| `401 UNAUTHENTICATED` on `/admin` | Anonymous | Sign in as an administrator |
| `403 FORBIDDEN` on `/admin` | Ordinary user | `python scripts\create_admin.py` or `--promote`; registration never grants admin |
| `404 NOT_FOUND` on `/api/v1/scans/<id>` | Missing row **or** a row you do not own | By design both are identical; use `/api/v1/scans` to list your own rows |
| Rate limits never fire in tests | `TestingConfig` sets `RATELIMIT_ENABLED = False` | Create the app with `RATELIMIT_ENABLED=True` (Gate 12 does this) |
| `/health` has no measured figures | Intentional (Stage 7 contract) | Use `/api/v1/model/info` or `/dashboard` for measured, sourced values |

## 11. Stage 12 exit criteria

`python scripts\verify_stage12.py` must print
`RESULT: PASS - all Stage 12 checks passed`. It verifies, with real temporary
databases, real HTTP requests and a local WSGI server:

* exact file inventory, absence of all Stage 13+ artefacts, and compilation;
* config-driven per-route limits (auth, scan, API), 429 JSON/HTML shapes,
  `Retry-After`, POST-only auth limits, no blanket throttle, and no throttling
  under `TestingConfig`;
* the full REST contract: token, health, model card, scan, scoped list and
  single-row endpoints, all documented fields, three decision states, one
  audit row per scan and no re-inference on reads;
* CSRF enforcement, generic failures, session-fixation defence, role-escalation
  resistance, scrypt hashes, XSS escaping and no URL enumeration;
* the exact unchanged CSP, unchanged vendor hashes, new hardening headers,
  `no-store` on sensitive paths, and socket-patched **SSRF** probes;
* explicit `503 MODEL_UNAVAILABLE` / `503 DATABASE_UNAVAILABLE` paths;
* documentation, ADRs and Windows-first commands;
* **Gates 1–11 still pass** and `pip check` is clean.

Only after that pass may Stage 13 (the full pytest suite) begin.
`PDS_GATE_NESTED=1` keeps the historical regression chain linear: Gate 12
runs Gates 1–11 directly, and child gates skip only their duplicated nested
re-runs. Standalone gates keep their full behaviour.
