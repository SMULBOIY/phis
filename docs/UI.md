# Stage 9 — Frontend: Templates, Themes, Offline Assets and Charts

**Stage rule:** Stage 10 does not start until `python scripts/verify_stage9.py` prints `RESULT: PASS`.

This guide covers the complete presentation layer. It is written for a final-year CS student: every design decision is explained, every command is Windows-first, and every claim is checked by the executable gate.

---

## 1. What Stage 9 builds

Before Stage 9 the app was functional but looked like a developer diagnostics page: the landing page, sign-in form and error pages were fixed inline HTML strings in `routes/core.py`, `routes/auth.py` and `services/http_security.py`. They worked, but they were not the modern, responsive cybersecurity interface the project brief asks for.

Stage 9 replaces those strings with a real **Jinja2 template hierarchy** and a complete **design system**:

| Deliverable | File(s) | Why |
| --- | --- | --- |
| Master layout | `templates/base.html` | One navbar, one theme toggle, one footer, one asset list — no duplication |
| Product overview | `templates/index.html` | Landing page with hero, live telemetry, method, decision states and a chart |
| Auth pages | `templates/login.html`, `templates/register.html`, `templates/auth_result.html` | Same POST contracts as Stage 8, now fully styled and accessible |
| Themed errors | `templates/errors/error.html` | 400/401/403/404/405/413/429/500/503 no longer look like a different product |
| Design system | `static/css/main.css` | Dark (default) + light palettes, SOC aesthetic, four breakpoints |
| Behaviour | `static/js/theme.js`, `static/js/main.js` | Theme persistence, Chart.js rendering, active nav, copy helper |
| Brand mark | `static/images/logo.svg` | Self-contained vector logo, no external reference |
| Offline libraries | `static/vendor/*` + `README.md` | Bootstrap 5.3.3, Popper, Chart.js 4.4.4 with recorded SHA-256 hashes |
| Documentation | `docs/UI.md` (this file), ADR-028/029 | Design rationale and reproducibility |

**What stays exactly the same:** `/health`, `/auth/session`, `/auth/csrf-token`, `POST /login`, `POST /register`, `POST /logout`, all status codes, all JSON shapes, scrypt hashing, CSRF, session rotation, the strict CSP and the Stage 8 database layer. Stage 9 changed *presentation*, not behaviour.

**A note on academic honesty:** the overview still contains **no scan form and no `"SCAN WEBSITE"` button**. The classification engine is Stage 10. A button that cannot produce a real model result would be pretending, which the brief forbids. A prominent banner says so directly. The only chart shows real dataset split **row counts** read from `metadata.json` at runtime — never an invented model statistic.

---

## 2. Design system and themes

### 2.1 CSS custom properties

`static/css/main.css` defines every colour as a CSS variable in `:root` (the dark default). `[data-theme="light"]` overrides the same variable names. Overriding Bootstrap 5's own `--bs-*` variables means Bootstrap components (navbar, grid, buttons, tables) follow our palette instead of fighting it.

| Token | Dark | Light | Meaning |
| --- | --- | --- | --- |
| `--pds-bg` | `#070d14` | `#f4f7fb` | Page background |
| `--pds-panel` | `#101a26` | `#ffffff` | Card surface |
| `--pds-text` | `#e6eef7` | `#10202e` | Primary text |
| `--pds-muted` | `#a8bdd2` | `#4a6076` | Secondary text |
| `--pds-accent` | `#22d3ee` | `#0b7285` | Links, focus, primary button |
| `--pds-ok` | `#34d399` | `#0f7a58` | LEGITIMATE / ready |
| `--pds-warn` | `#fbbf24` | `#a16207` | SUSPICIOUS / degraded |
| `--pds-danger` | `#f87171` | `#b91c1c` | PHISHING / errors |

`scripts/verify_stage9.py` parses both blocks, converts the hex values to WCAG relative luminance and asserts a **contrast ratio ≥ 4.5:1** for body text against the page background and for muted text against a card surface in *both* themes. Both comfortably exceed 6:1. The three decision states get their own border colours from the same tokens.

### 2.2 Why two JavaScript files

A theme stored in `localStorage` must be applied **before the browser paints**, otherwise the user sees a flash of the wrong palette. An inline `<script>` in `<head>` would solve that but is forbidden by the CSP (`script-src 'self'`, no `unsafe-inline`). The solution is a tiny **external, blocking** `static/js/theme.js` in `<head>`: it reads the stored theme, falls back to `prefers-color-scheme`, and sets `data-theme` on `<html>`. `static/js/main.js` is deferred and handles all interactive behaviour.

The Arena live preview and the in-app file viewer render inside `sandbox="allow-scripts"` iframes without `allow-same-origin`, where `localStorage` throws `SecurityError`. Every storage access is wrapped in `try/catch` — the toggle still switches the palette in that frame; only persistence degrades. This is a browser sandbox rule, not an application defect.

### 2.3 Load order

```
bootstrap.min.css  →  backend.css (Stage 7 legacy, kept for error-page compatibility)
                   →  main.css (wins: overrides globals and all --bs-* tokens)
theme.js (head, blocking) → bootstrap.bundle.min.js, chart.umd.min.js, main.js (defer)
```

---

## 3. Template map and inheritance

```
templates/base.html                     master layout, nav, theme toggle, footer, scripts
├── templates/index.html                GET  /
├── templates/login.html                GET/POST /login (HTML branch)
├── templates/register.html             GET/POST /register (HTML branch)
├── templates/auth_result.html          HTML success branch of /login and /register
└── templates/errors/error.html         HTML branch of make_error_response()
```

`app.py` adds a `@app.context_processor` publishing `app_name`, `app_version`, `build_stage`, `environment` and `debug` to every template. Flask-Login already supplies `current_user`; Flask-WTF supplies `csrf_token()`. No view passes secrets or measured results into a template.

**Jinja2 auto-escaping is on** for all `.html` files, which is the primary XSS defence for any future user-supplied text. Combined with the CSP this gives two independent layers.

| Route | Template | Context (all read at runtime) |
| --- | --- | --- |
| `GET /` | `index.html` | `info` (model metadata), `bundle` (hash status), `db_status`, `feature_order`, `states`, `split_chart`, `split_rows` |
| `GET/POST /login` | `login.html` | `action`, `token`, `problems`, switch links |
| `GET/POST /register` | `register.html` | same shape, plus confirmation field |
| success (HTML) | `auth_result.html` | `title`, `message`, `detail`, `authenticated` |
| errors (HTML) | `errors/error.html` | `status_code`, `code`, generic `message` only |

The Stage 8 JSON branches are untouched: JSON clients still get `{"authenticated": ...}` or `{"error": {...}}`, never HTML.

---

## 4. Offline vendor assets and CSP

`static/vendor/` holds three **unmodified upstream files** with recorded SHA-256 digests (see `static/vendor/README.md` and §8's verification commands):

| File | Version | Size | SHA-256 |
| --- | --- | --- | --- |
| `bootstrap.min.css` | 5.3.3 | 232,803 B | `3c8f27e6…736fc8` |
| `bootstrap.bundle.min.js` | 5.3.3 (with Popper) | 80,721 B | `0833b2e9…a61c6c` |
| `chart.umd.min.js` | 4.4.4 | 205,749 B | `b3807676…3bc7` |

Full digests are in `static/vendor/README.md`; the gate recomputes all three and fails on any mismatch. Bootstrap and Chart.js are MIT-licensed and their upstream licence headers are preserved.

**Why no CDN?** Three reasons, all relevant to a viva:

1. **CSP.** `services/http_security.py` sends `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'`. A CDN would need an allow-list entry and widen the attack surface.
2. **Offline demonstration.** A lab or exam machine may have no internet; local files render identically.
3. **Reproducibility.** Pinned versions + hashes make the exact UI reconstructible.

The gate asserts there is **no inline `<script>` content**, **no `style=` attribute**, **no inline event handler** (`onclick`, `onload`, …), and **no external `src`/`href`** in any template. Bootstrap's mobile navbar uses `data-bs-toggle` attributes handled by the local bundle, not inline JavaScript.

---

## 5. Chart.js data contract

The overview contains one doughnut chart: **"Leakage-free 70 / 15 / 15 split"**, showing the real row counts of the PhiUSIIL-derived train/validation/test partitions.

```
metadata.json#dataset.split_sizes
   → ModelRegistry.dataset_chart()   (services/model_metadata.py)
   → routes/core.py passes split_chart to Jinja
   → index.html renders  data-chart='{{ split_chart|tojson }}'
   → main.js JSON.parse(el.getAttribute("data-chart"))
   → new Chart(canvas, config)
```

Using an escaped `data-*` attribute instead of an inline `<script>` block is the key CSP-safe pattern. `|tojson` escapes `<`, `>`, `&` and quotes, so the payload cannot break out of the attribute. `main.js` uses only `textContent` for messages, never `innerHTML`.

The payload shape is fixed:

```json
{
  "labels": ["Train (70%)", "Validation (15%)", "Test (15%)"],
  "values": [164744, 35302, 35302],
  "series_label": "URL rows",
  "source": "ml/saved_model/metadata.json#dataset.split_sizes"
}
```

These are **dataset row counts, not model results**. Gate 9 asserts the rendered values equal `metadata.json` exactly, that the payload contains no measured-metric key, and that no template or script mentions `metrics.json` or `predict_proba`. If Chart.js is missing, `main.js` shows a plain-language fallback and the row counts are also printed as text; the page never displays an empty chart pretending to be data. `main.js` re-reads the CSS variables on theme change so legend and tooltip colours follow the palette.

Stage 11 will add dashboard charts from real aggregate queries in exactly the same way.

---

## 6. Responsive behaviour and accessibility

| Concern | Implementation |
| --- | --- |
| Viewport | `<meta name="viewport" content="width=device-width, initial-scale=1">` in `base.html` |
| Layout | Bootstrap 5 grid (`col-12 col-sm-6 col-lg-3`, `col-md-4`, `col-lg-7/5`) plus custom flex/grid |
| Breakpoints | `@media (max-width: 1200px)`, `992px`, `768px`, `576px` in `main.css` |
| Mobile nav | Bootstrap `collapse` with `data-bs-toggle`, `aria-controls`, `aria-expanded` |
| Touch targets | Nav links and buttons have `min-height: 44px` / `46px` |
| Keyboard | Skip link (`.pds-skip`), visible `:focus-visible` outline, no keyboard traps |
| Screen readers | `lang="en"`, `<main id="main-content">`, `aria-labelledby` sections, `role="alert"` for problems/errors, `aria-live` region for copy feedback, `alt=""` on decorative logo |
| Colour | WCAG AA contrast verified in both themes by the gate; never colour alone (every state also has text and a risk label) |
| Motion | `@media (prefers-reduced-motion: reduce)` disables transitions; `html { scroll-behavior: auto }` |
| Printing | `@media print` hides nav, toggles and footer |
| No-JS | `<noscript>` note plus the row counts printed as text; forms still work without JavaScript |

The theme toggle is a real `<button>` with `aria-pressed` and an updated `aria-label` ("Switch to dark/light theme"), so it is usable by keyboard and announced correctly.

---

## 7. What is deliberately NOT in Stage 9

| Absent | Why | Stage |
| --- | --- | --- |
| `"/scan"`, `"SCAN WEBSITE"` button, URL input | The detection engine does not exist yet; a non-functional control would be pretending | 10 |
| `predict_proba`, estimator loading, feature extraction at request time | Runtime classification | 10 |
| Dashboard, history, admin templates, KPI charts, CSV export | They need stored scans and aggregate queries | 11 |
| Per-route rate limits, REST API, `docs/SECURITY.md` | Security hardening stage | 12 |
| `tests/conftest.py`, the full pytest suite | Testing stage | 13 |
| Final report, deployment guide | Documentation/deployment stage | 14 |
| Any displayed model performance number | Stage 11 reads `metrics.json` / `ModelInformation` at runtime | 11 |

Gate 9 explicitly asserts these files and routes are absent, so a future stage cannot quietly be started early.

---

## 8. Run and test

### Install (Windows / PowerShell)

```powershell
cd phishing-detection-system
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into .env as SECRET_KEY
```

Stage 9 needs **no new Python packages**. Bootstrap and Chart.js are already vendored in `static/vendor/`.

### Initialise and run

```powershell
python scripts\init_db.py                 # required once for the READY database card
python -m flask --app app run --host 0.0.0.0 --port 5000
```

| URL | What to check |
| --- | --- |
| `http://127.0.0.1:5000/` | Overview, telemetry cards, doughnut chart, theme toggle |
| `http://127.0.0.1:5000/login` | Styled sign-in form |
| `http://127.0.0.1:5000/register` | Styled registration form |
| `http://127.0.0.1:5000/health` | Unchanged JSON contract, `build_stage: 9` |
| `http://127.0.0.1:5000/no-such-page` | Themed 404 with `NOT_FOUND`, no traceback |

Open the app in its **own browser tab** to test login: the cross-origin live-preview iframe cannot send `SameSite=Lax` session cookies for subrequests. Resize the window (or use browser DevTools device emulation) to check the four breakpoints.

### Verify the vendored hashes (Windows)

```powershell
Get-FileHash static\vendor\bootstrap.min.css -Algorithm SHA256
Get-FileHash static\vendor\bootstrap.bundle.min.js -Algorithm SHA256
Get-FileHash static\vendor\chart.umd.min.js -Algorithm SHA256
```

Compare with `static/vendor/README.md`. `scripts/verify_stage9.py` does this automatically.

### Test (exit gate)

```powershell
python scripts\verify_stage9.py
```

It checks: file existence and all three upstream hashes; the SVG logo parses as well-formed XML with no external reference; dark/light palettes and measured WCAG contrast; four responsive breakpoints; the JS contract (theme persistence, chart parsing, no inline code, no outbound request); every template (no inline script/style, no external assets, no placeholders, correct inheritance); the rendered pages in a ready app, a degraded-bundle app and a production app; honest chart data equal to `metadata.json`; all preserved Stage 7/8 HTTP and auth contracts; themed error responses and 500/413 paths; the absence of Stage 10+ features; documentation; and Gates 1–8 as regressions.

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
```

All nine must print `RESULT: PASS`. Linux/macOS: `source .venv/bin/activate`, `cp` instead of `copy`, `/` path separators.

---

## 9. Common errors and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| Page renders as unstyled black-on-white HTML | `main.css` or Bootstrap CSS failed to load (404 / wrong path) | Check DevTools Network; confirm `static/vendor/bootstrap.min.css` and `static/css/main.css` exist and `url_for('static', ...)` resolves |
| `jinja2.exceptions.TemplateNotFound` | Template directory wrong or file renamed | `app.py` sets `template_folder="templates"`; keep the six files listed in §3 |
| `UndefinedError: 'app_name' is undefined` | The Stage 9 context processor was removed | Restore `@app.context_processor` in `app.py` |
| Chart canvas stays blank | `chart.umd.min.js` missing, or `data-chart` JSON malformed | Check the file hash; inspect `data-chart` with `JSON.parse` in DevTools; `main.js` writes a fallback message when `Chart` is undefined |
| Chart legend is invisible in light theme | Stale colours after a theme switch | `refreshChartColours()` re-reads CSS variables and calls `chart.update('none')` |
| Theme toggle does not persist across reloads | `localStorage` blocked (sandboxed iframe) or disabled | Open in a normal tab; `theme.js` already guards `SecurityError` |
| Brief flash of the dark theme on a light-mode machine | External `theme.js` did not run before paint | Ensure the `<script src=".../theme.js">` tag stays in `<head>` **without** `defer` |
| `Refused to apply inline style` / `Refused to execute inline script` in DevTools | A `style=` attribute or inline `<script>` was added | Move the rule into `main.css` and the behaviour into `main.js`; the gate checks this |
| `TemplateSyntaxError` on `|zip(...)` | Jinja2 has no built-in `zip` filter | Pass pre-zipped `split_rows` from the view (as this project does) |
| `404` on a vendored file after copying the project | `static/vendor/` was excluded by a copy rule or `.gitignore` | Copy the whole `static/` tree; verify with the `Get-FileHash` commands above |
| Database card says `NOT_INITIALISED` | `instance/phishing.db` not created | `python scripts\init_db.py` |
| Login appears to do nothing inside the live preview | Cross-origin iframe + `SameSite=Lax` cookies | Open `http://127.0.0.1:5000/login` in its own browser tab |

---

## 10. Stage 9 exit criteria

| # | Criterion | Verified by |
| --- | --- | --- |
| 1 | Six real templates with inheritance; no inline HTML strings left in Python | Gate 9 §4, §5 |
| 2 | Bootstrap 5.3.3 + Chart.js 4.4.4 vendored locally with correct SHA-256 hashes | Gate 9 §1 |
| 3 | Dark + light themes with WCAG AA contrast, applied before paint | Gate 9 §2, §3 |
| 4 | Responsive at 1200/992/768/576 px, accessible nav, focus, skip link, reduced motion | Gate 9 §2, §4 |
| 5 | Chart.js renders from real, escaped, runtime `metadata.json` split counts | Gate 9 §3, §6 |
| 6 | Strict CSP preserved; no inline script/style, no external asset, no new network call | Gate 9 §4, §6 |
| 7 | `/`, `/health`, `/login`, `/register`, `/logout` and all error responses still honour Stage 7/8 contracts | Gate 9 §6, §7 |
| 8 | No scan form, no `"SCAN WEBSITE"` button, no dashboard/history/admin, no `predict_proba`, no displayed model metric | Gate 9 §4, §8 |
| 9 | Documentation, ADRs and Gates 1–8 green | Gate 9 §8 |

When `scripts/verify_stage9.py` prints `RESULT: PASS - all N checks passed`, Stage 9 is closed. **Do not start Stage 10 until then.**

---

*Stage 9 of 14. Next: Stage 10 — detection engine integration, the exact `"SCAN WEBSITE"` button, feature explanations and saved scan results.*

---

## Stage 10 update

Stage 9's honesty rule ("no scan control yet") was deliberately temporary;
Stage 10 replaces it with a real one. The design system in `main.css` is
extended with `.pds-hero-compact`, `.pds-input-row`, `.pds-result-*` state
colours, `.pds-meta-grid`, `.pds-flag-list`, `.pds-feature-table`,
`.pds-caveat-list` and print rules. Every new colour uses an existing theme
variable, so dark/light themes, WCAG AA contrast and the 1200/992/768/576 px
breakpoints still apply. No new hex palette, no `f1`-like metric string and no
`@import` was added.

New pages: `templates/scan.html` (the exact `SCAN WEBSITE` button),
`templates/partials/scan_result.html` (shared result/report body) and
`templates/scan_report.html` (printable report). `base.html` gains a
`Scan URL` navigation link; `index.html` gains a "Launch URL scanner"
call-to-action, a live detection-engine card and three new working-endpoint
rows. The Stage 9 provenance chart, decision-state cards, theme toggle,
`data-chart` contract and all six original templates are intact.

**CSP unchanged.** Printing is a progressive enhancement: `main.js` attaches
`window.print()` to `[data-print]` buttons; there is no inline handler, inline
script content, inline `style=` attribute or external asset. Forms are ordinary
POSTs and work with JavaScript disabled. Jinja autoescaping renders the
submitted URL; Gate 10 submits a URL containing `<script>` and asserts the
response contains `&lt;script&gt;`.

The result page explicitly labels the **model score** as an uncalibrated
estimate (never a guaranteed probability of maliciousness), shows the measured
abstention band, states "HTTPS alone does not mean a website is legitimate",
and lists limitations. No measured performance figure is displayed. The
Gate 9 rule "no scan control and no invented chart data" remains true for the
Stage 9 historical record; it is now satisfied by real functionality instead of
absence.

---

## Stage 11 update

Three new pages extend the same design system: `templates/dashboard.html`
(KPI grid, three `data-chart` canvases, measured model table and caveats),
`templates/history.html` (GET filter bar, scoped table, empty state,
pagination) and `templates/admin.html` (accounts, measured model audit row,
live system counts). `base.html` gains Dashboard and History navigation links
and an Admin link shown only to authenticated admins; `index.html` gains five
working-endpoint rows; `errors/error.html` gains a `Sign in` action on the 401
page without changing the status code or error code.

`main.css` adds `.pds-kpi-grid`, `.pds-chart-grid`, `.pds-chart-wide`,
`.pds-small-value`, `.pds-filter-bar`, `.pds-filter-field`, `.pds-history-table`,
`.pds-url-cell`, `.pds-table-link`, `.pds-badge-*`, `.pds-pagination` and
`.pds-empty-state`. All colours come from the existing CSS custom properties,
so both themes, WCAG AA contrast and the 1200/992/768/576 px breakpoints still
apply. No `@import`, no web font, no remote URL, no new hex palette and no
`@f1`-like metric string was added. Print rules hide the filter bar and
pagination.

`main.js` gains only `cycledColours()`: it repeats the three theme-derived
colours for any number of categories, so the seven-day volume chart works
without a second JS file. The Stage 9 `data-chart` → `JSON.parse` →
`new window.Chart` contract, the honest text fallback when Chart.js is
missing, theme re-colouring on toggle, active-nav marking and the
`pdsLiveRegion` announcements are intact. No `eval`, `innerHTML`,
`document.write`, `fetch`, `XMLHttpRequest` or absolute asset URL was added.

**CSP unchanged.** Stage 11 adds no inline `<script>` content, no inline
`style=` attribute, no inline event handler and no external asset. Jinja
`|tojson` escapes all chart payloads; Jinja autoescaping renders every
submitted URL. Gate 11 stores a URL containing `<script>` and asserts the
history table shows `&lt;script&gt;`.

The dashboard is the **first** UI surface allowed to show measured
performance figures, and only by reading `metrics.json` at request time with
the exact source key and the held-out test-split, HTTPS-bias, recall-priority
and abstention caveats printed next to them. No figure is typed into a
template. The Stage 9 historical rule "no scan control and no invented chart
data" remains true for that stage's record; it is now satisfied by real
functionality instead of absence, and the Gate 9 wording checks stay stage-aware.

## Stage 12 update — endpoint table and 429 page, no new assets

Stage 12 does **not** add a template, stylesheet, script or vendor file.
`templates/index.html` gains six rows in its "Working endpoints" table for the
`/api/v1` routes and its Security edge card now mentions per-route request
limits. `templates/errors/error.html` gains a conditional 429 paragraph that
points at `Retry-After` and the three `RATE_LIMIT_*` settings; it still shows
only `{{ code }}`, `{{ status_code }}` and `{{ message }}`, never an exception.

All twelve templates remain free of inline `<script>` bodies, inline `style`
attributes, inline event handlers and external `src`/`href` origins. The three
vendored SHA-256 hashes, `script-src 'self'`, `style-src 'self'` and the exact
CSP string are unchanged. The `SCAN WEBSITE` control, the three Chart.js
`data-chart` contracts and the Stage 11 dashboard/history/admin pages are
untouched. The Stage 9 historical rule "no scan control and no invented chart
data" remains true for that stage's record and is still satisfied by real
functionality rather than absence. See `docs/SECURITY.md` §6.
