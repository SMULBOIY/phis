# Stage 2 — Development Environment Setup

**Audience:** a Computer Science student using Visual Studio Code.
**Primary platform:** Windows (PowerShell). Linux and macOS commands are at the end.
**Verified in this workspace on:** Python 3.13.16 / Linux, with the exact package versions in `docs/ENVIRONMENT.md`.

---

## 1. What Stage 2 builds and why

| File | Purpose |
| --- | --- |
| `requirements.txt` | Exact, reproducible dependency pins for the whole project |
| `config.py` | Dev / Test / Prod configuration classes, secrets from environment, safe defaults |
| `.env.example` | Documents every environment variable without committing any secret |
| `docs/SETUP.md` | This guide |
| `docs/ENVIRONMENT.md` | Measured record of the verified interpreter and package versions |
| `scripts/verify_stage2.py` | Executable exit gate: dependency, configuration and wiring tests |
| `README.md`, `docs/STAGE_PLAN.md`, `scripts/verify_stage1.py` | Updated status / stage-aware historical gate |

**Why this stage exists:** "works on my machine" is the most common reason a project defence fails. If Flask 3, scikit-learn 1.6, NumPy 2.2 and pandas 2.3 are not installed in one isolated environment, then *every* later stage will look broken for reasons that have nothing to do with your code. Pinning versions also makes the Machine Learning results reproducible, which is an academic requirement, not a convenience.

**Why exact pins instead of loose `>=` ranges:** scikit-learn, pandas and NumPy change behaviour between releases. An examiner re-running your training script in 2027 must get the same numbers. We checked that every pin below has wheels for Python **3.10, 3.11, 3.12 and 3.13**, so the file also works on a lab machine with an older interpreter. A full `pip freeze` snapshot is recorded in `docs/ENVIRONMENT.md`.

**Why a `.env` file and a config module:** `SECRET_KEY` signs session cookies. Putting it in source code means anyone reading your GitHub repo can forge sessions. `config.py` reads it from the environment, `ProductionConfig` refuses to start without a strong one, and `DevelopmentConfig` generates a random throwaway key so you can start coding immediately.

> **Stage 2 does NOT create** `app.py`, the database, any model, any route or any template. Those belong to later stages. `scripts/verify_stage2.py` explicitly checks that they are still absent.

---

## 2. Prerequisites

| Requirement | Check | Notes |
| --- | --- | --- |
| Python 3.10–3.13 | `py -3 --version` | Python 3.12 or 3.13 recommended on Windows |
| Visual Studio Code | — | Install the **Python** and **Pylance** extensions |
| Git (optional but recommended) | `git --version` | For the staged commits in `docs/STAGE_PLAN.md` |
| ~600 MB free disk | — | NumPy/pandas/scikit-learn wheels |
| Internet access once | — | Only for `pip install`; scans themselves work offline |

If `py` is not recognised, install Python from python.org and tick **"Add python.exe to PATH"** during setup. The `py` launcher is installed automatically on Windows.

To see all installed interpreters:

```powershell
py -0p
```

---

## 3. Windows installation (PowerShell)

Run these from the project root (`phishing-detection-system`).

```powershell
# 1. Go to the project folder
cd $HOME\Documents\phishing-detection-system

# 2. Confirm the interpreter (3.10 - 3.13)
py -3 --version

# 3. Create an isolated virtual environment
py -3 -m venv .venv

# 4. Activate it
.\.venv\Scripts\Activate.ps1
#    If activation is blocked, use ONE of these instead:
#    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; .\.venv\Scripts\Activate.ps1
#    .\.venv\Scripts\activate.bat      (from cmd.exe)

# 5. Upgrade pip and install the pinned dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 6. Confirm there are no dependency conflicts
python -m pip check

# 7. Create your private environment file
copy .env.example .env

# 8. Generate a strong secret and paste it into .env as SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# 9. Run BOTH stage gates
python scripts\verify_stage1.py
python scripts\verify_stage2.py
```

**In VS Code:** press `Ctrl+Shift+P` → *Python: Select Interpreter* → choose `.\.venv\Scripts\python.exe`. Otherwise the editor may lint against the wrong interpreter and show false "module not found" errors.

`SECRET_KEY` is optional in development (an ephemeral key is generated), but **mandatory in production** — `ProductionConfig.require_valid()` raises `RuntimeError` without it.

### Optional: initialise Git

```powershell
git init
git add .
git commit -m "Stage 2: pinned environment, configuration, setup guide and gate"
```

`.gitignore` excludes `.env`, `.venv/`, `instance/*.db`, `ml/saved_model/*.joblib`, `dataset/raw/*.csv` and all caches. Verify with:

```powershell
git status --short
git check-ignore -v .env
```

---

## 4. Linux / macOS installation

```bash
cd ~/phishing-detection-system
python3 --version                      # 3.10 - 3.13
python3 -m venv .venv                  # Debian/Ubuntu may need: sudo apt install python3-venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into .env
python scripts/verify_stage1.py
python scripts/verify_stage2.py
```

---

## 5. What each dependency does

| Package | Version | Why the project needs it |
| --- | --- | --- |
| `Flask` | 3.1.3 | Web framework, blueprints, application factory |
| `Werkzeug` | 3.1.9 | `generate_password_hash` (scrypt), WSGI utilities, safe routing |
| `Jinja2` | 3.1.6 | Autoescaping templates — the main XSS defence |
| `Flask-SQLAlchemy` / `SQLAlchemy` | 3.1.1 / 2.0.55 | ORM + bound parameters — the main SQL-injection defence |
| `Flask-WTF` / `WTForms` | 1.3.0 / 3.2.2 | CSRF tokens and form validation |
| `email-validator` | 2.3.0 | Real e-mail validation for registration |
| `Flask-Login` | 0.6.3 | Session management, login-required decorators |
| `Flask-Limiter` / `limits` | 3.12 / 3.14.1 | Rate limiting on scan, auth and API endpoints |
| `python-dotenv` | 1.2.4 | Loads `.env`; keeps secrets out of source control |
| `numpy` | 2.2.6 | Numeric feature vectors |
| `pandas` | 2.3.3 | Dataset loading, preprocessing, class-distribution analysis |
| `scikit-learn` | 1.6.1 | Logistic Regression, Decision Tree, Random Forest, metrics, ROC-AUC |
| `joblib` | 1.5.3 | Saving/loading the trained model bundle |
| `pytest` | 9.0.3 | Automated test suite (Stage 13) |
| `waitress` | 3.0.2 | Pure-Python production WSGI server that works on Windows |

**XGBoost** is deliberately absent. The brief calls it optional; adding it would introduce a heavy binary dependency that does not change the research question. It can be added in Stage 5 if you want a fourth comparison model.

**Frontend note:** Bootstrap 5 and Chart.js are *not* pip packages. Stage 9 vendored them once into `static/vendor/` (with SHA-256 digests in `static/vendor/README.md`) so the UI works offline and the Content Security Policy can stay strict. No CDN is used and no extra install step is required.

---

## 6. How to run and how to test

This section documents the **Stage 2** gate as it was run at that time. The application now exists (Stages 7–8): see `docs/BACKEND.md` and `docs/DATABASE.md` for `python -m flask --app app run`, `python scripts\init_db.py` and `python scripts\create_admin.py`. The Stage 2 gate remains the environment regression check:

```powershell
python scripts\verify_stage2.py
```

It performs four groups of checks and exits `0` only when all pass:

1. **Environment** — Python ≥ 3.10, required files exist, `.env` is not tracked, `.env.example` contains the required keys and no real secret.
2. **Dependencies** — every line of `requirements.txt` is parsed, every distribution is installed, and every installed version satisfies its pin; every module imports successfully; `python -m pip check` reports no broken requirements.
3. **Configuration** — all three config classes exist; `get_config()` resolves names and aliases and rejects unknown environments; development has a ≥32-character ephemeral key; testing uses in-memory SQLite with CSRF and rate limiting disabled; production has secure cookies, debug off and **fails validation without a strong secret**; environment-variable overrides work; `describe_config()` masks secrets; paths and the provisional decision band are consistent.
4. **Integration wiring** — a tiny in-process exercise of the installed libraries: a `RandomForestClassifier`, `LogisticRegression` and `DecisionTreeClassifier` fit on a 6-row NumPy array, `predict_proba` works, a `joblib` round-trip reproduces predictions, a pandas DataFrame builds with a fixed column order, a minimal Flask app with `SQLAlchemy`, `CSRFProtect`, `LoginManager` and `Limiter` answers a test request, and `werkzeug.security` password hashing verifies correctly. This catches version incompatibilities *before* Stage 7.

It also re-runs `scripts/verify_stage1.py` as a regression check. Its "later-stage files must be absent" checks are **stage-aware**: once a stage has been delivered, the corresponding skips activate, so this gate stays green as the project grows (see `docs/STAGE_PLAN.md`, gate discipline rule 6).

Expected tail of a passing run:

```
====================================================================
RESULT: PASS - all N checks passed
Stage 2 exit gate satisfied. You may proceed to Stage 3.
```

### Manual checks worth doing yourself

```powershell
python -c "from config import describe_config; print(describe_config())"
python -c "import flask, sklearn, pandas, numpy, joblib, sqlalchemy; print('imports OK')"
python -m pip list --format=freeze
python -c "from config import ProductionConfig; ProductionConfig.require_valid()"  # should raise until SECRET_KEY is set
```

The last command *should* fail with `RuntimeError: Invalid production configuration: SECRET_KEY must be at least 32 characters...` while `SECRET_KEY` is empty. That is the security control working, not a bug.

---

## 7. Common errors and fixes

| Error / symptom | Cause | Fix |
| --- | --- | --- |
| `py : The term 'py' is not recognized` | Python not on PATH | Reinstall from python.org with "Add to PATH", or use `python -m venv .venv` |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | PowerShell execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then activate, or use `activate.bat` in cmd |
| `No module named 'flask'` | VS Code / terminal using the global interpreter | Activate the venv; in VS Code run *Python: Select Interpreter* → `.venv\Scripts\python.exe` |
| `error: externally-managed-environment` (Linux) | Distro Python blocks global installs | Always use a venv: `python3 -m venv .venv && source .venv/bin/activate` |
| `ensurepip is not available` / `python3-venv` missing | Debian/Ubuntu split package | `sudo apt install python3-venv`, then recreate `.venv` |
| `ERROR: Could not build wheels for numpy/pandas` | Very new/old Python, or 32-bit Python | Use 64-bit Python 3.12 or 3.13; ours are all prebuilt wheels. Delete `.venv` and reinstall |
| `Microsoft Visual C++ 14.0 or greater is required` | pip tried to compile from source | Upgrade pip (`python -m pip install --upgrade pip`) so it selects a wheel; use 64-bit Python |
| `ModuleNotFoundError: No module named 'packaging'` inside the gate | Broken partial install | `python -m pip install -r requirements.txt` again; `pytest` depends on `packaging` |
| `WARNING: Using the in-memory storage for rate limiting` | Flask-Limiter development default | Expected. Stage 12 deliberately keeps `memory://` for single-process use; a shared store is future work, not a missing feature |
| `RuntimeError: Invalid production configuration: SECRET_KEY ...` | `APP_ENV=production` with empty `SECRET_KEY` | Generate a key and put it in `.env` (see step 8 above) |
| `ValueError: DECISION_LOW_DEFAULT must be a number` | Typo in `.env` | Use `0.30` / `0.70`, not `30%` |
| `ImportError: cannot import name 'CSRFProtect' from 'flask_wtf'` | Flask-WTF not installed or wrong interpreter | Activate the venv and re-run `pip install -r requirements.txt` |
| Corporate proxy / `SSL: CERTIFICATE_VERIFY_FAILED` during pip | Network interception | Ask your lab admin for the proxy CA, or use `pip --trusted-host pypi.org --trusted-host files.pythonhosted.org` **only on a trusted network** |
| `git status` shows `.env` | `.gitignore` was deleted or the file was added before the rule | `git rm --cached .env` (removes from index, keeps the file on disk) |

---

## 8. Stage 2 exit gate

Stage 2 is complete only when all of the following are true:

- [x] `.venv` exists and `python -m pip check` prints *"No broken requirements found."*
- [x] `python scripts/verify_stage2.py` exits 0.
- [x] `python scripts/verify_stage1.py` still exits 0 (regression).
- [x] `.env` exists locally, is gitignored, and contains a generated `SECRET_KEY`.
- [x] No `app.py`, no database, no trained model and no dataset exist yet.
- [x] You can explain why secrets live in environment variables and why versions are pinned.

**Next:** Stage 3 — dataset acquisition and preprocessing. Because you asked for help finding a dataset, Stage 3 will begin with a verified shortlist (source, licence, download URL, collection date, columns and class balance) before any preprocessing code is written. No training data will be invented.

---

## Stage 10: run and test the scanner

The Stage 2 environment setup is unchanged — Stage 10 adds **no new Python
package**. After activating `.venv` and creating `.env`:

```powershell
python scripts\init_db.py
python scripts\init_db.py --verify-only
python -m pip check
python scripts\verify_stage10.py
python -m flask --app app run --host 0.0.0.0 --port 5000
```

`verify_stage10.py` re-runs `verify_stage1.py` … `verify_stage9.py`, checks the
new pipeline and dependency health, and must print `RESULT: PASS`. Then open
`http://localhost:5000/scan` and press **SCAN WEBSITE**. Use reserved strings
such as `https://example.com/` for a safe demonstration; the backend never
visits the address.

| Symptom | Fix |
| --- | --- |
| `503 MODEL_UNAVAILABLE` | Restore `ml/saved_model/model_bundle.joblib` and `metrics.json` (regenerate with `python -m ml.evaluate_model`), then restart. Do not add a heuristic fallback. |
| `503 DATABASE_UNAVAILABLE` | Run `python scripts\init_db.py`; confirm `python scripts\init_db.py --verify-only` says `ready`. |
| `400` on POST | Include the CSRF token (HTML hidden field or `X-CSRF-Token` header from `/auth/csrf-token`). |
| `ModuleNotFoundError: sklearn` | The virtual environment is not active; run `.\.venv\Scripts\Activate.ps1`. |

Full pipeline, failure paths and common errors: `docs/DETECTION.md`.

---

## Stage 11: dashboard, history, admin and CSV export

The Stage 2 environment setup is unchanged — Stage 11 adds **no new Python
package**. After activating `.venv` and creating `.env`:

```powershell
python scripts\init_db.py
python scripts\init_db.py --verify-only
python scripts\create_admin.py            # optional: needed to open /admin
python -m pip check
python scripts\verify_stage11.py
python -m flask --app app run --host 0.0.0.0 --port 5000
```

`verify_stage11.py` re-runs `verify_stage1.py` … `verify_stage10.py`, checks the
reporting layer against real temporary databases and must print `RESULT: PASS`.
Then open:

```
http://localhost:5000/dashboard
http://localhost:5000/history
http://localhost:5000/history/export.csv
http://localhost:5000/admin                 (sign in as an administrator first)
```

On Linux/macOS use `source .venv/bin/activate` and `/` path separators, e.g.
`python scripts/verify_stage11.py`.

| Symptom | Fix |
| --- | --- |
| `503 DATABASE_UNAVAILABLE` on `/dashboard` or `/history` | Run `python scripts\init_db.py`; confirm `python scripts\init_db.py --verify-only` says `ready`. |
| `503 MODEL_UNAVAILABLE` on `/dashboard` | Restore/regenerate `ml/saved_model/metrics.json` with `python -m ml.evaluate_model`. Stage 11 fails closed; do not type a number into a template. |
| `401 UNAUTHENTICATED` on `/admin` | Sign in as an administrator (the 401 page now has a *Sign in* link). |
| `403 FORBIDDEN` on `/admin` | Your account has `role="user"`; run `python scripts\create_admin.py` or `--promote`. Registration never grants admin. |
| Empty history after signing in | Guest scans belong to the browser session and are not claimed (ADR-034); scan again while signed in. |
| CSV looks garbled in Windows Excel | The file is UTF-8 with a BOM; use *Data → From Text/CSV* and choose UTF-8. |
| A URL beginning with `=` shows a leading apostrophe in CSV | Deliberate spreadsheet formula-injection protection, not data corruption. |

Full route, filter, CSV-security and exit-criteria documentation:
`docs/DASHBOARD.md`.

## Stage 12 setup note

No new package, table, secret or environment variable is required. The three
rate-limit keys already present in `.env.example` (`RATE_LIMIT_SCAN=10 per minute`,
`RATE_LIMIT_AUTH=5 per minute`, `RATE_LIMIT_API=30 per hour`) are now consumed
by the decorators; edit them in `.env` to tune quotas. Rate limiting is disabled
automatically under `TestingConfig`. `WARNING: Using the in-memory storage for
rate limiting` remains expected: Stage 12 deliberately keeps `memory://` for a
single-process deployment rather than adding a Redis dependency. A distributed
store is future work, not a missing feature.

After installing, verify with `python scripts\verify_stage12.py` (Linux:
`python scripts/verify_stage12.py`) — it must print `RESULT: PASS` and also runs
Gates 1–11 as regressions. Then try the API from a session that keeps cookies:
`GET /api/v1/csrf-token`, then `POST /api/v1/scan` with that value in the
`X-CSRF-Token` header and a JSON body `{"url":"https://example.com/"}`.
Full Windows-first examples and the error table are in `docs/SECURITY.md` §9–10.

## Stage 13 setup note — running the tests

Nothing new is installed: `pytest` has been pinned since Stage 2
(`requirements.txt`). The suite needs no database bootstrap, no `.env` secret and
no network.

```powershell
# From the project root, virtual environment active
python -m pytest -v            # exit gate for Stage 13: 259 passed
python scripts\init_db.py --verify-only
```

The suite creates its own temporary SQLite files and never opens
`instance/phishing.db`, so it is safe to run on a machine holding real scan
history. `APP_VERSION` is now `0.13.0` and `BUILD_STAGE` is `13`. Full strategy,
coverage matrix and troubleshooting: `docs/TEST_PLAN.md`.
