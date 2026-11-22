# Verified Environment Record

**Generated:** 2026-11-03 (Stage 2)
**Purpose:** an auditable record of the exact interpreter and library versions used
to verify Stage 2. Reproduce it with `python -m pip install -r requirements.txt`.

Every interpreter version, package version and wheel-availability result below was
produced by commands executed in this workspace. Nothing here was estimated or invented.

## Interpreter used for verification

| Item | Value |
| --- | --- |
| Python | `3.13.16` |
| Implementation | `CPython` |
| Platform | `Linux-6.1.158+-x86_64-with-glibc2.41` |
| Machine | `x86_64` |
| Executable | `/home/user/phishing-detection-system/.venv/bin/python` |
| Recommended on Windows | Python 3.12 or 3.13, 64-bit |

`python -m pip check` exit code: **0**
Output: `No broken requirements found.`

## Wheel availability of every pinned requirement

Method: for each pin and each target interpreter,

```
python -m pip install --dry-run --ignore-installed --no-deps \
    --only-binary=:all: --target <temp> --python-version X.Y <pin>
```

`OK` means a prebuilt wheel exists, so no C/C++ compiler is required on the
student's machine. Failures: **0** of 84 checks.

| Pinned requirement | Python 3.10 | 3.11 | 3.12 | 3.13 |
| --- | --- | --- | --- | --- |
| `Flask==3.1.3` | OK | OK | OK | OK |
| `Werkzeug==3.1.9` | OK | OK | OK | OK |
| `Jinja2==3.1.6` | OK | OK | OK | OK |
| `itsdangerous==2.2.0` | OK | OK | OK | OK |
| `click==8.5.0` | OK | OK | OK | OK |
| `blinker==1.9.0` | OK | OK | OK | OK |
| `Flask-SQLAlchemy==3.1.1` | OK | OK | OK | OK |
| `SQLAlchemy==2.0.55` | OK | OK | OK | OK |
| `Flask-WTF==1.3.0` | OK | OK | OK | OK |
| `WTForms==3.2.2` | OK | OK | OK | OK |
| `email-validator==2.3.0` | OK | OK | OK | OK |
| `Flask-Login==0.6.3` | OK | OK | OK | OK |
| `Flask-Limiter==3.12` | OK | OK | OK | OK |
| `limits==3.14.1` | OK | OK | OK | OK |
| `python-dotenv==1.2.4` | OK | OK | OK | OK |
| `numpy==2.2.6` | OK | OK | OK | OK |
| `pandas==2.3.3` | OK | OK | OK | OK |
| `scikit-learn==1.6.1` | OK | OK | OK | OK |
| `joblib==1.5.3` | OK | OK | OK | OK |
| `pytest==9.0.3` | OK | OK | OK | OK |
| `waitress==3.0.2` | OK | OK | OK | OK |

## Full dependency snapshot (`python -m pip freeze --all`)

```
blinker==1.9.0
click==8.5.0
Deprecated==3.0.1
dnspython==2.9.1
email-validator==2.3.0
Flask==3.1.3
Flask-Limiter==3.12
Flask-Login==0.6.3
Flask-SQLAlchemy==3.1.1
Flask-WTF==1.3.0
greenlet==3.5.6
idna==3.20
iniconfig==2.3.1
itsdangerous==2.2.0
Jinja2==3.1.6
joblib==1.5.3
limits==3.14.1
markdown-it-py==4.2.0
MarkupSafe==3.0.4
mdurl==0.1.2
numpy==2.2.6
ordered-set==4.1.0
packaging==24.2
pandas==2.3.3
pip==26.3
pluggy==1.7.0
Pygments==2.21.0
pytest==9.0.3
python-dateutil==4.0.0
python-dotenv==1.2.4
pytz==2026.6
rich==13.9.4
scikit-learn==1.6.1
scipy==1.18.1
SQLAlchemy==2.0.55
threadpoolctl==3.7.0
typing_extensions==4.16.0
tzdata==2026.6
waitress==3.0.2
Werkzeug==3.1.9
wrapt==2.5.2
WTForms==3.2.2
```

## Notes for the report

* Pinning exact versions makes the Machine Learning results reproducible; record
  this table in the "System Implementation" chapter.
* Your Windows venv may resolve a different transitive build (for example a
  platform-specific `MarkupSafe` wheel). Run
  `python -m pip freeze > my_environment.txt` locally and keep it with your
  project files if your supervisor asks for a local environment record.
* No dataset, trained model, database file or measured accuracy figure exists at
  Stage 2. Model metrics will be recorded in `ml/saved_model/metrics.json` in Stage 6.
