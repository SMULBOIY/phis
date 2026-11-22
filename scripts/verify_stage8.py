#!/usr/bin/env python3
"""Stage 8 exit gate: SQLite/SQLAlchemy models, relationships and auth.

    cd phishing-detection-system
    python scripts/verify_stage8.py

Everything is tested against ISOLATED temporary SQLite files or in-memory
databases. The real ``instance/phishing.db`` is never touched by this gate.
All test identities and passwords are synthetic; no live URL is contacted.

The gate checks the emitted DDL (column nullability, UNIQUE, CHECK, FK
``ON DELETE SET NULL``, indexes, ``PRAGMA foreign_keys``), real CRUD and
constraint violations, scrypt hashing, registration/login/logout over both
JSON and HTML forms, the honest 503 when the schema is absent, both bootstrap
CLIs, and that ``model_information`` contains EXACTLY the measured values from
``metrics.json`` — never a typed-in statistic. It re-runs Gates 1-7.
"""
from __future__ import annotations

import contextlib
import io
import json
import logging
import re
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# Set by a parent gate (e.g. verify_stage10.py) to avoid running
# the same historical gate exponentially many times. A standalone
# run has this unset and keeps its complete regression behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

with contextlib.redirect_stderr(io.StringIO()):
    from config import DevelopmentConfig, TestingConfig, describe_config  # noqa: E402
    from app import create_app  # noqa: E402
    from extensions import db, login_manager  # noqa: E402
    from models import (  # noqa: E402
        RISK_LEVELS, ROLES, PREDICTIONS, ModelInformation, ScanHistory, User,
        iso_utc, utc_value, utcnow,
    )
    from services.auth_service import (  # noqa: E402
        MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, RegistrationError,
        authenticate, create_user, get_user_by_id, normalize_email,
        normalize_username, validate_password, validate_registration,
    )
    from services.database_service import (  # noqa: E402
        ModelDataError, TABLE_NAMES, database_status, initialise_schema,
    )
    from flask import jsonify  # noqa: E402
    from flask_login import login_required  # noqa: E402
    from sqlalchemy import inspect, text  # noqa: E402
    from sqlalchemy.exc import IntegrityError  # noqa: E402

REQUIRED_FILES = (
    "models/__init__.py", "models/database_models.py",
    "services/auth_service.py", "services/database_service.py",
    "scripts/init_db.py", "scripts/create_admin.py",
    "docs/DATABASE.md", "scripts/verify_stage8.py",
)

NEW_PY = (
    "models/__init__.py", "models/database_models.py",
    "services/auth_service.py", "services/database_service.py",
    "scripts/init_db.py", "scripts/create_admin.py",
)

METRIC_WORDS = (
    "accuracy", "precision", "recall", "f1", "roc_auc", "roc-auc",
    "confusion_matrix", "confusion matrix",
)
FORBIDDEN_NETWORK = (
    "import requests", "import socket", "import httpx", "import aiohttp",
    "urllib.request", "urlopen(", "http.client",
)
PLACEHOLDER_MARKERS = (
    "NotImplemented" + "Error", "TODO: imple" + "ment", "placeholder" + " function",
)

FORBIDDEN_NOW = (
    "models/prediction_model.py",
    "services/detection_service.py", "services/decision_service.py",
    "services/explanation_service.py", "services/stats_service.py",
    "services/report_service.py",
    "routes/scanning.py", "routes/dashboard.py", "routes/admin.py",
    "routes/api.py", "routes/history.py",
    "templates/base.html", "templates/index.html", "templates/scan.html",
    "templates/dashboard.html", "templates/history.html", "templates/admin.html",
    "static/vendor/bootstrap.min.css", "static/vendor/chart.umd.min.js",
    "static/js/main.js", "static/images/logo.svg",
    "tests/conftest.py", "tests/test_features.py",
    "docs/SECURITY.md", "docs/TEST_PLAN.md", "docs/DEPLOYMENT.md", "docs/REPORT.md",
)

STAGE_9_DELIVERED = (
    (ROOT / "templates" / "index.html").is_file()
    and (ROOT / "scripts" / "verify_stage9.py").is_file()
)

DOC_SECTIONS = (
    "## 1. What Stage 8 builds", "## 2. Entity relationship model",
    "## 3. Table definitions", "## 4. Constraints and indexes",
    "## 5. Database security", "## 6. Bootstrap and admin creation",
    "## 7. Authentication flow", "## 8. Run and test",
    "## 9. Common errors and fixes", "## 10. Stage 8 exit criteria",
)

STRONG_PASSWORD = "Str0ng!Passphrase2026"

failures: list[str] = []
checks = 0


def check(label: str, condition: bool, hint: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        failures.append(label)
        print(f"  FAIL  {label}" + (f" :: {hint}" if hint else ""))


def skip(label: str, reason: str) -> None:
    print(f"  SKIP  {label} ({reason})")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def metric_free(value: str) -> bool:
    lowered = value.lower()
    return not any(word in lowered for word in METRIC_WORDS)


def published_metrics() -> dict[str, float]:
    data = json.loads(read("ml/saved_model/metrics.json"))
    return data["test"]["standard_0.5"]


def temp_uri(folder: Path, name: str) -> str:
    return f"sqlite:///{folder / name}"


def make_app(uri: str, *, csrf: bool = False):
    return create_app(DevelopmentConfig, overrides={
        "SQLALCHEMY_DATABASE_URI": uri,
        "DEBUG": False,
        "TESTING": False,
        "PROPAGATE_EXCEPTIONS": False,
        "WTF_CSRF_ENABLED": csrf,
        "WTF_CSRF_SSL_STRICT": False,
    })


def csrf_header(client: Any) -> dict[str, str]:
    token = client.get("/auth/csrf-token").get_json()["csrf_token"]
    return {"X-CSRF-Token": token}


# --------------------------------------------------------------------------- #
# 1. Files and source contracts
# --------------------------------------------------------------------------- #
def check_files_and_sources() -> None:
    print("\n[1] Delivered files and source contracts")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"exists and non-empty :: {rel}",
              path.is_file() and path.stat().st_size > 0)

    sources = {rel: read(rel) for rel in NEW_PY}
    joined = "\n".join(sources.values())
    models_src = sources["models/database_models.py"]
    auth_src = sources["services/auth_service.py"]
    routes_src = read("routes/auth.py")

    for cls in ("class User", "class ScanHistory", "class ModelInformation"):
        check(f"ORM declares {cls}", cls in models_src)
    check("password_hash is a mapped column",
          "password_hash: Mapped[str]" in models_src)
    check("no plaintext password column",
          re.search(r"^\s*password\s*:\s*Mapped", models_src, re.MULTILINE) is None)
    check("user_id is nullable for guest scans",
          "user_id: Mapped[int | None]" in models_src
          and "nullable=True" in models_src)
    check("FK uses ON DELETE SET NULL",
          'ForeignKey("users.id", ondelete="SET NULL")' in models_src)
    check("relationship uses passive_deletes",
          "passive_deletes=True" in models_src)
    check("CheckConstraint objects exist", "CheckConstraint(" in models_src)
    check("composite (user_id, scan_date) index exists",
          'Index("ix_scan_history_user_scan_date", "user_id", "scan_date")' in models_src)
    check("UTC timestamps used", "datetime.now(timezone.utc)" in models_src)
    check("SQLite foreign keys enabled per engine",
          "PRAGMA foreign_keys=ON" in models_src)
    check("User.to_dict does not return the hash value",
          "self.password_hash" not in models_src.split("def to_dict")[1].split("def __repr__")[0])

    check("User.set_password uses scrypt",
          'generate_password_hash(password, method="scrypt")' in models_src)
    check("auth_service uses scrypt for timing equalisation",
          'method="scrypt"' in auth_src)
    check("auth_service verifies with check_password_hash",
          "check_password_hash(" in auth_src)
    check("auth_service never logs or stores plaintext",
          "print(" not in auth_src and "logger" not in auth_src)
    check("unknown-account timing equalisation present",
          "_dummy_hash" in auth_src and "check_password_hash(_dummy_hash()" in auth_src)
    check("role is validated against the ROLES tuple", "role not in ROLES" in auth_src)

    check("routes/auth.py defines /login and /register",
          '"/login"' in routes_src and '"/register"' in routes_src)
    check("login rotates the session", "session.clear()" in routes_src)
    check("self-registration forces the plain user role",
          'role="user"' in routes_src)
    check("account routes report an explicit 503 without schema",
          "DATABASE_UNAVAILABLE" in routes_src)
    check("status page health reads real schema",
          "database_status()" in read("routes/core.py"))

    check("database_service copies metrics from metrics.json",
          "metrics.json#test.standard_0.5" in sources["services/database_service.py"])
    check("database_service refuses missing artefacts",
          "ModelDataError" in sources["services/database_service.py"])
    measured = published_metrics()
    literals = [f"{value:.6f}" for value in measured.values()
                if isinstance(value, (int, float)) and 0 < value < 1]
    leaked = [value for value in literals if value in joined]
    check("no measured statistic is hard-coded in Stage 8 source",
          not leaked, ", ".join(leaked[:5]))

    for token in FORBIDDEN_NETWORK:
        check(f"no outbound-network import :: {token}", token not in joined)
    for marker in PLACEHOLDER_MARKERS:
        check(f"no placeholder marker :: {marker}", marker not in joined)
    check("no bare pass statement in Stage 8 code",
          re.search(r"^\s*pass\s*$", joined, re.MULTILINE) is None)
    check("no f-string SQL assembled from input",
          'f"SELECT' not in joined and "f'SELECT" not in joined
          and "execute(f" not in joined)
    check("backend.css styles the account forms",
          ".auth-panel" in read("static/css/backend.css"))

    summary = describe_config()
    check("config reports Stage 8 or later", summary.get("build_stage") >= 8)
    check("config version follows the stage 0.x.0 series",
          re.fullmatch(r"0\.\d+\.0", str(summary.get("app_version", ""))) is not None)


# --------------------------------------------------------------------------- #
# 2. Emitted schema
# --------------------------------------------------------------------------- #
def check_schema(folder: Path) -> tuple[str, Any]:
    print("\n[2] Emitted SQLite schema")
    uri = temp_uri(folder, "schema.db")
    app = make_app(uri)
    check("schema starts uninitialised", database_status(app)["status"] == "not_initialised")
    result = initialise_schema(app)
    check("create_all produced exactly the three tables",
          set(result["tables"]) == set(TABLE_NAMES), ", ".join(result["tables"]))
    check("bootstrap seeded one model audit row",
          result["seeded"]["row_count"] == 1)

    with app.app_context():
        inspector = inspect(db.engine)
        users = {c["name"]: c for c in inspector.get_columns("users")}
        scans = {c["name"]: c for c in inspector.get_columns("scan_history")}
        model = {c["name"]: c for c in inspector.get_columns("model_information")}

        for column in ("id", "username", "email", "password_hash", "role",
                       "active", "created_at", "last_login_at"):
            check(f"users.{column} exists", column in users)
        check("users.password_hash is NOT NULL",
              users["password_hash"]["nullable"] is False)
        check("users.username is NOT NULL and unique",
              users["username"]["nullable"] is False
              and any(i["column_names"] == ["username"] and i["unique"]
                      for i in inspector.get_indexes("users")))
        check("users.email is NOT NULL and unique",
              users["email"]["nullable"] is False
              and any(i["column_names"] == ["email"] and i["unique"]
                      for i in inspector.get_indexes("users")))

        for column in ("id", "user_id", "url", "normalised_url", "prediction",
                       "model_score", "risk_level", "model_version", "scan_date",
                       "features_json"):
            check(f"scan_history.{column} exists", column in scans)
        check("scan_history.user_id IS NULL-able", scans["user_id"]["nullable"] is True)
        fks = inspector.get_foreign_keys("scan_history")
        check("FK targets users.id", any(
            fk["referred_table"] == "users" and fk["constrained_columns"] == ["user_id"]
            for fk in fks))
        check("FK declares ON DELETE SET NULL", any(
            fk.get("options", {}).get("ondelete") == "SET NULL" for fk in fks))
        idx = {i["name"]: i for i in inspector.get_indexes("scan_history")}
        for name in ("ix_scan_history_prediction", "ix_scan_history_scan_date",
                     "ix_scan_history_user_id", "ix_scan_history_user_scan_date"):
            check(f"index {name} exists", name in idx)
        check("composite index covers (user_id, scan_date)",
              idx.get("ix_scan_history_user_scan_date", {}).get("column_names")
              == ["user_id", "scan_date"])

        for column in ("model_name", "model_version", "training_date", "accuracy",
                       "precision", "recall", "f1_score", "roc_auc",
                       "dataset_fingerprint", "feature_count", "metrics_source"):
            check(f"model_information.{column} exists", column in model)
        check("model_information version is unique",
              any(i["unique"] for i in inspector.get_indexes("model_information")))

        ddl = {
            row[0]: row[1]
            for row in db.session.execute(text(
                "SELECT name, sql FROM sqlite_master WHERE type='table'"
            )).all()
        }
        for table in TABLE_NAMES:
            check(f"{table} DDL contains CHECK constraints",
                  "CHECK" in (ddl.get(table) or ""))
        check("prediction constrained to the three states",
              "'LEGITIMATE', 'SUSPICIOUS', 'PHISHING'" in ddl["scan_history"])
        check("risk_level constrained to LOW/MEDIUM/HIGH",
              "'LOW', 'MEDIUM', 'HIGH'" in ddl["scan_history"])
        check("model_score constrained to [0,1]",
              "model_score >= 0.0" in ddl["scan_history"])
        check("URL length constrained to 2048",
              "length(url) <= 2048" in ddl["scan_history"])
        check("role constrained to user/admin",
              "'user', 'admin'" in ddl["users"])

        fk_enabled = db.session.execute(text("PRAGMA foreign_keys")).scalar()
        check("PRAGMA foreign_keys is ON", bool(fk_enabled))
    return uri, app


# --------------------------------------------------------------------------- #
# 3. ORM behaviour, constraints and relationships
# --------------------------------------------------------------------------- #
def check_orm(folder: Path, uri: str, app: Any) -> None:
    print("\n[3] ORM behaviour, constraints and relationships")
    with app.app_context():
        user = User(username="alice", email="Alice@Example.com", role="user", active=True)
        user.set_password(STRONG_PASSWORD)
        db.session.add(user)
        check("hash uses scrypt", user.password_hash.startswith("scrypt:"))
        check("plaintext is not in the hash", STRONG_PASSWORD not in user.password_hash)
        check("check_password accepts the right password",
              user.check_password(STRONG_PASSWORD))
        check("check_password rejects a wrong password",
              not user.check_password("Wrong!Passphrase2026"))
        check("to_dict never serialises password_hash",
              "password_hash" not in user.to_dict())
        check("is_admin is false for a plain user", user.is_admin is False)
        check("is_active follows the active column", user.is_active is True)
        db.session.commit()
        check("UserMixin.get_id returns the persisted string id",
              user.id is not None and user.get_id() == str(user.id))

        # Duplicate constraints.
        for label, values in (
            ("duplicate username", {"username": "alice", "email": "other@example.com"}),
            ("duplicate email", {"username": "other", "email": "Alice@Example.com"}),
        ):
            duplicate = User(role="user", active=True, **values)
            duplicate.set_password(STRONG_PASSWORD)
            db.session.add(duplicate)
            try:
                db.session.commit()
                check(f"{label} is rejected", False, "commit succeeded")
            except IntegrityError:
                db.session.rollback()
                check(f"{label} is rejected", True)

        bad_role = User(username="rogue", email="rogue@example.com", role="superuser", active=True)
        bad_role.set_password(STRONG_PASSWORD)
        db.session.add(bad_role)
        try:
            db.session.commit()
            check("invalid role is rejected by CHECK", False, "commit succeeded")
        except IntegrityError:
            db.session.rollback()
            check("invalid role is rejected by CHECK", True)

        # Registered and guest scans.
        registered = ScanHistory(
            user_id=user.id, url="https://example.com/login",
            normalised_url="https://example.com/login", prediction="SUSPICIOUS",
            model_score=0.55, risk_level="MEDIUM", model_version="1.0.0",
        )
        guest = ScanHistory(
            user_id=None, url="http://guest.example/path",
            normalised_url="http://guest.example/path", prediction="LEGITIMATE",
            model_score=0.01, risk_level="LOW", model_version="1.0.0",
        )
        db.session.add_all([registered, guest])
        db.session.commit()
        check("guest scan persists with NULL user_id", guest.user_id is None)
        check("registered scan links to the user", registered.user_id == user.id)
        check("User.scans relationship works", len(user.scans) == 1)
        check("ScanHistory.user relationship works", registered.user.id == user.id)
        check("scan_date is UTC-aware after normalisation",
              utc_value(registered.scan_date).tzinfo is not None)
        check("iso_utc renders an ISO-8601 string",
              (iso_utc(registered.scan_date) or "").endswith("+00:00"))

        invalid_rows = (
            ("invalid prediction", {"prediction": "MAYBE"}),
            ("invalid risk level", {"risk_level": "CRITICAL"}),
            ("score above 1", {"model_score": 1.5}),
            ("score below 0", {"model_score": -0.1}),
            ("over-long URL", {"url": "x" * 2049}),
        )
        for label, overrides in invalid_rows:
            values = dict(
                url="https://example.com", normalised_url="https://example.com",
                prediction="PHISHING", model_score=0.9, risk_level="HIGH",
                model_version="1.0.0", user_id=None,
            )
            values.update(overrides)
            db.session.add(ScanHistory(**values))
            try:
                db.session.commit()
                check(f"{label} is rejected", False, "commit succeeded")
            except IntegrityError:
                db.session.rollback()
                check(f"{label} is rejected", True)

        saved_scan_id = registered.id
        db.session.delete(user)
        db.session.commit()
        db.session.expire_all()
        check("deleting a user preserves their scan history",
              db.session.get(ScanHistory, saved_scan_id) is not None)
        check("ON DELETE SET NULL cleared the FK",
              db.session.get(ScanHistory, saved_scan_id).user_id is None)
        check("guest scan is untouched by user deletion",
              db.session.get(ScanHistory, guest.id).user_id is None)

        # Keep one live account so the on-disk hash check is deterministic.
        keeper = User(username="keeper", email="keeper@example.com",
                      role="user", active=True)
        keeper.set_password(STRONG_PASSWORD)
        db.session.add(keeper)
        db.session.commit()

        existing = db.session.query(ModelInformation).one()
        duplicate_model = ModelInformation(
            model_name=existing.model_name, model_version=existing.model_version,
            training_date=utcnow(), dataset_fingerprint="0" * 64,
            feature_count=15, metrics_source="duplicate",
        )
        db.session.add(duplicate_model)
        try:
            db.session.commit()
            check("duplicate model version is rejected", False, "commit succeeded")
        except IntegrityError:
            db.session.rollback()
            check("duplicate model version is rejected", True)

    raw = (folder / "schema.db").read_bytes()
    check("plaintext password does not appear in the database file",
          STRONG_PASSWORD.encode() not in raw)
    check("scrypt hash does appear in the database file", b"scrypt:" in raw)


# --------------------------------------------------------------------------- #
# 4. Auth service
# --------------------------------------------------------------------------- #
def check_auth_service(folder: Path) -> None:
    print("\n[4] Authentication service")
    app = make_app(temp_uri(folder, "service.db"))
    initialise_schema(app)

    check("normalize_username trims", normalize_username("  Alice  ") == "Alice")
    check("normalize_email lower-cases and trims",
          normalize_email("  Alice@Example.COM ") == "alice@example.com")
    check("strong password passes the policy",
          validate_password(STRONG_PASSWORD) == [])
    for label, value in (
        ("short", "Ab1!"),
        ("no uppercase", "strongpass!2026"),
        ("no digit", "StrongPassphrase!"),
        ("no symbol", "StrongPassphrase2026"),
        ("common", "Password123!"),
        ("over-long", "A1!" + "a" * MAX_PASSWORD_LENGTH),
    ):
        check(f"weak password rejected :: {label}",
              bool(validate_password(value)))
    check("password equal to username is rejected",
          bool(validate_password("aliceexample", username="aliceexample")))
    check("MIN_PASSWORD_LENGTH is 12", MIN_PASSWORD_LENGTH == 12)

    clean_user, clean_mail, problems = validate_registration(
        "  Bob_1 ", " BOB@Example.COM ", STRONG_PASSWORD
    )
    check("registration normalises valid input",
          clean_user == "Bob_1" and clean_mail == "bob@example.com" and not problems)
    _, _, bad = validate_registration("a!", "not-an-email", "weak")
    check("registration rejects bad username/email/password", len(bad) >= 3)
    check("registration error text never contains the password",
          all(STRONG_PASSWORD not in item for item in bad))

    with app.app_context():
        bob = create_user("Bob_1", "BOB@Example.COM", STRONG_PASSWORD)
        check("create_user stores a scrypt hash", bob.password_hash.startswith("scrypt:"))
        check("create_user assigns role='user'", bob.role == "user")
        check("create_user lower-cases the email", bob.email == "bob@example.com")
        check("create_user never exposes password_hash in to_dict",
              "password_hash" not in bob.to_dict())
        try:
            create_user("bob_1", "different@example.com", STRONG_PASSWORD)
            check("duplicate registration raises RegistrationError", False)
        except RegistrationError as exc:
            check("duplicate registration raises RegistrationError",
                  "already registered" in str(exc))
        try:
            create_user("carol", "carol@example.com", "weak")
            check("weak-password registration raises RegistrationError", False)
        except RegistrationError:
            check("weak-password registration raises RegistrationError", True)

        check("authenticate by username", authenticate("Bob_1", STRONG_PASSWORD) is not None)
        check("authenticate by email, case-insensitive",
              authenticate("BOB@EXAMPLE.COM", STRONG_PASSWORD) is not None)
        check("wrong password fails", authenticate("Bob_1", "NotThePassword!2026") is None)
        check("unknown account fails", authenticate("nobody", STRONG_PASSWORD) is None)
        check("non-string identifier fails", authenticate(None, STRONG_PASSWORD) is None)
        bob.active = False
        db.session.commit()
        check("disabled account cannot authenticate",
              authenticate("Bob_1", STRONG_PASSWORD) is None)
        check("get_user_by_id refuses a disabled account",
              get_user_by_id(bob.id) is None)
        bob.active = True
        db.session.commit()
        check("get_user_by_id resolves an active account",
              get_user_by_id(bob.id) is not None)
        for bad_id in ("not-a-number", None, "-4", "0", 10**9):
            check(f"get_user_by_id fails closed for {bad_id!r}",
                  get_user_by_id(bad_id) is None)

    check("PREDICTIONS exactly matches the UI contract",
          PREDICTIONS == ("LEGITIMATE", "SUSPICIOUS", "PHISHING"))
    check("RISK_LEVELS exactly matches the UI contract",
          RISK_LEVELS == ("LOW", "MEDIUM", "HIGH"))
    check("ROLES has no unexpected values", ROLES == ("user", "admin"))


# --------------------------------------------------------------------------- #
# 5. Auth routes
# --------------------------------------------------------------------------- #
def check_routes(folder: Path) -> None:
    print("\n[5] Authentication routes (JSON, HTML forms, CSRF, failures)")
    app = make_app(temp_uri(folder, "routes.db"), csrf=True)
    initialise_schema(app)

    with app.test_client() as client:
        for path, marker in (("/login", "SIGN IN"), ("/register", "CREATE AN ACCOUNT")):
            page = client.get(path)
            check(f"GET {path} serves a real form",
                  page.status_code == 200 and b'name="csrf_token"' in page.data
                  and marker.encode() in page.data)
        check("login form never embeds a password",
              STRONG_PASSWORD.encode() not in client.get("/login").data)

        bare = client.post("/register", json={
            "username": "dave", "email": "dave@example.com", "password": STRONG_PASSWORD,
        })
        check("POST without CSRF token is rejected",
              bare.status_code == 400 and bare.get_json()["error"]["code"] == "CSRF_FAILED")

        headers = csrf_header(client)
        created = client.post("/register", json={
            "username": "dave", "email": "dave@example.com",
            "password": STRONG_PASSWORD, "role": "admin",
        }, headers=headers)
        check("POST /register returns 201", created.status_code == 201)
        body = created.get_json()
        check("registration does NOT auto-authenticate",
              body["authenticated"] is False)
        check("registration response has no password_hash",
              "password_hash" not in body["user"])
        check("self-registration cannot escalate to admin",
              body["user"]["role"] == "user")
        check("password is never echoed in the response",
              STRONG_PASSWORD not in json.dumps(body))

        duplicate = client.post("/register", json={
            "username": "dave", "email": "other@example.com", "password": STRONG_PASSWORD,
        }, headers=csrf_header(client))
        check("duplicate registration returns 400 with a generic code",
              duplicate.status_code == 400
              and duplicate.get_json()["error"]["code"] == "INVALID_REGISTRATION")
        weak = client.post("/register", json={
            "username": "eve", "email": "eve@example.com", "password": "weak",
        }, headers=csrf_header(client))
        check("weak password returns 400 with policy details",
              weak.status_code == 400 and len(weak.get_json()["error"]["details"]) > 0)
        check("weak-password error never echoes the password",
              "weak" not in json.dumps(weak.get_json()["error"]["details"]))

        bad_login = client.post("/login", json={
            "username": "dave", "password": "Wrong!Passphrase2026",
        }, headers=csrf_header(client))
        check("wrong password returns 401 UNAUTHENTICATED",
              bad_login.status_code == 401
              and bad_login.get_json()["error"]["code"] == "UNAUTHENTICATED")
        check("login failure does not echo the submitted password",
              "Wrong!Passphrase2026" not in json.dumps(bad_login.get_json()))

        good = client.post("/login", json={
            "username": "DAVE@EXAMPLE.COM", "password": STRONG_PASSWORD,
        }, headers=csrf_header(client))
        check("login by email (case-insensitive) returns 200", good.status_code == 200)
        check("login response reports authenticated=True",
              good.get_json()["authenticated"] is True)
        check("login response has no password_hash",
              "password_hash" not in good.get_json()["user"])
        state = client.get("/auth/session").get_json()
        check("session is authenticated after login", state["authenticated"] is True)
        check("session reports the user id", state["user_id"] is not None)
        check("session reports both auth routes", state["login_available"]
              and state["register_available"])
        check("session reports SQLite persistence",
              state["user_persistence"] == "sqlite")
        check("session response has no password_hash",
              "password_hash" not in state["user"])

        out = client.post("/logout", headers=csrf_header(client))
        check("logout clears the session",
              out.status_code == 200 and out.get_json()["logged_out"] is True)
        check("session is anonymous after logout",
              client.get("/auth/session").get_json()["authenticated"] is False)

        # Ordinary HTML form POST (no JS, no inline script, so CSP stays strict).
        html = client.get("/register").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        form_result = client.post("/register", data={
            "username": "frank", "email": "frank@example.com",
            "password": STRONG_PASSWORD, "confirm_password": STRONG_PASSWORD,
            "csrf_token": token,
        })
        check("HTML form registration returns 201 HTML",
              form_result.status_code == 201 and b"Account created" in form_result.data)
        mismatch = client.post("/register", data={
            "username": "grace", "email": "grace@example.com",
            "password": STRONG_PASSWORD, "confirm_password": "Different!2026",
            "csrf_token": token,
        })
        check("mismatched confirmation is rejected",
              mismatch.status_code == 400 and b"do not match" in mismatch.data)

        health = client.get("/health")
        payload = health.get_json()
        check("/health reports ready schema", payload["database"]["status"] == "ready")
        check("/health reports accurate user count",
              payload["database"]["counts"]["users"] == 2)
        check("/health contains no performance figures",
              metric_free(json.dumps(payload)))
        index = client.get("/")
        check("status page shows READY", b"READY" in index.data)
        check("status page still has no SCAN WEBSITE button",
              b"SCAN WEBSITE" not in index.data)
        check("status page contains no performance figures",
              metric_free(index.get_data(as_text=True)))

    check("login_manager.login_view points at the real route",
          login_manager.login_view == "auth.login")

    # Deliberately uninitialised schema -> explicit 503, not a hidden 500.
    empty_app = create_app(TestingConfig)
    with empty_app.test_client() as client:
        blocked = client.post("/login", json={
            "username": "dave", "password": STRONG_PASSWORD,
        })
        check("login without schema returns 503 DATABASE_UNAVAILABLE",
              blocked.status_code == 503
              and blocked.get_json()["error"]["code"] == "DATABASE_UNAVAILABLE")
        blocked_register = client.post("/register", json={
            "username": "dave", "email": "dave@example.com", "password": STRONG_PASSWORD,
        })
        check("register without schema returns 503 DATABASE_UNAVAILABLE",
              blocked_register.status_code == 503
              and blocked_register.get_json()["error"]["code"] == "DATABASE_UNAVAILABLE")
        check("logout still works without schema",
              client.post("/logout").status_code == 200)

    # @login_required still uses the documented 401 error contract.
    authz = create_app(TestingConfig)

    @authz.route("/_protected")
    @login_required
    def _protected() -> Any:
        return jsonify({"ok": True})

    with authz.test_client() as client:
        denied = client.get("/_protected")
        check("@login_required still yields 401 UNAUTHENTICATED",
              denied.status_code == 401 and b"UNAUTHENTICATED" in denied.data)


# --------------------------------------------------------------------------- #
# 6. Bootstrap CLIs and measured seeding
# --------------------------------------------------------------------------- #
def check_clis(folder: Path) -> None:
    print("\n[6] Bootstrap CLIs and measured model information")
    uri = temp_uri(folder, "cli.db")

    def run(script: str, *args: str) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script), *args],
            capture_output=True, text=True, timeout=90, cwd=ROOT,
        )
        return proc.returncode, proc.stdout + proc.stderr

    code, out = run("init_db.py", "--database-uri", uri, "--verify-only", "--json")
    check("init_db --verify-only reports uninitialised (exit 1)",
          code == 1 and "not_initialised" in out)
    check("init_db --verify-only writes no tables",
          "not_initialised" in out and '"tables": []' in out)

    code, out = run("init_db.py", "--database-uri", uri, "--json")
    check("init_db creates the schema (exit 0)", code == 0 and '"status": "ready"' in out)
    code, out = run("init_db.py", "--database-uri", uri, "--json")
    check("init_db is idempotent", code == 0 and '"model_information": 1' in out)
    code, out = run("init_db.py", "--database-uri", uri, "--reset")
    check("init_db refuses --reset without --yes", code != 0)

    app = make_app(uri)
    with app.app_context():
        rows = db.session.query(ModelInformation).all()
        check("exactly one model audit row exists", len(rows) == 1)
        row = rows[0]
        measured = published_metrics()
        for source_key, column in (
            ("accuracy", "accuracy"), ("precision", "precision"),
            ("recall", "recall"), ("f1", "f1_score"), ("roc_auc", "roc_auc"),
        ):
            check(f"stored {column} equals measured metrics.json",
                  getattr(row, column) == measured[source_key],
                  f"{getattr(row, column)} vs {measured[source_key]}")
        metadata = json.loads(read("ml/saved_model/metadata.json"))
        check("stored model name/version come from metadata.json",
              row.model_name == metadata["model_name"]
              and row.model_version == metadata["model_version"])
        check("stored feature count is 15", row.feature_count == 15)
        check("dataset fingerprint is a SHA-256 digest",
              re.fullmatch(r"[0-9a-f]{64}", row.dataset_fingerprint) is not None)
        check("metrics_source names the measured artefact",
              "metrics.json" in row.metrics_source)
        check("no user account is created by init_db",
              db.session.query(User).count() == 0)
        check("training_date is UTC-aware after normalisation",
              utc_value(row.training_date).tzinfo is not None)

    code, out = run("create_admin.py", "--database-uri", uri, "--verify-only")
    check("create_admin --verify-only reports zero admins", code == 0 and '"admins": 0' in out)
    code, out = run("create_admin.py", "--database-uri", uri,
                    "--username", "auditor", "--email", "auditor@example.com",
                    "--password", "weak")
    check("create_admin refuses a weak password", code != 0 and "ERROR" in out)
    code, out = run("create_admin.py", "--database-uri", uri, "--verify-only")
    check("no admin was created by the failed attempt", '"admins": 0' in out)

    admin_password = "Adm1n!Passphrase2026"
    code, out = run("create_admin.py", "--database-uri", uri,
                    "--username", "auditor", "--email", "auditor@example.com",
                    "--password", admin_password)
    check("create_admin creates one admin (exit 0)", code == 0 and "Administrator created" in out)
    check("create_admin never echoes the password", admin_password not in out)
    with app.app_context():
        admin = db.session.query(User).filter_by(username="auditor").one()
        check("admin has role='admin'", admin.role == "admin" and admin.is_admin)
        check("admin password is a scrypt hash", admin.password_hash.startswith("scrypt:"))
        check("admin password verifies",
              admin.check_password(admin_password))
        check("admin to_dict hides the hash", "password_hash" not in admin.to_dict())
    check("admin plaintext is absent from the DB file",
          admin_password.encode() not in (folder / "cli.db").read_bytes())
    code, out = run("create_admin.py", "--database-uri", uri, "--verify-only")
    check("create_admin --verify-only reports one admin", '"admins": 1' in out)


# --------------------------------------------------------------------------- #
# 7. Documentation, stage discipline, regressions
# --------------------------------------------------------------------------- #
def check_docs_and_discipline() -> None:
    print("\n[7] Documentation, stage discipline and regressions")
    database = read("docs/DATABASE.md")
    for section in DOC_SECTIONS:
        check(f"DATABASE.md :: {section}", section in database)
    check("DATABASE.md states guest scans are preserved",
          "guest" in database.lower() and "SET NULL" in database)
    check("DATABASE.md forbids plaintext passwords",
          "plaintext" in database.lower())
    check("README marks Stage 8 complete",
          re.search(r"\|\s*8\s*\|.*✅", read("README.md")) is not None)
    check("STAGE_PLAN records Stage 8 as delivered",
          "Stage 8 — delivered" in read("docs/STAGE_PLAN.md"))
    for adr in ("ADR-026", "ADR-027"):
        check(f"DECISIONS.md contains {adr}", adr in read("docs/DECISIONS.md"))
    check("ARCHITECTURE.md has a Stage 8 implementation note",
          "Stage 8 implementation note" in read("docs/ARCHITECTURE.md"))
    example = read(".env.example")
    for key in ("ADMIN_USERNAME", "ADMIN_EMAIL", "ADMIN_PASSWORD"):
        check(f".env.example documents {key}", f"{key}=" in example)
    check(".env.example ships an empty admin password",
          re.search(r"^ADMIN_PASSWORD=\s*$", example, re.MULTILINE) is not None)

    if not STAGE_9_DELIVERED:
        for rel in FORBIDDEN_NOW:
            check(f"not created yet :: {rel}", not (ROOT / rel).exists())
        expected = {
            "ml": {"__init__.py", "url_utils.py", "preprocess.py",
                   "feature_extraction.py", "train_model.py",
                   "evaluate_model.py", "thresholds.py"},
            "models": {"__init__.py", "database_models.py"},
            "services": {"__init__.py", "validation.py", "model_metadata.py",
                         "http_security.py", "auth_service.py", "database_service.py"},
            "routes": {"__init__.py", "core.py", "auth.py"},
            "tests": set(), "templates": set(),
        }
        for directory, names in expected.items():
            stray = [p.name for p in (ROOT / directory).glob("*.py") if p.name not in names]
            check(f"{directory}/ contains only Stage 1-8 modules", not stray,
                  ", ".join(stray))
        root_py = {p.name for p in ROOT.glob("*.py")}
        check("project root contains only Stage 1-8 Python modules",
              root_py <= {"config.py", "app.py", "wsgi.py", "extensions.py"},
              ", ".join(sorted(root_py)))
    else:
        skip("no Stage 9+ code yet", "delivered in Stage 9; enforced by verify_stage9.py")

    for gate in ("verify_stage1.py", "verify_stage2.py", "verify_stage3.py",
                 "verify_stage4.py", "verify_stage5.py", "verify_stage6.py",
                 "verify_stage7.py"):
        # The top-level gate already executes every historical gate directly.
        # Skipping this duplicated nested re-run keeps the suite linear rather
        # than exponential; standalone runs are completely unaffected.
        if PDS_NESTED_GATES:
            print(f"  SKIP  nested regression {gate} (top-level gate runs it)")
            continue
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / gate)],
            capture_output=True, text=True, timeout=400, cwd=ROOT,
        )
        tail = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
        check(f"{gate} still passes", proc.returncode == 0,
              tail[-1] if tail else "no output")


def main() -> int:
    logging.disable(logging.CRITICAL)
    print("=" * 78)
    print("STAGE 8 EXIT GATE - ORM models, relationships, authentication and bootstrap")
    print(f"Project root : {ROOT}")
    print("=" * 78)
    check_files_and_sources()
    folder = Path(tempfile.mkdtemp(prefix="stage8-"))
    try:
        uri, app = check_schema(folder)
        check_orm(folder, uri, app)
        check_auth_service(folder)
        check_routes(folder)
        check_clis(folder)
    finally:
        for item in folder.iterdir():
            item.unlink()
        folder.rmdir()
    check_docs_and_discipline()
    print("\n" + "=" * 78)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        return 1
    print(f"RESULT: PASS - all {checks} checks passed")
    print("Stage 8 exit gate satisfied. You may proceed to Stage 9.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
