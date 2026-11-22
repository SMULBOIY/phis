#!/usr/bin/env python3
"""Create ONE administrator account interactively (Stage 8).

    python scripts/create_admin.py                    # prompts for a password
    python scripts/create_admin.py --verify-only      # report admin count only
    python scripts/create_admin.py --username auditor --email me@example.edu
    python scripts/create_admin.py --promote         # promote an existing account

Password source, in order: ``--password`` (discouraged: shell history),
``ADMIN_PASSWORD`` from the environment/.env, then an interactive
``getpass`` prompt. A weak or empty password is REFUSED. The password is never
printed, logged, written to a file or stored in plaintext — only a scrypt hash
goes into ``users.password_hash``.

``scripts/init_db.py`` never creates an account, so a fresh database has zero
users and zero default credentials.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import func

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from config import get_config  # noqa: E402
from extensions import db  # noqa: E402
from models.database_models import User  # noqa: E402
from services.auth_service import (  # noqa: E402
    RegistrationError, create_user, validate_password,
)
from services.database_service import database_status  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bootstrap one administrator for the phishing detection system."
    )
    parser.add_argument("--username", default=None)
    parser.add_argument("--email", default=None)
    parser.add_argument("--password", default=None,
                        help="Discouraged: command-line arguments may be visible in shell history.")
    parser.add_argument("--verify-only", action="store_true",
                        help="Report how many admins exist; write nothing.")
    parser.add_argument("--promote", action="store_true",
                        help="Promote an existing account with this username instead of failing.")
    parser.add_argument("--database-uri", default=None)
    return parser


def _resolve_password(cli_value: str | None) -> str:
    if cli_value:
        print("WARNING: a --password argument may be recorded in shell history.",
              file=sys.stderr)
        return cli_value
    from_environment = os.environ.get("ADMIN_PASSWORD", "").strip()
    if from_environment:
        print("Using ADMIN_PASSWORD from the environment.", file=sys.stderr)
        return from_environment
    if not sys.stdin.isatty():
        raise RuntimeError(
            "No password supplied. Set ADMIN_PASSWORD, pass --password, or run "
            "this script in an interactive terminal."
        )
    first = getpass.getpass("New admin password: ")
    second = getpass.getpass("Confirm admin password: ")
    if first != second:
        raise RuntimeError("The two passwords do not match.")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    overrides: dict[str, Any] = {}
    if args.database_uri:
        overrides["SQLALCHEMY_DATABASE_URI"] = args.database_uri
    app = create_app(get_config(), overrides=overrides or None)

    with app.app_context():
        status = database_status(app)
        if args.verify_only:
            admins = (
                db.session.query(User).filter_by(role="admin").count()
                if status["status"] == "ready" else 0
            )
            print(json.dumps({"schema": status["status"], "admins": admins}, indent=2))
            return 0
        if status["status"] != "ready":
            print("ERROR: schema is not ready. Run: python scripts/init_db.py",
                  file=sys.stderr)
            return 2

        username = (args.username or os.environ.get("ADMIN_USERNAME") or "admin").strip()
        email = (args.email or os.environ.get("ADMIN_EMAIL") or "admin@example.com").strip()
        try:
            password = _resolve_password(args.password)
            problems = validate_password(password, username=username, email=email)
            if problems:
                raise RegistrationError(" ".join(problems))
        except (RuntimeError, RegistrationError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

        existing = db.session.query(User).filter(
            func.lower(User.username) == username.lower()
        ).first()
        if existing is not None and not args.promote:
            print("ERROR: that username already exists. Use --promote to update it.",
                  file=sys.stderr)
            return 2

        try:
            if existing is not None and args.promote:
                existing.role = "admin"
                existing.active = True
                existing.email = email.lower()
                existing.set_password(password)
                db.session.commit()
                action, user = "promoted", existing
            else:
                user = create_user(username, email, password, role="admin")
                action = "created"
        except RegistrationError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

        # Only safe, public fields are printed. No hash, no password.
        print(f"Administrator {action}: {user.to_dict()['username']} "
              f"(id={user.id}, role={user.role})")
        print("Password stored as a scrypt hash only.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
