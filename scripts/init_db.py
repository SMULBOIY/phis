#!/usr/bin/env python3
"""Create the SQLite schema and seed the measured model audit row (Stage 8).

    python scripts/init_db.py                 # create/refresh schema
    python scripts/init_db.py --verify-only  # report status, write nothing
    python scripts/init_db.py --reset --yes  # DESTRUCTIVE: drop then recreate
    python scripts/init_db.py --database-uri sqlite:///C:/abs/path/test.db

Booting a Flask app deliberately does NOT create tables. This explicit step is
the standard deployment pattern and keeps tests free of side effects. It also
copies the five MEASURED held-out test metrics from ``metrics.json`` into
``model_information``; if those artefacts are missing or inconsistent the run
fails rather than inserting fabricated numbers.

No user account is created here. Use ``scripts/create_admin.py`` afterwards.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from config import get_config  # noqa: E402
from services.database_service import (  # noqa: E402
    ModelDataError, database_status, initialise_schema,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Initialise the phishing detection SQLite database."
    )
    parser.add_argument(
        "--verify-only", action="store_true",
        help="Report schema status without writing anything; exit 1 if not ready.",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Drop all tables before recreating them (requires --yes).",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="Confirm a destructive --reset.",
    )
    parser.add_argument(
        "--database-uri", default=None,
        help="Override SQLALCHEMY_DATABASE_URI (use an ABSOLUTE SQLite path).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print the final status as JSON only.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.reset and not args.yes:
        parser.error("--reset is destructive and requires --yes")
    if args.reset and args.verify_only:
        parser.error("--verify-only cannot be combined with --reset")

    overrides: dict[str, Any] = {}
    if args.database_uri:
        overrides["SQLALCHEMY_DATABASE_URI"] = args.database_uri
    app = create_app(get_config(), overrides=overrides or None)

    try:
        if args.verify_only:
            status = database_status(app)
            print(json.dumps(status, indent=2))
            if not args.json:
                print(f"schema status: {status['status']}")
            return 0 if status["status"] == "ready" else 1

        if args.reset:
            print("WARNING: dropping all tables (--reset --yes).", file=sys.stderr)
        result = initialise_schema(app, drop=args.reset)
        status = database_status(app)
    except ModelDataError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(
            "Regenerate the Stage 5/6 artefacts with: python -m ml.train_model "
            "then python -m ml.evaluate_model", file=sys.stderr,
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI must report, never traceback
        print(f"ERROR: database initialisation failed ({type(exc).__name__})", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(status, indent=2))
        return 0
    print("Database initialised successfully.")
    print(f"  tables : {', '.join(status['tables'])}")
    print(f"  status : {status['status']}")
    print(f"  counts : {json.dumps(status['counts'])}")
    print(f"  foreign keys enabled : {status['foreign_keys_enabled']}")
    print(f"  model  : {result['seeded']['model_name']} v{result['seeded']['model_version']} "
          f"({'inserted' if result['seeded']['created'] else 'refreshed'})")
    print("  metrics: copied from ml/saved_model/metrics.json (measured values only)")
    print("Next (optional): python scripts/create_admin.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
