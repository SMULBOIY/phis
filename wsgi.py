"""WSGI entry point for production-style servers (Stage 7).

    waitress-serve --call wsgi:create_application
    python wsgi.py                 # direct waitress runner on HOST:PORT

Why a separate file? ``app.py`` defines a FACTORY and must stay free of import
time side effects for the test suite. This module creates the one long-lived
application object a WSGI server needs. Both names are exported so that
``waitress-serve wsgi:app`` and ``gunicorn wsgi:application`` both work.

The object is created at import time by design: a WSGI server imports this
module once per worker process and then serves many requests from it.
"""
from __future__ import annotations

import os
import sys

from flask import Flask

from app import create_app

app: Flask = create_app()
application = app


def create_application() -> Flask:
    """Callable factory for ``waitress-serve --call wsgi:create_application``."""
    return app


def main() -> int:
    """Run the app with waitress when this file is executed directly."""
    from waitress import serve

    host = app.config.get("HOST") or os.environ.get("HOST", "0.0.0.0")
    port = int(app.config.get("PORT") or os.environ.get("PORT", "5000"))
    print(
        f"Serving {app.config['APP_NAME']} on http://{host}:{port} "
        f"(env={app.config['ENV_NAME']}, debug={app.config['DEBUG']})",
        file=sys.stderr,
    )
    serve(app, host=host, port=port, threads=4)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
