"""HTTP security headers, secure error responses and typed service errors.

Stage 7 delivers the *plumbing* that every later blueprint inherits:

* ``install_security_headers`` sets a strict Content-Security-Policy and the
  usual hardening headers on EVERY response, including error responses.
* ``install_error_handlers`` converts exceptions into generic, safe responses:
  JSON for ``/api/*`` / JSON clients and a themed HTML error page otherwise
  (``templates/errors/error.html`` since Stage 9). Stack traces go to the
  server log only, never to the browser.
* ``ServiceError`` is the typed exception Stage 10/12 raises for
  ``400 INVALID_URL`` and ``503 MODEL_UNAVAILABLE``.

Stage 12 additions
------------------
The header hook now also sends ``Cross-Origin-Opener-Policy``,
``X-Permitted-Cross-Domain-Policies`` and ``Origin-Agent-Cluster``, and marks
every scan/history/admin/dashboard/API response as ``no-store``. A dedicated
429 handler keeps the documented ``RATE_LIMITED`` JSON/HTML error shape and
adds ``Retry-After``. The CSP directive list itself is UNCHANGED: Stage 12 adds
headers, not new policy sources.

Frame policy and the live preview
---------------------------------
Clickjacking defence (``X-Frame-Options: DENY`` and CSP ``frame-ancestors``) is
enforced in production. In development/test it is intentionally omitted because
the Arena live preview embeds the dev server in a cross-origin iframe; leaving
the header on would make the preview blank. This is a documented, config-driven
development-only relaxation, not a production weakness. See ADR-025.
"""
from __future__ import annotations

from typing import Any

from flask import Flask, Response, jsonify, make_response, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

ERROR_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHENTICATED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    413: "PAYLOAD_TOO_LARGE",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    503: "MODEL_UNAVAILABLE",
}

GENERIC_MESSAGES: dict[int, str] = {
    400: "The request could not be understood.",
    401: "Authentication is required for this resource.",
    403: "You do not have permission to access this resource.",
    404: "The requested resource was not found.",
    405: "That HTTP method is not allowed for this resource.",
    413: "The submitted data is too large.",
    429: "Too many requests. Please wait and try again.",
    500: "An internal error occurred. The incident has been logged.",
    503: "The detection model is not available. No result can be produced.",
}

CSRF_MESSAGE = (
    "The security token is missing, invalid or expired. Reload the page and try again."
)

# Stage 9: error responses now use templates/errors/error.html, which extends
# the same base layout as every other page. It contains no inline style or
# script, so the CSP stays strict and the offline preview renders it fully.
# The template receives only the generic code and message - never exception
# text, a stack trace or an absolute server path.

SENSITIVE_PREFIXES = (
    "/api/", "/auth/", "/health", "/scan", "/history", "/admin",
    "/dashboard", "/export",
)


class ServiceError(Exception):
    """A controlled error with an explicit HTTP status and contract code.

    Example (used from Stage 10):
        raise ServiceError(400, "INVALID_URL", "Enter an http or https URL.")
        raise ServiceError(503, "MODEL_UNAVAILABLE")
    """

    def __init__(self, status: int, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.status = status
        self.code = code
        self.message = message


def build_csp(app: Flask) -> str:
    """Return the Content-Security-Policy for this application."""
    directives = [
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "form-action 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
    ]
    ancestors = app.config.get("CSP_FRAME_ANCESTORS")
    if ancestors:
        directives.append(f"frame-ancestors {ancestors}")
    return "; ".join(directives)


def make_error_response(
    status: int, code: str | None = None, message: str | None = None
) -> Response:
    """Build a generic error response in the shape the caller expects."""
    resolved_code = code or ERROR_CODES.get(status, "HTTP_ERROR")
    resolved_message = message or GENERIC_MESSAGES.get(
        status, "The request could not be completed."
    )
    # REST paths and JSON clients get JSON; ordinary browser forms get HTML.
    # Stage 8's /login and /register accept both, so the error shape must
    # follow the request, not just the URL prefix.
    json_requested = (
        request.path.startswith("/api/")
        or request.is_json
        or request.args.get("format") == "json"
    )
    if json_requested:
        response: Response = jsonify({
            "error": {
                "code": resolved_code,
                "message": resolved_message,
                "status": status,
            }
        })
    else:
        response = make_response(
            render_template(
                "errors/error.html",
                status_code=status,
                code=resolved_code,
                message=resolved_message,
            ),
            status,
        )
    response.status_code = status
    return response


def install_security_headers(app: Flask) -> None:
    """Attach an ``after_request`` hook that hardens every response."""

    @app.after_request
    def _apply(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        response.headers["X-XSS-Protection"] = "0"
        # Stage 12 hardening. These are ordinary response headers; the CSP
        # directive list below is intentionally left exactly as Stage 7 wrote
        # it, with no extra origins or relaxed script/style rules.
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Origin-Agent-Cluster"] = "?1"
        response.headers["Content-Security-Policy"] = build_csp(app)

        frame_option = app.config.get("X_FRAME_OPTIONS")
        if frame_option:
            response.headers["X-Frame-Options"] = frame_option
        elif "X-Frame-Options" in response.headers:
            del response.headers["X-Frame-Options"]

        if app.config.get("ENV_NAME") == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        elif "Strict-Transport-Security" in response.headers:
            del response.headers["Strict-Transport-Security"]

        if response.status_code >= 400 or any(
            request.path.startswith(prefix) for prefix in SENSITIVE_PREFIXES
        ):
            response.headers["Cache-Control"] = "no-store"
        return response


def install_request_guards(app: Flask) -> None:
    """Enforce the request-body cap before any view runs.

    Flask only checks ``MAX_CONTENT_LENGTH`` when a view reads the body. A view
    that ignores the body would therefore accept an arbitrarily large upload.
    Rejecting on the declared ``Content-Length`` up front closes that gap;
    Werkzeug's own check still applies if a body is later read.
    """

    @app.before_request
    def _enforce_body_cap() -> None:
        limit = app.config.get("MAX_CONTENT_LENGTH")
        declared = request.content_length
        if isinstance(limit, int) and limit > 0 and declared is not None \
                and declared > limit:
            raise RequestEntityTooLarge()


def install_error_handlers(app: Flask) -> None:
    """Register safe handlers for CSRF, HTTP, typed and unexpected errors."""

    @app.errorhandler(CSRFError)
    def _csrf_error(exc: CSRFError) -> Response:
        return make_error_response(400, "CSRF_FAILED", CSRF_MESSAGE)

    @app.errorhandler(ServiceError)
    def _service_error(exc: ServiceError) -> Response:
        return make_error_response(exc.status, exc.code, exc.message)

    @app.errorhandler(429)
    def _rate_limited(exc: Exception) -> Response:
        """Keep the generic contract and tell the client when to retry."""
        response = make_error_response(429, "RATE_LIMITED")
        retry_after = getattr(exc, "retry_after", None)
        seconds = int(retry_after) if isinstance(retry_after, (int, float)) else 60
        response.headers["Retry-After"] = str(max(1, seconds))
        return response

    @app.errorhandler(500)
    def _internal_error(exc: Exception) -> Response:
        app.logger.exception("Unhandled error on %s %s", request.method, request.path)
        return make_error_response(500, "INTERNAL_ERROR")

    @app.errorhandler(503)
    def _unavailable(exc: Exception) -> Response:
        return make_error_response(503, "MODEL_UNAVAILABLE")

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException) -> Response:
        status = exc.code or 500
        return make_error_response(status, ERROR_CODES.get(status, "HTTP_ERROR"))


__all__ = [
    "ERROR_CODES", "GENERIC_MESSAGES", "ServiceError", "build_csp",
    "make_error_response", "install_security_headers", "install_error_handlers",
    "install_request_guards",
]
