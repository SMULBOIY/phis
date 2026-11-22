"""Live URL input validation (Stage 4).

This is the boundary between untrusted user input and the detection engine. It
does NOT fetch, resolve or execute anything: it reuses the SAME canonical
normaliser as dataset preprocessing and feature extraction.

Design
------
* ``ml.url_utils.normalize_url`` is the only normaliser. Importing it here (and
  in ``ml.feature_extraction``) guarantees training-serving parity: a string
  seen during training and the same string pasted by a user become identical
  canonical URLs, hence identical feature vectors.
* The maximum length comes from ``config.BaseConfig.MAX_URL_LENGTH`` so the
  config module remains the single authority on that number.
* Error messages are generic and never echo the submitted string, avoiding log
  injection and reflected-XSS risks.
* Rejected: non-strings, empty/whitespace input, over-long input, unsupported
  schemes (ftp, file, javascript, data, ...), malformed hosts and bad ports.

Typical use (Stage 10):
    validated = validate_url(form_input)
    features = extract_features(validated.normalized)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ml.url_utils import ALLOWED_SCHEMES, DEFAULT_MAX_URL_LENGTH, normalize_url


class URLValidationError(ValueError):
    """Raised when a submitted URL fails validation. Message is safe to display."""


@dataclass(frozen=True)
class ValidatedURL:
    """The bounded, typed object that crosses the trust boundary."""

    raw: str
    normalized: str
    scheme: str
    host: str
    max_length: int


def _configured_max_length() -> int:
    """Read the configured limit lazily so importing this module has no side effects."""
    try:
        from config import BaseConfig
        return int(BaseConfig.MAX_URL_LENGTH)
    except (ImportError, AttributeError, ValueError):
        return DEFAULT_MAX_URL_LENGTH


def validate_url(
    raw: Any,
    *,
    max_length: int | None = None,
    allowed_schemes: tuple[str, ...] = ALLOWED_SCHEMES,
) -> ValidatedURL:
    """Validate and normalise a submitted URL, or raise ``URLValidationError``.

    No network access occurs. ``raw`` is only inspected as a bounded string.
    """
    if not isinstance(raw, str):
        raise URLValidationError("Invalid URL: expected a text value.")
    stripped = raw.strip()
    if not stripped:
        raise URLValidationError("Invalid URL: the submitted value is empty.")

    limit = max_length if max_length is not None else _configured_max_length()
    if len(stripped) > limit:
        raise URLValidationError(f"Invalid URL: exceeds the {limit}-character limit.")

    canonical = normalize_url(stripped, max_length=limit)
    if canonical is None:
        raise URLValidationError(
            "Invalid URL: use a complete http:// or https:// address with a valid host."
        )

    parts = urlsplit(canonical)
    if parts.scheme.lower() not in allowed_schemes:
        raise URLValidationError("Invalid URL: only http and https are supported.")

    return ValidatedURL(
        raw=stripped,
        normalized=canonical,
        scheme=parts.scheme.lower(),
        host=parts.hostname or "",
        max_length=limit,
    )


def is_valid_submitted_url(raw: Any, *, max_length: int | None = None) -> bool:
    """Boolean convenience wrapper; never raises for bad input."""
    try:
        validate_url(raw, max_length=max_length)
        return True
    except URLValidationError:
        return False


def safe_display_url(normalized: str, *, limit: int = 120) -> str:
    """Truncate a URL for display without ever marking it HTML-safe.

    Jinja2 autoescaping still applies. The truncation prevents an extremely long
    submitted string from breaking the result page layout.
    """
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1] + "…"


__all__ = [
    "URLValidationError", "ValidatedURL", "validate_url",
    "is_valid_submitted_url", "safe_display_url",
]
