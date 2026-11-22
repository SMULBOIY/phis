"""Pure, network-free URL helpers shared by EVERY stage of the project.

This is the canonical implementation of URL normalisation. It is imported by:

* ``ml/preprocess.py``      (Stage 3 - dataset cleaning)
* ``ml/feature_extraction.py`` (Stage 4 - training-time features)
* ``services/validation.py``   (Stage 10 - live input validation)
* ``models/prediction_model.py`` (Stage 10 - inference)

Why a separate module? If training normalises URLs differently from the live
scanner, the model sees a different distribution at prediction time. That is
*training-serving skew* and it silently destroys accuracy. One small, pure,
dependency-free module removes the risk.

Safety: this module NEVER opens a socket, resolves DNS or fetches a URL. It only
parses strings with the standard library. It is therefore SSRF-safe by design.

Design choices that matter for feature extraction
-------------------------------------------------
* Only the scheme and hostname are lowercased; the path, query and fragment are
  preserved verbatim because case, ``@``, ``%xx`` escapes, repeated slashes and
  long tokens are exactly the lexical signals the model must learn.
* Userinfo (``user@host``) is preserved because ``has_at_symbol`` is a feature.
* Default ports (80 on http, 443 on https) are removed; non-default ports are
  preserved because ``has_unusual_port`` is a feature.
* The fragment is preserved. Fragments are part of the submitted string and may
  contain encoded characters.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

DEFAULT_MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")
DEFAULT_SCHEME = "http"

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_DIGIT_RUN = re.compile(r"\d+")
_LONG_HEX = re.compile(r"[0-9a-fA-F]{10,}")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9]{16,}")
_SLASH_RUN = re.compile(r"/{2,}")
_SEGMENT_SPLIT = re.compile(r"([A-Za-z0-9]+)")

# Common two-label public suffixes. Without an external Public Suffix List
# dependency we approximate eTLD+1 with this list; anything not listed falls
# back to the last two labels. Over-grouping (e.g. all "*.xsph.ru" together) is
# CONSERVATIVE: it can only reduce leakage, never increase it.
_TWO_LEVEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz",
    "co.za", "org.za", "com.br", "net.br", "org.br", "com.cn", "net.cn",
    "org.cn", "co.jp", "or.jp", "ne.jp", "ac.jp", "co.kr", "or.kr",
    "co.in", "net.in", "org.in", "com.mx", "com.ar", "com.tr", "com.sg",
    "com.hk", "com.tw", "com.pl", "com.ua", "co.id", "com.my", "com.ph",
    "com.vn", "com.pk", "com.eg", "com.ng", "com.pe", "com.cl", "com.co",
    "com.ve", "com.ec", "com.uy", "com.py", "com.bo", "com.cr", "com.pa",
    "com.do", "com.gt", "com.hn", "com.sv", "com.ni", "com.cu", "com.ee",
    "com.lv", "com.lt", "com.by", "com.kz", "com.ge", "com.am", "com.az",
    "com.uz", "com.bd", "com.np", "com.lk", "co.th", "com.es", "com.pt",
    "com.gr", "com.ro", "com.hu", "com.cz", "com.sk", "com.hr", "com.si",
    "com.il", "com.ru", "org.ru", "net.ru", "com.bd", "com.tr", "com.tn",
    "com.dz", "com.ma", "com.sa", "com.ae", "com.qa", "com.kw", "com.bh",
    "com.om", "com.jo", "com.lb", "com.sy", "com.iq", "com.ir", "com.af",
    "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app",
    "herokuapp.com", "firebaseapp.com", "appspot.com", "blogspot.com",
    "wordpress.com", "wixsite.com", "weebly.com", "000webhostapp.com",
    "duckdns.org", "no-ip.org", "ddns.net", "synology.me", "hopto.org",
    "zapto.org", "myftp.org", "redirectme.net", "freeddns.org", "dynu.net",
})


def normalize_url(
    raw: str,
    *,
    max_length: int = DEFAULT_MAX_URL_LENGTH,
    default_scheme: str = DEFAULT_SCHEME,
) -> str | None:
    """Return the canonical URL string, or ``None`` if the input is invalid.

    Performs NO network access. Invalid inputs include: non-strings, empty or
    over-long strings, control characters, unsupported schemes, missing hosts,
    bad ports and hostnames that are not valid DNS names or IP literals.
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or len(text) > max_length or _CONTROL_CHARS.search(text):
        return None
    if any(char.isspace() for char in text):
        return None

    if text.startswith("//"):
        text = f"{default_scheme}:{text}"
    elif "://" not in text:
        text = f"{default_scheme}://{text}"

    try:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            return None
        hostname = parts.hostname
        if not hostname:
            return None
        port = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return None

    # Preserve userinfo (the '@' symbol is a deliberate detection feature).
    userinfo = ""
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0] + "@"

    host = hostname.lower().rstrip(".")
    if ":" in host and not host.startswith("["):  # IPv6 literal
        host = f"[{host}]"
    if not host:
        return None

    default_port = 80 if scheme == "http" else 443
    port_suffix = "" if port is None or port == default_port else f":{port}"
    netloc = f"{userinfo}{host}{port_suffix}"

    canonical = urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))
    if len(canonical) > max_length:
        return None
    return canonical


def is_valid_url(raw: str, *, max_length: int = DEFAULT_MAX_URL_LENGTH) -> bool:
    """True when :func:`normalize_url` accepts the input."""
    return normalize_url(raw, max_length=max_length) is not None


def is_ip_host(url: str) -> bool:
    """True when the URL's host is a literal IPv4 or IPv6 address."""
    try:
        host = urlsplit(url).hostname or ""
        ipaddress.ip_address(host.strip("[]"))
        return True
    except (ValueError, AttributeError):
        return False


def registrable_domain(url: str) -> str:
    """Approximate eTLD+1 for group-aware splitting.

    Returns the host itself for IP literals. For DNS names it returns the last
    three labels when the last two form a known two-level public suffix,
    otherwise the last two labels. This is intentionally conservative: grouping
    more URLs together can only reduce train/test leakage.
    """
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return "<invalid>"
    if not host:
        return "<invalid>"
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _mask_tokens(value: str) -> str:
    """Replace digit runs and long opaque tokens with stable placeholders."""
    masked = _LONG_HEX.sub("<hex>", value)
    masked = _LONG_TOKEN.sub("<tok>", masked)
    masked = _DIGIT_RUN.sub("<n>", masked)
    return masked


def path_signature(url: str) -> str:
    """Near-duplicate signature of the URL's path and query keys.

    Two URLs produced by the same phishing kit but hosted on different domains
    usually share a path template (e.g. ``/secure/login/verify/<tok>``). Digit
    runs and long tokens are masked; query *values* are discarded but query
    *keys* are kept and sorted. Used to merge split groups and prevent leakage.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<invalid>"
    path = _SLASH_RUN.sub("/", parts.path or "/")
    masked = _mask_tokens(path)
    # Mask long alphabetic segments too (random kit slugs).
    masked = _SEGMENT_SPLIT.sub(
        lambda match: "<w>" if len(match.group(0)) >= 16 else match.group(0),
        masked,
    )
    try:
        keys = sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)})
    except ValueError:
        keys = []
    return f"{masked}?{','.join(keys)}" if keys else masked


def url_fingerprint(url: str) -> str:
    """SHA-256 of the canonical URL, used for deduplication and audit."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


__all__ = [
    "DEFAULT_MAX_URL_LENGTH", "ALLOWED_SCHEMES", "DEFAULT_SCHEME",
    "normalize_url", "is_valid_url", "is_ip_host", "registrable_domain",
    "path_signature", "url_fingerprint",
]
