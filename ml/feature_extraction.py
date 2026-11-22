"""URL feature extraction - the SHARED feature contract (Stage 4).

This module is the ONLY place where URL features are defined. It is imported by
``scripts/analyse_features.py`` (Stage 4 EDA), ``ml/train_model.py`` (Stage 5),
``ml/evaluate_model.py`` (Stage 6) and ``services/detection_service.py``
(Stage 10). Training and live prediction therefore compute identical vectors.

Guarantees
----------
* ``FEATURE_ORDER`` is the immutable authority on exactly 15 feature names and
  their column order. ``features_to_frame`` always emits that order.
* ``extract_features`` normalises its input with the SAME
  ``ml.url_utils.normalize_url`` used by preprocessing (Stage 3) and by the
  live validator (Stage 10) - this is the training-serving parity guarantee.
* Pure and deterministic: no I/O, no randomness, no network, no global state.
* Every value is an ``int`` (counts, or 0/1 flags). No NaN, no infinity.
* Invalid input raises ``ValueError``. It never silently produces a vector.

Safety: no socket, DNS, HTTP request or webpage download happens here. The
system analyses the URL STRING only, so it has no SSRF surface.

Important: these are *indicators*, not proof. A flagged feature does not make a
website malicious. In particular ``has_https`` is a WEAK feature - most modern
phishing sites use HTTPS - and is included so the model can learn its true
(low) weight from data rather than from a hand-written rule.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlsplit

import pandas as pd

from ml.url_utils import (
    ALLOWED_SCHEMES,
    DEFAULT_MAX_URL_LENGTH,
    is_ip_host,
    normalize_url,
    registrable_domain,
)

# --------------------------------------------------------------------------- #
# The contract. Changing this tuple requires retraining AND a schema bump.
# --------------------------------------------------------------------------- #
FEATURE_ORDER: tuple[str, ...] = (
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_special_chars",
    "num_digits",
    "has_ip_address",
    "has_at_symbol",
    "has_suspicious_pattern",
    "num_subdomains",
    "has_https",
    "is_shortened",
    "num_suspicious_words",
    "has_unusual_port",
    "has_encoded_chars",
)

FEATURE_DEFINITIONS: dict[str, str] = {
    "url_length": "Number of characters in the normalised URL string.",
    "domain_length": "Number of characters in the hostname (excluding userinfo, port and brackets).",
    "num_dots": "Count of '.' characters in the whole normalised URL.",
    "num_hyphens": "Count of '-' characters in the whole normalised URL.",
    "num_special_chars": "Count of non-alphanumeric characters that are not ordinary URL structure characters (see docs/FEATURES.md).",
    "num_digits": "Count of digit characters in the whole normalised URL.",
    "has_ip_address": "1 when the host is a literal IPv4/IPv6 address instead of a domain name, else 0.",
    "has_at_symbol": "1 when the URL contains '@' (userinfo before the real host), else 0.",
    "has_suspicious_pattern": "1 when any documented obfuscation pattern is present (double slash in path, multiple '?', deep subdomain chain, or brand token in a lookalike host), else 0.",
    "num_subdomains": "Number of host labels before the approximate registrable domain (0 for a bare domain or an IP host).",
    "has_https": "1 when the scheme is https, else 0. WEAK feature: HTTPS alone never means legitimate.",
    "is_shortened": "1 when the registrable domain is in the maintained static list of URL shorteners, else 0.",
    "num_suspicious_words": "Case-insensitive substring count of login, verify, update, secure, account, banking and confirm in the URL.",
    "has_unusual_port": "1 when an explicit port other than 80/443 is present, else 0.",
    "has_encoded_chars": "1 when percent-encoded (%xx) or legacy %uXXXX sequences are present, else 0.",
}

FEATURE_RATIONALES: dict[str, str] = {
    "url_length": "Very long URLs hide the real destination behind padding, tokens and query junk.",
    "domain_length": "Long, keyword-stuffed hosts are used to impersonate brands.",
    "num_dots": "Many dots create fake subdomain chains such as brand.com.login.evil.tld.",
    "num_hyphens": "Hyphens produce lookalike domains such as secure-paypal-verify.example.",
    "num_special_chars": "Unusual punctuation is used for obfuscation and delimiter abuse.",
    "num_digits": "Digit-heavy hosts and paths are common in generated phishing kits.",
    "has_ip_address": "Legitimate brands almost never use a bare IP address as the visible host.",
    "has_at_symbol": "Everything before '@' is userinfo; the real host is AFTER it. A classic deception trick.",
    "has_suspicious_pattern": "Structural obfuscation (double slashes, brand-in-subdomain, deep subdomain chains) disguises the true destination.",
    "num_subdomains": "Deep subdomain chains put the impersonated brand early while the actual registrable domain is elsewhere.",
    "has_https": "Included for completeness only; attackers obtain free certificates, so its learned weight should be low.",
    "is_shortened": "Shorteners conceal the final destination from a user reading the link.",
    "num_suspicious_words": "Credential-harvesting lures repeatedly use words like login, verify, secure and account.",
    "has_unusual_port": "Non-standard ports are typical of throwaway hosting and local phishing kits.",
    "has_encoded_chars": "Percent encoding conceals the true path or hostname and can defeat naive filters.",
}

# --------------------------------------------------------------------------- #
# Maintained static vocabularies (no network lookups, no external services)
# --------------------------------------------------------------------------- #
SUSPICIOUS_WORDS: tuple[str, ...] = (
    "login", "verify", "update", "secure", "account", "banking", "confirm",
)

SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "bitly.com", "j.mp", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "rb.gy",
    "shorte.st", "lnkd.in", "t.ly", "v.gd", "s.id", "qr.ae", "po.st", "u.to",
    "ift.tt", "gg.gg", "shorturl.at", "tiny.one", "short.ly", "cli.gs", "x.co",
    "urlzs.com", "trib.al", "hyperurl.co", "zipy.co", "cutt.us", "shrtco.de",
    "ezurl.cc", "soo.gd", "s2r.co", "bit.do", "mcaf.ee", "su.pr", "fon.gs",
    "ity.im", "go2.me", "flic.kr", "hex.io", "yep.it", "ad7.biz",
})

BRAND_TOKENS: tuple[str, ...] = (
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix",
    "ebay", "instagram", "linkedin", "dropbox", "dhl", "fedex", "chase",
    "hsbc", "barclays", "icloud", "office365", "outlook", "wellsfargo",
    "bankofamerica", "adobe", "steam", "whatsapp", "twitter",
)

# Characters that are ordinary URL structure. Anything else that is not
# alphanumeric counts as an "unusual special character".
_STRUCTURAL_CHARS: frozenset[str] = frozenset(":/?#&=._-%~+")

_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}")
_LABEL_RE = re.compile(r"[A-Za-z0-9-]+")

DEFAULT_PORTS: frozenset[int] = frozenset({80, 443})


def _count_labels(host: str) -> int:
    """Number of DNS labels in a hostname (0 for an empty host)."""
    return len([label for label in host.split(".") if label])


def _brand_in_subdomain(host: str, registrable: str) -> bool:
    """True when a brand token appears in the host but NOT as the real domain.

    Example: paypal.com.verify-login.evil.example has registrable domain
    'evil.example' yet contains 'paypal' -> suspicious. www.paypal.com has
    registrable domain 'paypal.com' -> not suspicious by this rule.
    """
    lowered = host.lower()
    for brand in BRAND_TOKENS:
        if brand in lowered and not registrable.startswith(brand):
            return True
    return False


def extract_features(url: str, *, max_length: int = DEFAULT_MAX_URL_LENGTH) -> dict[str, int]:
    """Return the 15-feature vector for one URL, in ``FEATURE_ORDER``.

    Raises ``ValueError`` for invalid input. Never returns a partial vector.
    The input is normalised with the shared ``ml.url_utils.normalize_url`` first,
    so a raw pasted URL and an already-normalised training URL produce the same
    vector (training-serving parity).
    """
    canonical = normalize_url(url, max_length=max_length)
    if canonical is None:
        raise ValueError("Invalid URL: cannot extract features from an invalid or over-long URL")

    parts = urlsplit(canonical)
    host = parts.hostname or ""
    scheme = parts.scheme.lower()
    path = parts.path or "/"
    registrable = registrable_domain(canonical)
    lower_url = canonical.lower()

    # --- raw counts ------------------------------------------------------- #
    url_length = len(canonical)
    domain_length = len(host)
    num_dots = canonical.count(".")
    num_hyphens = canonical.count("-")
    num_special_chars = sum(
        1 for char in canonical if not char.isalnum() and char not in _STRUCTURAL_CHARS
    )
    num_digits = sum(1 for char in canonical if char.isdigit())

    # --- binary indicators ------------------------------------------------ #
    has_ip_address = 1 if is_ip_host(canonical) else 0
    has_at_symbol = 1 if "@" in canonical else 0
    has_https = 1 if scheme == "https" else 0
    is_shortened = 1 if registrable in SHORTENER_DOMAINS else 0
    num_suspicious_words = sum(lower_url.count(word) for word in SUSPICIOUS_WORDS)

    try:
        port = parts.port
    except ValueError:
        port = None
    has_unusual_port = 1 if port is not None and port not in DEFAULT_PORTS else 0
    has_encoded_chars = 1 if _ENCODED_RE.search(canonical) else 0

    # --- structural ------------------------------------------------------- #
    if has_ip_address:
        num_subdomains = 0
    else:
        num_subdomains = max(_count_labels(host) - _count_labels(registrable), 0)

    deep_chain = host.count(".") >= 4
    suspicious_pattern = (
        "//" in path
        or canonical.count("?") > 1
        or deep_chain
        or _brand_in_subdomain(host, registrable)
    )
    has_suspicious_pattern = 1 if suspicious_pattern else 0

    features: dict[str, int] = {
        "url_length": url_length,
        "domain_length": domain_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_special_chars": num_special_chars,
        "num_digits": num_digits,
        "has_ip_address": has_ip_address,
        "has_at_symbol": has_at_symbol,
        "has_suspicious_pattern": has_suspicious_pattern,
        "num_subdomains": num_subdomains,
        "has_https": has_https,
        "is_shortened": is_shortened,
        "num_suspicious_words": num_suspicious_words,
        "has_unusual_port": has_unusual_port,
        "has_encoded_chars": has_encoded_chars,
    }
    # Contract enforcement: never return a vector with missing/extra keys.
    if tuple(features) != FEATURE_ORDER:
        raise RuntimeError("Feature vector does not match FEATURE_ORDER")
    return features


def features_to_frame(features: dict[str, int]) -> pd.DataFrame:
    """Convert one feature dict to a single-row DataFrame in the contract order."""
    missing = [name for name in FEATURE_ORDER if name not in features]
    if missing:
        raise ValueError(f"Missing features: {missing}")
    return pd.DataFrame([[features[name] for name in FEATURE_ORDER]], columns=list(FEATURE_ORDER))


def extract_frame(urls: Iterable[str], *, max_length: int = DEFAULT_MAX_URL_LENGTH) -> pd.DataFrame:
    """Extract features for many URLs into a DataFrame (batch training path).

    Order is preserved. Every row uses the exact same code path as a single live
    prediction - there is no separate "training feature" implementation.
    """
    rows = [extract_features(url, max_length=max_length) for url in urls]
    return pd.DataFrame(rows, columns=list(FEATURE_ORDER))


# Import-time consistency check: documentation must cover every feature.
if set(FEATURE_DEFINITIONS) != set(FEATURE_ORDER) or set(FEATURE_RATIONALES) != set(FEATURE_ORDER):
    raise RuntimeError("FEATURE_DEFINITIONS / FEATURE_RATIONALES must cover FEATURE_ORDER exactly")

__all__ = [
    "FEATURE_ORDER", "FEATURE_DEFINITIONS", "FEATURE_RATIONALES",
    "SUSPICIOUS_WORDS", "SHORTENER_DOMAINS", "BRAND_TOKENS", "DEFAULT_PORTS",
    "extract_features", "features_to_frame", "extract_frame",
]
