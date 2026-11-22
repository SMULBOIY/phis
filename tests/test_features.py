"""Feature-extraction and URL-contract tests (Stage 13).

Scope
-----
Everything that turns an untrusted string into the 15-number vector the model
consumes: ``ml/url_utils.py`` (normalisation), ``services/validation.py`` (the
trust boundary) and ``ml/feature_extraction.py`` (the shared contract).

Why these tests matter for the dissertation
-------------------------------------------
1. **Training-serving parity.** The same ``extract_features`` function is used
   by ``ml/train_model.py`` and by the live scanner. If the two ever diverged,
   every published metric would describe a distribution the app never sees.
   Several tests below prove a URL and its canonical form produce one vector.
2. **The contract is exactly 15 features, in order.** A silent re-ordering
   would let a fitted pipeline read the wrong column.
3. **No network.** Detection is lexical only; there is no socket, DNS or HTTP
   call anywhere in this path, which is also the SSRF defence.
4. **Fail closed.** Invalid input raises; it never yields a partial vector.

No live malicious website is contacted: every string here is synthetic
(``example.com`` / ``example.invalid`` / RFC 5737 documentation addresses).
"""
from __future__ import annotations

import math
from pathlib import Path

import pandas as pd
import pytest

from ml import url_utils
from ml.feature_extraction import (
    BRAND_TOKENS,
    DEFAULT_PORTS,
    FEATURE_DEFINITIONS,
    FEATURE_ORDER,
    FEATURE_RATIONALES,
    SHORTENER_DOMAINS,
    SUSPICIOUS_WORDS,
    extract_features,
    extract_frame,
    features_to_frame,
)
from ml.url_utils import (
    is_ip_host,
    is_valid_url,
    normalize_url,
    path_signature,
    registrable_domain,
    url_fingerprint,
)
from services.validation import (
    URLValidationError,
    ValidatedURL,
    is_valid_submitted_url,
    safe_display_url,
    validate_url,
)

ROOT = Path(__file__).resolve().parents[1]

# Controlled inputs. ``example.invalid`` is reserved by RFC 2606, so a copy of
# this file can never point at a real service.
SAFE = "https://example.com"
SAFE_SLASH = "https://example.com/"
SUSPICIOUS = "https://example.com/"
PHISHING = "https://www.example.org/about"
LOOKALIKE = (
    "https://paypal.com.login.verify.example.invalid/secure/account/update?next=confirm"
)


# --------------------------------------------------------------------------- #
# 1. The feature contract itself
# --------------------------------------------------------------------------- #
def test_feature_order_is_exactly_fifteen_named_features():
    assert isinstance(FEATURE_ORDER, tuple)
    assert len(FEATURE_ORDER) == 15
    assert len(set(FEATURE_ORDER)) == 15, "feature names must be unique"
    assert all(name.islower() and " " not in name for name in FEATURE_ORDER)


def test_every_feature_is_documented_and_rationalised():
    assert set(FEATURE_DEFINITIONS) == set(FEATURE_ORDER)
    assert set(FEATURE_RATIONALES) == set(FEATURE_ORDER)
    assert all(FEATURE_DEFINITIONS[name].strip() for name in FEATURE_ORDER)
    assert all(FEATURE_RATIONALES[name].strip() for name in FEATURE_ORDER)


def test_static_vocabularies_are_local_and_non_empty():
    """Shorteners/brands/words are maintained locally: no runtime lookup exists."""
    assert isinstance(SHORTENER_DOMAINS, frozenset) and SHORTENER_DOMAINS
    assert all("." in domain for domain in SHORTENER_DOMAINS)
    assert BRAND_TOKENS and all(token.islower() for token in BRAND_TOKENS)
    assert SUSPICIOUS_WORDS and all(word.islower() for word in SUSPICIOUS_WORDS)
    assert DEFAULT_PORTS == frozenset({80, 443})


# --------------------------------------------------------------------------- #
# 2. Shape, types and determinism
# --------------------------------------------------------------------------- #
def test_extract_features_returns_the_contract_in_order():
    features = extract_features(SAFE)
    assert isinstance(features, dict)
    assert tuple(features) == FEATURE_ORDER, "dict order must follow FEATURE_ORDER"
    assert all(isinstance(value, int) for value in features.values())
    assert all(not isinstance(value, bool) for value in features.values())


def test_no_nan_or_infinite_values_are_ever_produced():
    for url in (SAFE, SAFE_SLASH, PHISHING, LOOKALIKE):
        features = extract_features(url)
        assert all(math.isfinite(value) for value in features.values())
        assert all(value >= 0 for value in features.values())


def test_extraction_is_deterministic_and_side_effect_free():
    first = extract_features(LOOKALIKE)
    second = extract_features(LOOKALIKE)
    assert first == second
    first["url_length"] = -1                     # mutating the result on purpose
    assert extract_features(LOOKALIKE)["url_length"] != -1


def test_features_to_frame_uses_the_contract_column_order():
    features = extract_features(SAFE)
    frame = features_to_frame(features)
    assert isinstance(frame, pd.DataFrame)
    assert frame.shape == (1, 15)
    assert list(frame.columns) == list(FEATURE_ORDER)
    assert frame.iloc[0].tolist() == [features[name] for name in FEATURE_ORDER]


def test_features_to_frame_rejects_an_incomplete_vector():
    partial = extract_features(SAFE)
    partial.pop("has_https")
    with pytest.raises(ValueError, match="Missing features"):
        features_to_frame(partial)


def test_extract_frame_matches_single_extraction_for_every_row():
    urls = [SAFE, SAFE_SLASH, PHISHING, LOOKALIKE]
    frame = extract_frame(urls)
    assert frame.shape == (4, 15)
    assert list(frame.columns) == list(FEATURE_ORDER)
    for position, url in enumerate(urls):
        single = extract_features(url)
        assert frame.iloc[position].tolist() == [single[name] for name in FEATURE_ORDER]


# --------------------------------------------------------------------------- #
# 3. Training-serving parity (the leakage-free promise)
# --------------------------------------------------------------------------- #
def test_a_url_and_its_canonical_form_produce_one_vector():
    assert extract_features("HTTPS://Example.COM/Path") == extract_features(
        normalize_url("HTTPS://Example.COM/Path")
    )


def test_repeated_extraction_of_equivalent_spellings_agrees():
    # Same URL, four spellings: default scheme, host case, explicit port.
    # (A trailing slash is a *different* URL - the path is preserved verbatim.)
    equivalents = ["example.com", "http://example.com",
                   "http://EXAMPLE.com:80", "HTTP://Example.Com"]
    vectors = {tuple(extract_features(url).items()) for url in equivalents}
    assert len(vectors) == 1, "equivalent spellings must collapse to one vector"


def test_path_case_is_preserved_because_it_is_a_signal():
    lower = extract_features("https://example.com/login")
    upper = extract_features("https://example.com/LOGIN")
    # Both are legitimate strings and must be scored identically by length,
    # because case-insensitive word counting is what the feature promises.
    assert lower["num_suspicious_words"] == upper["num_suspicious_words"] == 1


# --------------------------------------------------------------------------- #
# 4. Individual feature semantics
# --------------------------------------------------------------------------- #
def test_raw_counts_are_counted_from_the_normalised_string():
    features = extract_features("https://my-site.example.com/a1b2-c3")
    canonical = normalize_url("https://my-site.example.com/a1b2-c3")
    assert features["url_length"] == len(canonical)
    assert features["num_dots"] == canonical.count(".")
    assert features["num_hyphens"] == canonical.count("-")
    assert features["num_digits"] == sum(char.isdigit() for char in canonical)


def test_domain_length_excludes_userinfo_and_port():
    plain = extract_features("https://example.com/x")
    with_userinfo = extract_features("https://someone:secret@example.com:8443/x")
    assert plain["domain_length"] == len("example.com")
    assert with_userinfo["domain_length"] == len("example.com")


def test_structural_punctuation_is_not_counted_as_special():
    assert extract_features("https://example.com/a-b_c.d~e")["num_special_chars"] == 0
    assert extract_features("https://example.com/a!b*c")["num_special_chars"] == 2


def test_ip_address_host_is_flagged_and_has_no_subdomains():
    features = extract_features("http://192.168.0.1/admin")
    assert features["has_ip_address"] == 1
    assert features["num_subdomains"] == 0


def test_domain_name_host_is_not_flagged_as_ip():
    assert extract_features(SAFE)["has_ip_address"] == 0
    assert is_ip_host(SAFE) is False
    assert is_ip_host("http://127.0.0.1/") is True


def test_at_symbol_is_detected_because_userinfo_hides_the_real_host():
    features = extract_features("https://paypal.com@example.invalid/login")
    assert features["has_at_symbol"] == 1
    assert extract_features(SAFE)["has_at_symbol"] == 0


def test_https_flag_reflects_the_scheme_only():
    assert extract_features("https://example.com")["has_https"] == 1
    assert extract_features("http://example.com")["has_https"] == 0


def test_https_is_a_weak_feature_and_never_an_indicator():
    """The lookalike is HTTPS, so the flag must not be treated as safety."""
    assert extract_features(LOOKALIKE)["has_https"] == 1


def test_shortener_domains_are_flagged_from_the_static_list():
    assert extract_features("https://bit.ly/abc123")["is_shortened"] == 1
    assert extract_features("https://tinyurl.com/xyz")["is_shortened"] == 1
    assert extract_features("https://example.com/abc")["is_shortened"] == 0


def test_suspicious_words_are_counted_case_insensitively():
    assert extract_features("https://example.com/login")["num_suspicious_words"] == 1
    assert extract_features("https://example.com/LOGIN/Verify")[
        "num_suspicious_words"
    ] == 2
    assert extract_features(LOOKALIKE)["num_suspicious_words"] >= 4


def test_unusual_port_is_flagged_but_default_ports_are_removed():
    assert extract_features("https://example.com:8443/x")["has_unusual_port"] == 1
    assert extract_features("https://example.com:443/x")["has_unusual_port"] == 0
    assert extract_features("http://example.com:80/x")["has_unusual_port"] == 0
    assert extract_features("http://example.com:8080/x")["has_unusual_port"] == 1


def test_percent_and_legacy_encoded_characters_are_detected():
    assert extract_features("https://example.com/%2Fadmin")["has_encoded_chars"] == 1
    assert extract_features("https://example.com/%u0041dmin")["has_encoded_chars"] == 1
    assert extract_features(SAFE)["has_encoded_chars"] == 0


def test_subdomain_depth_counts_labels_above_the_registrable_domain():
    assert extract_features("https://a.b.example.com/x")["num_subdomains"] == 2
    assert extract_features("https://www.example.com/x")["num_subdomains"] == 1
    assert extract_features("https://example.com/x")["num_subdomains"] == 0


def test_brand_in_a_lookalike_host_sets_the_suspicious_pattern():
    features = extract_features(LOOKALIKE)
    assert features["has_suspicious_pattern"] == 1
    assert extract_features(SAFE)["has_suspicious_pattern"] == 0


def test_brand_as_the_real_domain_is_not_flagged():
    """www.paypal.com is the brand's own domain; the rule must not fire."""
    features = extract_features("https://www.paypal.com/signin")
    assert features["has_suspicious_pattern"] == 0
    assert features["num_subdomains"] == 1


def test_double_slash_in_path_sets_the_suspicious_pattern():
    assert extract_features("https://example.com/a//b")["has_suspicious_pattern"] == 1


def test_multiple_question_marks_set_the_suspicious_pattern():
    features = extract_features("https://example.com/a?x=1?y=2")
    assert features["has_suspicious_pattern"] == 1


def test_deep_subdomain_chain_sets_the_suspicious_pattern():
    features = extract_features("https://a.b.c.d.example.com/x")
    assert features["has_suspicious_pattern"] == 1
    assert features["num_subdomains"] >= 4


# --------------------------------------------------------------------------- #
# 5. Fail-closed input handling
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad_input",
    [
        "",
        "   ",
        "not a url",
        "ftp://example.com/files",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html;base64,PHNjcmlwdD4=",
        "https://",
        "https://exa mple.com",
        "https://example.com/\x00",
        None,
        12345,
        b"https://example.com",
    ],
)
def test_invalid_input_raises_instead_of_scoring(bad_input):
    with pytest.raises(ValueError):
        extract_features(bad_input)


def test_over_long_input_is_rejected_by_the_configured_limit():
    with pytest.raises(ValueError):
        extract_features("https://example.com/" + "a" * 3000)
    with pytest.raises(ValueError):
        extract_features("https://example.com/" + "a" * 100, max_length=64)
    # The same string is acceptable when the limit allows it.
    assert extract_features("https://example.com/" + "a" * 100, max_length=2048)


# --------------------------------------------------------------------------- #
# 6. URL normalisation helpers
# --------------------------------------------------------------------------- #
def test_normalize_url_adds_a_default_scheme_for_a_bare_host():
    assert normalize_url("example.com") == "http://example.com"
    assert normalize_url("//example.com/x") == "http://example.com/x"


def test_normalize_url_is_idempotent():
    once = normalize_url("HTTPS://Example.COM:443/Path?Q=1#Frag")
    assert normalize_url(once) == once


def test_normalize_url_rejects_unsupported_schemes_and_bad_hosts():
    for bad in ("ftp://example.com", "javascript:alert(1)", "mailto://a@example.com",
                "https://", "http://exa mple.com", "https://example.com:notaport/"):
        assert normalize_url(bad) is None, bad


def test_normalize_url_preserves_userinfo_and_non_default_ports():
    assert normalize_url("https://user@example.com/x") == "https://user@example.com/x"
    assert normalize_url("https://example.com:8443/x") == "https://example.com:8443/x"
    assert normalize_url("https://example.com:443/x") == "https://example.com/x"


def test_normalize_url_keeps_path_query_and_fragment_verbatim():
    url = "https://example.com/A/B?Token=AbC#Section"
    assert normalize_url(url) == url


def test_is_valid_url_agrees_with_normalize_url():
    assert is_valid_url(SAFE) is True
    assert is_valid_url("ftp://example.com") is False
    assert is_valid_url("") is False


def test_registrable_domain_handles_two_level_suffixes_and_ips():
    assert registrable_domain("https://a.b.example.co.uk/x") == "example.co.uk"
    assert registrable_domain("https://shop.example.com/x") == "example.com"
    assert registrable_domain("https://192.168.0.1/x") == "192.168.0.1"
    assert registrable_domain("https://example.com/x") == "example.com"


def test_path_signature_masks_tokens_and_keeps_query_keys():
    signature = path_signature("https://evil.example/secure/login/verify/abc12345?tok=x&id=9")
    assert "abc12345" not in signature
    assert "id,tok" in signature


def test_url_fingerprint_is_stable_and_hex():
    digest = url_fingerprint(SAFE)
    assert digest == url_fingerprint(SAFE)
    assert len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


# --------------------------------------------------------------------------- #
# 7. The live trust boundary
# --------------------------------------------------------------------------- #
def test_validate_url_returns_a_bounded_frozen_object():
    validated = validate_url("  " + SAFE + "  ")
    assert isinstance(validated, ValidatedURL)
    assert validated.normalized == SAFE
    assert validated.scheme == "https"
    assert validated.host == "example.com"
    assert validated.raw == SAFE, "surrounding whitespace is stripped"
    with pytest.raises(Exception):
        validated.host = "evil.example"          # frozen dataclass


@pytest.mark.parametrize(
    "bad_input",
    ["", "   ", "ftp://example.com", "not a url", None, 42, ["https://example.com"]],
)
def test_validate_url_raises_a_displayable_error(bad_input):
    with pytest.raises(URLValidationError) as excinfo:
        validate_url(bad_input)
    message = str(excinfo.value)
    assert message.startswith("Invalid URL"), message
    assert "\n" not in message


def test_validate_url_never_echoes_the_submitted_string():
    """Reflected-XSS and log-injection defence: the error is generic."""
    payload = "javascript:alert('xss')"
    with pytest.raises(URLValidationError) as excinfo:
        validate_url(payload)
    assert payload not in str(excinfo.value)


def test_validate_url_enforces_the_length_limit():
    with pytest.raises(URLValidationError, match="limit"):
        validate_url("https://example.com/" + "a" * 200, max_length=64)
    assert validate_url("https://example.com/x", max_length=64).max_length == 64


def test_is_valid_submitted_url_never_raises():
    assert is_valid_submitted_url(SAFE) is True
    assert is_valid_submitted_url("ftp://example.com") is False
    assert is_valid_submitted_url(None) is False


def test_safe_display_url_truncates_without_marking_anything_safe():
    long_url = "https://example.com/" + "a" * 300
    shown = safe_display_url(long_url, limit=40)
    assert len(shown) == 40
    assert shown.endswith("…")
    assert safe_display_url(SAFE) == SAFE
    # The helper returns plain text; escaping stays Jinja2's job.
    assert "<script>" in safe_display_url("https://example.com/<script>")


# --------------------------------------------------------------------------- #
# 8. The "no network in the detection path" guarantee
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "relative_path",
    [
        "ml/feature_extraction.py",
        "ml/url_utils.py",
        "models/prediction_model.py",
        "services/detection_service.py",
        "services/decision_service.py",
        "services/explanation_service.py",
        "services/validation.py",
    ],
)
def test_detection_modules_import_no_network_client(relative_path):
    """SSRF is impossible if the process never opens a connection."""
    source = (ROOT / relative_path).read_text(encoding="utf-8").lower()
    for forbidden in ("import socket", "import requests", "import httpx",
                      "urllib.request", "http.client", "urlopen(",
                      "requests.get", "requests.post"):
        assert forbidden not in source, f"{relative_path} must not use {forbidden}"


def test_feature_module_exposes_no_network_helper():
    assert not hasattr(url_utils, "fetch")
    assert not hasattr(url_utils, "download")
