# URL Feature Catalogue and Extraction Contract

**Stage 4 deliverable — generated 2026-11-03T19:52:36+00:00**
**Implementation:** `ml/feature_extraction.py` (single source of truth)
**Live input boundary:** `services/validation.py`
**Measured statistics:** `dataset/processed/feature_summary.json` (training split only)

Every statistic in this document was computed by `scripts/analyse_features.py` from
164,744 REAL training URLs. No model was fitted and no accuracy figure is claimed.

---

## 1. Purpose and the parity contract

The brief requires 15 URL characteristics, computed identically during training
and live prediction. This module is the ONLY implementation of those features:

```
raw URL string
    -> ml.url_utils.normalize_url()      (Stage 3, shared, network-free)
    -> ml.feature_extraction.extract_features()
    -> 15 named integers in FEATURE_ORDER
    -> features_to_frame() / extract_frame()
    -> training CSV (Stage 5) OR live scan (Stage 10)
```

`services/validation.py` calls the SAME `normalize_url` before handing a string to
the detector, so a URL pasted by a user produces exactly the feature vector the
model saw during training. This is the **training-serving parity** guarantee in
`docs/ARCHITECTURE.md` §7; `scripts/verify_stage4.py` asserts it on controlled
inputs and on a sample of real training rows.

Contract rules:

* `FEATURE_ORDER` is an immutable tuple of exactly **15** names and is the only
  authority on column order. The model bundle in Stage 5 stores it and Stage 10
  validates it at load time.
* `extract_features(url)` returns `dict[str, int]` whose keys are *in that exact
  order*; a mismatch raises `RuntimeError` rather than silently reindexing.
* Every value is a non-negative `int` (a count, or 0/1 for a flag). No NaN, no
  infinity, no floats, no categorical strings.
* Pure function: no I/O, no randomness, no global state, **no network access**.
  Invalid input raises `ValueError`; it never returns a partial vector.
* Feature extraction never visits the URL. No `requests`, `socket`, DNS or
  `urllib.request` import exists in this module (asserted by the stage gate).

---

## 2. Feature catalogue

| Feature | Kind | What it measures | Why it may indicate phishing |
| --- | --- | --- | --- |
| `url_length` | count | Number of characters in the normalised URL string. | Very long URLs hide the real destination behind padding, tokens and query junk. |
| `domain_length` | count | Number of characters in the hostname (excluding userinfo, port and brackets). | Long, keyword-stuffed hosts are used to impersonate brands. |
| `num_dots` | count | Count of '.' characters in the whole normalised URL. | Many dots create fake subdomain chains such as brand.com.login.evil.tld. |
| `num_hyphens` | count | Count of '-' characters in the whole normalised URL. | Hyphens produce lookalike domains such as secure-paypal-verify.example. |
| `num_special_chars` | count | Count of non-alphanumeric characters that are not ordinary URL structure characters (see docs/FEATURES.md). | Unusual punctuation is used for obfuscation and delimiter abuse. |
| `num_digits` | count | Count of digit characters in the whole normalised URL. | Digit-heavy hosts and paths are common in generated phishing kits. |
| `has_ip_address` | binary | 1 when the host is a literal IPv4/IPv6 address instead of a domain name, else 0. | Legitimate brands almost never use a bare IP address as the visible host. |
| `has_at_symbol` | binary | 1 when the URL contains '@' (userinfo before the real host), else 0. | Everything before '@' is userinfo; the real host is AFTER it. A classic deception trick. |
| `has_suspicious_pattern` | binary | 1 when any documented obfuscation pattern is present (double slash in path, multiple '?', deep subdomain chain, or brand token in a lookalike host), else 0. | Structural obfuscation (double slashes, brand-in-subdomain, deep subdomain chains) disguises the true destination. |
| `num_subdomains` | count | Number of host labels before the approximate registrable domain (0 for a bare domain or an IP host). | Deep subdomain chains put the impersonated brand early while the actual registrable domain is elsewhere. |
| `has_https` | binary | 1 when the scheme is https, else 0. WEAK feature: HTTPS alone never means legitimate. | Included for completeness only; attackers obtain free certificates, so its learned weight should be low. |
| `is_shortened` | binary | 1 when the registrable domain is in the maintained static list of URL shorteners, else 0. | Shorteners conceal the final destination from a user reading the link. |
| `num_suspicious_words` | count | Case-insensitive substring count of login, verify, update, secure, account, banking and confirm in the URL. | Credential-harvesting lures repeatedly use words like login, verify, secure and account. |
| `has_unusual_port` | binary | 1 when an explicit port other than 80/443 is present, else 0. | Non-standard ports are typical of throwaway hosting and local phishing kits. |
| `has_encoded_chars` | binary | 1 when percent-encoded (%xx) or legacy %uXXXX sequences are present, else 0. | Percent encoding conceals the true path or hostname and can defeat naive filters. |

### Precise definitions that could otherwise be ambiguous

| Feature | Exact rule |
| --- | --- |
| `url_length` | `len(normalised_url)` after `normalize_url` |
| `domain_length` | `len(urlsplit(normalised_url).hostname)` — excludes userinfo, port, brackets |
| `num_dots` / `num_hyphens` / `num_digits` | counted over the WHOLE normalised URL, not only the host |
| `num_special_chars` | count of characters that are **not alphanumeric** and **not** in the ordinary structural set `:/?#&=._-%~+`. So `@`, `,`, `;`, `!`, `$`, quotes, brackets, braces, pipes and backslashes count; ordinary URL punctuation does not |
| `has_ip_address` | `ipaddress.ip_address(host)` succeeds (IPv4 or IPv6 literal) |
| `has_at_symbol` | `'@' in normalised_url` — `@` introduces *userinfo*, so the true host is after it |
| `has_suspicious_pattern` | 1 if ANY of: (a) `//` inside the path; (b) more than one `?` in the URL; (c) hostname has ≥4 dots (≥5 labels); (d) a brand token appears in the host but the registrable domain does not start with that brand |
| `num_subdomains` | host label count minus the label count of the approximate registrable domain; 0 for an IP host or a bare domain |
| `has_https` | `scheme == 'https'` |
| `is_shortened` | registrable domain is in a maintained STATIC list of 48 shortener domains (no network lookup) |
| `num_suspicious_words` | sum of case-insensitive substring counts of: `login`, `verify`, `update`, `secure`, `account`, `banking`, `confirm` |
| `has_unusual_port` | explicit port present and not in {80, 443} (default ports are removed by normalisation) |
| `has_encoded_chars` | regex `%[0-9a-fA-F]{2}` or legacy `%uXXXX` found |

The brand list for pattern (d) begins with `paypal`, `google`, `microsoft`, `apple`, `amazon`, `facebook`, `netflix`, `ebay`, `instagram`, `linkedin`, `dropbox`, `dhl` … and is maintained in
`BRAND_TOKENS`. These are lexical heuristics, deliberately transparent and
testable — but note they are **inputs to a trained model, not the decision rule**.
No hand-written rule produces a verdict in this system.

---

## 3. Worked examples (safe, controlled strings)

These use reserved example domains only. No live or malicious website is contacted.

| URL string | Selected non-zero features | Teaching point |
| --- | --- | --- |
| `https://example.com/` | `url_length=20`, `domain_length=11`, `num_dots=1`, `has_https=1` | A short, plain, HTTPS URL |
| `example.com` | `url_length=18`, `has_https=0` | Missing scheme is safely defaulted to `http://`, matching training normalisation |
| `http://user@192.168.1.1:8080/secure/login/verify?account=1&next=%2F%2Fevil` | `has_ip_address=1`, `has_at_symbol=1`, `has_unusual_port=1`, `has_encoded_chars=1`, `num_suspicious_words=4`, `num_digits=15` | Several indicators at once; `@` hides the real host |
| `https://a.b.c.example.co.uk//x?y=1?z=2` | `has_suspicious_pattern=1`, `num_subdomains=3`, `num_dots=5` | Deep subdomain chain + double slash + double query |
| `https://bit.ly/abc123` | `is_shortened=1` | Shortener conceals the destination |
| `https://paypal.com.verify-login.evil.example/update` | `has_suspicious_pattern=1`, `num_hyphens=1`, `num_suspicious_words=3` | Brand-in-subdomain impersonation |

A single flagged feature is **not** a verdict. Only the trained estimator in
Stage 5 produces a classification, and Stage 10 adds an abstention band.

---

## 4. Measured feature distributions (training split only)

93,690 legitimate / 71,054 phishing rows from
`dataset/processed/train.csv`. Validation and test were **not** read.

| Feature | Legitimate mean | Phishing mean | Legit present | Phishing present | Observed range |
| --- | --- | --- | --- | --- | --- |
| `url_length` | 27.215 | 51.381 | 100.00% | 100.00% | 14–1769 |
| `domain_length` | 19.215 | 25.865 | 100.00% | 100.00% | 4–110 |
| `num_dots` | 2.188 | 2.526 | 100.00% | 100.00% | 1–43 |
| `num_hyphens` | 0.083 | 0.821 | 7.43% | 40.88% | 0–48 |
| `num_special_chars` | 0.000 | 0.100 | 0.00% | 3.62% | 0–31 |
| `num_digits` | 0.051 | 5.375 | 2.64% | 56.40% | 0–662 |
| `has_ip_address` | 0.000 | 0.008 | 0.00% | 0.77% | 0–1 |
| `has_at_symbol` | 0.000 | 0.019 | 0.00% | 1.90% | 0–1 |
| `has_suspicious_pattern` | 0.019 | 0.091 | 1.90% | 9.12% | 0–1 |
| `num_subdomains` | 1.092 | 1.170 | 100.00% | 79.77% | 0–10 |
| `has_https` | 1.000 | 0.569 | 100.00% | 56.90% | 0–1 |
| `is_shortened` | 0.000 | 0.011 | 0.00% | 1.14% | 0–1 |
| `num_suspicious_words` | 0.001 | 0.092 | 0.07% | 6.87% | 0–6 |
| `has_unusual_port` | 0.000 | 0.000 | 0.00% | 0.02% | 0–1 |
| `has_encoded_chars` | 0.000 | 0.011 | 0.00% | 1.09% | 0–1 |

Descriptive interpretation (correlation, NOT causation):

* `num_hyphens`, `num_digits`, `num_special_chars`, `has_ip_address`, `has_at_symbol`,
  `is_shortened`, `has_encoded_chars` and `num_suspicious_words` are **far more
  common in phishing** in this dataset — consistent with the literature.
* `url_length` averages 27.2 characters for legitimate vs
  51.4 for phishing.

### Critical dataset-bias warnings (confirmed by Stage 6)

1. **`has_https` is a dataset shortcut.** Measured: **100.00%** of
   legitimate URLs and only **56.90%** of phishing URLs use HTTPS.
   In the real world most phishing sites now use free TLS certificates. HTTPS alone does not mean a website is legitimate.
   A model may learn "https → safe" from this data and still be wrong in deployment.
   **Stage 6 confirmed this by measurement**: permutation importance in `docs/EVALUATION.md` §6.1 shows
   `has_https` is the single most influential feature, so reported accuracy is optimistic for real-world
   traffic. Read that section before quoting any performance figure; this limitation appears in the model card
   and must appear in the final report.
2. **`num_subdomains` is dataset-shaped too.** 100.00% of
   legitimate rows have ≥1 subdomain (typically `www.`) versus
   79.77% of phishing rows. Do not present this as a
   universal phishing signal.
3. **`has_unusual_port` has almost no signal here** (0.02% of
   phishing rows). A feature can be required by the brief yet carry little
   information in a given dataset; the model will learn its weight from data.
4. These are *indicators*, never proof. Feature importance in Stage 6 is global
   and correlational; the explanation UI must not claim causation.

---

## 5. What is deliberately NOT a feature

* Page content, HTML, title, favicon, forms, JavaScript count — all 54
  pre-computed source columns were dropped in Stage 3 (ADR-013) because a static
  scanner cannot compute them.
* DNS resolution, WHOIS/domain age, TLS certificate details, redirect chains,
  IP geolocation, reputation APIs. All require network access and would create
  an SSRF surface; the architecture explicitly forbids it.
* Any hand-written "phishing score". Features go into a trained estimator;
  the model makes the decision.

---

## 6. How to run and test

```powershell
# Windows
python scripts\analyse_features.py --limit 5000     # quick check
python scripts\analyse_features.py                 # full training split
python scripts\verify_stage4.py
```

```bash
# Linux / macOS
python scripts/analyse_features.py --limit 5000
python scripts/verify_stage4.py
```

Environment at measurement: Python 3.13.16, pandas 2.3.3.
Full extraction of 164,744 URLs took under 10 seconds on the verification machine.

---

## 7. Limitations

* Lexical features cannot detect a compromised legitimate domain, a redirect
  chain, a malicious page on a clean URL, or a brand-new lookalike domain.
* Static vocabularies (shorteners, brand tokens, suspicious words) can go stale
  and are English-centric; they are documented in code so they can be updated.
* The eTLD+1 approximation used for `num_subdomains` and grouping is a heuristic
  with a built-in two-level suffix list, not a full Public Suffix Library.
* URL shorteners and newly registered domains can evade these features.
* Dataset bias (§4) can make measured performance optimistic. Stage 6 reports
  results with this caveat rather than presenting them as universal accuracy.

**Stage 4 itself trained no model and measured no performance metric.** Stages 5–6 subsequently fitted,
selected and measured a model; the real figures are in `ml/saved_model/metrics.json`,
`docs/EVALUATION.md` and `docs/MODEL_CARD.md`. Nothing in this Stage 4 catalogue is a performance claim.
