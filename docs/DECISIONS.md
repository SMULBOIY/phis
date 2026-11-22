# Architecture Decision Records (ADRs)

Each record states the context, the decision, why it was made, its consequences and how it will be verified. These are the "why" behind `docs/ARCHITECTURE.md`. Status: **Accepted (Stage 1)** unless noted.

---

## ADR-001: One shared feature extractor for training and inference

**Context.** The system must classify URLs in a web request using a model trained on a dataset. If training and live prediction compute features differently (different column order, different normalisation, different library versions), predictions are meaningless — a failure mode called *training–serving skew*.

**Decision.** `ml/feature_extraction.py` is the single source of truth. It exports `FEATURE_ORDER`, `extract_features(url)` and `features_to_frame()`. `ml/preprocess.py`, `ml/train_model.py` and `models/prediction_model.py` all import it. The bundle stores `FEATURE_ORDER` and a `schema_version`; the loader refuses to run on a mismatch.

**Consequences.** One file to maintain; a deliberate constraint that no blueprint may compute ad-hoc features. A feature change requires retraining and a schema-version bump.

**Verification.** Stage 13 test asserts `extract_features` returns exactly 15 keys in `FEATURE_ORDER`, and that `features_to_frame` columns equal the bundle's stored order.

---

## ADR-002: Binary estimator plus an abstention band, not a fake third class

**Context.** The brief requires three result states (LEGITIMATE / PHISHING / SUSPICIOUS), but reputable labelled URL datasets are binary. Inventing "suspicious" labels would be fabricated data.

**Decision.** Train a binary `phishing vs legitimate` classifier. Map `p = P(phishing)` to three states using `T_low` and `T_high`: `p <= T_low` → LEGITIMATE, `p >= T_high` → PHISHING, otherwise SUSPICIOUS. This is *selective prediction / abstention*. SUSPICIOUS means "the model is not confident; unresolved", not a 50% chance of maliciousness.

**Consequences.** Honest three-state UI on genuine binary supervision. Requires threshold calibration (ADR-006) and careful wording (ADR-003). Some legitimate/phishing examples will be abstained on; the abstention rate must be reported.

**Verification.** Stage 13 tests cover all three branches and both boundaries. `metadata.json` records the calibrated values and the selection criterion.

---

## ADR-003: The model score is not a probability of maliciousness

**Context.** `predict_proba` returns the model's estimated class probability under the training distribution; it is often uncalibrated and says nothing about page content, redirects or current reputation.

**Decision.** Every surface labels the number "**Model score**" and defines it as "the model's uncalibrated estimate of P(phishing | URL features)". The UI adds the required warnings: LEGITIMATE is not a guarantee of safety; SUSPICIOUS is an abstention, not a coin flip; PHISHING is "potential phishing detected", not a conviction.

**Consequences.** Slightly longer result text, but no misleading claims. Academic integrity is preserved.

**Verification.** Stage 13 route test asserts the exact wording appears in the HTML and JSON for each state; no template contains "% chance this site is malicious".

---

## ADR-004: Zero outbound network requests in the detection path

**Context.** Accepting arbitrary URLs in a backend is a classic SSRF vector. The brief explicitly forbids automatically visiting submitted URLs.

**Decision.** Feature extraction is lexical only: `urllib.parse`, `ipaddress`, `re`, string counters. No `requests`, `httpx`, `urllib.request`, `socket`, DNS resolution, redirects or reputation APIs anywhere in `services/`, `ml/feature_extraction.py` or `models/prediction_model.py`. Only `http`/`https` schemes are accepted. v2 reputation checks, if ever added, go in an isolated service with host allowlisting, timeouts and size caps.

**Consequences.** No SSRF, no exposure to live malicious sites, offline-capable, deterministic, fast. **Limitation:** cannot inspect content, redirects, certificates, WHOIS or domain age. This limitation goes into the final report.

**Verification.** Stage 13 security test asserts no network-capable module is imported by detection code and that a crafted internal IP URL is analysed as a string only (never fetched).

---

## ADR-005: Layered modular monolith with an application factory and a service layer

**Context.** The suggested structure puts routes at the centre. Detection logic inside a blueprint cannot be reused by the REST API and is hard to test in isolation.

**Decision.** Flask `create_app()` factory; thin blueprints in `routes/`; business logic in `services/`; ORM in `models/`; ML in `ml/`. Adds `routes/api.py`, `wsgi.py`, `scripts/`, `docs/`, `static/vendor/`, `tests/conftest.py` to the suggested layout.

**Consequences.** Slightly more files, but each has one job; tests can create an isolated app with a temp DB and a stub/missing model.

**Verification.** Stage 13 tests use `create_app(TestingConfig)` from `tests/conftest.py`; no blueprint imports another blueprint's internals.

---

## ADR-006: Thresholds and model choice are measured, never assumed

**Context.** The brief forbids invented or hard-coded performance statistics and requires an explicitly defined, justified uncertainty threshold.

**Decision.** Provisional defaults `T_low = 0.30`, `T_high = 0.70` exist in `config.py` as **fallbacks only** and are documented as unmeasured. In Stage 6, `ml/thresholds.py` grid-searches candidate bands **on the validation split** and selects the pair that (1) meets a documented recall constraint on non-abstained phishing predictions, (2) maximises F1, (3) tie-breaks on fewest false negatives, and (4) reports the abstention rate. Model selection uses measured validation F1 with recall as the priority criterion; the **test split is touched once** for final figures. All values go to `metadata.json`/`metrics.json` and one `ModelInformation` row; the UI reads them at runtime.

**Consequences.** No number in the UI can be a lie. The dashboard shows "Model not trained yet" until Stage 6 has run. Requires keeping three splits and a threshold script.

**Verification.** Stage 13 test asserts no numeric accuracy/precision/recall/F1 literal exists in any template or JS file, and that the dashboard renders from `metrics.json`.

---

## ADR-007: Leakage-safe, group-aware dataset splitting

**Context.** Phishing datasets contain near-duplicate URLs (same kit, different tokens). A random row split can place near-identical URLs in train and test, inflating scores — the brief explicitly bans this.

**Decision.** `ml/preprocess.py` removes exact duplicates, normalises URLs, drops null/invalid rows, encodes labels (`0 legitimate`, `1 phishing`), reports class distribution, then splits by **group** (registrable domain + path signature), stratified by label, into train / validation / test. Split manifests (row hashes) are saved under `dataset/processed/` for reproducibility.

**Consequences.** Honest, usually slightly lower, reported performance; reproducible experiments. A less convenient split implementation.

**Verification.** Stage 13 test asserts zero group overlap between splits and that class counts in `docs/DATASET.md` match the processed files.

---

## ADR-008: SQLAlchemy ORM + SQLite, with nullable `user_id` for guest scans

**Context.** The brief wants SQLite, SQLAlchemy, secure password storage, relationships and three tables. Landing-page visitors should be able to try a scan.

**Decision.** Three tables: `User`, `ScanHistory`, `ModelInformation`. `ScanHistory.user_id` is nullable (`ON DELETE SET NULL`) so guest scans persist; `prediction` and `risk_level` are constrained to the three allowed values; indexes on `scan_date`, `prediction`, `user_id`. All access through the ORM with bound parameters. Passwords via `werkzeug.security.generate_password_hash`; `password_hash` is never serialised or logged. Timestamps UTC. SQLite file lives in `instance/` (outside the static root) and is gitignored.

**Consequences.** Simple single-file deployment, no DBA needed. SQLite is not suited to high-concurrency multi-writer production — noted as a limitation. If you require login for every scan, flip this ADR before Stage 8 (see open decision 3).

**Verification.** Stage 13 tests cover CRUD, cascade behaviour, uniqueness, constraints and hashing (assert the stored value is not the plaintext).

---

## ADR-009: Fail loudly when the model artefact is unavailable

**Context.** A missing/corrupt/version-mismatched `model_bundle.joblib` must not produce a confident-looking verdict. A rule-based fallback would misrepresent the project as ML-driven.

**Decision.** `ModelUnavailableError` is raised by `models/prediction_model.py` on any load/validation failure. Web routes show a neutral "Detection model unavailable" state; `/api/v1/scan` returns `503 MODEL_UNAVAILABLE`. No fallback classifier, no hard-coded score.

**Consequences.** An honest outage instead of a fake result; straightforward to test.

**Verification.** Stage 13 test renames/removes the bundle in a temp directory and asserts 503 / the neutral page, with no verdict text.

---

## ADR-010: Local vendor assets and a strict Content Security Policy

**Context.** The in-app file preview has no network access; a CDN-dependent dashboard would be blank. CDNs also weaken CSP and leak visitor IPs to third parties.

**Decision.** Bootstrap 5, Bootstrap JS and Chart.js are downloaded once into `static/vendor/` in Stage 9, served locally. CSP disallows third-party script/style origins. Chart data is passed as inline JSON generated by Jinja (never by concatenating user input into a script tag).

**Consequences.** Offline-capable, CSP-friendly, reproducible. A few vendored files in the repo.

**Verification.** Stage 13 route test asserts no `cdn.` / `https://` asset URL appears in rendered HTML and that the CSP header is present.

---

## ADR-011: No application code before its stage is reached

**Context.** The brief demands staged delivery, complete files, and no placeholder functions pretending to work.

**Decision.** Stage 1 contains only documentation, the directory skeleton, `.gitignore` and the verification script. `scripts/verify_stage1.py` fails if any `*.py` file appears in `ml/`, `models/`, `routes/`, `services/` or `tests/` before its stage. Each later stage provides complete, runnable files — never stubs.

**Consequences.** Slower start, but every stage can be tested and defended independently, which is exactly what a final-year project defence needs.

**Verification.** `python scripts/verify_stage1.py` exits 0.

---

## ADR-012: PhiUSIIL / UCI dataset 967 is the training source

**Context.** The brief demands a properly labelled dataset from a reputable source, with documented provenance, and forbids fabricated training rows. The chosen dataset must contain **raw URL strings** because the project's contribution is URL-based lexical feature extraction.

**Decision.** Use *PhiUSIIL Phishing URL (Website)*, UCI Machine Learning Repository dataset 967 (CC BY 4.0, DOI `10.1016/j.cose.2023.103545`), downloaded from the fixed UCI archive URL with pinned SHA-256 hashes. Measured: 235,795 rows, 56 columns, 134,850 legitimate / 100,945 phishing, no missing values. UCI dataset 327 was rejected because it contains 30 pre-computed features and **no raw URLs**.

**Consequences.** Citable and reproducible; requires attribution in the report. The data was donated in March 2024, so age/representativeness limitations must be stated. The download is a one-off developer action (`scripts/download_dataset.py`); the running app makes no network requests.

**Verification.** `scripts/verify_stage3.py` checks both pinned SHA-256 hashes and that `docs/DATASET.md` contains every measured fact from `manifest.json`.

---

## ADR-013: Discard all 54 pre-computed columns

**Context.** The source CSV includes features derived from downloaded webpage source code (`LineOfCode`, `HasTitle`, `HasPasswordField`, `NoOfJS`, ...), plus URL-derived features computed by the original authors, plus a `FILENAME` identifier.

**Decision.** Read **only** `URL` and `label`. Recompute all features in Stage 4 from the raw string with our own `ml/feature_extraction.py`.

**Consequences.** Prevents *unavailable-feature leakage*: a model trained on page-content features cannot be deployed by a scanner that never fetches URLs. Also prevents two subtly different definitions of "URL length" coexisting. Symbolically weaker than the original paper's model, but honest and deployable — this is a project about static URL analysis, not a reproduction of PhiUSIIL's full framework.

**Verification.** `ml/preprocess.py` uses `usecols=["URL", "label"]`; the manifest records all 54 dropped column names; `verify_stage3.py` asserts each split CSV has exactly `url, label, group_id`.

---

## ADR-014: Group-aware splitting with union-find, not a random row split

**Context.** Phishing datasets contain near-identical kit URLs across many disposable-hosting domains. A random `train_test_split` leaks these across train and test, inflating measured accuracy — the brief explicitly forbids this.

**Decision.** Build whole leakage groups via union-find over (a) an approximate registrable domain and (b) near-duplicate path signatures (masked digit runs / long tokens, sorted query keys). Path signatures seen in more than 20 distinct domains are treated as "generic" and excluded from merging, otherwise the single `/` signature would connect the entire dataset. Assign whole groups to splits with a largest-remaining-capacity greedy pass, then repair class balance by swapping whole size-1 groups. Split 70/15/15, seed 42.

**Consequences.** Measured zero overlap of groups, URLs and non-generic signatures across splits. A 23,675-URL, 99.7%-phishing kit cluster spanning 420 hosting domains is confined entirely to training. Test-set diversity is slightly reduced — an accepted trade-off to avoid inflated metrics. Two earlier greedy objectives (relative deviation, absolute chi-square cost) were tried, measured, found to distort the ratio and class balance, and replaced.

**Verification.** `dataset/processed/leakage_report.json` plus independent recomputation in `scripts/verify_stage3.py`; split sizes 164,744 / 35,302 / 35,302; phishing rate within 1pp of the overall 42.70% in every split.

---

## ADR-015: One canonical, network-free URL normaliser

**Context.** `docs/ARCHITECTURE.md` §7 requires that preprocessing and live prediction see the same normalised string. Stage 3 needed normalisation before Stage 4's `services/validation.py` exists.

**Decision.** Create `ml/url_utils.py` in Stage 3 as the single authority. It uses only the standard library, performs no I/O, lowercases scheme/host only, preserves userinfo (`@`), non-default ports, encoded characters and fragments, and enforces the 2,048-character limit. Stage 4's feature extractor and Stage 10's live validator will import it rather than reimplementing it.

**Consequences.** Adds one small module to the suggested folder structure, but removes training–serving skew and gives the SSRF guarantee a concrete enforcement point (no socket/DNS/HTTP imports).

**Verification.** `verify_stage3.py` asserts idempotence, controlled valid/invalid cases, multi-label suffix handling, signature masking, and that `url_utils.py` contains no network-capable imports.

---

## ADR-016: One implementation of the 15-feature contract

**Context.** `docs/ARCHITECTURE.md` §7 fixes 15 URL features. If training computes them in a notebook and the live app reimplements them in a route, the two definitions drift silently — the classic training-serving skew that produces a model which looks good offline and fails in use.

**Decision.** `ml/feature_extraction.py` is the ONLY implementation. It exports an immutable `FEATURE_ORDER` tuple, `FEATURE_DEFINITIONS`, `FEATURE_RATIONALES`, `extract_features(url)`, `features_to_frame(dict)` and `extract_frame(urls)`. `extract_features` normalises with `ml.url_utils.normalize_url`, returns exactly 15 non-negative `int` values in that order, raises `ValueError` on invalid input, and raises `RuntimeError` if its own output ever disagrees with the contract. `scripts/analyse_features.py`, Stage 5 training, Stage 6 evaluation and Stage 10 detection all import it.

**Consequences.** No duplicate feature code, no reindexing bugs, no NaN. Slight coupling: any future feature change requires a schema-version bump and full retraining. `services/validation.py` (Stage 4) wraps the same normaliser at the trust boundary; the stage gate asserts parity between raw, validated and stored-normalised inputs.

**Verification.** `verify_stage4.py` checks the exact tuple, documentation coverage, 16 controlled URL cases, invalid-input rejection, frame shapes/dtypes, 2,000 real training rows, and absence of any network-capable import.

---

## ADR-017: Lexical heuristics are model INPUTS, not the classifier

**Context.** `has_suspicious_pattern`, `is_shortened`, `num_suspicious_words` and the brand/shortener vocabularies look like rules. The brief explicitly forbids rules as the primary detection method.

**Decision.** These are transparent, deterministic, testable feature extractors whose output is a number. No combination of them produces a verdict. Only a trained estimator (Stage 5) maps the 15-number vector to a phishing score, and Stage 6 calibrates the abstention band from validation data. The vocabularies are static code constants, never fetched from an API.

**Consequences.** The system satisfies "genuine ML pipeline". Explanations in the UI (Stage 10) are flagged indicators and learned feature importance — described as correlations, not causation. Static lists can go stale and are documented as a limitation.

**Verification.** `verify_stage4.py` asserts no model artefact or verdict logic exists yet, and `docs/FEATURES.md` states that no hand-written rule produces a decision.

---

## ADR-018: Disclose the HTTPS dataset shortcut instead of exploiting it

**Context.** Stage 4 EDA on 164,744 training URLs measured `has_https` present in **100.00%** of legitimate rows and **56.90%** of phishing rows. A model trained on this data could learn "https → safe", which is false in the real world where attackers obtain free TLS certificates. The brief states "HTTPS alone does not mean a website is legitimate."

**Decision.** Keep `has_https` (it is a required feature) but record the bias prominently in `docs/FEATURES.md`, `README.md` and the model card in Stage 6. Do not drop it silently, do not rebalance to hide it, and do not present measured accuracy as universal. EDA reads ONLY the training split; validation and test are explicitly excluded and recorded as such.

**Consequences.** Reported metrics may be optimistic; this belongs in the Limitations chapter and must be discussed at the viva. It also gives the project a defensible, honest evaluation narrative rather than an inflated accuracy claim.

**Verification.** `verify_stage4.py` asserts the measured percentages appear in `docs/FEATURES.md`, that the bias really exists in `feature_summary.json`, and that `splits_read == ["train"]`.

---

## ADR-019: Training and evaluation are separate stages

**Context.** The brief requires training three models, comparing them by measured performance and selecting the best. Doing all of that in one script makes it very easy to peek at the test split while tuning — and then to report an inflated number.

**Decision.** Stage 5 (`ml/train_model.py`) fits and persists exactly three candidate pipelines on `train.csv` only. It imports no metric functions, computes no score, and writes a manifest with `evaluation_performed: false`, `selection_performed: false`, `metrics_measured: []`. Stage 6 owns validation scoring, model comparison, abstention-band calibration, final test scoring and the `model_bundle.joblib` / `metrics.json` / `metadata.json` artefacts.

**Consequences.** A clean, defensible audit trail. Slight extra work (candidate bundles exist before a winner is known), but the whole candidate directory is under 1 MB. The gate enforces the separation by scanning `ml/train_model.py` for `sklearn.metrics` and for the names of the held-out CSV files.

**Verification.** `verify_stage5.py` checks the three honesty flags, recalculates every artefact SHA-256, and asserts that no Stage 6 files exist yet.

---

## ADR-020: Fixed, documented hyperparameters instead of a hidden grid search

**Context.** A depth-capped Random Forest is a design choice, not an optimum. The brief asks for a genuine ML pipeline but does not require hyperparameter optimisation.

**Decision.** Use fixed, recorded settings: `seed=42`, LR `lbfgs`/`max_iter=1000` with `StandardScaler`, tree/forest `max_depth=12`, `min_samples_leaf=10`, forest `n_estimators=100`. `class_weight=None`. No cross-validated search is performed at this stage; a tuning study is listed as future work in the report's Recommendations chapter. The recall priority required by the brief is implemented in Stage 6 through a validation-set threshold constraint, not by reweighting here (which would distort `predict_proba` before calibration).

**Consequences.** Fully reproducible, small artefacts, honest "these are not claimed optima" statement. Stage 6's measured comparison may show a candidate underperforming — that result will be reported, not hidden.

**Verification.** Every hyperparameter is in `training_manifest.json` and `docs/TRAINING.md`; `verify_stage5.py` asserts they are non-empty and that the seed is recorded in each bundle.

---

## ADR-021: Bitwise-deterministic inference via `n_jobs=1`

**Context.** While verifying Stage 5, two calls to `RandomForestClassifier.predict_proba` on the SAME 30 URLs differed by **2.22e-16** when `n_jobs=-1`. scikit-learn accumulates tree votes into a shared array from several threads, so floating-point summation order varies. The difference is numerically irrelevant but would let two scans of the same URL display slightly different model scores.

**Decision.** Fit and predict the Random Forest with `n_jobs=1`. Measured cost: training rose from ~2.2 s to ~4.2 s on 164,744 rows — negligible. `numpy.array_equal` now returns `True` across repeated predictions.

**Consequences.** Stable, reproducible scores in the UI and in the scan-history table. Parallelism can be reconsidered only if a future dataset makes training genuinely slow, and only with a documented tolerance for the last-bit jitter.

**Verification.** `verify_stage5.py` asserts `np.array_equal(proba, proba_again)` for all three delivered bundles and checks determinism of a freshly trained fixture forest with a fixed seed.

---

## ADR-022: Selection criterion and abstention band are fixed a priori

**Context.** The brief asks for the "best" model by measured performance, prioritising recall / false negatives, and for an "explicitly defined uncertainty threshold" with documented selection. A criterion chosen after seeing the results would be scientific cherry-picking.

**Decision.** In `ml/thresholds.py`, fixed before any evaluation: grid-search `(T_low, T_high)` on validation only, step 0.05, `T_low ∈ [0.05, 0.45]`, `T_high ∈ [0.55, 0.95]`, gap ≥ 0.10. Feasible pairs must satisfy recall ≥ **0.90** on decisive predictions, abstention ≤ **0.25**, gap ≥ 0.10. Objective: maximise F1 on decisive predictions; tie-break by fewest false negatives, then lowest abstention rate, then thresholds. Model selection uses the same objective across candidates, tie-broken by highest validation ROC-AUC. The test split is loaded and scored exactly once after selection.

**Consequences.** A phishing URL inside the band is SUSPICIOUS (unresolved), not a false negative, because it was never declared safe. The 25% abstention cap prevents gaming recall by abstaining on every hard case. The measured outcome is a fairly wide band with roughly one in five URLs unresolved — an honest trade-off for fewer false negatives, reported explicitly in `docs/EVALUATION.md` §6.2 rather than presented as extra accuracy. A tighter cap or abstention penalty is documented as future work, not retrofitted.

**Verification.** `verify_stage6.py` re-derives the ranking from published per-model numbers, asserts the selected model equals the objective winner, checks both constraints on the chosen band, and tests the grid search on controlled fixtures including an infeasible case that must raise.

---

## ADR-023: Publish the measured HTTPS shortcut, do not hide or "fix" it

**Context.** Stage 4 found 100.00% of legitimate training URLs use HTTPS vs 56.90% of phishing URLs. Stage 6 permutation importance confirmed the consequence: `has_https` has by far the largest mean decrease in ROC-AUC, ahead of `url_length` and `domain_length`.

**Decision.** Keep `has_https` (the brief requires it) and publish the measured importance in `metrics.json` (`bias_analysis`), `metadata.json` limitations, `docs/MODEL_CARD.md` §5 and `docs/EVALUATION.md` §6.1, with the explicit statement that **HTTPS alone does not mean a website is legitimate** and that reported accuracy is optimistic for real-world traffic. Do not silently drop the feature, rebalance the data to hide the bias, or claim the metrics are universal. An ablation study retraining without `has_https` is recorded as recommended future work for the Recommendations chapter.

**Consequences.** The project's headline accuracy must always be presented with the qualifier "on a held-out sample of the PhiUSIIL distribution". This is a defensible academic stance and a strong viva talking point. It also constrains Stage 9–11: charts and cards must read `metrics.json` at runtime so they can never show a stale or invented number.

**Verification.** `verify_stage6.py` asserts the measured `has_https` importance is present in the metrics and docs, that both generated docs contain the exact caveat, and that `bias_analysis.https_is_largest_feature` is derived from the measured values.

---

## ADR-024: The auth blueprint ships only what genuinely works; `/login` and `/register` move to Stage 8

**Context.** The Stage 1 architecture listed `routes/auth.py` under "Stage 7/12" with register, login, logout, password hashing and sessions. The Stage 7 preview promised "the first blueprint (`routes/auth.py`)". But `/login` and `/register` need the `User` entity, a `password_hash` column, `generate_password_hash`/`check_password_hash` and an ORM-backed `user_loader` — all Stage 8. Creating those routes now would require either a fake in-memory user store that Stage 8 immediately throws away, or endpoints that return "coming soon". The brief explicitly forbids empty stubs and pretending incomplete functionality works.

**Decision.** Deliver `routes/auth.py` in Stage 7 with three fully working endpoints: `GET /auth/session`, `GET /auth/csrf-token`, `POST /logout`. `/auth/session` reports which auth routes *actually exist* by inspecting `current_app.view_functions`, so it cannot claim a login page that is absent. `login_manager.user_loader` returns `None` because no persistence layer exists — that is fail-closed, correct behaviour for a stale session cookie, not a stub. Stage 8 extends the same blueprint with `/login`, `/register`, scrypt hashing and an ORM lookup, and sets `login_manager.login_view = "auth.login"`.

*Correction recorded in Stage 8:* the original ADR predicted that `app.py` and `routes/__init__.py` would not change. They did — `app.py` must import `configure_database` and replace the `user_loader`, and `routes/__init__.py`'s roadmap comment needed updating. Flask-Login's callback precedence also made a plain `login_view` redirect impossible (see ADR-027). The ADR is kept, with this correction, rather than silently rewritten.

**Consequences.** The project remains guest-only for one stage, which is compatible with `guest_scans=guests_yes`. CSRF becomes demonstrably testable immediately (token-less POST → `400 CSRF_FAILED`). The Stage 7 gate asserts `login_available` and `register_available` are `False` and that `/scan`, `/dashboard`, `/api/v1/scan`, `/login` and `/register` are absent from the URL map. This is a file-level scheduling refinement, not a skipped stage.

**Verification.** `verify_stage7.py` checks the session-state response, the URL map, CSRF rejection/acceptance, and the `401 UNAUTHENTICATED` path from `@login_required`.

---

## ADR-025: Frame-ancestor protection is strict in production and relaxed only for the development live preview

**Context.** Clickjacking defence requires `X-Frame-Options: DENY` and CSP `frame-ancestors 'self'`. The Arena live preview, however, displays a development server inside an iframe served from a different origin. Sending either header in development produces a blank preview, which would hide the working Stage 7 UI from the student.

**Decision.** Move the framing policy into configuration: `BaseConfig.X_FRAME_OPTIONS = "DENY"` and `CSP_FRAME_ANCESTORS = "'self'"`; `DevelopmentConfig` and `TestingConfig` set both to `None` so `services/http_security.py` omits those directives. Production keeps them strict and additionally sends HSTS. `create_app()` re-validates the effective config, so an accidental `DEBUG=True` or weakened CSRF/cookie setting in production still refuses startup. The CSP remains strict in every environment (no `unsafe-inline` scripts, local assets only).

**Consequences.** The relaxation is development-only, config-driven and documented in `docs/BACKEND.md`; it is not present in the deployed posture. A related browser rule is documented too: `SESSION_COOKIE_SAMESITE="Lax"` means the cross-origin preview iframe will not send session cookies for subrequests, so interactive CSRF tests use Flask's test client rather than the iframe. Neither relaxation affects static URL analysis or SSRF safety.

**Verification.** `verify_stage7.py` asserts that development/test omit `X-Frame-Options` and HSTS, that production sends `DENY`, `frame-ancestors 'self'` and HSTS, and that the CSP never allows inline scripts.

---

## ADR-026: Keep the 401 error contract; make `login_view` declarative, not a redirect promise

**Context.** Stage 7 registered a `LoginManager.unauthorized_handler` that returns `401 UNAUTHENTICATED` (JSON on `/api/*`, HTML elsewhere). Stage 8's brief requires `/login` and `/register` plus an ORM-backed `user_loader`; the Stage 1 architecture also mentions a `login_view` redirect. Reading the installed `flask_login.LoginManager.unauthorized()` source showed that a registered `unauthorized_callback` is invoked **before** `login_view` is consulted. Therefore simply assigning `login_manager.login_view = "auth.login"` would never produce a redirect, and any documentation claiming it did would be false.

**Decision.** Set `login_manager.login_view = "auth.login"` as declarative configuration (so `login_manager.login_view` is discoverable and future `login_manager.unauthorized()`-based helpers can use it), but **keep** the explicit `401 UNAUTHENTICATED` handler as the active behaviour. Rationale: protected resources include a future REST API, which must receive JSON 401 rather than an HTML 302; a single global redirect would break that contract and leak information about session state. Stage 11 may add content negotiation (HTML GET → redirect with `?next=`, JSON/API → 401) in one place, with tests for both branches. Stage 8 also widens `make_error_response()` to honour `request.is_json` and `?format=json`, so JSON clients calling `/login` or `/register` get JSON errors instead of HTML.

**Consequences.** Positive: the documented error contract is unchanged, Gate 7's `@login_required` 401 test still passes, and no endpoint pretends to redirect. Negative: an HTML-only protected page currently shows a 401 error rather than bouncing to the sign-in form; this is documented in `docs/DATABASE.md` §7 and `docs/BACKEND.md`, not hidden. `login_manager.login_view` is asserted by `verify_stage8.py`, and the 401 behaviour is asserted by both Gates 7 and 8.

**Verification.** `verify_stage8.py` checks `login_manager.login_view == "auth.login"` and that `@login_required` still returns `401 UNAUTHENTICATED`; `verify_stage7.py` retains its own 401 regression check.

---

## ADR-027: `ModelInformation` is a measured audit record, seeded only by an explicit CLI

**Context.** The Stage 8 brief requires a `ModelInformation` table with model performance fields. It would have been easy — and academically indefensible — to type the Stage 6 headline numbers into `scripts/init_db.py`, or to insert nulls/defaults when artefacts are missing. Either would create a second copy of the results that could drift, or an invented statistic. Stage 7 already established the rule that no measured metric appears in backend source, `/` or `/health`.

**Decision.** Split responsibilities: (1) booting a Flask app **never** creates tables, so a multi-worker WSGI deployment cannot race on `create_all()`; (2) `python scripts/init_db.py` is the explicit, idempotent bootstrap; (3) `services/database_service._measured_values()` reads `metadata.json`, `metrics.json` and `training_manifest.json` at runtime, validates `test.scored_once`, the five `[0,1]` metrics, the three split SHA-256 digests and the 15-feature contract, then copies the values into one row keyed by `(model_name, model_version)`; (4) any missing/inconsistent artefact raises `ModelDataError` and exits `2` — no nulls, no defaults; (5) `init_db.py` creates **zero** user accounts and `scripts/create_admin.py` is the only path to an administrator, so the repository ships no default credentials.

**Consequences.** The five stored numbers always equal the published held-out test figures; `verify_stage8.py` compares each one to `metrics.json`. Running `init_db.py` twice refreshes rather than duplicates the row. The `/health` payload and status page show only table names and row counts — never a metric — so the "no hard-coded statistics in the UI" rule survives. A fresh clone must run the Stage 5/6 pipeline (or restore the artefacts) before bootstrap can succeed; the error message says exactly which commands to run. Stage 11's admin dashboard reads this row or `metrics.json` at runtime.

**Verification.** `verify_stage8.py` §6 asserts all five stored metrics equal `metrics.json`, that the fingerprint is a 64-hex SHA-256, that `metrics_source` names the artefact, that `init_db.py` is idempotent and creates no users, and that `create_admin.py` refuses weak passwords and never echoes the password. §1 statically rejects any measured float literal inside Stage 8 source.

---

## ADR-028: Vendor the UI libraries locally and keep a single, strict CSP

**Context.** The brief requires HTML5/CSS3/JS, Bootstrap 5 and Chart.js. The obvious implementation is two CDN `<link>`/`<script>` tags. That conflicts with three established constraints: `services/http_security.py` sends `default-src 'self'` with `script-src 'self'` and `style-src 'self'` (no `unsafe-inline`); the Arena live preview and the workspace file viewer are sandboxed iframes with no external network; and a final-year project must render identically on an offline lab machine. A second problem: the theme must be applied **before** first paint, which normally invites an inline `<script>` in `<head>` — also blocked by the CSP.

**Decision.** Copy Bootstrap 5.3.3 CSS, its `bootstrap.bundle.min.js` (including Popper) and Chart.js 4.4.4 UMD **unmodified** into `static/vendor/`, record their exact sizes and SHA-256 digests in `static/vendor/README.md`, and recompute those digests in the stage gate. Serve all assets from Flask's `static` endpoint. Split the JavaScript: a tiny external blocking `theme.js` in `<head>` sets `data-theme` before paint; `main.js` (deferred) owns all interactive behaviour. Pass data to Chart.js through an escaped `data-*` attribute rendered with Jinja's `|tojson`, never through an inline script block. Guard every `localStorage` access with `try/catch` because a sandboxed iframe without `allow-same-origin` throws `SecurityError`.

**Consequences.** Positive: the UI is fully offline, reproducible from pinned hashes, and the CSP is unchanged and still testable. The theme toggle works in the preview iframe (persistence alone degrades). Negative: ~520 KB of vendored files are committed, and the upstream `chart.umd.min.js` is the un-minified UMD build (jsDelivr notes that it was already bundled). Both are acceptable for an academic project and documented in `docs/UI.md` §4. Any CDN addition in a later stage must be an explicit ADR, not a convenience edit.

**Verification.** `verify_stage9.py` recomputes all three hashes, asserts every template has no inline script content / `style=` attribute / inline event handler / external `src`/`href`, asserts `theme.js` sets `data-theme` and guards storage errors, asserts `main.js` parses `data-chart` with `JSON.parse` and creates `new window.Chart(...)`, and re-checks the CSP on the rendered page.

---

## ADR-029: The Stage 9 landing page stays honest — no scan control, no invented chart data

**Context.** Stage 9 delivers the "modern cybersecurity UI", and the brief eventually requires a landing page with a hero scan box and an exact `"SCAN WEBSITE"` button. But the detection engine is Stage 10: there is no `predict_proba`, no `ScanHistory` write and no decision service yet. Showing a scan box now would either be a dead control or a fake result — both explicitly forbidden. Separately, Stage 9's exit criterion asks for charts that "render from inline data", which could be satisfied by typing attractive numbers into JavaScript.

**Decision.** Keep **no** `/scan` route, **no** URL input and **no** `"SCAN WEBSITE"` string anywhere in templates or static files. Add a prominent "URL scanning is not wired yet" banner to the overview explaining that Stage 10 delivers it. Deliver exactly one chart: a doughnut of the real PhiUSIIL-derived **dataset split row counts**, read at runtime from `metadata.json#dataset.split_sizes` through `ModelRegistry.dataset_chart()`, embedded as `data-chart='{{ split_chart|tojson }}'` and parsed by `main.js`. Those are provenance counts, not model results. No template or script may reference `metrics.json` or `predict_proba`, and no measured-metric word may appear in the rendered page. The three decision-state cards show the exact contract strings/colours/warnings from `ml/thresholds.py`, because those are definitions, not measurements.

**Consequences.** Positive: the interface is visually complete and academically defensible; a viva examiner cannot find an invented statistic or a button that lies. Negative: the hero has no primary call-to-action for scanning yet, which is a deliberate, documented one-stage gap. Stage 10 will replace the banner with the real form and keep all other layout intact. The Stage 7/8 gates assert the button's absence; they become stage-aware when Stage 10 is delivered.

**Verification.** `verify_stage9.py` asserts `"SCAN WEBSITE"` and `/scan` are absent from templates and the URL map, that no template/JS hard-codes a measured-metric word or `predict_proba`, that the rendered chart payload equals `metadata.json` exactly, that the HTTPS caveat and the "LEGITIMATE is not a guarantee" warning are present, and that `/` and `/health` remain free of performance figures. Gates 7 and 8 retain their own independent absence checks.


---

## ADR-030: Fail closed on every detection dependency — no rule fallback, no unlogged result

**Context.** Stage 10 must wire `predict_proba`, but a deployed web app has three
independent dependencies that can break: the hash-verified Joblib bundle, the
measured provenance in `metrics.json`, and the SQLite schema. A tempting
"robust" implementation would show a heuristic verdict when the model is
missing, or show a result even when the audit insert fails. Both would be
academic misconduct: the first silently replaces machine learning with rules,
and the second lets the UI claim something the history cannot corroborate.
Stage 7 already established the `503 MODEL_UNAVAILABLE` contract for a bad
bundle hash.

**Decision.** Introduce one `DetectionRegistry` attached to `app.extensions`,
constructed at boot **after** `ModelRegistry` verifies the bundle SHA-256. It
loads the estimator exactly once and reads measured feature importance; either
failure sets `error` instead of raising out of `create_app`. `POST /scan` maps
`InvalidSubmissionError` → `400 INVALID_URL`, `DetectionUnavailableError` →
`503 MODEL_UNAVAILABLE`, and `DetectionStorageError` → `503
DATABASE_UNAVAILABLE`. A scan result is returned **only after**
`db.session.commit()` succeeds. `/health` reports the engine's real status, and
`GET /scan` shows an ENGINE UNAVAILABLE banner rather than a working-looking
button. There is no fallback score, no default prediction and no
`if feature then verdict` rule anywhere in the request path.

**Consequences.** Positive: a viva examiner can delete or corrupt the bundle and
see an honest, documented failure; the audit table is guaranteed to describe
every result a user saw. Negative: a database outage blocks scanning even
though inference itself is local — an intentional trade-off for auditability.
`verify_stage10.py` builds a **hash-consistent but corrupt pickle** (so the
integrity check passes and `joblib.load` genuinely fails), plus missing-bundle
and missing-provenance cases, and asserts `/health` degrades to 503, the form
advertises the outage, and no verdict card or classification key is emitted.

**Verification.** Gate 10 asserts `joblib.load(` appears only in
`models/prediction_model.py`, that `detection_service.py` has no fallback
symbols, that the commit precedes the return, and that all three failure cases
produce the documented codes with no traceback and no classification.

---

## ADR-031: Keep policy, explanation and orchestration as separate pure modules

**Context.** The brief requires suspicious-feature explanations, a recommended
action and an explicit uncertainty statement, but also requires a genuine ML
pipeline rather than a rule engine. Putting "if `has_at_symbol` then suspicious"
logic next to the verdict would blur that line and would effectively create a
second, unmeasured classifier. It would also make it easy for UI prose to drift
from `ml/thresholds.py`.

**Decision.** Split three concerns:

* `services/decision_service.py` — a pure `decide(score, low, high)` that reuses
  `ml.thresholds.decision_codes`, `STATE_NAMES`, `DECISION_STATES` and
  `SCORE_MEANING`. It never parses a URL and never inspects a feature.
* `services/explanation_service.py` — a pure `explain(features, decision,
  importance)` that reads definitions/rationales from
  `ml.feature_extraction` and ranks by **measured** permutation importance
  supplied at runtime. It contains no `decide()` call and sets no `prediction`.
  `has_https` is deliberately excluded from the indicator set; the exact
  caveat "HTTPS alone does not mean a website is legitimate" is always shown.
* `services/detection_service.py` — the only stateful orchestrator, owning
  validation, inference, the transaction and the result object.

`metadata.json` is asserted equal to `DECISION_STATES` and `SCORE_MEANING` by
the gate, so prose cannot drift. The score is always labelled an uncalibrated
`predict_proba` estimate, never a guaranteed probability of maliciousness.

**Consequences.** Positive: the verdict is unambiguously model-based; every
explanation sentence is traceable to a documented feature or a measured value;
all three modules are unit-testable without Flask. Negative: explanations are
descriptive rather than counterfactual ("changing X would change the score"),
because the standardised linear model's correlated features do not support
honest per-feature contribution claims. The observed sensitivity to trivial URL
edits is disclosed in `docs/DETECTION.md` §6 instead of being re-tuned away.

**Verification.** Gate 10 checks boundary decisions at 9 score points, exact
strings/colours/warnings, rejection of invalid scores and thresholds, 15
documented insights, measured-importance ordering, the HTTPS caveat,
correlational wording, and that `explanation_service.py` contains no verdict
assignment.

---

## ADR-032: One dedicated scan page, strict URL-only analysis, access-controlled reports

**Context.** The original brief sketches a landing-page hero scan box with the
exact `"SCAN WEBSITE"` button, but Stage 9's landing page is a telemetry
overview with a provenance chart and decision-state cards. Duplicating the form
on both `/` and `/scan` would create two CSRF forms to maintain and would make
Gate 7/8/9's honest "no non-functional scan button" assertions meaningless.
Separately, a printable report endpoint can trivially become an unauthenticated
URL enumeration oracle, and any live URL fetching would introduce SSRF.

**Decision.** Keep the exact `"SCAN WEBSITE"` button on **one** dedicated page,
`GET/POST /scan`, reached from a prominent "Launch URL scanner" call-to-action
and a `Scan URL` navigation link. The overview keeps every Stage 9 telemetry
card and now shows the live engine status. Share the form and result markup via
`templates/partials/scan_result.html`. `GET /scan/<id>/report` rebuilds its
display from the saved row (no re-inference, no second row) and is authorised:
a signed-in user sees only their own rows; a guest row is visible only to the
signed Flask session that created it (bounded id list); missing and unauthorised
ids return the same generic `404`. The backend performs **zero** outbound
network I/O — no HTTP client, no DNS, no socket — and the gate proves it by
patching `socket.socket.connect` to raise while scanning loopback and
link-local URL strings.

**Consequences.** Positive: one form, one audit path, no SSRF surface, no
history leak, and the Stage 9 gates remain meaningful with a small stage-aware
adjustment. Negative: the landing hero is a link rather than an inline input —
a deliberate, documented deviation from the sketch, recorded here. Claiming
guest rows after sign-in, full history, dashboards, admin views and CSV export
are Stage 11. Rate limiting and the REST API remain Stage 12.

**Verification.** Gate 10 asserts the exact button appears in `scan.html` and in
no other template, that `/` still has no non-functional button, that the report
creates no extra row, that a second browser session gets `404`, and that scans
succeed with all socket connections patched to raise.

---

## ADR-033 — Dashboard statistics are runtime reads, never typed values

**Context.** Stage 9 deliberately forbade any measured performance figure in
the UI because none had been wired to a real source. Stage 11 is the first
stage that must display "KPIs" and charts. The brief requires dashboard
statistics to come from the database and the measured artefacts; a template
containing `0.983854` or a JS file containing invented counts would create a
second copy that could silently drift from `metrics.json`.

**Decision.** `services/stats_service.py` is the only source of dashboard
numbers. It counts `scan_history` / `users` / `model_information` with SQL
`COUNT` / `GROUP BY` at request time and reads `metrics.json#test` with strict
validation (`test.scored_once`, five bounded metrics, a usable confusion
matrix, calibrated band figures). Any missing or inconsistent artefact raises
`StatsDataError` and the route returns `503 MODEL_UNAVAILABLE`; an empty
database returns honest zeros and empty states. The single derived value, the
SUSPICIOUS share, is labelled as a share of *this database's rows*. Every
displayed metric names its exact source key and is accompanied by the held-out
test-split, HTTPS-bias, recall-priority and abstention caveats. No published
figure appears in a template, a JS file or Stage 11 Python source.

**Consequences.** Positive: no drift, no invented statistics, no demo data, and
the "measured-only" rule from Stage 6 remains enforceable. The three charts
reuse Stage 9's `data-chart` payload contract, so no new JS file is needed;
`cycledColours()` extends the theme palette to seven daily bars without a
hard-coded colour list. Negative: the dashboard and admin page are unavailable
if `metrics.json` is missing — a deliberate fail-closed choice, documented in
`docs/DASHBOARD.md` §11.

**Verification.** Gate 11 compares every KPI and chart value against exact SQL
counts, checks honest zeros on an empty database, checks the daily chart has
seven UTC labels and sums to the row count, checks all five measured values
against `metrics.json`, writes a tampered copy of `metrics.json` with a changed
accuracy and asserts the rendered page changes, and asserts no published
literal exists in any Stage 11 template or module.

---

## ADR-034 — History visibility is reused from Stage 10, not redesigned

**Context.** A scan-history table can trivially become an unauthenticated URL
enumeration oracle. Stage 10 already defined a deliberately simple policy for
printable reports: a signed-in user sees only rows linked to their account; a
guest row is readable only by the signed Flask session that created it (a
bounded id list). Inventing a different policy for Stage 11 would create two
authorisation truth sources and a likely privilege escalation.

**Decision.** `stats_service.visible_query()` implements the same rule, and
`routes/history.py::viewer_scope()` reuses `routes.scanning.GUEST_SCAN_SESSION_KEY`
rather than duplicating the constant. An empty guest id list produces an
always-false filter, never the whole table. `/history` stays open to guests
(no `@login_required`), so guest scans remain useful; an honest banner explains
that the list is session-limited and offers sign-in. Scans made before signing
in are **not** claimed automatically. `/admin/export.csv` is the only full
export and requires the admin role. Filters are clamped by `parse_filters()`
and bound through the ORM with `contains(..., autoescape=True)`, so `%`, `_`
and SQL-looking strings cannot widen a match.

**Consequences.** Positive: one authorisation policy, no cross-user URL leak,
no new table or migration, and Stage 10's report endpoint and Gate 10 checks
remain valid. Negative: a user who scans as a guest and then signs in does not
see those earlier scans — documented plainly in the UI, in `docs/DASHBOARD.md`
and in `docs/DATABASE.md`. A claim-flow remains out of scope.

**Verification.** Gate 11 checks a different anonymous browser gets an empty
history and an empty CSV, a member sees exactly their own rows, an admin's
personal history is scoped to their own scans, a guest CSV contains no other
account's reserved hostnames, and a SQL-injection-shaped search string returns
zero rows without error.

---

## ADR-035 — CSV export is a hostile-input boundary; the 401 contract is untouched

**Context.** A submitted URL is attacker-controlled text. Exporting it to a
spreadsheet introduces CSV formula injection (`=HYPERLINK(...)`, `+`, `-`,
`@`), CR/LF row injection and `Content-Disposition` header injection — none of
which `csv.writer` quoting alone prevents. Separately, Stage 11 needs a
role-restricted admin page, and adding a friendly HTML redirect for anonymous
visitors would have changed Stage 8's global `401 UNAUTHENTICATED` contract.

**Decision.** `services/report_service.py` applies `safe_cell()` to every text
cell: formula prefixes are prefixed with an apostrophe, CR/LF/NUL are removed,
and rows are bounded to `CSV_ROW_LIMIT`. Filenames are reduced to
`[A-Za-z0-9_.-]`; responses carry `attachment`, `no-store`, `nosniff`, an
exact `Content-Length` and a UTF-8 BOM for Windows Excel. Password hashes are
never a column. `admin_required()` composes `login_required` (which still uses
the Stage 8 `unauthorized_callback` → `401 UNAUTHENTICATED`) with an explicit
`is_admin` check returning `403 FORBIDDEN` for ordinary users. The generic 401
page gains only a `Sign in` link; the status code, error code, HTML/JSON
negotiation and `login_view` are unchanged. The CSP is byte-for-byte identical
and all three vendored SHA-256 hashes are re-verified.

**Consequences.** Positive: Excel/LibreOffice cannot evaluate a stored URL as a
formula, one URL cannot create extra CSV rows, and no closed-stage security
behaviour is weakened. Negative: a cell whose URL starts with `=` displays a
leading apostrophe — a deliberate, documented safety marker, not data loss.

**Verification.** Gate 11 inserts a stored row containing
`=SUM(1+1)\r\n<script>alert(1)</script>` through the ORM, asserts the CSV
contains `'=SUM(1+1)` with exactly one row per record, asserts the history
table renders `&lt;script&gt;`, tests every formula prefix and the filename
sanitiser, checks `401`/`403`/`200` for the three caller types, checks
JSON-negotiated 401, and asserts no `password_hash` or scrypt hash reaches
the admin page.

---

## ADR-036 — One detection pipeline for HTML and REST, with a deliberate projection

**Status:** Accepted (Stage 12)

**Context.** Stage 12 must expose `POST /api/v1/scan` with the field names
documented in `docs/ARCHITECTURE.md` §11 (`submitted_url`, `normalized_url`,
`prediction`, `model_score`, `score_meaning`, `risk_level`, `decision_band`,
`flagged_features`, `recommended_action`, `scanned_at`, `model`). The existing
`DetectionResult.to_dict()` was built for the Stage 10 HTML result page and uses
different names (`classification`, `thresholds`, `date_time_utc`,
`characteristics`, `top_measured_features`) plus extra fields.

**Decision.** `routes/api.py` calls `get_detection_registry().scan()` — the exact
same object and method the form uses — and projects the result through a small
`_contract()` function into the documented names. No second feature extractor,
no second `predict_proba`, no rule fallback and no independent write path. The
read endpoint `GET /api/v1/scans/<id>` uses a separate `_stored_contract()`
that rebuilds only from the audit row, so a GET never re-runs inference.
`decision_band.source` names `metadata.json#thresholds`; the model identity and
all caveats come from the live artefacts.

**Consequences.** Positive: a successful API scan is audited exactly like a
form scan, the three decision states and measured thresholds cannot drift
between interfaces, and the API cannot silently bypass validation or CSRF.
Negative: `_contract()` duplicates a handful of field names, so a future
contract change must update it and Gate 12. Acceptable, because returning the
Stage 10 dict would have broken the published contract and adding a second
pipeline would have broken the single-source-of-truth rule.

**Verification.** Gate 12 asserts `get_detection_registry().scan(` is present,
`predict_proba`/`joblib.load` are absent from `routes/api.py`, one audit row is
written per scan, the DB row count is unchanged after a detail GET, and every
documented field is present for all three decision states.

---

## ADR-037 — Config-driven per-route limits with no blanket throttle

**Status:** Accepted (Stage 12)

**Context.** `flask_limiter 3.12` was wired in Stage 7 with
`default_limits=[]` and `RATELIMIT_ENABLED=False` in Development/Test. The
brief requires per-route limits on `/scan`, `/api/v1/scan`, `/login` and
`/register`; a global default would throttle static assets, health checks,
CSRF-token issuance and ordinary GET pages, breaking the offline preview.

**Decision.** Limits are attached only to the abuse-prone routes, read from
`current_app.config` at REQUEST time, and exempt themselves via
`exempt_when=limits_disabled()`:

* `POST /login`, `POST /register` -> `RATE_LIMIT_AUTH` (`5 per minute`), with
  `methods=["POST"]` so rendering the form is never counted.
* `POST /scan` -> `RATE_LIMIT_SCAN` (`10 per minute`).
* `POST /api/v1/scan` -> both `RATE_LIMIT_API` (`30 per hour`, per IP) and
  `RATE_LIMIT_SCAN` with a per-account/per-IP `key_func`, stacking two
  independent decorators.
* `GET /api/v1/model/info`, `/api/v1/scans`, `/api/v1/scans/<id>` ->
  `RATE_LIMIT_API`.
* `/api/v1/health`, `/api/v1/csrf-token`, static assets and all GET pages ->
  deliberately unthrottled.

`default_limits=[]` stays. `limits_disabled()` reads the EFFECTIVE
`current_app.config` instead of decoration-time state, because the Limiter is a
process-wide singleton: without it, an app created after a limited app would
inherit the wrong enabled state. `RATELIMIT_HEADERS_ENABLED` adds transparent
`X-RateLimit-*` headers when limits are on. Storage remains `memory://` — a
documented single-process limitation, not a production-grade distributed store.

**Consequences.** Positive: limits can be tuned in `.env` without code changes,
tests stay deterministic, and monitoring/CSRF bootstrap remain reachable during
a breach. Negative: in a multi-worker deployment each process keeps its own
counters; a shared store (Redis) is future work explicitly outside Stage 12.
On breach, a dedicated `@app.errorhandler(429)` returns the generic
`429 RATE_LIMITED` JSON/HTML shape and `Retry-After`; the themed error page
gets a short non-diagnostic hint.

**Verification.** Gate 12 builds one app with limits enabled and low quotas,
asserts the exact 401/401/429 and 200/200/429 sequences, JSON and HTML 429
shapes, `Retry-After`, `no-store` on 429, POST-only auth limits, unthrottled
health/CSRF endpoints, and no throttling at all under `TestingConfig`.

---

## ADR-038 — REST security reuses the signed session; no weaker auth scheme

**Status:** Accepted (Stage 12)

**Context.** `docs/ARCHITECTURE.md` has long said "session/token + CSRF or
bearer". A browser session with `CSRFProtect`, scrypt hashes, `session.clear()`
on login and role-checked admin already exists (Stages 7/8/11). Adding bearer
tokens in Stage 12 would mean inventing key issuance, rotation, revocation,
auditing and storage with no schema change allowed — a weaker second mechanism.
Exempting API POSTs from CSRF would be worse.

**Decision.** The REST API uses the SAME signed Flask session.
`GET /api/v1/csrf-token` (and the existing `/auth/csrf-token`) call
`generate_csrf()`; every state-changing request, including
`POST /api/v1/scan`, must echo the token in `X-CSRF-Token`. There is no
`csrf.exempt`, no bearer token, no API key, no OAuth/JWT. Authorisation reuses
Stage 10/11 policy unchanged: `can_view_scan()` for one row,
`stats_service.history_page()` (which calls `visible_query()`) for lists, so
anonymous guests see only ids in their own signed session and a missing id is
indistinguishable from someone else's id (both generic `404 NOT_FOUND`).

Hardening is additive and does NOT touch the CSP directive list:
`Cross-Origin-Opener-Policy: same-origin`,
`X-Permitted-Cross-Domain-Policies: none`, `Origin-Agent-Cluster: ?1`,
`Cache-Control: no-store` on `/api/`, `/auth/`, `/health`, `/scan`, `/history`,
`/admin`, `/dashboard` and exports, plus the 429 handler. `RATE_LIMIT_*` values
remain the only new configuration; no new secret, table or seed script.

**Consequences.** Positive: a single, already-tested authentication surface;
CSRF, scrypt hashing, session-fixation defence, generic 401/403, the exact CSP,
Jinja autoescaping, offline vendor hashes and the no-network/SSRF rule all
carry into the API. Negative: non-browser API clients must maintain a cookie
jar and a CSRF token, which is documented in `docs/SECURITY.md` with a
Windows-first example. A truly stateless token API is deliberately deferred.

**Verification.** Gate 12 asserts a token-less `POST /api/v1/scan` returns
`400 CSRF_FAILED`, the whole generic error family stays JSON on `/api/*`,
unknown/wrong credentials share one 401, an injected `role=admin` registration
still stores `role="user"` with a scrypt hash, `User.to_dict()` exposes no
hash, a pre-login session value is cleared, encoded markup is escaped, the CSP
is byte-for-byte identical on six response types, and socket-patched loopback /
link-local URL strings still scan successfully with zero network I/O.

---

## ADR-039 — `pytest` is Stage 13's gate, not a thirteenth `verify_*.py`

**Status:** Accepted (Stage 13)

**Context.** Stages 1–12 each shipped an executable `scripts/verify_stageN.py`.
Stage 1's plan, however, has said from the outset that *Stage 13's gate is the
full `pytest` suite*. Once a real suite exists, a second hand-rolled gate would
duplicate it, drift from it, and give a marker two sources of truth.

**Decision.** The exit gate for Stage 13 is `python -m pytest -v` against
`tests/`. **No `scripts/verify_stage13.py` is created**, and
`scripts/verify_stage12.py` continues to assert that the file is absent. The
historical gates remain the regression harness for Stages 1–12 and are re-run
after the suite, exactly as before.

**Consequences.** Positive: one authority for "does the code work", standard
tooling, per-test granularity, no duplicated assertions. Negative: `pytest` alone
does not re-run the twelve historical gates, so the documented procedure is
"`pytest -v`, then Gates 1–12". That is written in `docs/TEST_PLAN.md` §2 and §8
and shown in the README.

**Verification.** `scripts/verify_stage12.py` checks
`not (ROOT / "scripts" / "verify_stage13.py").exists()`; `docs/TEST_PLAN.md`
records the measured result (`259 passed`) and the regression command list.

---

## ADR-040 — One isolated application per configuration, never a shared global

**Status:** Accepted (Stage 13)

**Context.** A test suite is only trustworthy if it cannot touch production
state and cannot leak state into the next test. The project already exposed
`create_app(config_class, overrides=...)`, and `config.TestingConfig` disables
CSRF and rate limiting for determinism. But several behaviours — CSRF
enforcement, the 429 contract, production framing, a missing model, a missing
schema — are the *opposite* of the testing defaults, so they must be exercised
with a differently-configured app.

**Decision.** `tests/conftest.py` builds a separate Flask application per
configuration, each on its own temporary SQLite file: `app` (TestingConfig),
`csrf_app` (CSRF on), `limited_app` (limiter on with tiny quotas),
`production_app`, `broken_model_app`, `tampered_model_app`, `no_schema_app` and
`raising_app`. `instance/phishing.db` is never opened. An autouse fixture
truncates per-test rows, and the Flask-Limiter singleton is reset around every
limiting test because its in-memory storage is process-wide.

**Consequences.** Positive: no test can corrupt the developer's audit history;
order-independence; the relaxations in `TestingConfig` are themselves tested
rather than trusted. Negative: suite setup costs a few hundred milliseconds per
differently-configured app, and adding a configuration means adding a fixture.

**Verification.** After the full suite, `python scripts/init_db.py --verify-only`
still reports the pre-existing row counts, and every module passes when run
alone (`pytest tests/test_security.py`) as well as in the full run.

---

## ADR-041 — Simulated browsers must not inherit a preserved application context

**Status:** Accepted (Stage 13)

**Context.** While writing the authorisation tests, a member's session appeared
to vanish after an anonymous request from a second client. The cause was
`with app.test_client() as client`: that sets `preserve_context=True`, which
keeps one Flask application context alive between requests, and Flask-Login
caches `current_user` on `g`. Two simulated browsers therefore shared one
identity. Nothing in the product was wrong — a real request always gets its own
context.

**Decision.** Every fixture and test creates a **plain** test client
(`client = app.test_client()`), never a context-managed one. A second "browser"
is a second plain client. Where a shared context genuinely exists (an app
context pushed by a fixture), `g._login_user` is popped before use.

**Consequences.** Positive: two clients behave like two visitors, which is what
the authorisation and visibility tests must prove. Negative: no automatic
request-context teardown, which is irrelevant for assertions on the response
object.

**Verification.** `test_a_user_cannot_open_another_users_report`,
`test_admin_export_is_authorised_only_for_administrators` and
`test_scans_lists_only_the_callers_session_rows` each depend on two clients
having independent identities; the behaviour is documented in
`docs/TEST_PLAN.md` §7 so it cannot be reintroduced by accident.

---

## ADR-042 — The report may only contain numbers that a measurement produced

**Status:** Accepted (Stage 14)

**Context.** A final report is the one artefact nobody re-runs. A metric typed by hand into prose
drifts from the artefact the moment anything is retrained, and a reader has no way to tell a measured
figure from a remembered one. Stage 6 already enforced this for the *application*: every metric shown
in the UI is read from `ml/saved_model/metrics.json` at request time, never hardcoded.

**Decision.** Extend the same rule to the report, and make it executable. `scripts/verify_stage14.py`
extracts every decimal printed to four or more fractional places in `docs/REPORT.md` and requires each
one to exist, at the same precision, in `metrics.json` or `metadata.json`. A hand-typed metric fails the
gate. Two exclusions are explicit rather than quiet: bibliographic DOIs in the reference list are not
claims about the system, and a typographic minus is compared by magnitude so that a rounded `-1e-06` in
the artefact matches `0.000001` in a table.

**Consequences.** Positive: the report cannot silently acquire an invented number, and a retrain that
changes a metric will fail the gate until the prose is updated to match — which is the correct
behaviour. Negative: derived quantities (percentages, counts of counts) cannot be checked this way, so
they are kept few, always shown next to the primary figure they derive from, and checked by eye in
review. The gate prints its coverage (`83 decimals traced to 158 measured values`) so the strength of
the assertion is visible rather than implied.

**Verification.** `python scripts/verify_stage14.py` → `ok every reported decimal exists in
metrics.json/metadata.json`. When the check was first written it failed on three tokens: two DOIs and
one legitimate table entry rounded from `-1e-06`. The exclusions above were added deliberately, not by
weakening the comparison.

---

## ADR-043 — UML diagrams are hand-authored SVG, not rendered by a tool at build time

**Status:** Accepted (Stage 14)

**Context.** Five new diagrams were required (use case, class, sequence, activity, deployment). The
obvious options were Mermaid (rendered by an external service or a bundled JS runtime), a Python
diagram DSL, or a graphical editor with a binary file format. Each adds a dependency to a project whose
selling point is that it renders with no network and no build step, and each produces an artefact that a
reader cannot diff in version control.

**Decision.** Author the diagrams as plain SVG written by hand, with text widths measured against a
font metric rather than guessed, and no external assets. Each file must parse as XML, declare a
`viewBox`, contain at least 40 elements and contain no `<script>`, no raster `<image>`, no remote font
import and no `http(s)://` reference. Those five properties are asserted by the Stage 14 gate.

**Consequences.** Positive: the diagrams open in any browser, embed in Word or LibreOffice, diff as
text, and cannot break when a CDN changes. Negative: layout is manual, so text-overflow defects are
possible and must be caught by rendering — which is exactly what happened during authoring: the first
version of the activity diagram had overlapping boxes and a clipped note, and the class diagram's
multiplicity labels were hidden behind a class box. Both were found by rendering to PNG with a real
renderer and corrected; the check is now part of the authoring loop rather than an afterthought.

**Verification.** `python scripts/verify_stage14.py` → six "well-formed XML / no external reference /
no script element / no raster image / declares a viewBox / is not a stub" checks per diagram.

---

## ADR-044 — Stage 14 ships an executable gate instead of a checklist

**Status:** Accepted (Stage 14)

**Context.** Stage 14's stated exit gate is a single command: `waitress-serve --call
wsgi:create_application`. Running it once by hand proves a process started; it does not prove that the
bundle was verified, that the database was ready, that the measured thresholds were served, that
production headers were present, that CSRF still guarded the JSON write path, or that the documentation
quotations still match the artefacts. Every earlier stage answered that objection with a script that
re-derives its claims from the code.

**Decision.** Ship `scripts/verify_stage14.py`. It launches waitress in a real subprocess with
`APP_ENV=production` on a free loopback port, polls until the server answers, asserts thirteen
runtime properties of the production start (server identity, version, stage, environment, bundle
hash, database state, engine state, thresholds, CSP, HSTS, frame and MIME headers, referrer policy),
exercises four endpoints plus one deliberately unauthenticated POST, terminates the process and
requires a clean exit with no traceback. It then checks the documentation and stage discipline in the
same run.

**Consequences.** Positive: the deployment claim is reproducible by anyone with the tree, and
regressions in deployment behaviour are caught by a script rather than by a reviewer's memory. Negative:
the gate binds to a specific free port and to the presence of the `waitress-serve` console script, so it
must skip (rather than fail) when run from an interpreter without the package installed — the skip is
printed, never silent. Option ordering matters and is documented: waitress parses the module spec
positionally, so `--listen` must precede `wsgi:create_application` or the server exits with `Error:
Specify one application only`.

**Verification.** `python scripts/verify_stage14.py` → `CHECKS: 128 SKIPPED: 0 FAILURES: 0` and
`RESULT: PASS`.
