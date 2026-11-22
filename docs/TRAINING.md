# Stage 5 — Model Training Record

**Generated 2026-11-03T20:13:26+00:00**
**Implementation:** `ml/train_model.py`
**Artefacts:** `ml/saved_model/candidates/`
**Status (Stage 5 record):** three candidates fitted. **No model selected. No performance metric computed.**
**Stage 6 note:** selection, threshold calibration and all measured performance figures now exist in
`ml/saved_model/metrics.json`, `metadata.json`, `docs/EVALUATION.md` and `docs/MODEL_CARD.md`.
The "no metric" statement above describes the state of the project **at Stage 5 only**.

Every number below was read from `ml/saved_model/candidates/training_manifest.json`,
which is written by the training run itself. Nothing is estimated.

---

## 1. Scope of this stage

The brief requires Logistic Regression, Decision Tree and Random Forest to be
trained and compared. **Training** is Stage 5; **comparison, selection and
measurement** are Stage 6. Splitting them is deliberate: it prevents the
temptation to tune against the test set and keeps the audit trail honest.

This module therefore:

* reads **only** `dataset/processed/train.csv`;
* computes features with the shared `ml.feature_extraction.extract_frame`;
* fits exactly three scikit-learn `Pipeline` objects;
* saves three joblib candidate bundles plus a complete training manifest;
* reports **only** measured wall-clock training times and artefact sizes.

It does **not** compute accuracy, precision, recall, F1, a confusion matrix or
ROC-AUC; it does not read the held-out splits; it does not choose a "best" model;
it does not calibrate the SUSPICIOUS abstention band.

---

## 2. Training data (measured)

| Property | Value |
| --- | --- |
| File | `dataset/processed/train.csv` |
| SHA-256 | `bdb7ba6bb2a8118c04cd8bf6b06a3b733a8d7e58003b29159c6c8cecad9d0734` |
| Rows | 164,744 |
| Legitimate (label 0) | 93,690 |
| Phishing (label 1) | 71,054 |
| Phishing rate | 43.13% |
| Features | 15 |
| Splits used | `train` only |
| Held-out splits read | **no** |

The class balance is close enough that no resampling was applied. Oversampling
would change the meaning of `predict_proba` and is unnecessary here.

### Feature contract (unchanged from Stage 4)

1. `url_length` — Number of characters in the normalised URL string.
2. `domain_length` — Number of characters in the hostname (excluding userinfo, port and brackets).
3. `num_dots` — Count of '.' characters in the whole normalised URL.
4. `num_hyphens` — Count of '-' characters in the whole normalised URL.
5. `num_special_chars` — Count of non-alphanumeric characters that are not ordinary URL structure characters (see docs/FEATURES.md).
6. `num_digits` — Count of digit characters in the whole normalised URL.
7. `has_ip_address` — 1 when the host is a literal IPv4/IPv6 address instead of a domain name, else 0.
8. `has_at_symbol` — 1 when the URL contains '@' (userinfo before the real host), else 0.
9. `has_suspicious_pattern` — 1 when any documented obfuscation pattern is present (double slash in path, multiple '?', deep subdomain chain, or brand token in a lookalike host), else 0.
10. `num_subdomains` — Number of host labels before the approximate registrable domain (0 for a bare domain or an IP host).
11. `has_https` — 1 when the scheme is https, else 0. WEAK feature: HTTPS alone never means legitimate.
12. `is_shortened` — 1 when the registrable domain is in the maintained static list of URL shorteners, else 0.
13. `num_suspicious_words` — Case-insensitive substring count of login, verify, update, secure, account, banking and confirm in the URL.
14. `has_unusual_port` — 1 when an explicit port other than 80/443 is present, else 0.
15. `has_encoded_chars` — 1 when percent-encoded (%xx) or legacy %uXXXX sequences are present, else 0.

The column order is enforced: `load_training_data` raises if the extracted matrix
does not match `FEATURE_ORDER`. Each saved bundle stores the same list so the
Stage 10 loader can detect a schema mismatch before predicting.

---

## 3. The three pipelines

| Model | Pipeline | Why |
| --- | --- | --- |
| Logistic Regression | `StandardScaler` → `LogisticRegression(solver='lbfgs')` | Count features such as `url_length` (0–6000) would otherwise dominate 0/1 flags in an L2-regularised linear model |
| Decision Tree | `DecisionTreeClassifier` | Baseline non-linear, interpretable model; trees need no feature scaling |
| Random Forest | `RandomForestClassifier` | Ensemble that reduces the single tree's variance; required by the brief and provides feature importances for Stage 10 explanations |

Recorded hyperparameters:

| Candidate | Parameters |
| --- | --- |
| `logistic_regression` | `random_state=42`, `class_weight=None`, `solver=lbfgs`, `max_iter=1000` |
| `decision_tree` | `random_state=42`, `class_weight=None`, `max_depth=12`, `min_samples_leaf=10` |
| `random_forest` | `random_state=42`, `class_weight=None`, `n_estimators=100`, `max_depth=12`, `min_samples_leaf=10`, `n_jobs=1` |

Common settings: `random_state=42`, `class_weight=None`.

**Why a depth cap of 12 and `min_samples_leaf=10`?**
Three reasons, all practical: (1) regularisation against the dataset shortcuts
documented in `docs/FEATURES.md` §4 (notably the HTTPS bias); (2) bounded training
time; (3) a serialised artefact small enough to version and deploy — the entire
candidate directory is under 1 MB. A fully grown forest on 164k rows would be
hundreds of megabytes without improving this project's educational value.

**Why `n_jobs=1` for the Random Forest?** With `n_jobs=-1`, scikit-learn
accumulates tree votes into a shared array from several threads, so two calls of
`predict_proba` on the SAME URL differ in the last floating-point bit (measured:
2.22e-16). That is numerically harmless but means a user scanning the same URL
twice could see inconsistent scores. Single-threaded training/prediction is
bitwise deterministic and still fits in a few seconds here. `verify_stage5.py`
asserts this with `numpy.array_equal`.

**Why no `class_weight='balanced'`?** The brief prioritises recall / false
negatives, but that is handled in Stage 6 by an explicit *validation-set
threshold constraint* (`T_high`, `T_low`). Reweighting here would distort the
score distribution before that calibration and would make the "model score"
wording in the UI harder to justify honestly.

**No hyperparameter search was performed.** These are documented, fixed,
reproducible settings, not claimed optima. Stage 6 compares the three candidates
on validation data; a further tuning study is listed as future work in the
report's Recommendations chapter.

---

## 4. Artefacts (measured)

| File | Bytes | SHA-256 (first 16) | Fit time |
| --- | --- | --- | --- |
| `logistic_regression.joblib` | 1,807 | `49cee8b00e2926f0…` | 1.18 s |
| `decision_tree.joblib` | 15,250 | `7f6ca9457a86f842…` | 0.15 s |
| `random_forest.joblib` | 834,540 | `8f0b62c74e949015…` | 4.17 s |
| `training_manifest.json` | 3,764 | — | — |

Each `.joblib` bundle is a dictionary containing:

```python
{
    "estimator": <fitted sklearn Pipeline>,
    "feature_order": <the 15 names, in order>,
    "schema_version": "1.0",
    "model_name": <name>,
    "model_version": "0.5.0-candidate",
    "trained_at_utc": <timestamp>,
    "random_state": 42,
    "hyperparameters": {...},
    "training_rows": 164744,
    "training_seconds": <measured>,
    "library_versions": {...},
}
```

Bundles are written with `joblib.dump(..., compress=3)`. The **final**
`ml/saved_model/model_bundle.joblib` is created in Stage 6 after selection;
these three files are unselected candidates.

### Manifest flags (the honesty check)

| Flag | Value |
| --- | --- |
| `evaluation_performed` | `false` |
| `selection_performed` | `false` |
| `metrics_measured` | `[]` |
| `dataset.splits_used` | `['train']` |
| `dataset.held_out_splits_not_read` | `true` |

---

## 5. Environment (measured)

| Library | Version |
| --- | --- |
| Python | 3.13.16 |
| NumPy | 2.2.6 |
| pandas | 2.3.3 |
| scikit-learn | 1.6.1 |
| joblib | 1.5.3 |

All versions are pinned by `requirements.txt` (Stage 2) and recorded in
`docs/ENVIRONMENT.md`.

---

## 6. Reproduce and test

```powershell
# Windows
python -m ml.train_model
python scripts\verify_stage5.py
```

```bash
# Linux / macOS
python -m ml.train_model
python scripts/verify_stage5.py
```

Useful overrides:

```powershell
python -m ml.train_model --seed 42 --n-estimators 100 --max-depth 12 --min-samples-leaf 10
python -m ml.train_model --train dataset\processed\train.csv --output-dir ml\saved_model\candidates
```

Determinism: for a fixed seed, input file and library versions, all three
estimators produce identical `predict_proba` output. `verify_stage5.py` proves
this on a small, safe, synthetic fixture (never added to the training data) and
checks the delivered bundles load and predict correctly.

---

## 7. Common errors and fixes

| Error | Cause | Fix |
| --- | --- | --- |
| `FileNotFoundError: Training split not found` | Raw/derived dataset missing, or wrong working directory | `cd phishing-detection-system`; run `python -m ml.preprocess` (Stage 3) |
| `ValueError: Unexpected training columns` | `train.csv` was regenerated with a different schema | Re-run Stage 3 preprocessing with the documented command |
| `ValueError: Training labels must be exactly {0, 1}` | Label encoding changed | Re-run Stage 3; do not hand-edit the CSV |
| `RuntimeError: Feature matrix column order does not match FEATURE_ORDER` | Stage 4 contract edited without retraining | Restore `FEATURE_ORDER` or bump the schema version and retrain |
| `OptimizeWarning: Unknown solver options: iprint` | Benign sklearn 1.6.1 / SciPy notice on `lbfgs` | Already filtered narrowly in `train_all`; real convergence warnings remain visible |
| `ConvergenceWarning` from Logistic Regression | `max_iter` too low for the data | Increase `--lr-max-iter` (default 1000) and retrain |
| `MemoryError` during Random Forest fit | Depth cap removed or a much larger dataset | Keep `--max-depth 12`; reduce `--n-estimators` |
| `ModuleNotFoundError: ml` | Wrong interpreter / directory | Activate the venv and run from the project root |
| Candidate `.joblib` fails to load | Interrupted write, or a different scikit-learn version | Delete the candidates directory and re-run; keep the pinned versions |
| `predict_proba` differs by ~1e-16 between calls | `n_jobs=-1` threaded accumulation | Keep `n_jobs=1`; see §3 |
| Someone quotes an accuracy figure from Stage 5 | Misreading the manifest | There is none. Stage 6 measures it. |

---

## 8. Limitations

* Fixed hyperparameters, no cross-validated grid search — documented as future work.
* Depth-capped trees may underfit rare patterns; selection in Stage 6 is based on
  measured validation performance, not assumption.
* `predict_proba` values are **uncalibrated**. They are model scores, not
  guaranteed probabilities of maliciousness, and the UI must say so.
* The HTTPS dataset bias from `docs/FEATURES.md` §4 may let a model learn a
  shortcut; Stage 6's measured results must be reported with that caveat.
* No model has been selected, no threshold is defined and no prediction is yet
  served to a user.

**Next: Stage 6 — evaluation, model selection and abstention-band calibration.**
