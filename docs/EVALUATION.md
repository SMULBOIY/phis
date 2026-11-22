# Stage 6 — Evaluation, Model Selection and Threshold Calibration

**Generated 2026-11-06T12:48:02+00:00**
**Implementation:** `ml/evaluate_model.py`, `ml/thresholds.py`
**Artefacts:** `ml/saved_model/model_bundle.joblib`, `metadata.json`, `metrics.json`
**Status:** model selected, thresholds calibrated, test split scored once. All figures measured.

---

## 1. Evaluation protocol

| Step | Split | What was measured |
| --- | --- | --- |
| 1 | training (164,744) | Fitting only (Stage 5); no metrics |
| 2 | validation (35,302) | Per-model accuracy, precision, recall, F1, confusion matrix, ROC-AUC at 0.5; threshold grid search |
| 3 | validation | Model selection by calibrated F1 under the recall constraint |
| 4 | test (35,302) | **One** final scoring of the single selected model |

Group-aware splitting from Stage 3 guarantees no URL, leakage group or non-generic path signature crosses splits. The test split was not read during EDA (Stage 4), training (Stage 5), threshold tuning or model selection.

### Selection criterion (fixed a priori)

Validation-split grid search over (T_low, T_high). Feasible: recall >= 0.90 on decisive predictions, abstention rate <= 0.25, band gap >= 0.10. Objective: maximise F1 on decisive predictions; tie-break by fewest false negatives, then lowest abstention rate, then threshold values. Model selection uses the same objective across candidates, tie-broken by highest validation ROC-AUC.

Constraints: recall ≥ 0.9, abstention ≤ 25%, band gap ≥ 0.1, grid step 0.05. Recall priority reflects the brief: a missed phishing site (false negative) is costlier than a false alarm.

---

## 2. Measured per-model comparison (validation split)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Cal. F1 | Cal. recall | FN | Abstention | Feasible pairs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `logistic_regression` ★ | 0.983712 | 0.992618 | 0.968143 | 0.980228 | 0.997818 | 0.998337 | 0.996980 | 40 | 19.80% | 81/81 |
| `decision_tree` | 0.993230 | 0.993727 | 0.990015 | 0.991868 | 0.997769 | 0.997283 | 0.995400 | 67 | 7.65% | 81/81 |
| `random_forest` | 0.986715 | 0.984170 | 0.983970 | 0.984070 | 0.997644 | 0.996880 | 0.995449 | 65 | 8.82% | 60/81 |

★ = selected. "Cal." = measured on decisive (non-abstained) predictions at that model's best feasible band.

Ranking by the documented objective:

1. `logistic_regression` — calibrated F1 0.998337, recall 0.996980, FN 40, abstention 19.80%, ROC-AUC 0.997818
2. `decision_tree` — calibrated F1 0.997283, recall 0.995400, FN 67, abstention 7.65%, ROC-AUC 0.997769
3. `random_forest` — calibrated F1 0.996880, recall 0.995449, FN 65, abstention 8.82%, ROC-AUC 0.997644

**Selected model: `logistic_regression` (`LogisticRegression`).**

---

## 3. Thresholds (explicitly defined uncertainty band)

| Item | Value |
| --- | --- |
| `T_low` | 0.05 |
| `T_high` | 0.95 |
| Provisional defaults replaced | 0.3 / 0.7 |
| Grid pairs evaluated | 81 |
| Feasible pairs | 81 |
| Validation abstention rate | 19.80% |
| Validation recall | 0.996980 |
| Validation false negatives | 40 |

`p >= 0.95` → PHISHING (HIGH); `p <= 0.05` → LEGITIMATE (LOW); otherwise SUSPICIOUS (MEDIUM). Runtime reads these from `metadata.json`; `config.py` holds only the provisional fallbacks.

---

## 4. Selected model — validation results

**Binary metrics at 0.5:** accuracy 0.983712, precision 0.992618, recall 0.968143, F1 0.980228, ROC-AUC 0.997818. Confusion `[[TN, FP], [FN, TP]]` = `[[20474, 106], [469, 14253]]`.

**Calibrated three-state:** decisive 28,312, abstained 6,990 (19.80%), precision 0.999697, recall 0.996980, F1 0.998337, FN 40. Confusion `[[15063, 4], [40, 13205]]`.

---

## 5. Selected model — FINAL held-out test results (quote these)

| Metric | At 0.5 | Decisive (calibrated) |
| --- | --- | --- |
| Accuracy | 0.983854 | 0.998866 |
| Precision | 0.993307 | 0.999848 |
| Recall | 0.967803 | 0.997732 |
| F1 | 0.980389 | 0.998789 |
| ROC-AUC | 0.998055 | n/a (threshold-independent) |
| Confusion matrix | `[[20484, 96], [474, 14248]]` | `[[14988, 2], [30, 13197]]` |
| False negatives | 474 | 30 |

Test state counts: LEGITIMATE 15,018, SUSPICIOUS 7,085, PHISHING 13,199. Abstention rate 20.07%.

**Score wording:** Model score: the model's uncalibrated estimate of P(phishing | URL features), computed by predict_proba on 15 lexical URL features. It is not a calibrated probability that the website is malicious, and it is not a guarantee.

---

## 6. Feature importance (measured)

sklearn.inspection.permutation_importance(scoring='roc_auc'); 5,000 validation rows, 3 repeats, seed 42. Values are mean decrease in ROC-AUC when one feature is shuffled.

| Feature | Mean decrease | Std |
| --- | --- | --- |
| `has_https` | +0.584041 | 0.004683 |
| `url_length` | +0.327594 | 0.000870 |
| `domain_length` | +0.285580 | 0.003190 |
| `num_digits` | +0.010226 | 0.000615 |
| `num_dots` | +0.000715 | 0.000183 |
| `has_suspicious_pattern` | +0.000317 | 0.000072 |
| `num_subdomains` | +0.000303 | 0.000064 |
| `has_at_symbol` | +0.000221 | 0.000036 |
| `num_suspicious_words` | +0.000117 | 0.000013 |
| `num_hyphens` | +0.000099 | 0.000066 |
| `has_encoded_chars` | +0.000033 | 0.000031 |
| `has_ip_address` | +0.000000 | 0.000000 |
| `is_shortened` | +0.000000 | 0.000000 |
| `has_unusual_port` | +0.000000 | 0.000000 |
| `num_special_chars` | -0.000001 | 0.000007 |

Correlation, not causation. See `docs/FEATURES.md` for what each feature means.

### 6.1 Measured dataset bias — read this before quoting any accuracy figure

Top measured permutation decreases in ROC-AUC:

- `has_https`: +0.584041 (±0.004683)
- `url_length`: +0.327594 (±0.000870)
- `domain_length`: +0.285580 (±0.003190)

`has_https` alone accounts for a measured decrease of **+0.584041** versus **+0.327594** for the next largest feature; it is the single most influential feature: **true**. This is the concrete, measured confirmation of the Stage 4 warning that 100.00% of legitimate URLs in this dataset use HTTPS versus 56.90% of phishing URLs.

**Consequence:** the model has learned a dataset shortcut, not a security truth. Attackers routinely obtain free TLS certificates, so HTTPS alone does not mean a website is legitimate. The reported test accuracy describes a held-out sample of the PhiUSIIL distribution; it is **optimistic** for real-world traffic in which phishing sites also use HTTPS. An ablation study retraining without `has_https` is recommended future work and must appear in the Limitations and Recommendations chapters of the final report.

### 6.2 The abstention trade-off

The a priori cap was 25%. The measured validation abstention rate is 19.80% and the test rate is 20.07%. On the test split, false negatives fall from 474 at a fixed 0.5 boundary to 30 among decisive predictions — but 7,085 URLs become SUSPICIOUS instead of receiving a binary verdict. This is selective prediction in action: it is **not** extra accuracy, and it must be explained that way in the report.

---

## 7. Reproduce

```powershell
python -m ml.evaluate_model
python scripts\verify_stage6.py
```

```bash
python -m ml.evaluate_model
python scripts/verify_stage6.py
```

`verify_stage6.py` RE-COMPUTES the reported metrics from the saved bundle and the split CSVs, and fails if any published number disagrees with the measurement. No figure in the UI, docs or JSON is allowed to be hand-typed.

---

## 8. Limitations

- Static URL-only analysis: no page content, redirects, DNS age, TLS certificate, domain reputation or external API is consulted. The backend never visits a submitted URL.
- Measured on a held-out sample of the PhiUSIIL (UCI 967) distribution donated in 2024; newer phishing tactics may not be represented. Results are not universal web accuracy.
- Dataset shortcut: 100.00% of legitimate training URLs used HTTPS versus 56.90% of phishing URLs. HTTPS alone does not mean a website is legitimate.
- MEASURED CONFIRMATION OF THAT BIAS: validation permutation importance is dominated by has_https (+0.5840), url_length (+0.3276), domain_length (+0.2856). The has_https decrease in ROC-AUC is +0.584041, far above every other feature, so the selected model relies heavily on a signal that is not a real-world safety indicator. Reported accuracy is therefore OPTIMISTIC on traffic where phishing sites also use TLS. An ablation study removing has_https is recommended future work and must be discussed at the viva.
- Model scores from predict_proba are UNCALIBRATED and must never be presented as a guaranteed probability that a website is malicious.
- SUSPICIOUS is an abstention band over a binary classifier, not a third ground-truth class; a phishing URL in the band is unresolved, not classified safe.
- The a priori 25% abstention cap allowed a measured 19.80% validation abstention rate; roughly one in five URLs is unresolved rather than given a binary verdict. This is an honest trade-off for fewer false negatives, not extra accuracy. A tighter cap or an abstention penalty is a design alternative for future work.
- Fixed hyperparameters without cross-validated tuning; depth-capped trees may underfit rare patterns. See docs/TRAINING.md.
- URL shorteners, newly registered lookalike domains and compromised legitimate domains can evade lexical features.
- Not a safety guarantee; the system is an educational screening aid and must not replace user judgement or dedicated security tooling.

**Interpretation:** these numbers describe performance on a held-out sample of the PhiUSIIL distribution, not on the live web. They must be presented with that qualifier in the final report.
