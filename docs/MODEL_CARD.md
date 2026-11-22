# Model Card — Intelligent Phishing Website Detection System

**Generated 2026-11-06T12:48:02+00:00**
**Model version:** `1.0.0` · **Schema:** `1.0`
**All figures below are measured** by `ml/evaluate_model.py` with `sklearn.metrics` and stored in `ml/saved_model/metrics.json`.

---

## 1. Model details

| Item | Value |
| --- | --- |
| Selected estimator | `logistic_regression` (`LogisticRegression`) |
| Selected from | `logistic_regression`, `decision_tree`, `random_forest` |
| Features | 15 lexical URL characteristics (`FEATURE_ORDER`, schema `1.0`) |
| Training split | 164,744 rows (93,690 legitimate / 71,054 phishing) |
| Validation split | 35,302 rows |
| Test split | 35,302 rows, scored once after selection |
| Random seed | 42 |
| Libraries | Python 3.13.16, scikit-learn 1.6.1, pandas 2.3.3, numpy 2.2.6 |
| Bundle SHA-256 | `841bb211e4b043335a81407c0f2ebe39de7293b73cdb4c7e013ea9766b11dd50` |

**Intended use:** an educational, static, URL-string screening aid. Given a URL, it produces a phishing-class score and a three-state decision with explanations.

**Out of scope / not a guarantee:** the system never visits a website, inspects page content, checks certificates, DNS age, redirects or reputation. A `LEGITIMATE` result is **not** a safety guarantee. It must not replace user judgement or dedicated security tooling.

## 2. Measured performance

### Held-out test split (35,302 rows) — binary metrics at 0.5

| Metric | Measured value |
| --- | --- |
| Accuracy | 0.983854 |
| Precision | 0.993307 |
| Recall | 0.967803 |
| F1 | 0.980389 |
| ROC-AUC | 0.998055 |

Confusion matrix `[[TN, FP], [FN, TP]]` = `[[20484, 96], [474, 14248]]` → TN 20,484, FP 96, FN 474, TP 14,248.

### Held-out test split — three-state decision layer

| Metric | Measured value |
| --- | --- |
| `T_low` / `T_high` | 0.05 / 0.95 |
| Decisive predictions | 28,217 of 35,302 |
| Abstention rate (SUSPICIOUS) | 20.07% |
| Precision (decisive) | 0.999848 |
| Recall (decisive) | 0.997732 |
| F1 (decisive) | 0.998789 |
| False negatives (decisive) | 30 |

`[[TN, FP], [FN, TP]]` = `[[14988, 2], [30, 13197]]`. State counts: `{'LEGITIMATE': 15018, 'SUSPICIOUS': 7085, 'PHISHING': 13199}`.

> **Why validation numbers differ from test numbers:** thresholds and model selection were tuned on validation only; the test split was scored **once** afterwards. The test figures are the ones to quote.

## 3. Decision states (exact UI contract)

| State | Colour | Risk | Message |
| --- | --- | --- | --- |
| `LEGITIMATE` | green | LOW | "No phishing indicators detected by this model." |
| `PHISHING` | red | HIGH | "Potential phishing website detected." |
| `SUSPICIOUS` | orange | MEDIUM | "This website requires further investigation." |

**Score wording (mandatory):** Model score: the model's uncalibrated estimate of P(phishing | URL features), computed by predict_proba on 15 lexical URL features. It is not a calibrated probability that the website is malicious, and it is not a guarantee.

## 4. Threshold selection (documented, measured)

- Criterion: Validation-split grid search over (T_low, T_high). Feasible: recall >= 0.90 on decisive predictions, abstention rate <= 0.25, band gap >= 0.10. Objective: maximise F1 on decisive predictions; tie-break by fewest false negatives, then lowest abstention rate, then threshold values. Model selection uses the same objective across candidates, tie-broken by highest validation ROC-AUC.
- Grid pairs evaluated: 81; feasible pairs: 81
- Validation rows used: 35,302
- Validation abstention rate at the chosen band: 19.80%
- Validation recall at the chosen band: 0.996980
- The provisional defaults 0.3/0.7 from `config.py` were **replaced** by the measured values above; runtime reads `metadata.json`.

`SUSPICIOUS` is an abstention over a binary classifier, **not** a trained third class. A phishing URL inside the band is unresolved, not a false negative (it was never declared safe). The 25% abstention cap prevents gaming the recall constraint.

## 5. Feature importance (measured, correlational)

Permutation importance on 5,000 validation rows, 3 repeats, ROC-AUC scoring. Top five by mean decrease in ROC-AUC:

| Feature | Mean decrease | Std |
| --- | --- | --- |
| `has_https` | +0.584041 | 0.004683 |
| `url_length` | +0.327594 | 0.000870 |
| `domain_length` | +0.285580 | 0.003190 |
| `num_digits` | +0.010226 | 0.000615 |
| `num_dots` | +0.000715 | 0.000183 |

These are correlations learned from the training distribution, **not causation**. A single flagged feature does not make a site malicious. No SHAP causality claim is made.

> ⚠️ **Measured bias warning.** `has_https` produces the largest decrease in ROC-AUC (+0.584041), confirming the dataset shortcut: all legitimate URLs in this corpus use HTTPS while many phishing URLs do not. **HTTPS alone does not mean a website is legitimate.** The reported performance is optimistic for real-world traffic and must be presented with this qualifier.

## 6. Limitations and ethical considerations

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
- **PATH/LENGTH ARTEFACT (measured in the final acceptance review, `docs/ACCEPTANCE_REVIEW.md` §4.2).** In the training corpus 0.00% of legitimate URLs contain a path, against 33.59% of phishing URLs. The model consequently treats any path or query string as evidence of phishing: `https://www.saffronart.com` is LEGITIMATE, the same URL with a trailing slash is SUSPICIOUS, and with `/about` appended it is PHISHING. On an illustrative hand-picked sample of 20 well-known benign URLs the verdicts were 2 LEGITIMATE (both corpus rows), 7 SUSPICIOUS and 11 PHISHING. The published metrics are correct for the corpus distribution; the model is NOT a usable real-world screener until the negative class contains deep links and the pipeline is retrained.
- **No claim of real-world screening capability.** Given the two measured artefacts (HTTPS dominance and the path/length effect), the system must be presented as an academic demonstration of a leak-free, honestly-measured pipeline, not as protection against live phishing.

Dataset (CC BY 4.0, attribution required): Prasad, A. & Chandra, S. (2023), *PhiUSIIL*, Computers & Security 103545, https://doi.org/10.1016/j.cose.2023.103545, UCI dataset 967. See `docs/DATASET.md`.

---

*Generated from `ml/saved_model/metadata.json` and `metrics.json`. Re-running `python -m ml.evaluate_model` regenerates this card with fresh measurements.*
