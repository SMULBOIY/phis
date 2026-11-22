# Dataset Provenance and Preprocessing Record

**Stage 3 deliverable — generated 2026-11-03T19:32:10+00:00**
**Status:** real, verified, downloaded dataset. No synthetic training rows exist anywhere in this project.

Every number in this document was read from `dataset/processed/manifest.json`, which is written by
`ml/preprocess.py` from the actual file. Nothing here is estimated.

---

## 1. Source and citation

| Item | Value |
| --- | --- |
| Dataset name | PhiUSIIL Phishing URL (Website) |
| Repository | UCI Machine Learning Repository, dataset 967 |
| Source page | https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset |
| Direct archive | https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip |
| DOI | https://doi.org/10.1016/j.cose.2023.103545 |
| Introductory paper | Prasad, A. & Chandra, S. (2024), *PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning*, Computers & Security, 103545 |
| UCI donation date | 3 March 2024 (archive member timestamp 4 March 2024) |
| Downloaded for this project | 2026-11-03 |
| Licence | Creative Commons Attribution 4.0 International (CC BY 4.0) — attribution required |
| Original collection window | **Not published by UCI.** The paper describes "latest / active" URLs; do not state a collection period that the source does not give |

### Integrity of the exact file used

| Artefact | Size (bytes) | SHA-256 |
| --- | --- | --- |
| `dataset/raw/phiusiil+phishing+url+dataset.zip` | measured at download | `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a` |
| `dataset/raw/PhiUSIIL_Phishing_URL_Dataset.csv` | 56,854,345 | `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` |

`scripts/download_dataset.py` re-downloads the fixed UCI URL and refuses to proceed on a hash mismatch.
It is **developer-only offline tooling**. The running web application never fetches a URL supplied by a user.

### Citation to paste into your report

> Prasad, A., & Chandra, S. (2023). PhiUSIIL: A diverse security profile empowered phishing URL
> detection framework based on similarity index and incremental learning. *Computers & Security*,
> 103545. https://doi.org/10.1016/j.cose.2023.103545. Dataset: UCI Machine Learning Repository,
> dataset 967 (CC BY 4.0).

---

## 2. Why this dataset was selected

| Requirement from the brief | How PhiUSIIL satisfies it |
| --- | --- |
| Reputable source | UCI Machine Learning Repository — explicitly named in the brief; peer-reviewed *Computers & Security* paper; DOI |
| Legitimate AND phishing URLs present | Yes: 134,850 legitimate, 100,498 phishing after cleaning |
| **Raw URL strings** (needed by our feature extractor) | Yes: the `URL` column contains the full URL text |
| Legally usable in a student project | CC BY 4.0 with attribution |
| Reproducible | Direct ZIP download, pinned SHA-256, deterministic preprocessing |
| No fabricated data | Every row comes from the downloaded file |

**Rejected alternative:** UCI dataset 327 ("Phishing Websites") supplies 11,055 rows of 30 *pre-computed*
integer features and **no raw URL strings**. Our Stage 4 extractor must run on URL text, so that dataset
cannot be used without fabricating URLs. It is also older (donated 2015).

---

## 3. Measured dataset description

| Property | Measured value |
| --- | --- |
| Rows in raw CSV | 235,795 |
| Columns in raw CSV | 56 |
| Columns used | `URL`, `label` (2) |
| Columns excluded | 54 |
| Missing values | 0 (UCI reports none; confirmed on the raw file) |
| Rows containing URLs longer than the 2,048-char limit | 8 |
| Exact duplicate URLs after normalisation | 439 |
| URLs with conflicting labels | 0 |
| Clean rows carried forward | 235,348 |

### Label semantics (verified empirically, not assumed)

UCI states: *"Label 1 corresponds to a legitimate URL, label 0 to a phishing URL."* This was independently
confirmed by inspecting samples: label 1 rows contain institutional domains such as `uni-mainz.de` and
`voicefmradio.co.uk`, while label 0 rows contain disposable-hosting domains such as `f0519141.xsph.ru`
and `kuradox92.lima-city.de`. The inversion below was then asserted again on the merged raw/processed
rows by `scripts/verify_stage3.py`.

| Source `label` | Meaning | Project label after encoding |
| --- | --- | --- |
| 1 | legitimate | **0** |
| 0 | phishing | **1** |

The project convention `0 = legitimate, 1 = phishing` is fixed in `docs/ARCHITECTURE.md` §5 so that
`predict_proba(X)[:, 1]` always means the phishing-class score.

---

## 4. The 54 excluded columns and why (critical for validity)

Only `URL` and `label` are read from the CSV. The excluded columns are:

`FILENAME`, `URLLength`, `Domain`, `DomainLength`, `IsDomainIP`, `TLD`, `URLSimilarityIndex`, `CharContinuationRate`, `TLDLegitimateProb`, `URLCharProb`, `TLDLength`, `NoOfSubDomain`, `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`, `IsHTTPS`, `LineOfCode`, `LargestLineLength`, `HasTitle`, `Title`, `DomainTitleMatchScore`, `URLTitleMatchScore`, `HasFavicon`, `Robots`, `IsResponsive`, `NoOfURLRedirect`, `NoOfSelfRedirect`, `HasDescription`, `NoOfPopup`, `NoOfiFrame`, `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`, `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef`

Two independent reasons:

1. **Unavailable-feature leakage.** Many of these were computed by the original authors from *downloaded
   webpage source code* — `LineOfCode`, `LargestLineLength`, `HasTitle`, `Title`, `HasFavicon`, `Robots`,
   `IsResponsive`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `HasPasswordField`, `NoOfPopup`, `NoOfiFrame` and
   similar. Our system deliberately never visits a submitted URL (SSRF-safe static analysis), so it
   cannot compute them at scan time. A model trained on them would be impossible to deploy honestly.
2. **Training-serving consistency.** Even the URL-derived columns (`URLLength`, `NoOfSubDomain`,
   `IsDomainIP`, ...) are recomputed by our OWN `ml/feature_extraction.py` in Stage 4. Reusing the
   dataset's versions would create a second, subtly different definition of each feature. `FILENAME` is
   an identifier that UCI says can be ignored and could act as a label shortcut.

This is the single most important methodological decision in Stage 3: **the system is trained on exactly
the information it will have at prediction time.**

---

## 5. Preprocessing pipeline (all counts measured)

`ml/url_utils.py` is the canonical, network-free URL normaliser. It lowercases only the scheme and host,
preserves userinfo (the `@` feature), preserves non-default ports, encoded characters and fragments, and
rejects control characters, unsupported schemes, missing hosts and strings over 2,048 characters. The
SAME function is used in Stage 4 (training features) and Stage 10 (live input).

| # | Step | Rows remaining |
| --- | --- | --- |
| 1 | Load `URL` + `label` only | 235,795 |
| 2 | Drop missing values | 235,795 |
| 3 | Drop rows with unknown labels | 235,795 |
| 4 | Normalise URL, remove invalid / over-long | 235,787 |
| 5 | Encode labels (1→0, 0→1) | 235,787 |
| 6 | Remove conflicting-label URLs | 235,787 (0 rows removed, 0 conflicting URLs) |
| 7 | Remove exact duplicates | 235,348 (439 removed) |

---

## 6. Leakage control (the brief's explicit requirement)

A random row-level split would leak near-identical URLs into train and test and inflate the reported
metrics. Instead, `ml/preprocess.py` builds **whole groups** that are never divided:

* **Group nodes:** the approximate registrable domain (eTLD+1, with a documented two-level public-suffix
  list) and the near-duplicate **path signature** (digit runs and long tokens masked, query values dropped,
  query keys sorted).
* **Union-find** merges every domain with every non-generic path signature it contains. Path signatures
  occurring in more than 20 distinct domains are treated as **generic** and excluded
  from merging; otherwise the single `/` signature (which covers 211,719 rows)
  would connect the entire dataset into one group.
* **Split assignment:** largest-remaining-capacity greedy allocation (largest groups first, seed
  42), followed by class-balance repair that swaps WHOLE size-1 groups. Split sizes stay exact and
  group integrity is preserved.

Measured grouping results:

| Property | Value |
| --- | --- |
| Distinct registrable domains | 179,488 |
| Distinct path signatures | 13,885 |
| Generic signatures excluded | 44 |
| Leakage groups | 177,201 |
| Singleton groups | 171,285 |
| Largest group | 23,675 rows |
| Balance swaps performed | 11,310 |

**Notable finding:** the largest group contains 23,675 URLs spanning 420 free-hosting
domains (`web.app`, `repl.co`, `ipfs.io`, ...) and is **99.7% phishing**. These are near-identical
phishing-kit URLs. Because they are one group, the entire cluster is confined to the **training** split.
A naive random split would have scattered them into validation/test and produced an artificially high
score. This is direct evidence that the leakage control matters.

### Leakage report (`dataset/processed/leakage_report.json`)

| Check | Result |
| --- | --- |
| Groups appearing in more than one split | 0 |
| URLs appearing in more than one split | 0 |
| Non-generic signatures appearing in more than one split | 0 |
| Rows in splits == clean rows | 235,348 == 235,348 |
| Labels are binary | true |
| **Overall `leakage_free`** | **true** |

---

## 7. Class distribution and final splits

Ratios: **70% / 15% / 15%**, seed 42.

| Split | Total | Legitimate | Phishing | Legitimate % | Phishing % |
| --- | --- | --- | --- | --- | --- |
| all_clean | 235,348 | 134,850 | 100,498 | 57.30% | 42.70% |
| train | 164,744 | 93,690 | 71,054 | 56.87% | 43.13% |
| validation | 35,302 | 20,580 | 14,722 | 58.30% | 41.70% |
| test | 35,302 | 20,580 | 14,722 | 58.30% | 41.70% |

Overall phishing rate: **42.70%**. All splits are within the documented
1.0% class-balance tolerance. No class resampling was performed (the dataset is
already reasonably balanced); oversampling would distort the meaning of `predict_proba`.

Artefacts written to `dataset/processed/`: `train.csv`, `validation.csv`, `test.csv`,
`class_distribution.csv`, `manifest.json`, `preprocessing_stats.json`, `leakage_report.json`.
Each split CSV contains exactly three columns: `url`, `label`, `group_id`.

---

## 8. Reproducing Stage 3

```bash
# Windows: use py -3 / .venv\Scripts\python.exe instead of python
python scripts/download_dataset.py --verify-only
python -m ml.preprocess --input dataset/raw/PhiUSIIL_Phishing_URL_Dataset.csv \
    --output-dir dataset/processed --ratios 0.70 0.15 0.15 --seed 42
python scripts/verify_stage3.py
```

Environment at generation: Python 3.13.16, pandas 2.3.3.
The split is deterministic for a given seed and input file SHA-256.

---

## 9. Limitations and ethical handling

* **No live malicious website was visited.** The dataset was downloaded from UCI as a CSV and parsed as
  strings. Feature extraction in Stage 4 is purely lexical. This satisfies the testing constraint in the brief.
* **Age and representativeness.** The data was donated in March 2024. Phishing tactics change; a model
  trained on it may not generalise to newer kits. This belongs in the Limitations chapter.
* **Source bias.** Legitimate URLs in this dataset are largely short homepages of real institutions and
  phishing URLs are largely free-hosting subdomains. A classifier may learn dataset-specific shortcuts
  (for example "long URL = phishing"). Stage 6 will report performance honestly with this caveat.
* **Authentication is not available.** The authors' webpage-derived columns were discarded, so the model
  cannot use page content, redirects, certificates, domain age or reputation.
* **Conservative grouping cost.** Confining the 23,675-URL kit cluster to training
  reduces the diversity of phishing examples in the held-out splits; this is an accepted trade-off for
  avoiding inflated metrics.
* **Attribution.** CC BY 4.0 requires the citation in §1 in the final report and README.
* **At Stage 3, no model or metric existed.** Stage 5 later trained candidates and Stage 6 measured
  accuracy, precision, recall, F1 and ROC-AUC; those results are in `ml/saved_model/metrics.json` and
  `docs/EVALUATION.md`. This document remains the Stage 3 provenance record — it deliberately claims
  no performance figure.
