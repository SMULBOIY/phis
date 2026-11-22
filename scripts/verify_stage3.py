#!/usr/bin/env python3
"""Stage 3 exit gate: dataset provenance, cleaning, leakage and reproducibility.

    cd phishing-detection-system
    python scripts/verify_stage3.py

Exits 0 only when every check passes. Uses ONLY local files and safe, controlled
synthetic FIXTURES for unit tests - no live or malicious website is contacted,
and no synthetic row is ever added to the real training data.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
# Set by a parent gate (e.g. verify_stage10.py) to avoid running
# the same historical gate exponentially many times. A standalone
# run has this unset and keeps its complete regression behaviour.
PDS_NESTED_GATES = os.environ.get("PDS_GATE_NESTED") == "1"
for entry in (str(ROOT), str(ROOT / "scripts")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from download_dataset import EXPECTED_ARCHIVE_SHA256, EXPECTED_CSV_SHA256  # noqa: E402
from ml import preprocess  # noqa: E402
from ml.url_utils import (  # noqa: E402
    is_valid_url, normalize_url, path_signature, registrable_domain,
)

RAW_DIR = ROOT / "dataset" / "raw"
PROCESSED_DIR = ROOT / "dataset" / "processed"
ARCHIVE = RAW_DIR / "phiusiil+phishing+url+dataset.zip"
RAW_CSV = RAW_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"

REQUIRED_FILES = (
    "dataset/raw/PhiUSIIL_Phishing_URL_Dataset.csv",
    "dataset/raw/phiusiil+phishing+url+dataset.zip",
    "dataset/processed/train.csv",
    "dataset/processed/validation.csv",
    "dataset/processed/test.csv",
    "dataset/processed/class_distribution.csv",
    "dataset/processed/manifest.json",
    "dataset/processed/preprocessing_stats.json",
    "dataset/processed/leakage_report.json",
    "docs/DATASET.md",
    "ml/__init__.py",
    "ml/url_utils.py",
    "ml/preprocess.py",
    "scripts/download_dataset.py",
    "scripts/verify_stage3.py",
)

REQUIRED_DOC_SECTIONS = (
    "## 1. Source and citation",
    "## 2. Why this dataset was selected",
    "## 3. Measured dataset description",
    "## 4. The",
    "## 5. Preprocessing pipeline",
    "## 6. Leakage control",
    "## 7. Class distribution and final splits",
    "## 8. Reproducing Stage 3",
    "## 9. Limitations and ethical handling",
)

# Files belonging to Stage 4+ that must not exist yet.
FORBIDDEN_NOW = (
    "ml/feature_extraction.py", "ml/train_model.py", "ml/evaluate_model.py",
    "ml/thresholds.py", "docs/FEATURES.md", "docs/MODEL_CARD.md",
    "ml/saved_model/model_bundle.joblib", "ml/saved_model/metrics.json",
    "services/validation.py", "services/detection_service.py",
    "models/database_models.py", "models/prediction_model.py",
    "app.py", "wsgi.py", "instance/phishing.db", "templates/index.html",
)

# Once Stage 4 is delivered, its own gate enforces "no later-stage code".
STAGE_4_DELIVERED = (
    (ROOT / "ml" / "feature_extraction.py").is_file()
    and (ROOT / "docs" / "FEATURES.md").is_file()
)
STAGE_6_DELIVERED = (
    (ROOT / "ml" / "saved_model" / "metrics.json").is_file()
    and (ROOT / "docs" / "EVALUATION.md").is_file()
)

failures: list[str] = []
checks = 0


def check(label: str, condition: bool, hint: str = "") -> None:
    global checks
    checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -> {hint}" if hint else ""))
        failures.append(label)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(rel: str) -> dict[str, Any]:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def check_files_and_integrity() -> dict[str, Any]:
    print("\n[1] Files and dataset integrity")
    for rel in REQUIRED_FILES:
        path = ROOT / rel
        check(f"file {rel}", path.is_file() and path.stat().st_size > 0, "missing or empty")
    check("raw archive SHA-256 matches pinned value",
          ARCHIVE.is_file() and sha256_file(ARCHIVE) == EXPECTED_ARCHIVE_SHA256)
    check("raw CSV SHA-256 matches pinned value",
          RAW_CSV.is_file() and sha256_file(RAW_CSV) == EXPECTED_CSV_SHA256)
    manifest = load_json("dataset/processed/manifest.json")
    check("manifest records the same CSV SHA-256",
          manifest["dataset"]["sha256"] == EXPECTED_CSV_SHA256)
    check("manifest records the same CSV size",
          manifest["dataset"]["file_size_bytes"] == RAW_CSV.stat().st_size)
    return manifest


def check_documentation(manifest: dict[str, Any]) -> None:
    print("\n[2] Provenance documentation")
    doc = (ROOT / "docs/DATASET.md").read_text(encoding="utf-8")
    for section in REQUIRED_DOC_SECTIONS:
        check(f"DATASET.md :: {section}", section in doc)
    facts = (
        manifest["dataset"]["sha256"],
        f"{manifest['dataset']['source_row_count']:,}",
        f"{manifest['accounting']['clean_rows']:,}",
        f"{manifest['grouping']['largest_group_size']:,}",
        "CC BY 4.0",
        "10.1016/j.cose.2023.103545",
    )
    for fact in facts:
        check(f"DATASET.md contains measured fact {fact[:32]}...", fact in doc)
    if STAGE_6_DELIVERED:
        check("DATASET.md points to the Stage 6 measured results",
              "docs/EVALUATION.md" in doc and "At Stage 3, no model or metric existed" in doc)
    else:
        check("DATASET.md states no model metrics are claimed",
              "No model or metric exists yet" in doc)
    check("DATASET.md records UCI label semantics", "Label 1" in doc and "legitimate" in doc)


def check_url_utils() -> None:
    print("\n[3] URL normalisation utilities (controlled fixtures)")
    cases = [
        ("https://Example.COM/Path?Q=1#Frag", "https://example.com/Path?Q=1#Frag"),
        ("example.com", "http://example.com"),
        ("http://user:pass@EXAMPLE.com:80/a", "http://user:pass@example.com/a"),
        ("https://example.com:8443/verify%20now", "https://example.com:8443/verify%20now"),
        ("http://192.168.1.1/login", "http://192.168.1.1/login"),
    ]
    for raw, expected in cases:
        actual = normalize_url(raw)
        check(f"normalize_url({raw[:34]!r})", actual == expected, f"got {actual!r}")

    invalid = ("", "   ", "ftp://example.com", "javascript:alert(1)", "http://",
               "http://exa mple.com", "https://example.com:notaport/x", "x" * 2100)
    for raw in invalid:
        check(f"reject invalid {raw[:24]!r}", normalize_url(raw) is None)

    check("is_valid_url agrees with normalize_url",
          is_valid_url("https://example.com") and not is_valid_url("ftp://example.com"))
    check("normalisation is idempotent",
          normalize_url(normalize_url("HTTPS://WWW.Example.COM/a") or "")
          == normalize_url("HTTPS://WWW.Example.COM/a"))
    check("registrable_domain handles multi-label suffixes",
          registrable_domain("https://www.shop.example.co.uk/a") == "example.co.uk")
    check("registrable_domain handles plain domains",
          registrable_domain("http://www.example.com/a") == "example.com")
    check("path_signature masks tokens and digits",
          path_signature("https://a.com/secure/verify/1234567890abcdef?id=7&next=x")
          == path_signature("https://b.com/secure/verify/9988776655fedcba?next=y&id=9"))
    check("path_signature distinguishes different paths",
          path_signature("https://a.com/login") != path_signature("https://a.com/about"))
    # No network module may be used by the normaliser.
    source = (ROOT / "ml/url_utils.py").read_text(encoding="utf-8")
    for forbidden in ("import requests", "import socket", "urllib.request", "http.client"):
        check(f"url_utils.py has no {forbidden}", forbidden not in source)


def check_splits(manifest: dict[str, Any]) -> None:
    print("\n[4] Processed splits and measured leakage")
    import pandas as pd

    parts = {
        name: pd.read_csv(PROCESSED_DIR / f"{name}.csv")
        for name in preprocess.SPLIT_NAMES
    }
    combined = pd.concat([part.assign(split=name) for name, part in parts.items()], ignore_index=True)
    expected_columns = list(preprocess.OUTPUT_COLUMNS)
    for name, part in parts.items():
        check(f"{name}.csv columns are exactly {expected_columns}", list(part.columns) == expected_columns)
        check(f"{name}.csv is non-empty", len(part) > 1000)
        check(f"{name}.csv labels are binary", set(part["label"].unique()).issubset({0, 1}))
        check(f"{name}.csv every URL is valid", part["url"].map(is_valid_url).all())

    accounting = manifest["accounting"]
    check("accounting: raw rows", accounting["raw_rows"] == manifest["dataset"]["source_row_count"])
    check("accounting: invalid URLs removed > 0", accounting["after_invalid_urls_removed"] < accounting["raw_rows"])
    check("accounting: duplicates removed",
          accounting["exact_duplicates_removed"] > 0)
    expected_clean = (
        accounting["after_invalid_urls_removed"]
        - accounting["conflicting_rows_removed"]
        - accounting["exact_duplicates_removed"]
    )
    check("accounting: clean row count is fully explained",
          accounting["clean_rows"] == expected_clean,
          f"{accounting['clean_rows']} != {expected_clean}")
    check("all clean rows are present in splits", len(combined) == accounting["clean_rows"])
    check("no duplicate URL anywhere", not combined["url"].duplicated().any())

    url_splits = combined.groupby("url")["split"].nunique()
    group_splits = combined.groupby("group_id")["split"].nunique()
    check("zero URLs in multiple splits", int((url_splits > 1).sum()) == 0)
    check("zero groups in multiple splits", int((group_splits > 1).sum()) == 0)

    # Independent recomputation of the non-generic signature leakage check.
    domains = combined["url"].map(registrable_domain)
    signatures = combined["url"].map(path_signature)
    tmp = pd.DataFrame({"signature": signatures, "domain": domains, "split": combined["split"]})
    domains_per_sig = tmp.groupby("signature")["domain"].nunique()
    generic = set(domains_per_sig[domains_per_sig > manifest["grouping"]["max_template_domains"]].index)
    non_generic = tmp[~tmp["signature"].isin(generic)]
    sig_splits = non_generic.groupby("signature")["split"].nunique()
    check("zero non-generic signatures in multiple splits", int((sig_splits > 1).sum()) == 0)

    leakage = load_json("dataset/processed/leakage_report.json")
    check("leakage_report.json says leakage_free", leakage["leakage_free"] is True)
    check("manifest leakage_report matches file", manifest["leakage_report"] == leakage)

    ratios = manifest["split"]["ratios"]
    total = len(combined)
    for name, part in parts.items():
        deviation = abs(len(part) / total - ratios[name])
        check(f"{name} ratio within 0.2% of target", deviation < 0.002,
              f"deviation {deviation:.5f}")
    overall_rate = manifest["split"]["overall_phishing_rate"]
    for name, part in parts.items():
        rate = float((part["label"] == 1).mean())
        check(f"{name} phishing rate within 1.5pp of overall",
              abs(rate - overall_rate) <= 0.015,
              f"{rate:.4f} vs {overall_rate:.4f}")

    dist_file = pd.read_csv(PROCESSED_DIR / "class_distribution.csv")
    check("class_distribution.csv covers all splits",
          set(dist_file["split"]) == {"all_clean", *preprocess.SPLIT_NAMES})
    for row in dist_file.to_dict(orient="records"):
        if row["split"] == "all_clean":
            continue
        part = parts[row["split"]]
        check(f"class_distribution.csv matches {row['split']}.csv counts",
              row["total"] == len(part)
              and row["legitimate"] == int((part["label"] == 0).sum())
              and row["phishing"] == int((part["label"] == 1).sum()))


def check_label_inversion() -> None:
    print("\n[5] Label encoding verified against the raw file")
    import pandas as pd

    raw = pd.read_csv(RAW_CSV, usecols=["URL", "label"])
    raw_map = dict(zip(raw["URL"].astype(str), raw["label"]))
    sample = pd.read_csv(PROCESSED_DIR / "train.csv").head(5000)
    matched = [(raw_map.get(str(url)), int(label)) for url, label in
               zip(sample["url"], sample["label"]) if str(url) in raw_map]
    check("sample rows matched against raw labels", len(matched) > 1000)
    check("source label 1 (legitimate) became project 0",
          all(project == 0 for source, project in matched if source == 1))
    check("source label 0 (phishing) became project 1",
          all(project == 1 for source, project in matched if source == 0))
    check("both classes appear in matched sample",
          {source for source, _ in matched} == {0, 1})


def check_controlled_fixture() -> None:
    print("\n[6] End-to-end pipeline on a SAFE synthetic fixture (never training data)")
    import pandas as pd

    fixture_rows = [
        ("https://legit-example.com/", 1),
        ("https://legit-example.com/about", 1),
        ("https://news-example.org/article", 1),
        ("https://shop-example.net/item?id=4", 1),
        ("http://kit-host-a.web.app/secure/verify/1234567890abcdef", 0),
        ("http://kit-host-b.web.app/secure/verify/9988776655fedcba", 0),
        ("http://kit-host-c.repl.co/secure/verify/aaaabbbbccccdddd", 0),
        ("http://192.168.0.99/login", 0),
        ("https://LEGIT-EXAMPLE.com/", 1),          # duplicate after normalisation
        ("not a url with spaces", 1),                # invalid
        ("ftp://bad-scheme.example", 1),             # invalid scheme
        ("x" * 2100, 0),                             # over-long
        ("", 1),                                     # empty
        ("https://conflict-example.com/", 1),
        ("https://conflict-example.com/", 0),        # conflicting labels -> both dropped
    ]
    with tempfile.TemporaryDirectory(prefix="stage3_fixture_") as tmp:
        tmp_path = Path(tmp)
        input_csv = tmp_path / "fixture.csv"
        pd.DataFrame(fixture_rows, columns=["URL", "label"]).to_csv(input_csv, index=False)
        config = preprocess.PreprocessConfig(
            input_path=input_csv,
            output_dir=tmp_path / "out",
            ratios=(0.60, 0.20, 0.20),
            seed=7,
            max_template_domains=5,
        )
        first = preprocess.run(config)
        check("fixture pipeline completes", first["leakage"]["leakage_free"] is True)
        check("fixture drops invalid and over-long rows", first["clean_rows"] < len(fixture_rows))
        check("fixture removes the conflicting-label URL",
              not any("conflict-example" in url for url in
                      pd.read_csv(tmp_path / "out" / "train.csv")["url"].tolist()
                      + pd.read_csv(tmp_path / "out" / "validation.csv")["url"].tolist()
                      + pd.read_csv(tmp_path / "out" / "test.csv")["url"].tolist()))
        encoded = pd.concat([
            pd.read_csv(tmp_path / "out" / f"{name}.csv") for name in preprocess.SPLIT_NAMES
        ])
        lookup = dict(zip(encoded["url"], encoded["label"]))
        check("fixture: source label 1 (legitimate) became project 0",
              lookup.get("https://legit-example.com/") == 0)
        check("fixture: source label 0 (phishing) became project 1",
              lookup.get("http://kit-host-a.web.app/secure/verify/1234567890abcdef") == 1)
        check("fixture URLs are all valid", encoded["url"].map(is_valid_url).all())
        check("fixture has both classes", set(encoded["label"]) == {0, 1})
        check("fixture contains no invalid / over-long rows",
              all(len(url) <= 2048 for url in encoded["url"]))
        # Determinism: a second identical run must reproduce byte-identical splits.
        second_dir = tmp_path / "out2"
        preprocess.run(preprocess.PreprocessConfig(
            input_path=input_csv, output_dir=second_dir,
            ratios=(0.60, 0.20, 0.20), seed=7, max_template_domains=5,
        ))
        for name in preprocess.SPLIT_NAMES:
            first_bytes = (tmp_path / "out" / f"{name}.csv").read_bytes()
            second_bytes = (second_dir / f"{name}.csv").read_bytes()
            check(f"fixture {name} split is deterministic", first_bytes == second_bytes)

    check("no synthetic fixture written into dataset/",
          not any(ROOT.glob("dataset/**/fixture*.csv")))


def check_stage_discipline() -> None:
    print("\n[7] Stage discipline and regressions")
    if not STAGE_4_DELIVERED:
        for rel in FORBIDDEN_NOW:
            check(f"not created yet :: {rel}", not (ROOT / rel).exists())
        for rel in ("ml", "models", "routes", "services", "tests"):
            allowed = {"__init__.py", "url_utils.py", "preprocess.py"} if rel == "ml" else set()
            stray = [p.name for p in (ROOT / rel).glob("*.py") if p.name not in allowed]
            check(f"{rel}/ contains only Stage 1-3 modules", not stray, ", ".join(stray))
    else:
        print("  SKIP  no Stage 4+ code yet (delivered in Stage 4; enforced by verify_stage4.py)")

    for gate in ("verify_stage1.py", "verify_stage2.py"):
        # The top-level gate already executes every historical gate directly.
        # Skipping this duplicated nested re-run keeps the suite linear rather
        # than exponential; standalone runs are completely unaffected.
        if PDS_NESTED_GATES:
            print(f"  SKIP  nested regression {gate} (top-level gate runs it)")
            continue
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / gate)],
            capture_output=True, text=True, timeout=180, cwd=ROOT,
        )
        tail = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
        check(f"{gate} still passes", proc.returncode == 0, tail[-1] if tail else "no output")


def main() -> int:
    print("=" * 74)
    print("STAGE 3 EXIT GATE - dataset acquisition and preprocessing")
    print(f"Project root : {ROOT}")
    print("=" * 74)
    manifest = check_files_and_integrity()
    check_documentation(manifest)
    check_url_utils()
    check_splits(manifest)
    check_label_inversion()
    check_controlled_fixture()
    check_stage_discipline()
    print("\n" + "=" * 74)
    if failures:
        print(f"RESULT: FAIL - {len(failures)} of {checks} checks failed")
        for label in failures:
            print(f"  - {label}")
        return 1
    print(f"RESULT: PASS - all {checks} checks passed")
    print("Stage 3 exit gate satisfied. You may proceed to Stage 4.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
