#!/usr/bin/env python3
"""Exploratory feature analysis on the TRAINING split only (Stage 4).

Computes the 15 features for every training URL, measures their distribution
per class, and writes ``dataset/processed/feature_summary.json`` and
``feature_summary.csv``. These are DESCRIPTIVE statistics, not model results:
no classifier is fitted and no accuracy figure is produced.

The validation and test splits are deliberately NOT read here. Looking at their
feature distributions while designing features would be a form of leakage.

    python scripts/analyse_features.py
    python scripts/analyse_features.py --limit 5000   # quick check
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from ml.feature_extraction import (  # noqa: E402
    FEATURE_DEFINITIONS, FEATURE_ORDER, extract_frame,
)

BINARY_FEATURES = frozenset({
    "has_ip_address", "has_at_symbol", "has_suspicious_pattern", "has_https",
    "is_shortened", "has_unusual_port", "has_encoded_chars",
})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path,
                        default=ROOT / "dataset" / "processed" / "train.csv")
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "dataset" / "processed")
    parser.add_argument("--limit", type=int, default=None,
                        help="Analyse only the first N rows (quick check).")
    args = parser.parse_args(argv)

    if not args.input.is_file():
        raise FileNotFoundError(f"Training split not found: {args.input}")
    train = pd.read_csv(args.input)
    if args.limit:
        train = train.head(args.limit).copy()
    if list(train.columns) != ["url", "label", "group_id"]:
        raise ValueError(f"Unexpected training columns: {list(train.columns)}")

    print(f"Extracting {len(FEATURE_ORDER)} features for {len(train):,} training URLs ...")
    features = extract_frame(train["url"].tolist())
    work = pd.concat([train[["label"]].reset_index(drop=True), features], axis=1)

    if not work[list(FEATURE_ORDER)].notna().all().all():
        raise RuntimeError("Feature extraction produced missing values")
    if not all(pd.api.types.is_numeric_dtype(work[name]) for name in FEATURE_ORDER):
        raise RuntimeError("Feature extraction produced a non-numeric column")

    legit = work[work["label"] == 0]
    phish = work[work["label"] == 1]
    rows = []
    for name in FEATURE_ORDER:
        rows.append({
            "feature": name,
            "definition": FEATURE_DEFINITIONS[name],
            "kind": "binary" if name in BINARY_FEATURES else "count",
            "overall_mean": round(float(work[name].mean()), 4),
            "legitimate_mean": round(float(legit[name].mean()), 4),
            "phishing_mean": round(float(phish[name].mean()), 4),
            "overall_present_pct": round(100 * float((work[name] > 0).mean()), 3),
            "legitimate_present_pct": round(100 * float((legit[name] > 0).mean()), 3),
            "phishing_present_pct": round(100 * float((phish[name] > 0).mean()), 3),
            "min": int(work[name].min()),
            "max": int(work[name].max()),
        })

    summary = {
        "stage": 4,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "description": "Descriptive feature statistics on the TRAINING split only. Not model performance.",
        "input_file": str(args.input.relative_to(ROOT)) if args.input.is_relative_to(ROOT) else str(args.input),
        "rows_analysed": int(len(train)),
        "legitimate_rows": int(len(legit)),
        "phishing_rows": int(len(phish)),
        "splits_read": ["train"],
        "splits_explicitly_excluded": ["validation", "test"],
        "feature_count": len(FEATURE_ORDER),
        "feature_order": list(FEATURE_ORDER),
        "features": rows,
        "environment": {"python": platform.python_version(), "pandas": pd.__version__},
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "feature_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    pd.DataFrame(rows).to_csv(args.output_dir / "feature_summary.csv", index=False)

    print(f"\nAnalysed {len(train):,} training rows "
          f"({len(legit):,} legitimate / {len(phish):,} phishing)")
    print(f"{'feature':<24} {'legit mean':>11} {'phish mean':>11} {'legit %':>9} {'phish %':>9}")
    for row in rows:
        print(f"{row['feature']:<24} {row['legitimate_mean']:>11.3f} "
              f"{row['phishing_mean']:>11.3f} {row['legitimate_present_pct']:>9.2f} "
              f"{row['phishing_present_pct']:>9.2f}")
    print(f"\nWrote {args.output_dir / 'feature_summary.json'}")
    print("No model was trained and no performance metric was computed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
