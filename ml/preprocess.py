"""Dataset preprocessing for the Phishing Website Detection System (Stage 3).

Reads a REAL labelled CSV (default: PhiUSIIL / UCI dataset 967), keeps only the
raw URL string and the label, and produces a leakage-safe train / validation /
test split.

Why only two columns are kept
-----------------------------
The source CSV has 56 columns. 54 of them are pre-computed features, many of
which were derived from downloaded webpage source code (LineOfCode, HasTitle,
NoOfJS, HasPasswordField ...). A live scanner that never fetches a URL cannot
compute those, so training on them would be *unavailable-feature leakage* and
would produce a model that cannot be deployed. Only ``URL`` and ``label`` are
used; features are recomputed from the raw string in Stage 4 by the shared
``ml.feature_extraction`` module.

Pipeline (every step is counted and recorded in the manifest)
------------------------------------------------------------
1. Load only raw URL + label; record the full source column list.
2. Drop missing values and rows with unknown labels.
3. Normalise URLs with ``ml.url_utils.normalize_url`` (same function used live).
4. Drop invalid / over-long URLs.
5. Encode labels: source 1 = legitimate, 0 = phishing; project standard is
   0 = legitimate, 1 = phishing, so labels are explicitly inverted.
6. Remove exact duplicates; remove all rows of any URL with conflicting labels.
7. Build leakage groups with union-find over (a) registrable domain and
   (b) non-generic path signatures. Generic signatures appearing in more than
   ``--max-template-domains`` distinct domains are excluded from merging,
   otherwise the single ``/`` signature would connect the whole dataset.
8. Assign WHOLE groups to splits with a stratified greedy algorithm targeting
   both the 70/15/15 size ratio and the overall class balance.
9. Verify zero group, URL and non-generic-signature overlap between splits.
10. Write train/validation/test CSVs, class distribution, manifest, statistics
    and a leakage report.

Usage
-----
    python -m ml.preprocess --input dataset/raw/PhiUSIIL_Phishing_URL_Dataset.csv
    python -m ml.preprocess --help

This module never fetches a URL. It only reads local CSV files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from ml.url_utils import (
    DEFAULT_MAX_URL_LENGTH,
    normalize_url,
    path_signature,
    registrable_domain,
)

RAW_URL_COLUMN = "URL"
RAW_LABEL_COLUMN = "label"

# UCI PhiUSIIL: label 1 = legitimate, label 0 = phishing.
# Project convention (docs/ARCHITECTURE.md section 5): 0 = legitimate, 1 = phishing.
RAW_LABEL_TO_PROJECT: dict[int, int] = {1: 0, 0: 1}
LABEL_NAMES: dict[int, str] = {0: "legitimate", 1: "phishing"}
SPLIT_NAMES: tuple[str, ...] = ("train", "validation", "test")
OUTPUT_COLUMNS: tuple[str, ...] = ("url", "label", "group_id")


@dataclass(frozen=True)
class PreprocessConfig:
    """All parameters of one preprocessing run (recorded in the manifest)."""

    input_path: Path
    output_dir: Path
    ratios: tuple[float, float, float] = (0.70, 0.15, 0.15)
    seed: int = 42
    max_template_domains: int = 20
    max_url_length: int = DEFAULT_MAX_URL_LENGTH
    url_column: str = RAW_URL_COLUMN
    label_column: str = RAW_LABEL_COLUMN
    dataset_name: str = "PhiUSIIL Phishing URL (Website)"
    dataset_source: str = "UCI Machine Learning Repository, dataset 967"


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file (streamed, low memory)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_raw(config: PreprocessConfig) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Load ONLY the URL and label columns; return the frame and source facts."""
    if not config.input_path.is_file():
        raise FileNotFoundError(f"Input CSV not found: {config.input_path}")

    all_columns = list(pd.read_csv(config.input_path, nrows=0).columns)
    missing = [col for col in (config.url_column, config.label_column) if col not in all_columns]
    if missing:
        raise ValueError(
            f"Missing required column(s) {missing}. Available columns: {all_columns}"
        )

    frame = pd.read_csv(
        config.input_path,
        usecols=[config.url_column, config.label_column],
        dtype={config.url_column: "string"},
        low_memory=False,
    )
    facts = {
        "source_columns": all_columns,
        "source_column_count": len(all_columns),
        "columns_used": [config.url_column, config.label_column],
        "columns_dropped": [c for c in all_columns if c not in (config.url_column, config.label_column)],
        "source_row_count": int(len(frame)),
        "sha256": sha256_file(config.input_path),
        "file_size_bytes": config.input_path.stat().st_size,
    }
    return frame, facts


def clean(frame: pd.DataFrame, config: PreprocessConfig) -> tuple[pd.DataFrame, dict[str, int]]:
    """Validate, normalise, encode labels and remove duplicates."""
    counts: dict[str, int] = {"raw_rows": int(len(frame))}
    work = frame.rename(columns={config.url_column: "raw_url", config.label_column: "raw_label"}).copy()

    # 1. Missing values.
    work = work.dropna(subset=["raw_url", "raw_label"])
    counts["after_missing_removed"] = int(len(work))

    # 2. Known labels only.
    numeric_labels = pd.to_numeric(work["raw_label"], errors="coerce")
    work = work.loc[numeric_labels.isin(list(RAW_LABEL_TO_PROJECT))].copy()
    work["raw_label"] = numeric_labels.loc[work.index].astype(int)
    counts["after_unknown_labels_removed"] = int(len(work))

    # 3. Normalisation (identical function to the live scanner) and validity.
    work["url"] = work["raw_url"].astype(str).map(
        lambda raw: normalize_url(raw, max_length=config.max_url_length)
    )
    work = work.loc[work["url"].notna()].copy()
    work["url"] = work["url"].astype(str)
    counts["after_invalid_urls_removed"] = int(len(work))

    # 4. Explicit label encoding with the documented inversion.
    work["label"] = work["raw_label"].map(RAW_LABEL_TO_PROJECT).astype(int)
    if set(work["label"].unique()) - set(LABEL_NAMES):
        raise ValueError("Unexpected encoded label values after mapping")
    counts["label_encoded_rows"] = int(len(work))

    # 5. Exact duplicates and label conflicts.
    conflicts = work.groupby("url")["label"].nunique()
    conflicting_urls = set(conflicts[conflicts > 1].index)
    counts["conflicting_label_urls"] = len(conflicting_urls)
    before_conflicts = len(work)
    work = work.loc[~work["url"].isin(conflicting_urls)].copy()
    counts["conflicting_rows_removed"] = int(before_conflicts - len(work))
    counts["after_conflicts_removed"] = int(len(work))
    before_dedup = len(work)
    work = work.drop_duplicates(subset="url", keep="first").copy()
    counts["exact_duplicates_removed"] = int(before_dedup - len(work))
    counts["clean_rows"] = int(len(work))

    result = work[["url", "label"]].reset_index(drop=True)
    assert result["url"].map(normalize_url).notna().all()
    return result, counts


class _DisjointSet:
    """Minimal union-find with path compression, used for leakage grouping."""

    def __init__(self) -> None:
        self.parent: dict[tuple[str, str], tuple[str, str]] = {}

    def add(self, item: tuple[str, str]) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: tuple[str, str]) -> tuple[str, str]:
        self.add(item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, left: tuple[str, str], right: tuple[str, str]) -> None:
        root_left, root_right = self.find(left), self.find(right)
        if root_left != root_right:
            # Deterministic root choice (lexicographic) keeps group ids stable.
            smaller, larger = sorted((root_left, root_right))
            self.parent[larger] = smaller


def build_groups(
    frame: pd.DataFrame, max_template_domains: int
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Attach an integer ``group_id`` that must never be split across datasets."""
    work = frame.copy()
    work["domain"] = work["url"].map(registrable_domain)
    work["signature"] = work["url"].map(path_signature)

    domains_per_signature = work.groupby("signature")["domain"].nunique()
    generic = set(domains_per_signature[domains_per_signature > max_template_domains].index)
    generic_rows = int(work["signature"].isin(generic).sum())

    dsu = _DisjointSet()
    for domain, signature in zip(work["domain"], work["signature"]):
        domain_node = ("D", domain)
        dsu.add(domain_node)
        if signature not in generic:
            dsu.union(domain_node, ("S", signature))

    roots = sorted({dsu.find(node) for node in dsu.parent})
    root_to_id = {root: index for index, root in enumerate(roots)}
    work["group_id"] = [
        root_to_id[dsu.find(("D", domain))] for domain in work["domain"]
    ]

    group_sizes = work["group_id"].value_counts()
    stats = {
        "method": "union-find over registrable domain + non-generic path signature",
        "max_template_domains": max_template_domains,
        "distinct_domains": int(work["domain"].nunique()),
        "distinct_path_signatures": int(work["signature"].nunique()),
        "generic_signatures_excluded": len(generic),
        "rows_with_generic_signature": generic_rows,
        "group_count": int(len(group_sizes)),
        "largest_group_size": int(group_sizes.iloc[0]),
        "singleton_group_count": int((group_sizes == 1).sum()),
    }
    return work[["url", "label", "group_id", "domain", "signature"]], stats


def split_by_group(
    frame: pd.DataFrame,
    ratios: tuple[float, float, float],
    seed: int,
    balance_tolerance: float = 0.01,
) -> tuple[dict[str, pd.DataFrame], dict[str, Any]]:
    """Assign WHOLE groups to splits, then repair class balance.

    Pass 1 (longest-processing-time / largest-remaining-capacity): groups are
    considered largest first and each goes to the split with the biggest
    ABSOLUTE remaining capacity. Using a relative deviation here is a classic
    mistake - it always favours the smallest split first and wrecks the ratio.
    Class imbalance is used only as a deterministic tie-breaker.

    Pass 2 (balance repair): while any split's phishing rate is more than
    ``balance_tolerance`` away from the overall rate, swap one phishing
    singleton group from the most phishing-heavy split with one legitimate
    singleton group from the least phishing-heavy split. Both groups move as
    whole units and both have size 1, so group integrity AND exact split sizes
    are preserved. There are ~171k singleton groups in this dataset, so this
    converges quickly.
    """
    if abs(sum(ratios) - 1.0) > 1e-9 or any(r <= 0 for r in ratios):
        raise ValueError(f"Split ratios must be positive and sum to 1.0, got {ratios}")

    aggregates = frame.groupby("group_id").agg(
        size=("label", "size"),
        legitimate=("label", lambda values: int((values == 0).sum())),
        phishing=("label", lambda values: int((values == 1).sum())),
    )
    total = int(len(frame))
    total_legit = int((frame["label"] == 0).sum())
    total_phish = int((frame["label"] == 1).sum())
    overall_phish_rate = total_phish / total

    targets = {
        split: {
            "size": ratio * total,
            "legitimate": ratio * total_legit,
            "phishing": ratio * total_phish,
        }
        for split, ratio in zip(SPLIT_NAMES, ratios)
    }
    keys = ("size", "legitimate", "phishing")
    current = {split: {key: 0 for key in keys} for split in SPLIT_NAMES}
    remaining = {
        split: {key: targets[split][key] for key in keys} for split in SPLIT_NAMES
    }

    # Deterministic order: seeded shuffle, then stable largest-first sort.
    order = list(aggregates.index)
    random.Random(seed).shuffle(order)
    order.sort(key=lambda gid: -int(aggregates.at[gid, "size"]))

    assignment: dict[int, str] = {}
    for gid in order:
        row = aggregates.loc[gid]
        addition = {
            "size": int(row["size"]),
            "legitimate": int(row["legitimate"]),
            "phishing": int(row["phishing"]),
        }
        best_key = None
        best_split = None
        for index, split in enumerate(SPLIT_NAMES):
            projected_size = current[split]["size"] + addition["size"]
            projected_rate = (
                current[split]["phishing"] + addition["phishing"]
            ) / max(projected_size, 1)
            # Primary: biggest remaining capacity. Secondary: least class
            # imbalance. Tertiary: fixed split order for full determinism.
            key = (
                -remaining[split]["size"],
                abs(projected_rate - overall_phish_rate),
                index,
            )
            if best_key is None or key < best_key:
                best_key, best_split = key, split
        assert best_split is not None
        assignment[gid] = best_split
        for key in keys:
            current[best_split][key] += addition[key]
            remaining[best_split][key] -= addition[key]

    # --- Pass 2: class-balance repair by swapping whole singleton groups ---
    phishing_singletons: dict[str, list[int]] = {split: [] for split in SPLIT_NAMES}
    legitimate_singletons: dict[str, list[int]] = {split: [] for split in SPLIT_NAMES}
    for gid, split in assignment.items():
        if int(aggregates.at[gid, "size"]) != 1:
            continue
        bucket = phishing_singletons if int(aggregates.at[gid, "phishing"]) == 1 else legitimate_singletons
        bucket[split].append(gid)

    swaps = 0
    max_swaps = 200_000
    for _ in range(max_swaps):
        rates = {
            split: current[split]["phishing"] / max(current[split]["size"], 1)
            for split in SPLIT_NAMES
        }
        excess = max(SPLIT_NAMES, key=lambda s: rates[s] - overall_phish_rate)
        deficit = min(SPLIT_NAMES, key=lambda s: rates[s] - overall_phish_rate)
        if rates[excess] - overall_phish_rate <= balance_tolerance and \
                overall_phish_rate - rates[deficit] <= balance_tolerance:
            break
        if excess == deficit or not phishing_singletons[excess] or not legitimate_singletons[deficit]:
            break
        gid_phish = phishing_singletons[excess].pop()
        gid_legit = legitimate_singletons[deficit].pop()
        assignment[gid_phish] = deficit
        assignment[gid_legit] = excess
        phishing_singletons[deficit].append(gid_phish)
        legitimate_singletons[excess].append(gid_legit)
        current[excess]["phishing"] -= 1
        current[excess]["legitimate"] += 1
        current[deficit]["phishing"] += 1
        current[deficit]["legitimate"] -= 1
        swaps += 1

    split_column = frame["group_id"].map(assignment)
    splits = {
        split: frame.loc[split_column == split, list(OUTPUT_COLUMNS)]
        .reset_index(drop=True)
        for split in SPLIT_NAMES
    }
    details = {
        "ratios": dict(zip(SPLIT_NAMES, ratios)),
        "seed": seed,
        "balance_tolerance": balance_tolerance,
        "balance_swaps": swaps,
        "overall_phishing_rate": round(overall_phish_rate, 6),
        "target_counts": {k: {kk: round(vv, 2) for kk, vv in v.items()} for k, v in targets.items()},
        "actual_counts": current,
        "actual_phishing_rate": {
            split: round(current[split]["phishing"] / max(current[split]["size"], 1), 6)
            for split in SPLIT_NAMES
        },
    }
    return splits, details


def verify_no_leakage(
    frame: pd.DataFrame, splits: dict[str, pd.DataFrame], max_template_domains: int
) -> dict[str, Any]:
    """Measure (not assume) every leakage property required by the brief."""
    report: dict[str, Any] = {}

    group_owner: dict[int, set[str]] = {}
    url_owner: dict[str, set[str]] = {}
    signature_owner: dict[str, set[str]] = {}
    for name, part in splits.items():
        for gid in part["group_id"].unique():
            group_owner.setdefault(int(gid), set()).add(name)
        for url in part["url"]:
            url_owner.setdefault(url, set()).add(name)
    for name, part in splits.items():
        joined = part.merge(frame[["url", "signature", "domain"]], on="url", how="left")
        for sig in joined["signature"].unique():
            signature_owner.setdefault(str(sig), set()).add(name)

    domains_per_signature = frame.groupby("signature")["domain"].nunique()
    generic = set(domains_per_signature[domains_per_signature > max_template_domains].index)

    report["groups_in_multiple_splits"] = sum(len(v) > 1 for v in group_owner.values())
    report["urls_in_multiple_splits"] = sum(len(v) > 1 for v in url_owner.values())
    report["non_generic_signatures_in_multiple_splits"] = sum(
        len(v) > 1 for sig, v in signature_owner.items() if sig not in generic
    )
    report["generic_signatures_allowed_across_splits"] = len(generic)
    report["total_rows_in_splits"] = sum(len(part) for part in splits.values())
    report["source_rows_before_split"] = int(len(frame))
    report["labels_are_binary"] = all(
        set(part["label"].unique()).issubset({0, 1}) for part in splits.values()
    )
    report["leakage_free"] = (
        report["groups_in_multiple_splits"] == 0
        and report["urls_in_multiple_splits"] == 0
        and report["non_generic_signatures_in_multiple_splits"] == 0
        and report["total_rows_in_splits"] == report["source_rows_before_split"]
        and report["labels_are_binary"]
    )
    return report


def class_distribution(splits: dict[str, pd.DataFrame], cleaned: pd.DataFrame) -> pd.DataFrame:
    """Build a tidy per-split class distribution table."""
    rows = []
    for name in ("all_clean", *SPLIT_NAMES):
        part = cleaned if name == "all_clean" else splits[name]
        legit = int((part["label"] == 0).sum())
        phish = int((part["label"] == 1).sum())
        denominator = max(legit + phish, 1)
        rows.append({
            "split": name,
            "total": legit + phish,
            "legitimate": legit,
            "phishing": phish,
            "legitimate_pct": round(100 * legit / denominator, 3),
            "phishing_pct": round(100 * phish / denominator, 3),
        })
    return pd.DataFrame(rows)


def run(config: PreprocessConfig) -> dict[str, Any]:
    """Execute the full pipeline and write every artefact. Returns a summary."""
    config.output_dir.mkdir(parents=True, exist_ok=True)

    raw, facts = load_raw(config)
    cleaned, counts = clean(raw, config)
    grouped, group_stats = build_groups(cleaned, config.max_template_domains)
    splits, split_details = split_by_group(grouped, config.ratios, config.seed)
    leakage = verify_no_leakage(grouped, splits, config.max_template_domains)
    if not leakage["leakage_free"]:
        raise RuntimeError(f"Leakage check failed: {json.dumps(leakage, indent=2)}")

    distribution = class_distribution(splits, cleaned)
    for name, part in splits.items():
        part.to_csv(config.output_dir / f"{name}.csv", index=False)
    distribution.to_csv(config.output_dir / "class_distribution.csv", index=False)

    manifest = {
        "schema_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stage": 3,
        "dataset": {
            "name": config.dataset_name,
            "source": config.dataset_source,
            "input_file": str(config.input_path),
            **facts,
        },
        "label_encoding": {
            "source_meaning": {"1": "legitimate", "0": "phishing"},
            "project_meaning": {"0": "legitimate", "1": "phishing"},
            "mapping_applied": {"1": 0, "0": 1},
        },
        "parameters": {
            "ratios": dict(zip(SPLIT_NAMES, config.ratios)),
            "seed": config.seed,
            "max_template_domains": config.max_template_domains,
            "max_url_length": config.max_url_length,
            "url_column": config.url_column,
            "label_column": config.label_column,
        },
        "accounting": counts,
        "grouping": group_stats,
        "split": split_details,
        "class_distribution": distribution.to_dict(orient="records"),
        "leakage_report": leakage,
        "output_files": [f"{name}.csv" for name in SPLIT_NAMES] + ["class_distribution.csv"],
        "environment": {
            "python": platform.python_version(),
            "pandas": pd.__version__,
        },
    }

    (config.output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=False), encoding="utf-8"
    )
    (config.output_dir / "preprocessing_stats.json").write_text(
        json.dumps({"accounting": counts, "grouping": group_stats}, indent=2), encoding="utf-8"
    )
    (config.output_dir / "leakage_report.json").write_text(
        json.dumps(leakage, indent=2), encoding="utf-8"
    )

    summary = {
        "source_rows": facts["source_row_count"],
        "clean_rows": counts["clean_rows"],
        "dropped_columns": len(facts["columns_dropped"]),
        "groups": group_stats["group_count"],
        "largest_group": group_stats["largest_group_size"],
        "split_sizes": {name: len(part) for name, part in splits.items()},
        "class_distribution": distribution.to_dict(orient="records"),
        "leakage": leakage,
    }
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Clean a labelled URL dataset and create leakage-safe splits (Stage 3)."
    )
    parser.add_argument("--input", type=Path,
                        default=Path("dataset/raw/PhiUSIIL_Phishing_URL_Dataset.csv"),
                        help="Path to the raw labelled CSV.")
    parser.add_argument("--output-dir", type=Path, default=Path("dataset/processed"),
                        help="Directory for train/validation/test CSVs and reports.")
    parser.add_argument("--ratios", type=float, nargs=3, default=[0.70, 0.15, 0.15],
                        metavar=("TRAIN", "VALIDATION", "TEST"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-template-domains", type=int, default=20,
                        help="Path signatures seen in more domains than this are 'generic'.")
    parser.add_argument("--max-url-length", type=int, default=DEFAULT_MAX_URL_LENGTH)
    parser.add_argument("--url-column", default=RAW_URL_COLUMN)
    parser.add_argument("--label-column", default=RAW_LABEL_COLUMN)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = PreprocessConfig(
        input_path=args.input,
        output_dir=args.output_dir,
        ratios=tuple(args.ratios),
        seed=args.seed,
        max_template_domains=args.max_template_domains,
        max_url_length=args.max_url_length,
        url_column=args.url_column,
        label_column=args.label_column,
    )
    print(f"Reading {config.input_path} ...")
    summary = run(config)
    print("\nStage 3 preprocessing complete")
    print(f"  source rows            : {summary['source_rows']:,}")
    print(f"  clean rows             : {summary['clean_rows']:,}")
    print(f"  non-URL columns dropped: {summary['dropped_columns']}")
    print(f"  leakage groups         : {summary['groups']:,} (largest {summary['largest_group']:,})")
    for name, size in summary["split_sizes"].items():
        print(f"  {name:<12}            : {size:,}")
    for row in summary["class_distribution"]:
        print(f"    {row['split']:<12} legit {row['legitimate']:>7,} "
              f"phish {row['phishing']:>7,}  phishing rate {row['phishing_pct']:.2f}%")
    print(f"  leakage free           : {summary['leakage']['leakage_free']}")
    print(f"  artefacts              : {config.output_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
