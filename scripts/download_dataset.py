#!/usr/bin/env python3
"""Reproducible acquisition of the PhiUSIIL / UCI dataset 967 (Stage 3).

This is a DEVELOPER-ONLY, one-off script. It is NOT part of the running web
application and is NEVER called during a URL scan. It downloads a single fixed,
trusted UCI URL (no user-controlled input), verifies the SHA-256 of the archive
and of the extracted CSV, then writes the CSV to dataset/raw/.

Pinned integrity values were measured on 2026-11-03 from the real download.
If UCI ever republishes the archive, the script fails loudly instead of silently
training on different data - that is deliberate.

Usage:
    python scripts/download_dataset.py
    python scripts/download_dataset.py --force     # re-download even if present
    python scripts/download_dataset.py --verify-only

No third-party packages are required (standard library only).
"""
from __future__ import annotations

import argparse
import hashlib
import ssl
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "dataset" / "raw"

SOURCE_NAME = "PhiUSIIL Phishing URL (Website)"
SOURCE_PAGE = "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
ARCHIVE_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
ARCHIVE_FILENAME = "phiusiil+phishing+url+dataset.zip"
CSV_FILENAME = "PhiUSIIL_Phishing_URL_Dataset.csv"

# Measured 2026-11-03. Both hashes are checked.
EXPECTED_ARCHIVE_SHA256 = "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a"
EXPECTED_CSV_SHA256 = "a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6"
DOWNLOAD_TIMEOUT_SECONDS = 300


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(archive: Path, force: bool) -> None:
    if archive.is_file() and not force:
        print(f"Archive already present: {archive}")
        return
    print(f"Downloading {SOURCE_NAME}")
    print(f"  source page : {SOURCE_PAGE}")
    print(f"  archive URL : {ARCHIVE_URL}")
    request = urllib.request.Request(
        ARCHIVE_URL,
        headers={"User-Agent": "phishing-detection-system/0.3 (academic project)"},
    )
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS, context=context) as response:
        payload = response.read()
    archive.write_bytes(payload)
    print(f"  downloaded  : {len(payload):,} bytes -> {archive}")


def verify_archive(archive: Path) -> None:
    actual = sha256_file(archive)
    print(f"  archive SHA-256: {actual}")
    if actual != EXPECTED_ARCHIVE_SHA256:
        raise RuntimeError(
            "Archive SHA-256 mismatch. UCI may have republished the file.\n"
            f"  expected: {EXPECTED_ARCHIVE_SHA256}\n  actual  : {actual}\n"
            "Do NOT train on unverified data. Re-check the source page and update "
            "the documented hash deliberately."
        )
    print("  archive integrity: OK")


def extract(archive: Path, csv_path: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if CSV_FILENAME not in names:
            raise RuntimeError(f"Expected {CSV_FILENAME} inside archive, found {names}")
        print(f"  extracting {CSV_FILENAME} ...")
        csv_path.write_bytes(bundle.read(CSV_FILENAME))
    actual = sha256_file(csv_path)
    print(f"  CSV SHA-256: {actual}")
    if actual != EXPECTED_CSV_SHA256:
        raise RuntimeError(
            "CSV SHA-256 mismatch. The extracted data differs from the documented file.\n"
            f"  expected: {EXPECTED_CSV_SHA256}\n  actual  : {actual}"
        )
    print(f"  CSV integrity: OK ({csv_path.stat().st_size:,} bytes)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Re-download the archive.")
    parser.add_argument("--verify-only", action="store_true",
                        help="Only verify existing files; do not download.")
    args = parser.parse_args(argv)

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    archive = RAW_DIR / ARCHIVE_FILENAME
    csv_path = RAW_DIR / CSV_FILENAME

    if args.verify_only:
        for label, path, expected in (
            ("archive", archive, EXPECTED_ARCHIVE_SHA256),
            ("CSV", csv_path, EXPECTED_CSV_SHA256),
        ):
            if not path.is_file():
                print(f"  MISSING {label}: {path}")
                return 1
            actual = sha256_file(path)
            print(f"  {label}: {actual} {'OK' if actual == expected else 'MISMATCH'}")
            if actual != expected:
                return 1
        print("Verification passed.")
        return 0

    download(archive, args.force)
    verify_archive(archive)
    if not csv_path.is_file() or args.force or sha256_file(csv_path) != EXPECTED_CSV_SHA256:
        extract(archive, csv_path)
    else:
        print(f"  CSV already present and verified: {csv_path}")
    print("\nDataset ready. Next:")
    print("  python -m ml.preprocess --input dataset/raw/PhiUSIIL_Phishing_URL_Dataset.csv")
    print("  python scripts/verify_stage3.py")
    print("\nRemember: this script is offline developer tooling. The web app never")
    print("downloads or fetches any URL submitted by a user.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
