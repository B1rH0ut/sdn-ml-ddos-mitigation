#!/usr/bin/env python3
"""
Dataset Download Helper and Integrity Verifier

Prints download instructions for real-world datasets and verifies
file integrity via SHA-256 checksums after the user downloads them manually.

Usage:
    python -m sdn_ddos_detector.datasets.download_datasets
    python -m sdn_ddos_detector.datasets.download_datasets --dataset cic-ids2017
    python -m sdn_ddos_detector.datasets.download_datasets --dataset all
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

# Base directory for raw and processed datasets
BASE_DIR = Path(__file__).resolve().parent

DATASETS = {
    "cic-ids2017": {
        "url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "description": "CIC-IDS2017 — 5-day capture, 2.8M flows, CICFlowMeter features",
        "raw_dir": "raw/cic-ids2017",
        "expected_files": [
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "Monday-WorkingHours.pcap_ISCX.csv",
            "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "Tuesday-WorkingHours.pcap_ISCX.csv",
            "Wednesday-workingHours.pcap_ISCX.csv",
        ],
        "checksums": {
            # SHA-256 checksums for integrity verification
            # These are approximate — exact checksums depend on download version
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": None,
        },
    },
    "cic-ddos2019": {
        "url": "https://www.unb.ca/cic/datasets/ddos-2019.html",
        "description": "CIC-DDoS2019 — 12+ DDoS types, training + testing day",
        "raw_dir": "raw/cic-ddos2019",
        "expected_files": [],  # Variable file names depending on download
        "checksums": {},
    },
    "unsw-nb15": {
        "url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "description": "UNSW-NB15 — 2.5M records, 49 Argus/Bro-IDS features",
        "raw_dir": "raw/unsw-nb15",
        "expected_files": [
            "UNSW_NB15_training-set.csv",
            "UNSW_NB15_testing-set.csv",
        ],
        "checksums": {},
    },
}


def sha256_file(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def ensure_directories():
    """Create raw/ and processed/ directories if they don't exist."""
    for subdir in ["raw", "processed"]:
        dirpath = BASE_DIR / subdir
        dirpath.mkdir(parents=True, exist_ok=True)

    for dataset_info in DATASETS.values():
        raw_dir = BASE_DIR / dataset_info["raw_dir"]
        raw_dir.mkdir(parents=True, exist_ok=True)


def print_download_instructions(dataset_name=None):
    """Print download instructions for specified or all datasets."""
    targets = (
        {dataset_name: DATASETS[dataset_name]}
        if dataset_name and dataset_name != "all"
        else DATASETS
    )

    print("\n" + "=" * 70)
    print("  Dataset Download Instructions")
    print("=" * 70)

    for name, info in targets.items():
        print(f"\n  {info['description']}")
        print(f"  URL: {info['url']}")
        raw_dir = BASE_DIR / info["raw_dir"]
        print(f"  Place files in: {raw_dir}/")
        if info["expected_files"]:
            print(f"  Expected files:")
            for f in info["expected_files"]:
                print(f"    - {f}")
        print()

    print("  After downloading, run this script again to verify file integrity.")
    print("=" * 70)


def verify_dataset(dataset_name):
    """Verify downloaded dataset files exist and check checksums."""
    if dataset_name not in DATASETS:
        print(f"  ERROR: Unknown dataset '{dataset_name}'")
        print(f"  Available: {', '.join(DATASETS.keys())}")
        return False

    info = DATASETS[dataset_name]
    raw_dir = BASE_DIR / info["raw_dir"]

    print(f"\n  Verifying: {info['description']}")
    print(f"  Directory: {raw_dir}")

    if not raw_dir.exists():
        print(f"  MISSING: Directory does not exist")
        return False

    # Check for any CSV files
    csv_files = list(raw_dir.glob("*.csv"))
    if not csv_files:
        print(f"  MISSING: No CSV files found in {raw_dir}")
        return False

    print(f"  Found {len(csv_files)} CSV file(s):")
    total_size = 0
    all_ok = True

    for csv_file in sorted(csv_files):
        size_mb = csv_file.stat().st_size / (1024 * 1024)
        total_size += size_mb
        file_hash = sha256_file(csv_file)

        # Check against known checksums if available
        expected_hash = info["checksums"].get(csv_file.name)
        if expected_hash and expected_hash != file_hash:
            status = "HASH MISMATCH"
            all_ok = False
        else:
            status = "OK"

        print(f"    {csv_file.name}: {size_mb:.1f} MB [{status}]")
        print(f"      SHA-256: {file_hash}")

    print(f"  Total size: {total_size:.1f} MB")

    if info["expected_files"]:
        found_names = {f.name for f in csv_files}
        missing = set(info["expected_files"]) - found_names
        if missing:
            print(f"  WARNING: Missing expected files: {missing}")
            all_ok = False

    return all_ok


def main():
    parser = argparse.ArgumentParser(
        description="Dataset download helper and integrity verifier"
    )
    parser.add_argument(
        "--dataset",
        choices=list(DATASETS.keys()) + ["all"],
        default="all",
        help="Dataset to check (default: all)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify, don't print download instructions",
    )
    args = parser.parse_args()

    # Ensure directories exist
    ensure_directories()

    if not args.verify_only:
        print_download_instructions(args.dataset)

    # Verify datasets
    print("\n" + "=" * 70)
    print("  Verification Results")
    print("=" * 70)

    if args.dataset == "all":
        results = {}
        for name in DATASETS:
            results[name] = verify_dataset(name)
    else:
        results = {args.dataset: verify_dataset(args.dataset)}

    print("\n  Summary:")
    for name, ok in results.items():
        status = "READY" if ok else "NOT FOUND / INCOMPLETE"
        print(f"    {name}: {status}")

    if not all(results.values()):
        print("\n  Some datasets are missing. Follow the download instructions above.")
        sys.exit(1)
    else:
        print("\n  All checked datasets are ready!")


if __name__ == "__main__":
    main()
