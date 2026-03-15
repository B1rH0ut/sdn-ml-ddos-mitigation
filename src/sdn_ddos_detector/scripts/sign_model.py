#!/usr/bin/env python3
"""
Model signing tool — computes HMAC-SHA256 (or SHA-256 fallback) checksums.

Generates integrity checksums for model artifact files and writes them
to config/model_checksums.hmac. The controller verifies these checksums
before loading any .pkl file to prevent pickle RCE attacks.

Usage:
    # With HMAC key (recommended):
    SDN_MODEL_HMAC_KEY=mysecretkey python -m sdn_ddos_detector.scripts.sign_model path/to/flow_model.pkl path/to/scaler.pkl

    # Without HMAC key (SHA-256 only, reduced security):
    python -m sdn_ddos_detector.scripts.sign_model path/to/flow_model.pkl path/to/scaler.pkl
"""

import argparse
import hashlib
import hmac
import json
import os
import sys


def compute_checksum(filepath, hmac_key=None):
    """Compute HMAC-SHA256 or SHA-256 checksum for a file.

    Args:
        filepath: Path to the file to hash.
        hmac_key: HMAC key bytes. If None, uses plain SHA-256.

    Returns:
        str: Hex digest of the checksum.
    """
    with open(filepath, 'rb') as f:
        file_bytes = f.read()

    if hmac_key:
        return hmac.new(hmac_key, file_bytes, hashlib.sha256).hexdigest()
    return hashlib.sha256(file_bytes).hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description='Sign model files with HMAC-SHA256 checksums'
    )
    parser.add_argument(
        'model_files',
        nargs='+',
        help='Paths to model .pkl files to sign'
    )
    parser.add_argument(
        '--output', '-o',
        default=None,
        help='Output checksum file (default: config/model_checksums.hmac)'
    )
    args = parser.parse_args()

    hmac_key = os.environ.get('SDN_MODEL_HMAC_KEY', '').encode()
    method = 'HMAC-SHA256' if hmac_key else 'SHA-256'

    if not hmac_key:
        print(
            "WARNING: SDN_MODEL_HMAC_KEY not set. Using plain SHA-256.\n"
            "Set the environment variable for HMAC-SHA256 signing.",
            file=sys.stderr
        )

    checksums = {}
    for filepath in args.model_files:
        if not os.path.isfile(filepath):
            print(f"ERROR: File not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        filename = os.path.basename(filepath)
        checksum = compute_checksum(filepath, hmac_key or None)
        checksums[filename] = checksum
        print(f"  {method}: {filename} = {checksum}")

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        # Default: config/ directory relative to project root
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_dir = os.path.join(script_dir, '..', 'config')
        os.makedirs(config_dir, exist_ok=True)
        output_path = os.path.join(config_dir, 'model_checksums.hmac')

    with open(output_path, 'w') as f:
        json.dump(checksums, f, indent=2)

    print(f"\n  Checksums written to: {output_path}")
    print(f"  Method: {method}")
    print(f"  Files signed: {len(checksums)}")


if __name__ == '__main__':
    main()
