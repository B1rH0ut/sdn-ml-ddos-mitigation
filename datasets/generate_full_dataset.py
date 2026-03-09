#!/usr/bin/env python3
"""
Full Dataset Generator for DDoS Detection Model Training

Generates a realistic synthetic dataset of network flow statistics for
training the Random Forest DDoS detection classifier. Produces flows
with realistic value distributions across six traffic categories.

Feature definitions are imported from utilities/feature_extractor.py
(the single source of truth).

Normal Traffic (65%):
    - ICMP (ping):  Low packet rates, small payloads
    - TCP (data):   Medium-high duration, moderate rates
    - HTTP (web):   Short bursts, small-medium payloads

Attack Traffic (35%):
    - ICMP Flood:   Extremely high ICMP packet rates
    - SYN Flood:    High TCP SYN rates (tiny packets)
    - UDP Flood:    High UDP packet rates

Output CSV columns (13 total = 12 features + 1 label):
    flow_duration_sec, packet_count, byte_count,
    packet_count_per_second, byte_count_per_second, avg_packet_size,
    ip_proto, icmp_code, icmp_type,
    flows_to_dst, unique_sources_to_dst, flow_creation_rate,
    label

Usage:
    python3 generate_full_dataset.py
    python3 generate_full_dataset.py --total 505433
    python3 generate_full_dataset.py --total 50000 --output custom_dataset.csv

"""

import numpy as np
import pandas as pd
import random
import argparse
import os
import sys

# Import feature definitions from the single source of truth
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from utilities.feature_extractor import CSV_HEADERS, FEATURE_NAMES, EXPECTED_FEATURE_COUNT

# Attempt to import tqdm for progress bar; fall back gracefully
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("  Note: Install tqdm for progress bars (pip install tqdm)")
    print("  Continuing without progress bar...\n")


# Traffic distribution within normal and attack categories
NORMAL_RATIO = 0.65
ATTACK_RATIO = 0.35

NORMAL_SUBTYPES = {
    'icmp_ping':  0.30,
    'tcp_data':   0.50,
    'http_web':   0.20,
}

ATTACK_SUBTYPES = {
    'icmp_flood': 1 / 3,
    'syn_flood':  1 / 3,
    'udp_flood':  1 / 3,
}


def add_noise(value, noise_pct=0.05):
    """
    Add small random noise to a value for realism.

    Args:
        value (float): Base value to add noise to.
        noise_pct (float): Maximum noise as fraction of value (default: 5%).

    Returns:
        float: Value with noise applied, clamped to >= 0.
    """
    noise = random.gauss(0, abs(value) * noise_pct)
    return max(0, value + noise)


def _build_flow(duration, packet_count, byte_count, ip_proto, icmp_code,
                icmp_type, flows_to_dst, unique_sources_to_dst,
                flow_creation_rate):
    """
    Build a 12-feature row from raw values.

    Computes derived features (pps, bps, avg_packet_size) from base values.

    Returns:
        list: 12 feature values in FEATURE_NAMES order.
    """
    # Rates
    if duration > 0:
        pps = packet_count / duration
        bps = byte_count / duration
    else:
        pps = packet_count
        bps = byte_count

    # Average packet size (proxy for TCP flag behavior)
    if packet_count > 0:
        avg_pkt_size = byte_count / packet_count
    else:
        avg_pkt_size = 0

    return [
        round(add_noise(duration), 4),
        int(add_noise(packet_count)),
        int(add_noise(byte_count)),
        round(add_noise(pps), 4),
        round(add_noise(bps), 4),
        round(add_noise(avg_pkt_size), 4),
        ip_proto,
        icmp_code,
        icmp_type,
        int(add_noise(flows_to_dst)),
        int(add_noise(unique_sources_to_dst)),
        round(add_noise(flow_creation_rate), 4),
    ]


# =============================================================================
# Normal traffic generators
# =============================================================================

def generate_icmp_ping():
    """Generate a single normal ICMP ping flow (12 features)."""
    duration = random.uniform(0.5, 10.0)
    packet_count = random.randint(5, 50)
    byte_count = random.randint(500, 5000)

    # Normal aggregate behavior: few flows, few sources
    flows_to_dst = random.randint(1, 8)
    unique_sources = random.randint(1, 4)
    flow_rate = random.uniform(0.1, 1.0)

    return _build_flow(
        duration, packet_count, byte_count,
        ip_proto=1, icmp_code=0, icmp_type=8,
        flows_to_dst=flows_to_dst,
        unique_sources_to_dst=unique_sources,
        flow_creation_rate=flow_rate,
    )


def generate_tcp_data():
    """Generate a single normal TCP data transfer flow (12 features)."""
    duration = random.uniform(1.0, 300.0)
    packet_count = random.randint(50, 5000)
    byte_count = random.randint(5000, 500000)

    flows_to_dst = random.randint(1, 15)
    unique_sources = random.randint(1, 8)
    flow_rate = random.uniform(0.1, 2.0)

    return _build_flow(
        duration, packet_count, byte_count,
        ip_proto=6, icmp_code=0, icmp_type=0,
        flows_to_dst=flows_to_dst,
        unique_sources_to_dst=unique_sources,
        flow_creation_rate=flow_rate,
    )


def generate_http_web():
    """Generate a single normal HTTP web browsing flow (12 features)."""
    duration = random.uniform(0.1, 5.0)
    packet_count = random.randint(10, 200)
    byte_count = random.randint(1000, 100000)

    flows_to_dst = random.randint(1, 20)
    unique_sources = random.randint(1, 10)
    flow_rate = random.uniform(0.2, 3.0)

    return _build_flow(
        duration, packet_count, byte_count,
        ip_proto=6, icmp_code=0, icmp_type=0,
        flows_to_dst=flows_to_dst,
        unique_sources_to_dst=unique_sources,
        flow_creation_rate=flow_rate,
    )


# =============================================================================
# Attack traffic generators
# =============================================================================

def generate_icmp_flood():
    """Generate a single ICMP Flood attack flow (12 features)."""
    duration = random.uniform(0.1, 5.0)
    packet_count = random.randint(10000, 100000)
    byte_count = random.randint(500000, 5000000)

    # Attack aggregate behavior: many flows, many sources targeting same dst
    flows_to_dst = random.randint(50, 500)
    unique_sources = random.randint(20, 200)
    flow_rate = random.uniform(10.0, 100.0)

    return _build_flow(
        duration, packet_count, byte_count,
        ip_proto=1, icmp_code=0, icmp_type=8,
        flows_to_dst=flows_to_dst,
        unique_sources_to_dst=unique_sources,
        flow_creation_rate=flow_rate,
    )


def generate_syn_flood():
    """Generate a single SYN Flood attack flow (12 features)."""
    duration = random.uniform(0.1, 10.0)
    packet_count = random.randint(5000, 80000)
    # SYN floods have tiny packets (~60 bytes each)
    byte_count = random.randint(packet_count * 40, packet_count * 80)

    flows_to_dst = random.randint(80, 600)
    unique_sources = random.randint(30, 300)
    flow_rate = random.uniform(15.0, 120.0)

    return _build_flow(
        duration, packet_count, byte_count,
        ip_proto=6, icmp_code=0, icmp_type=0,
        flows_to_dst=flows_to_dst,
        unique_sources_to_dst=unique_sources,
        flow_creation_rate=flow_rate,
    )


def generate_udp_flood():
    """Generate a single UDP Flood attack flow (12 features)."""
    duration = random.uniform(0.1, 8.0)
    packet_count = random.randint(8000, 90000)
    byte_count = random.randint(400000, 4500000)

    flows_to_dst = random.randint(60, 450)
    unique_sources = random.randint(25, 250)
    flow_rate = random.uniform(12.0, 90.0)

    return _build_flow(
        duration, packet_count, byte_count,
        ip_proto=17, icmp_code=0, icmp_type=0,
        flows_to_dst=flows_to_dst,
        unique_sources_to_dst=unique_sources,
        flow_creation_rate=flow_rate,
    )


# Generator function mapping for each traffic subtype
GENERATORS = {
    'icmp_ping':  generate_icmp_ping,
    'tcp_data':   generate_tcp_data,
    'http_web':   generate_http_web,
    'icmp_flood': generate_icmp_flood,
    'syn_flood':  generate_syn_flood,
    'udp_flood':  generate_udp_flood,
}


def generate_dataset(total_flows, seed=42):
    """
    Generate the complete synthetic flow dataset.

    Creates a balanced dataset with 65% normal and 35% attack flows,
    distributed across six traffic subtypes. Each flow has 12 features
    plus a label column (13 columns total).

    Args:
        total_flows (int): Total number of flows to generate.
        seed (int): Random seed for reproducibility (default: 42).

    Returns:
        pandas.DataFrame: DataFrame with 13 columns (12 features + label),
            shuffled randomly.
    """
    random.seed(seed)
    np.random.seed(seed)

    normal_total = int(total_flows * NORMAL_RATIO)
    attack_total = total_flows - normal_total

    # Calculate counts per subtype
    normal_counts = {}
    allocated = 0
    subtypes = list(NORMAL_SUBTYPES.items())
    for i, (subtype, ratio) in enumerate(subtypes):
        if i == len(subtypes) - 1:
            normal_counts[subtype] = normal_total - allocated
        else:
            count = int(normal_total * ratio)
            normal_counts[subtype] = count
            allocated += count

    attack_counts = {}
    allocated = 0
    subtypes = list(ATTACK_SUBTYPES.items())
    for i, (subtype, ratio) in enumerate(subtypes):
        if i == len(subtypes) - 1:
            attack_counts[subtype] = attack_total - allocated
        else:
            count = int(attack_total * ratio)
            attack_counts[subtype] = count
            allocated += count

    # Print generation plan
    print("\n  Generation Plan:")
    print(f"    Total flows:      {total_flows}")
    print(f"    Features:         {EXPECTED_FEATURE_COUNT}")
    print(f"    Normal flows:     {normal_total} ({NORMAL_RATIO * 100:.0f}%)")
    for subtype, count in normal_counts.items():
        print(f"      {subtype:15s} {count:>8,}")
    print(f"    Attack flows:     {attack_total} ({ATTACK_RATIO * 100:.0f}%)")
    for subtype, count in attack_counts.items():
        print(f"      {subtype:15s} {count:>8,}")
    print()

    # Build task list
    tasks = []
    for subtype, count in normal_counts.items():
        tasks.append((GENERATORS[subtype], 0, count, subtype))
    for subtype, count in attack_counts.items():
        tasks.append((GENERATORS[subtype], 1, count, subtype))

    # Generate all flows
    rows = []
    total_generated = 0

    if HAS_TQDM:
        progress = tqdm(total=total_flows, desc="  Generating flows", unit="flow")
    else:
        progress = None

    for generator_func, label, count, subtype in tasks:
        for _ in range(count):
            features = generator_func()
            rows.append(features + [label])
            total_generated += 1

            if progress:
                progress.update(1)
            elif total_generated % 10000 == 0:
                pct = (total_generated / total_flows) * 100
                print(f"  Progress: {total_generated:,}/{total_flows:,} "
                      f"({pct:.1f}%) - {subtype}")

    if progress:
        progress.close()

    print("\n  Creating DataFrame...")
    df = pd.DataFrame(rows, columns=CSV_HEADERS)

    print("  Shuffling dataset...")
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    return df


def validate_dataset(df):
    """
    Validate the generated dataset for correctness.

    Args:
        df (pandas.DataFrame): Generated dataset to validate.

    Returns:
        bool: True if all validation checks pass.
    """
    print("\n  Validating dataset...")
    passed = True

    expected_cols = len(CSV_HEADERS)  # 13
    if len(df.columns) != expected_cols:
        print(f"    FAIL: Expected {expected_cols} columns, got {len(df.columns)}")
        passed = False
    else:
        print(f"    OK: Column count = {len(df.columns)}")

    if list(df.columns) != CSV_HEADERS:
        print(f"    FAIL: Column names don't match expected headers")
        passed = False
    else:
        print(f"    OK: Column names match")

    nan_count = df.isnull().sum().sum()
    if nan_count > 0:
        print(f"    FAIL: Found {nan_count} NaN values")
        passed = False
    else:
        print(f"    OK: No NaN values")

    feature_cols = FEATURE_NAMES
    inf_count = np.isinf(df[feature_cols].values).sum()
    if inf_count > 0:
        print(f"    FAIL: Found {inf_count} Inf values")
        passed = False
    else:
        print(f"    OK: No Inf values")

    unique_labels = set(df['label'].unique())
    if unique_labels != {0, 1}:
        print(f"    FAIL: Unexpected labels: {unique_labels}")
        passed = False
    else:
        print(f"    OK: Labels are {{0, 1}}")

    normal_pct = (df['label'] == 0).mean() * 100
    attack_pct = (df['label'] == 1).mean() * 100
    if abs(normal_pct - 65.0) > 1.0:
        print(f"    WARN: Normal ratio {normal_pct:.1f}% (expected ~65%)")
    else:
        print(f"    OK: Normal ratio = {normal_pct:.1f}%")
    if abs(attack_pct - 35.0) > 1.0:
        print(f"    WARN: Attack ratio {attack_pct:.1f}% (expected ~35%)")
    else:
        print(f"    OK: Attack ratio = {attack_pct:.1f}%")

    for col in ['packet_count', 'byte_count']:
        neg_count = (df[col] < 0).sum()
        if neg_count > 0:
            print(f"    FAIL: {neg_count} negative values in {col}")
            passed = False

    return passed


def print_summary(df):
    """
    Print comprehensive summary statistics of the generated dataset.

    Args:
        df (pandas.DataFrame): Generated dataset.
    """
    print("\n" + "=" * 65)
    print("  Dataset Summary Statistics")
    print("=" * 65)

    total = len(df)
    normal = (df['label'] == 0).sum()
    attack = (df['label'] == 1).sum()
    print(f"\n  Total flows:    {total:,}")
    print(f"  Normal (0):     {normal:,} ({normal / total * 100:.1f}%)")
    print(f"  Attack (1):     {attack:,} ({attack / total * 100:.1f}%)")

    print(f"\n  Protocol Distribution:")
    proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    for proto_num, proto_name in proto_map.items():
        count = (df['ip_proto'] == proto_num).sum()
        if count > 0:
            print(f"    {proto_name} (proto={proto_num}): {count:,} "
                  f"({count / total * 100:.1f}%)")

    print(f"\n  Feature Statistics (Normal vs Attack):")
    print(f"  {'Feature':<30s} {'Normal Mean':>14s} {'Attack Mean':>14s}")
    print(f"  {'-' * 30} {'-' * 14} {'-' * 14}")

    normal_df = df[df['label'] == 0]
    attack_df = df[df['label'] == 1]

    for col in FEATURE_NAMES:
        n_mean = normal_df[col].mean()
        a_mean = attack_df[col].mean()
        print(f"  {col:<30s} {n_mean:>14.2f} {a_mean:>14.2f}")

    print(f"\n  Key Differentiators (Attack vs Normal ratio):")
    for col in ['packet_count_per_second', 'byte_count_per_second',
                'avg_packet_size', 'flows_to_dst', 'unique_sources_to_dst',
                'flow_creation_rate']:
        n_mean = normal_df[col].mean()
        a_mean = attack_df[col].mean()
        ratio = a_mean / n_mean if n_mean > 0 else float('inf')
        print(f"    {col:<30s} {ratio:>8.1f}x higher in attacks")


def main():
    """Main entry point for dataset generation."""
    parser = argparse.ArgumentParser(
        description='Generate synthetic flow dataset for DDoS detection'
    )
    parser.add_argument(
        '--total', type=int, default=50000,
        help='Total number of flows to generate (default: 50000)'
    )
    parser.add_argument(
        '--output', type=str, default=None,
        help='Output CSV filename (default: flow_dataset.csv)'
    )
    parser.add_argument(
        '--seed', type=int, default=42,
        help='Random seed for reproducibility (default: 42)'
    )
    args = parser.parse_args()

    if args.total <= 0:
        print("ERROR: Total must be a positive integer")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    if args.output:
        output_path = os.path.join(script_dir, args.output)
    else:
        output_path = os.path.join(script_dir, 'flow_dataset.csv')

    print("\n" + "=" * 65)
    print("  DDoS Detection - Synthetic Dataset Generator")
    print("=" * 65)
    print(f"  Total flows:  {args.total:,}")
    print(f"  Features:     {EXPECTED_FEATURE_COUNT}")
    print(f"  Normal:       {int(args.total * NORMAL_RATIO):,} (65%)")
    print(f"  Attack:       {args.total - int(args.total * NORMAL_RATIO):,} (35%)")
    print(f"  Output:       {output_path}")
    print(f"  Seed:         {args.seed}")

    df = generate_dataset(args.total, seed=args.seed)

    valid = validate_dataset(df)
    if not valid:
        print("\n  WARNING: Dataset validation found issues")
        print("  The dataset may still be usable but review the warnings above")

    print(f"\n  Saving to {output_path}...")
    df.to_csv(output_path, index=False)
    file_size = os.path.getsize(output_path) / (1024 * 1024)
    print(f"  File saved: {file_size:.2f} MB")

    print_summary(df)

    print("\n" + "=" * 65)
    print("  Dataset generation complete!")
    print("=" * 65)
    print(f"\n  Next steps:")
    print(f"    1. Train model:  cd ml_model && python3 train_model.py")
    print(f"    2. Create ROC:   cd ml_model && python3 create_roc.py")
    print(f"    3. Start controller and test detection")
    print()


if __name__ == '__main__':
    main()
