#!/usr/bin/env python3
"""
Full Dataset Generator for DDoS Detection Model Training

Generates a realistic synthetic dataset of network flow statistics for
training the Random Forest DDoS detection classifier. Produces flows
with realistic value distributions across six traffic categories:

Normal Traffic (65%):
    - ICMP (ping):  Low packet rates, small payloads
    - TCP (data):   Medium-high duration, moderate rates
    - HTTP (web):   Short bursts, small-medium payloads

Attack Traffic (35%):
    - ICMP Flood:   Extremely high ICMP packet rates
    - SYN Flood:    High TCP SYN rates to port 80
    - UDP Flood:    High UDP packet rates to port 53

Output CSV columns (11 total):
    flow_duration_sec, idle_timeout, hard_timeout, packet_count,
    byte_count, packet_count_per_second, byte_count_per_second,
    ip_proto, icmp_code, icmp_type, label

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

# Attempt to import tqdm for progress bar; fall back gracefully
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("  Note: Install tqdm for progress bars (pip install tqdm)")
    print("  Continuing without progress bar...\n")


# CSV column headers — must match train_model.py and mitigation_module.py
CSV_HEADERS = [
    'flow_duration_sec',
    'idle_timeout',
    'hard_timeout',
    'packet_count',
    'byte_count',
    'packet_count_per_second',
    'byte_count_per_second',
    'ip_proto',
    'icmp_code',
    'icmp_type',
    'label'
]

# Traffic distribution within normal and attack categories
# Normal: 65% of total dataset
#   - ICMP ping:  30% of normal
#   - TCP data:   50% of normal
#   - HTTP web:   20% of normal
# Attack: 35% of total dataset
#   - ICMP Flood: 33.3% of attack
#   - SYN Flood:  33.3% of attack
#   - UDP Flood:  33.4% of attack

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

    Applies gaussian noise scaled to a percentage of the value,
    ensuring the result is never negative.

    Args:
        value (float): Base value to add noise to.
        noise_pct (float): Maximum noise as fraction of value
            (default: 5%).

    Returns:
        float: Value with noise applied, clamped to >= 0.
    """
    noise = random.gauss(0, abs(value) * noise_pct)
    return max(0, value + noise)


def generate_icmp_ping():
    """
    Generate a single normal ICMP ping flow.

    Simulates a standard ping session with low packet counts,
    small payloads, and low packet rates.

    Returns:
        list: 10 feature values representing a normal ICMP flow.
    """
    duration = random.uniform(0.5, 10.0)
    idle_timeout = random.choice([10, 15, 20, 30])
    hard_timeout = random.choice([30, 60])
    packet_count = random.randint(5, 50)
    byte_count = random.randint(500, 5000)

    # Calculate rates from counts and duration
    pps = packet_count / duration if duration > 0 else packet_count
    bps = byte_count / duration if duration > 0 else byte_count

    # ICMP protocol fields
    ip_proto = 1       # ICMP
    icmp_code = 0      # No error code for echo
    icmp_type = 8      # Echo request

    return [
        round(add_noise(duration), 4),
        idle_timeout,
        hard_timeout,
        int(add_noise(packet_count)),
        int(add_noise(byte_count)),
        round(add_noise(pps), 4),
        round(add_noise(bps), 4),
        ip_proto,
        icmp_code,
        icmp_type,
    ]


def generate_tcp_data():
    """
    Generate a single normal TCP data transfer flow.

    Simulates file transfers, database queries, and general TCP
    communication with moderate-to-high duration and packet counts.

    Returns:
        list: 10 feature values representing a normal TCP flow.
    """
    duration = random.uniform(1.0, 300.0)
    idle_timeout = random.choice([10, 15, 30, 60])
    hard_timeout = random.choice([30, 60, 120, 300])
    packet_count = random.randint(50, 5000)
    byte_count = random.randint(5000, 500000)

    pps = packet_count / duration if duration > 0 else packet_count
    bps = byte_count / duration if duration > 0 else byte_count

    # TCP protocol fields
    ip_proto = 6       # TCP
    icmp_code = 0      # Not applicable for TCP
    icmp_type = 0      # Not applicable for TCP

    return [
        round(add_noise(duration), 4),
        idle_timeout,
        hard_timeout,
        int(add_noise(packet_count)),
        int(add_noise(byte_count)),
        round(add_noise(pps), 4),
        round(add_noise(bps), 4),
        ip_proto,
        icmp_code,
        icmp_type,
    ]


def generate_http_web():
    """
    Generate a single normal HTTP web browsing flow.

    Simulates short web page requests with quick response times,
    small-to-medium payloads, and moderate packet rates.

    Returns:
        list: 10 feature values representing a normal HTTP flow.
    """
    duration = random.uniform(0.1, 5.0)
    idle_timeout = random.choice([5, 10, 15])
    hard_timeout = random.choice([10, 20, 30])
    packet_count = random.randint(10, 200)
    byte_count = random.randint(1000, 100000)

    pps = packet_count / duration if duration > 0 else packet_count
    bps = byte_count / duration if duration > 0 else byte_count

    # HTTP uses TCP
    ip_proto = 6       # TCP
    icmp_code = 0
    icmp_type = 0

    return [
        round(add_noise(duration), 4),
        idle_timeout,
        hard_timeout,
        int(add_noise(packet_count)),
        int(add_noise(byte_count)),
        round(add_noise(pps), 4),
        round(add_noise(bps), 4),
        ip_proto,
        icmp_code,
        icmp_type,
    ]


def generate_icmp_flood():
    """
    Generate a single ICMP Flood attack flow.

    Simulates an ICMP flood DDoS attack with extremely high packet
    rates (>10,000 pps), large byte counts, and short durations.

    Returns:
        list: 10 feature values representing an ICMP flood attack.
    """
    duration = random.uniform(0.1, 5.0)
    idle_timeout = random.choice([0, 5])
    hard_timeout = random.choice([0, 10])
    packet_count = random.randint(10000, 100000)
    byte_count = random.randint(500000, 5000000)

    pps = packet_count / duration if duration > 0 else packet_count
    bps = byte_count / duration if duration > 0 else byte_count

    # ICMP protocol fields
    ip_proto = 1       # ICMP
    icmp_code = 0
    icmp_type = 8      # Echo request (flood)

    return [
        round(add_noise(duration), 4),
        idle_timeout,
        hard_timeout,
        int(add_noise(packet_count)),
        int(add_noise(byte_count)),
        round(add_noise(pps), 4),
        round(add_noise(bps), 4),
        ip_proto,
        icmp_code,
        icmp_type,
    ]


def generate_syn_flood():
    """
    Generate a single SYN Flood attack flow.

    Simulates a TCP SYN flood DDoS attack targeting port 80 with
    high packet rates (>5,000 pps) and randomized source IPs.

    Returns:
        list: 10 feature values representing a SYN flood attack.
    """
    duration = random.uniform(0.1, 10.0)
    idle_timeout = random.choice([0, 5])
    hard_timeout = random.choice([0, 10])
    packet_count = random.randint(5000, 80000)
    byte_count = random.randint(300000, 4000000)

    pps = packet_count / duration if duration > 0 else packet_count
    bps = byte_count / duration if duration > 0 else byte_count

    # TCP SYN protocol fields
    ip_proto = 6       # TCP
    icmp_code = 0      # Not applicable for TCP
    icmp_type = 0      # Not applicable for TCP

    return [
        round(add_noise(duration), 4),
        idle_timeout,
        hard_timeout,
        int(add_noise(packet_count)),
        int(add_noise(byte_count)),
        round(add_noise(pps), 4),
        round(add_noise(bps), 4),
        ip_proto,
        icmp_code,
        icmp_type,
    ]


def generate_udp_flood():
    """
    Generate a single UDP Flood attack flow.

    Simulates a UDP flood DDoS attack targeting port 53 (DNS) with
    high packet rates (>8,000 pps) and large byte volumes.

    Returns:
        list: 10 feature values representing a UDP flood attack.
    """
    duration = random.uniform(0.1, 8.0)
    idle_timeout = random.choice([0, 5])
    hard_timeout = random.choice([0, 10])
    packet_count = random.randint(8000, 90000)
    byte_count = random.randint(400000, 4500000)

    pps = packet_count / duration if duration > 0 else packet_count
    bps = byte_count / duration if duration > 0 else byte_count

    # UDP protocol fields
    ip_proto = 17      # UDP
    icmp_code = 0      # Not applicable for UDP
    icmp_type = 0      # Not applicable for UDP

    return [
        round(add_noise(duration), 4),
        idle_timeout,
        hard_timeout,
        int(add_noise(packet_count)),
        int(add_noise(byte_count)),
        round(add_noise(pps), 4),
        round(add_noise(bps), 4),
        ip_proto,
        icmp_code,
        icmp_type,
    ]


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
    distributed across six traffic subtypes. Each flow has 10 features
    plus a label column.

    Args:
        total_flows (int): Total number of flows to generate.
        seed (int): Random seed for reproducibility (default: 42).

    Returns:
        pandas.DataFrame: DataFrame with 11 columns (10 features + label),
            shuffled randomly.
    """
    # Set random seeds for reproducibility
    random.seed(seed)
    np.random.seed(seed)

    # Calculate flow counts per category
    normal_total = int(total_flows * NORMAL_RATIO)
    attack_total = total_flows - normal_total  # Remainder goes to attack

    # Calculate counts per subtype
    normal_counts = {}
    allocated = 0
    subtypes = list(NORMAL_SUBTYPES.items())
    for i, (subtype, ratio) in enumerate(subtypes):
        if i == len(subtypes) - 1:
            # Last subtype gets the remainder to avoid rounding errors
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
    print(f"    Normal flows:     {normal_total} ({NORMAL_RATIO * 100:.0f}%)")
    for subtype, count in normal_counts.items():
        print(f"      {subtype:15s} {count:>8,}")
    print(f"    Attack flows:     {attack_total} ({ATTACK_RATIO * 100:.0f}%)")
    for subtype, count in attack_counts.items():
        print(f"      {subtype:15s} {count:>8,}")
    print()

    # Build task list: [(generator_func, label, count), ...]
    tasks = []
    for subtype, count in normal_counts.items():
        tasks.append((GENERATORS[subtype], 0, count, subtype))
    for subtype, count in attack_counts.items():
        tasks.append((GENERATORS[subtype], 1, count, subtype))

    # Generate all flows
    rows = []
    total_generated = 0

    # Create progress iterator
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
                # Fallback progress without tqdm
                pct = (total_generated / total_flows) * 100
                print(f"  Progress: {total_generated:,}/{total_flows:,} "
                      f"({pct:.1f}%) - {subtype}")

    if progress:
        progress.close()

    # Create DataFrame
    print("\n  Creating DataFrame...")
    df = pd.DataFrame(rows, columns=CSV_HEADERS)

    # Shuffle the dataset to mix normal and attack flows
    print("  Shuffling dataset...")
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    return df


def validate_dataset(df):
    """
    Validate the generated dataset for correctness.

    Checks for NaN values, Inf values, correct column count,
    valid labels, and expected class distribution.

    Args:
        df (pandas.DataFrame): Generated dataset to validate.

    Returns:
        bool: True if all validation checks pass.
    """
    print("\n  Validating dataset...")
    passed = True

    # Check column count
    if len(df.columns) != 11:
        print(f"    FAIL: Expected 11 columns, got {len(df.columns)}")
        passed = False
    else:
        print(f"    OK: Column count = {len(df.columns)}")

    # Check column names
    if list(df.columns) != CSV_HEADERS:
        print(f"    FAIL: Column names don't match expected headers")
        passed = False
    else:
        print(f"    OK: Column names match")

    # Check for NaN values
    nan_count = df.isnull().sum().sum()
    if nan_count > 0:
        print(f"    FAIL: Found {nan_count} NaN values")
        passed = False
    else:
        print(f"    OK: No NaN values")

    # Check for Inf values
    feature_cols = CSV_HEADERS[:10]
    inf_count = np.isinf(df[feature_cols].values).sum()
    if inf_count > 0:
        print(f"    FAIL: Found {inf_count} Inf values")
        passed = False
    else:
        print(f"    OK: No Inf values")

    # Check labels are only 0 and 1
    unique_labels = set(df['label'].unique())
    if unique_labels != {0, 1}:
        print(f"    FAIL: Unexpected labels: {unique_labels}")
        passed = False
    else:
        print(f"    OK: Labels are {{0, 1}}")

    # Check class distribution
    normal_pct = (df['label'] == 0).mean() * 100
    attack_pct = (df['label'] == 1).mean() * 100
    if abs(normal_pct - 65.0) > 1.0:
        print(f"    WARN: Normal ratio {normal_pct:.1f}% "
              f"(expected ~65%)")
    else:
        print(f"    OK: Normal ratio = {normal_pct:.1f}%")

    if abs(attack_pct - 35.0) > 1.0:
        print(f"    WARN: Attack ratio {attack_pct:.1f}% "
              f"(expected ~35%)")
    else:
        print(f"    OK: Attack ratio = {attack_pct:.1f}%")

    # Check no negative values in counts
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

    # Overall counts
    total = len(df)
    normal = (df['label'] == 0).sum()
    attack = (df['label'] == 1).sum()
    print(f"\n  Total flows:    {total:,}")
    print(f"  Normal (0):     {normal:,} ({normal / total * 100:.1f}%)")
    print(f"  Attack (1):     {attack:,} ({attack / total * 100:.1f}%)")

    # Protocol distribution
    print(f"\n  Protocol Distribution:")
    proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    for proto_num, proto_name in proto_map.items():
        count = (df['ip_proto'] == proto_num).sum()
        if count > 0:
            print(f"    {proto_name} (proto={proto_num}): {count:,} "
                  f"({count / total * 100:.1f}%)")

    # Feature statistics for normal vs attack
    feature_cols = CSV_HEADERS[:10]
    print(f"\n  Feature Statistics (Normal vs Attack):")
    print(f"  {'Feature':<30s} {'Normal Mean':>14s} {'Attack Mean':>14s}")
    print(f"  {'-' * 30} {'-' * 14} {'-' * 14}")

    normal_df = df[df['label'] == 0]
    attack_df = df[df['label'] == 1]

    for col in feature_cols:
        n_mean = normal_df[col].mean()
        a_mean = attack_df[col].mean()
        print(f"  {col:<30s} {n_mean:>14.2f} {a_mean:>14.2f}")

    # Key differentiating features
    print(f"\n  Key Differentiators (Attack vs Normal ratio):")
    for col in ['packet_count_per_second', 'byte_count_per_second',
                'packet_count', 'byte_count']:
        n_mean = normal_df[col].mean()
        a_mean = attack_df[col].mean()
        ratio = a_mean / n_mean if n_mean > 0 else float('inf')
        print(f"    {col:<30s} {ratio:>8.1f}x higher in attacks")


def main():
    """
    Main entry point for dataset generation.

    Parses command-line arguments, generates the dataset, validates it,
    saves to CSV, and prints summary statistics.
    """
    parser = argparse.ArgumentParser(
        description='Generate synthetic flow dataset for DDoS detection'
    )
    parser.add_argument(
        '--total',
        type=int,
        default=50000,
        help='Total number of flows to generate (default: 50000)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output CSV filename (default: flow_dataset.csv)'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=42,
        help='Random seed for reproducibility (default: 42)'
    )
    args = parser.parse_args()

    # Validate total
    if args.total <= 0:
        print("ERROR: Total must be a positive integer")
        sys.exit(1)

    # Resolve output path relative to this script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if args.output:
        output_path = os.path.join(script_dir, args.output)
    else:
        output_path = os.path.join(script_dir, 'flow_dataset.csv')

    # Print banner
    print("\n" + "=" * 65)
    print("  DDoS Detection - Synthetic Dataset Generator")
    print("=" * 65)
    print(f"  Total flows:  {args.total:,}")
    print(f"  Normal:       {int(args.total * NORMAL_RATIO):,} (65%)")
    print(f"  Attack:       {args.total - int(args.total * NORMAL_RATIO):,} (35%)")
    print(f"  Output:       {output_path}")
    print(f"  Seed:         {args.seed}")

    # Generate dataset
    df = generate_dataset(args.total, seed=args.seed)

    # Validate
    valid = validate_dataset(df)
    if not valid:
        print("\n  WARNING: Dataset validation found issues")
        print("  The dataset may still be usable but review the warnings above")

    # Save to CSV
    print(f"\n  Saving to {output_path}...")
    df.to_csv(output_path, index=False)
    file_size = os.path.getsize(output_path) / (1024 * 1024)
    print(f"  File saved: {file_size:.2f} MB")

    # Print summary
    print_summary(df)

    # Final message
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
