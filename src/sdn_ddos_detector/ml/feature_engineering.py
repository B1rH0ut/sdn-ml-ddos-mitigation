#!/usr/bin/env python3
"""
Feature Extraction Utility for DDoS Detection

This module is the SINGLE SOURCE OF TRUTH for the ML feature set.
All other modules import feature definitions from here:
    - sdn_ddos_detector.controller.ddos_controller
    - sdn_ddos_detector.ml.train (training pipeline)
    - sdn_ddos_detector.ml.create_roc (ROC curve generation)
    - sdn_ddos_detector.datasets.generate_full_dataset
    - sdn_ddos_detector.ml.dataset_adapters (real dataset adapters)

Features (12 total, in exact order):
    1.  flow_duration_sec        - Flow duration in seconds
    2.  packet_count             - Total packets in flow
    3.  byte_count               - Total bytes in flow
    4.  packet_count_per_second  - Packets per second rate
    5.  byte_count_per_second    - Bytes per second rate
    6.  avg_packet_size          - Average bytes per packet
    7.  ip_proto                 - IP protocol number (1=ICMP, 6=TCP, 17=UDP)
    8.  icmp_code                - ICMP code value
    9.  icmp_type                - ICMP type value
    10. flows_to_dst             - Number of flows targeting same destination
    11. unique_sources_to_dst    - Unique source IPs targeting same destination
    12. flow_creation_rate       - New flows per second to same destination

Changes from previous 10-feature set:
    - REMOVED: idle_timeout, hard_timeout (feature leakage — controller-set
      values that differ between training and serving)
    - ADDED: avg_packet_size (proxy for TCP flag behavior; SYN floods have
      tiny packets, normal TCP has larger ones)
    - ADDED: flows_to_dst, unique_sources_to_dst, flow_creation_rate
      (aggregate behavior features that capture DDoS patterns invisible
      at the individual flow level)

Usage:
    from sdn_ddos_detector.ml.feature_engineering import (
        FEATURE_NAMES, EXPECTED_FEATURE_COUNT, CSV_HEADERS,
        extract_flow_features, validate_features
    )

"""

from __future__ import annotations

import numpy as np
import pandas as pd


# Feature names in exact extraction order — the canonical definition.
# Every module that uses features MUST import this list.
FEATURE_NAMES = [
    'flow_duration_sec',
    'packet_count',
    'byte_count',
    'packet_count_per_second',
    'byte_count_per_second',
    'avg_packet_size',
    'ip_proto',
    'icmp_code',
    'icmp_type',
    'flows_to_dst',
    'unique_sources_to_dst',
    'flow_creation_rate',
]

EXPECTED_FEATURE_COUNT = len(FEATURE_NAMES)  # 12

# CSV column headers for dataset files: features + label
CSV_HEADERS = FEATURE_NAMES + ['label']

# Label column name
LABEL_COLUMN = 'label'


def extract_flow_features(flow_stats: dict, aggregates: dict | None = None) -> np.ndarray:
    """
    Extract 12 ML features from a flow statistics dictionary.

    Extracts features in the exact order expected by the trained Random
    Forest model and StandardScaler. Missing fields default to 0.
    Rate features handle division by zero when duration or packet count
    is 0 by falling back to safe defaults.

    Args:
        flow_stats (dict): Flow statistics dictionary containing any of:
            - duration_sec (int/float): Flow duration in seconds
            - packet_count (int): Total packet count
            - byte_count (int): Total byte count
            - ip_proto (int): IP protocol number
            - icmp_code (int): ICMP code
            - icmp_type (int): ICMP type

        aggregates (dict, optional): Pre-computed aggregate features for
            the destination IP of this flow. Expected keys:
            - flows_to_dst (int): Number of flows targeting this dst
            - unique_sources_to_dst (int): Unique src IPs targeting this dst
            - flow_creation_rate (float): New flows per second to this dst
            If None, aggregate features default to 0.

    Returns:
        numpy.ndarray: Feature array with shape (1, 12), ready for
            scaler.transform() and model.predict().

    Raises:
        TypeError: If flow_stats is not a dictionary.
    """
    if not isinstance(flow_stats, dict):
        raise TypeError(
            f"flow_stats must be a dictionary, got {type(flow_stats).__name__}"
        )

    # Extract base fields with default of 0 for missing keys
    duration_sec = flow_stats.get('duration_sec', 0)
    packet_count = flow_stats.get('packet_count', 0)
    byte_count = flow_stats.get('byte_count', 0)
    ip_proto = flow_stats.get('ip_proto', 0)
    icmp_code = flow_stats.get('icmp_code', 0)
    icmp_type = flow_stats.get('icmp_type', 0)

    # Calculate rate features with division-by-zero protection
    if duration_sec > 0:
        packet_count_per_second = packet_count / duration_sec
        byte_count_per_second = byte_count / duration_sec
    else:
        packet_count_per_second = packet_count
        byte_count_per_second = byte_count

    # Average packet size as proxy for TCP flag behavior
    if packet_count > 0:
        avg_packet_size = byte_count / packet_count
    else:
        avg_packet_size = 0

    # Aggregate features (per-destination behavior)
    # NOTE: Train/serve distribution mismatch — training data computes these
    # via dataset-wide groupby; live serving uses a sliding time window.
    # See docs/KNOWN_LIMITATIONS.md for details.
    if aggregates is not None:
        flows_to_dst = aggregates.get('flows_to_dst', 0)
        unique_sources_to_dst = aggregates.get('unique_sources_to_dst', 0)
        flow_creation_rate = aggregates.get('flow_creation_rate', 0)
    else:
        flows_to_dst = 0
        unique_sources_to_dst = 0
        flow_creation_rate = 0

    # Assemble features in exact order matching FEATURE_NAMES
    features = [
        duration_sec,               # 1.  flow_duration_sec
        packet_count,               # 2.  packet_count
        byte_count,                 # 3.  byte_count
        packet_count_per_second,    # 4.  packet_count_per_second
        byte_count_per_second,      # 5.  byte_count_per_second
        avg_packet_size,            # 6.  avg_packet_size
        ip_proto,                   # 7.  ip_proto
        icmp_code,                  # 8.  icmp_code
        icmp_type,                  # 9.  icmp_type
        flows_to_dst,               # 10. flows_to_dst
        unique_sources_to_dst,      # 11. unique_sources_to_dst
        flow_creation_rate,         # 12. flow_creation_rate
    ]

    return np.array(features).reshape(1, -1)


def validate_features(features: np.ndarray) -> tuple[bool, str]:
    """
    Validate a feature array for ML prediction compatibility.

    Checks that the feature array has the correct shape (1, 12),
    contains no NaN or Inf values, and is a numpy array.

    Args:
        features: Feature array to validate. Expected to be a numpy
            ndarray with shape (1, 12).

    Returns:
        tuple: (is_valid, error_message) where:
            - is_valid (bool): True if features pass all checks.
            - error_message (str): Empty string if valid, otherwise
              a description of the first validation failure found.
    """
    if not isinstance(features, np.ndarray):
        return False, (
            f"Expected numpy.ndarray, got {type(features).__name__}"
        )

    if features.shape != (1, EXPECTED_FEATURE_COUNT):
        return False, (
            f"Expected shape (1, {EXPECTED_FEATURE_COUNT}), "
            f"got {features.shape}"
        )

    nan_count = np.isnan(features).sum()
    if nan_count > 0:
        nan_indices = np.argwhere(np.isnan(features))
        nan_features = [FEATURE_NAMES[idx[1]] for idx in nan_indices]
        return False, (
            f"Found {nan_count} NaN value(s) in features: {nan_features}"
        )

    inf_count = np.isinf(features).sum()
    if inf_count > 0:
        inf_indices = np.argwhere(np.isinf(features))
        inf_features = [FEATURE_NAMES[idx[1]] for idx in inf_indices]
        return False, (
            f"Found {inf_count} Inf value(s) in features: {inf_features}"
        )

    return True, ""


def features_to_dict(features: np.ndarray) -> dict[str, float]:
    """
    Convert a feature array back to a labeled dictionary.

    Args:
        features (numpy.ndarray): Feature array with shape (1, 12).

    Returns:
        dict: Dictionary mapping feature names to their values.

    Raises:
        ValueError: If features array does not have 12 elements.
    """
    values = features.flatten()

    if len(values) != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_FEATURE_COUNT} features, "
            f"got {len(values)}"
        )

    return dict(zip(FEATURE_NAMES, values))


def extract_flow_features_from_stats(flow_stats: dict, prev_stats: dict | None = None, window_seconds: float = 5.0) -> dict[str, float]:
    """
    Extract features from raw OpenFlow flow stats.

    THIS FUNCTION MUST BE CALLED BY BOTH TRAINING AND INFERENCE CODE.
    Never reimplement these calculations elsewhere.

    Args:
        flow_stats (dict): Current flow statistics from OFPFlowStatsReply.
            Expected keys: duration_sec, packet_count, byte_count,
            ip_proto, icmp_code, icmp_type.
            Optional aggregate keys: flows_to_dst, unique_sources_to_dst,
            flow_creation_rate.
        prev_stats (dict, optional): Previous stats for the same flow
            (for delta-based rate calculation). If provided, rates are
            computed from deltas rather than cumulative values.
        window_seconds (float): Time between stats polls (default 5s).

    Returns:
        dict: Feature values keyed by FEATURE_NAMES.
    """
    if not isinstance(flow_stats, dict):
        raise TypeError(
            f"flow_stats must be a dictionary, got {type(flow_stats).__name__}"
        )

    duration_sec = flow_stats.get('duration_sec', 0)
    packet_count = flow_stats.get('packet_count', 0)
    byte_count = flow_stats.get('byte_count', 0)
    ip_proto = flow_stats.get('ip_proto', 0)
    icmp_code = flow_stats.get('icmp_code', 0)
    icmp_type = flow_stats.get('icmp_type', 0)

    # If previous stats available, compute delta-based rates
    if prev_stats is not None and window_seconds > 0:
        delta_packets = max(0, packet_count - prev_stats.get('packet_count', 0))
        delta_bytes = max(0, byte_count - prev_stats.get('byte_count', 0))
        packet_count_per_second = delta_packets / window_seconds
        byte_count_per_second = delta_bytes / window_seconds
    elif duration_sec > 0:
        packet_count_per_second = packet_count / duration_sec
        byte_count_per_second = byte_count / duration_sec
    else:
        packet_count_per_second = 0
        byte_count_per_second = 0

    if packet_count > 0:
        avg_packet_size = byte_count / packet_count
    else:
        avg_packet_size = 0

    # Aggregate features (per-destination behavior)
    flows_to_dst = flow_stats.get('flows_to_dst', 0)
    unique_sources_to_dst = flow_stats.get('unique_sources_to_dst', 0)
    flow_creation_rate = flow_stats.get('flow_creation_rate', 0)

    return {
        'flow_duration_sec': duration_sec,
        'packet_count': packet_count,
        'byte_count': byte_count,
        'packet_count_per_second': packet_count_per_second,
        'byte_count_per_second': byte_count_per_second,
        'avg_packet_size': avg_packet_size,
        'ip_proto': ip_proto,
        'icmp_code': icmp_code,
        'icmp_type': icmp_type,
        'flows_to_dst': flows_to_dst,
        'unique_sources_to_dst': unique_sources_to_dst,
        'flow_creation_rate': flow_creation_rate,
    }


def features_dict_to_array(features_dict: dict[str, float]) -> np.ndarray:
    """Convert a features dict (from extract_flow_features_from_stats) to a numpy array.

    Returns:
        numpy.ndarray: Feature array with shape (1, 12), in FEATURE_NAMES order.
    """
    return np.array([[features_dict[name] for name in FEATURE_NAMES]])


def validate_feature_distributions(train_df: pd.DataFrame, serve_df: pd.DataFrame, threshold: float = 0.05) -> dict:
    """Detect distribution shift between training and serving features.

    Uses the Kolmogorov-Smirnov test per feature to detect whether the
    serving data distribution has drifted from training data.

    Args:
        train_df (pd.DataFrame): Training data features.
        serve_df (pd.DataFrame): Serving/live data features.
        threshold (float): p-value threshold below which drift is flagged.

    Returns:
        dict: Per-feature results with statistic, p_value, and drifted flag.
    """
    from scipy.stats import ks_2samp
    results = {}
    for col in FEATURE_NAMES:
        if col in train_df.columns and col in serve_df.columns:
            stat, p_value = ks_2samp(
                train_df[col].dropna(), serve_df[col].dropna()
            )
            results[col] = {
                "statistic": stat,
                "p_value": p_value,
                "drifted": p_value < threshold,
            }
    return results


if __name__ == '__main__':
    """
    Demonstration and self-test for the feature extraction module.
    """
    print("=" * 60)
    print("  Feature Extractor - Self Test (12-feature set)")
    print("=" * 60)

    # =========================================================================
    # Test 1: Normal TCP traffic with aggregates
    # =========================================================================
    print("\n  Test 1: Normal TCP traffic with aggregates")
    normal_stats = {
        'duration_sec': 15,
        'packet_count': 120,
        'byte_count': 84000,
        'ip_proto': 6,       # TCP
        'icmp_code': 0,
        'icmp_type': 0
    }
    normal_agg = {
        'flows_to_dst': 5,
        'unique_sources_to_dst': 3,
        'flow_creation_rate': 0.5,
    }
    features = extract_flow_features(normal_stats, aggregates=normal_agg)
    valid, error = validate_features(features)
    print(f"    Shape: {features.shape}")
    print(f"    Valid: {valid}")
    assert valid, f"Validation failed: {error}"
    assert features.shape == (1, 12), f"Wrong shape: {features.shape}"
    assert features[0][3] == 120 / 15, "PPS calculation wrong"
    assert features[0][5] == 84000 / 120, "avg_packet_size wrong"
    assert features[0][9] == 5, "flows_to_dst wrong"
    print("    PASSED")

    # =========================================================================
    # Test 2: ICMP Flood attack (high aggregates)
    # =========================================================================
    print("\n  Test 2: ICMP Flood attack traffic")
    attack_stats = {
        'duration_sec': 5,
        'packet_count': 50000,
        'byte_count': 3000000,
        'ip_proto': 1,       # ICMP
        'icmp_code': 0,
        'icmp_type': 8       # Echo request
    }
    attack_agg = {
        'flows_to_dst': 150,
        'unique_sources_to_dst': 80,
        'flow_creation_rate': 30.0,
    }
    features = extract_flow_features(attack_stats, aggregates=attack_agg)
    valid, error = validate_features(features)
    assert valid, f"Validation failed: {error}"
    assert features[0][3] == 10000.0, "PPS calculation wrong"
    assert features[0][5] == 3000000 / 50000, "avg_packet_size wrong"
    assert features[0][9] == 150, "flows_to_dst wrong"
    print("    PASSED")

    # =========================================================================
    # Test 3: No aggregates provided (defaults to 0)
    # =========================================================================
    print("\n  Test 3: No aggregates (defaults to 0)")
    features = extract_flow_features(normal_stats)
    valid, error = validate_features(features)
    assert valid
    assert features[0][9] == 0, "flows_to_dst should be 0"
    assert features[0][10] == 0, "unique_sources_to_dst should be 0"
    assert features[0][11] == 0, "flow_creation_rate should be 0"
    print("    PASSED")

    # =========================================================================
    # Test 4: Empty dictionary (all defaults)
    # =========================================================================
    print("\n  Test 4: Empty dictionary (all defaults to 0)")
    features = extract_flow_features({})
    valid, error = validate_features(features)
    assert valid
    assert np.all(features == 0), "Empty dict should produce all zeros"
    print("    PASSED")

    # =========================================================================
    # Test 5: Zero duration and zero packet_count
    # =========================================================================
    print("\n  Test 5: Zero duration (division by zero)")
    features = extract_flow_features({
        'duration_sec': 0,
        'packet_count': 100,
        'byte_count': 5000
    })
    valid, error = validate_features(features)
    assert valid
    assert features[0][3] == 100, "Zero duration PPS fallback wrong"
    assert features[0][4] == 5000, "Zero duration BPS fallback wrong"
    assert features[0][5] == 50.0, "avg_packet_size wrong"
    print("    PASSED")

    # =========================================================================
    # Test 6: Validation failures
    # =========================================================================
    print("\n  Test 6: Validation failure cases")
    valid, _ = validate_features([1, 2, 3])
    assert not valid
    valid, _ = validate_features(np.array([1, 2, 3]))
    assert not valid
    nan_f = np.zeros((1, 12)); nan_f[0][2] = np.nan
    valid, _ = validate_features(nan_f)
    assert not valid
    inf_f = np.zeros((1, 12)); inf_f[0][4] = np.inf
    valid, _ = validate_features(inf_f)
    assert not valid
    print("    PASSED")

    # =========================================================================
    # Test 7: TypeError for non-dict input
    # =========================================================================
    print("\n  Test 7: TypeError for non-dict input")
    try:
        extract_flow_features("not a dict")
        assert False, "Should have raised TypeError"
    except TypeError:
        print("    PASSED")

    # =========================================================================
    # Test 8: features_to_dict round-trip
    # =========================================================================
    print("\n  Test 8: features_to_dict conversion")
    features = extract_flow_features(normal_stats, aggregates=normal_agg)
    labeled = features_to_dict(features)
    assert labeled['ip_proto'] == 6
    assert labeled['flow_duration_sec'] == 15
    assert labeled['flows_to_dst'] == 5
    assert len(labeled) == 12
    print("    PASSED")

    # =========================================================================
    # Test 9: CSV_HEADERS has 13 entries (12 features + label)
    # =========================================================================
    print("\n  Test 9: CSV_HEADERS structure")
    assert len(CSV_HEADERS) == 13, f"Expected 13, got {len(CSV_HEADERS)}"
    assert CSV_HEADERS[-1] == 'label'
    assert CSV_HEADERS[:12] == FEATURE_NAMES
    print("    PASSED")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 60)
    print(f"  All 9 tests PASSED ({EXPECTED_FEATURE_COUNT} features)")
    print("=" * 60 + "\n")
