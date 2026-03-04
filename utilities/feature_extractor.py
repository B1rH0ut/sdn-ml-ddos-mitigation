#!/usr/bin/env python3
"""
Feature Extraction Utility for DDoS Detection

Provides standalone functions for extracting and validating the 10 flow-based
features used by the Random Forest classifier. This module can be imported
by other components or used directly for testing.

The feature extraction logic here must stay synchronized with:
    - sdn_controller/mitigation_module.py (flow_stats_reply_handler)
    - ml_model/train_model.py (FEATURE_COLUMNS)
    - datasets/generate_full_dataset.py (CSV column order)

Features (in exact order):
    1. flow_duration_sec       - Flow duration in seconds
    2. idle_timeout            - Idle timeout value
    3. hard_timeout            - Hard timeout value
    4. packet_count            - Total packets in flow
    5. byte_count              - Total bytes in flow
    6. packet_count_per_second - Packets per second rate
    7. byte_count_per_second   - Bytes per second rate
    8. ip_proto                - IP protocol number (1=ICMP, 6=TCP, 17=UDP)
    9. icmp_code               - ICMP code value
    10. icmp_type              - ICMP type value

Usage:
    As module:
        from utilities.feature_extractor import extract_flow_features, validate_features
        features = extract_flow_features(flow_stats_dict)
        valid, error = validate_features(features)

    Standalone test:
        cd utilities
        python3 feature_extractor.py

"""

import numpy as np


# Feature names in exact extraction order
# This list is the single source of truth for feature ordering
FEATURE_NAMES = [
    'flow_duration_sec',
    'idle_timeout',
    'hard_timeout',
    'packet_count',
    'byte_count',
    'packet_count_per_second',
    'byte_count_per_second',
    'ip_proto',
    'icmp_code',
    'icmp_type'
]

EXPECTED_FEATURE_COUNT = 10


def extract_flow_features(flow_stats):
    """
    Extract 10 ML features from a flow statistics dictionary.

    Extracts features in the exact order expected by the trained Random
    Forest model and StandardScaler. Missing fields default to 0.
    Rate features (packets/s, bytes/s) handle division by zero when
    flow duration is 0 by falling back to the raw count.

    Args:
        flow_stats (dict): Flow statistics dictionary containing any of
            the following keys:
            - duration_sec (int/float): Flow duration in seconds
            - idle_timeout (int): Idle timeout value
            - hard_timeout (int): Hard timeout value
            - packet_count (int): Total packet count
            - byte_count (int): Total byte count
            - ip_proto (int): IP protocol number
            - icmp_code (int): ICMP code
            - icmp_type (int): ICMP type

            Rate features (packet_count_per_second, byte_count_per_second)
            are calculated automatically from the above fields.

    Returns:
        numpy.ndarray: Feature array with shape (1, 10), ready for
            scaler.transform() and model.predict().

    Raises:
        TypeError: If flow_stats is not a dictionary.

    Examples:
        >>> stats = {'duration_sec': 10, 'packet_count': 500,
        ...          'byte_count': 50000, 'ip_proto': 6}
        >>> features = extract_flow_features(stats)
        >>> features.shape
        (1, 10)
    """
    if not isinstance(flow_stats, dict):
        raise TypeError(
            f"flow_stats must be a dictionary, got {type(flow_stats).__name__}"
        )

    # Extract base fields with default of 0 for missing keys
    duration_sec = flow_stats.get('duration_sec', 0)
    idle_timeout = flow_stats.get('idle_timeout', 0)
    hard_timeout = flow_stats.get('hard_timeout', 0)
    packet_count = flow_stats.get('packet_count', 0)
    byte_count = flow_stats.get('byte_count', 0)
    ip_proto = flow_stats.get('ip_proto', 0)
    icmp_code = flow_stats.get('icmp_code', 0)
    icmp_type = flow_stats.get('icmp_type', 0)

    # Calculate rate features with division-by-zero protection
    # When duration is 0 (flow just installed), use raw count as rate
    if duration_sec > 0:
        packet_count_per_second = packet_count / duration_sec
        byte_count_per_second = byte_count / duration_sec
    else:
        packet_count_per_second = packet_count
        byte_count_per_second = byte_count

    # Assemble features in exact order matching training data columns
    features = [
        duration_sec,               # 1. flow_duration_sec
        idle_timeout,               # 2. idle_timeout
        hard_timeout,               # 3. hard_timeout
        packet_count,               # 4. packet_count
        byte_count,                 # 5. byte_count
        packet_count_per_second,    # 6. packet_count_per_second
        byte_count_per_second,      # 7. byte_count_per_second
        ip_proto,                   # 8. ip_proto
        icmp_code,                  # 9. icmp_code
        icmp_type,                  # 10. icmp_type
    ]

    # Return as numpy array shaped (1, 10) for sklearn compatibility
    # scaler.transform() and model.predict() expect 2D input
    return np.array(features).reshape(1, -1)


def validate_features(features):
    """
    Validate a feature array for ML prediction compatibility.

    Checks that the feature array has the correct shape (1, 10),
    contains no NaN or Inf values, and is a numpy array. This
    validation should be run before passing features to the scaler
    or model.

    Args:
        features: Feature array to validate. Expected to be a numpy
            ndarray with shape (1, 10).

    Returns:
        tuple: (is_valid, error_message) where:
            - is_valid (bool): True if features pass all checks.
            - error_message (str): Empty string if valid, otherwise
              a description of the first validation failure found.

    Examples:
        >>> features = np.array([[10, 5, 30, 100, 5000,
        ...                       10.0, 500.0, 6, 0, 0]])
        >>> valid, error = validate_features(features)
        >>> valid
        True

        >>> bad = np.array([1, 2, 3])
        >>> valid, error = validate_features(bad)
        >>> valid
        False
    """
    # Check type
    if not isinstance(features, np.ndarray):
        return False, (
            f"Expected numpy.ndarray, got {type(features).__name__}"
        )

    # Check shape is exactly (1, 10)
    if features.shape != (1, EXPECTED_FEATURE_COUNT):
        return False, (
            f"Expected shape (1, {EXPECTED_FEATURE_COUNT}), "
            f"got {features.shape}"
        )

    # Check for NaN values
    nan_count = np.isnan(features).sum()
    if nan_count > 0:
        nan_indices = np.argwhere(np.isnan(features))
        nan_features = [FEATURE_NAMES[idx[1]] for idx in nan_indices]
        return False, (
            f"Found {nan_count} NaN value(s) in features: {nan_features}"
        )

    # Check for Inf values
    inf_count = np.isinf(features).sum()
    if inf_count > 0:
        inf_indices = np.argwhere(np.isinf(features))
        inf_features = [FEATURE_NAMES[idx[1]] for idx in inf_indices]
        return False, (
            f"Found {inf_count} Inf value(s) in features: {inf_features}"
        )

    return True, ""


def features_to_dict(features):
    """
    Convert a feature array back to a labeled dictionary.

    Useful for debugging and logging — maps each value in the feature
    array to its corresponding feature name.

    Args:
        features (numpy.ndarray): Feature array with shape (1, 10).

    Returns:
        dict: Dictionary mapping feature names to their values.

    Raises:
        ValueError: If features array does not have 10 elements.
    """
    values = features.flatten()

    if len(values) != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_FEATURE_COUNT} features, "
            f"got {len(values)}"
        )

    return dict(zip(FEATURE_NAMES, values))


if __name__ == '__main__':
    """
    Demonstration and self-test for the feature extraction module.

    Tests extraction with normal traffic, attack traffic, edge cases
    (empty dict, zero duration), and validation scenarios.
    """
    print("=" * 60)
    print("  Feature Extractor - Self Test")
    print("=" * 60)

    # =========================================================================
    # Test 1: Normal TCP traffic
    # =========================================================================
    print("\n  Test 1: Normal TCP traffic")
    normal_stats = {
        'duration_sec': 15,
        'idle_timeout': 10,
        'hard_timeout': 30,
        'packet_count': 120,
        'byte_count': 84000,
        'ip_proto': 6,       # TCP
        'icmp_code': 0,
        'icmp_type': 0
    }
    features = extract_flow_features(normal_stats)
    valid, error = validate_features(features)
    print(f"    Shape: {features.shape}")
    print(f"    Valid: {valid}")
    print(f"    Values: {features.flatten()}")
    print(f"    PPS: {features[0][5]:.2f}, BPS: {features[0][6]:.2f}")
    assert valid, f"Validation failed: {error}"
    assert features[0][5] == 120 / 15, "PPS calculation wrong"
    print("    PASSED")

    # =========================================================================
    # Test 2: ICMP Flood attack
    # =========================================================================
    print("\n  Test 2: ICMP Flood attack traffic")
    attack_stats = {
        'duration_sec': 5,
        'idle_timeout': 0,
        'hard_timeout': 0,
        'packet_count': 50000,
        'byte_count': 3000000,
        'ip_proto': 1,       # ICMP
        'icmp_code': 0,
        'icmp_type': 8       # Echo request
    }
    features = extract_flow_features(attack_stats)
    valid, error = validate_features(features)
    print(f"    Shape: {features.shape}")
    print(f"    Valid: {valid}")
    print(f"    PPS: {features[0][5]:.2f} (high = attack indicator)")
    assert valid, f"Validation failed: {error}"
    assert features[0][5] == 10000.0, "PPS calculation wrong"
    print("    PASSED")

    # =========================================================================
    # Test 3: Empty dictionary (all defaults)
    # =========================================================================
    print("\n  Test 3: Empty dictionary (all defaults to 0)")
    features = extract_flow_features({})
    valid, error = validate_features(features)
    print(f"    Shape: {features.shape}")
    print(f"    Valid: {valid}")
    print(f"    All zeros: {np.all(features == 0)}")
    assert valid, f"Validation failed: {error}"
    assert np.all(features == 0), "Empty dict should produce all zeros"
    print("    PASSED")

    # =========================================================================
    # Test 4: Zero duration (division by zero handling)
    # =========================================================================
    print("\n  Test 4: Zero duration (division by zero)")
    zero_dur_stats = {
        'duration_sec': 0,
        'packet_count': 100,
        'byte_count': 5000
    }
    features = extract_flow_features(zero_dur_stats)
    valid, error = validate_features(features)
    print(f"    Shape: {features.shape}")
    print(f"    Valid: {valid}")
    print(f"    PPS: {features[0][5]} (fallback to packet_count)")
    print(f"    BPS: {features[0][6]} (fallback to byte_count)")
    assert valid, f"Validation failed: {error}"
    assert features[0][5] == 100, "Zero duration PPS fallback wrong"
    assert features[0][6] == 5000, "Zero duration BPS fallback wrong"
    print("    PASSED")

    # =========================================================================
    # Test 5: Validation failures
    # =========================================================================
    print("\n  Test 5: Validation failure cases")

    # Wrong type
    valid, error = validate_features([1, 2, 3])
    print(f"    Wrong type:  valid={valid}, error='{error}'")
    assert not valid

    # Wrong shape
    valid, error = validate_features(np.array([1, 2, 3]))
    print(f"    Wrong shape: valid={valid}, error='{error}'")
    assert not valid

    # NaN values
    nan_features = np.array([[1, 2, np.nan, 4, 5, 6, 7, 8, 9, 10]])
    valid, error = validate_features(nan_features)
    print(f"    NaN values:  valid={valid}, error='{error}'")
    assert not valid

    # Inf values
    inf_features = np.array([[1, 2, 3, 4, 5, np.inf, 7, 8, 9, 10]])
    valid, error = validate_features(inf_features)
    print(f"    Inf values:  valid={valid}, error='{error}'")
    assert not valid

    print("    PASSED")

    # =========================================================================
    # Test 6: TypeError for non-dict input
    # =========================================================================
    print("\n  Test 6: TypeError for non-dict input")
    try:
        extract_flow_features("not a dict")
        assert False, "Should have raised TypeError"
    except TypeError as e:
        print(f"    Caught expected error: {e}")
        print("    PASSED")

    # =========================================================================
    # Test 7: features_to_dict round-trip
    # =========================================================================
    print("\n  Test 7: features_to_dict conversion")
    features = extract_flow_features(normal_stats)
    labeled = features_to_dict(features)
    print(f"    Keys: {list(labeled.keys())}")
    assert labeled['ip_proto'] == 6, "Round-trip failed"
    assert labeled['flow_duration_sec'] == 15, "Round-trip failed"
    print("    PASSED")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 60)
    print("  All 7 tests PASSED")
    print("=" * 60 + "\n")
