"""Tests for utilities/feature_extractor.py"""

import pytest
import numpy as np
from utilities.feature_extractor import (
    FEATURE_NAMES,
    EXPECTED_FEATURE_COUNT,
    CSV_HEADERS,
    LABEL_COLUMN,
    extract_flow_features,
    validate_features,
    features_to_dict,
)


class TestFeatureDefinitions:
    """Test feature constants and definitions."""

    def test_feature_count_matches_names(self):
        assert len(FEATURE_NAMES) == EXPECTED_FEATURE_COUNT

    def test_csv_headers_include_all_features_plus_label(self):
        assert len(CSV_HEADERS) == EXPECTED_FEATURE_COUNT + 1
        assert CSV_HEADERS[-1] == LABEL_COLUMN

    def test_csv_headers_start_with_feature_names(self):
        assert CSV_HEADERS[:EXPECTED_FEATURE_COUNT] == FEATURE_NAMES

    def test_label_column_name(self):
        assert LABEL_COLUMN == 'label'

    def test_expected_feature_count_is_12(self):
        assert EXPECTED_FEATURE_COUNT == 12


class TestExtractFlowFeatures:
    """Test extract_flow_features function."""

    def test_basic_extraction(self):
        flow_stats = {
            'duration_sec': 10,
            'packet_count': 100,
            'byte_count': 50000,
            'ip_proto': 6,
            'icmp_code': 0,
            'icmp_type': 0,
        }
        features = extract_flow_features(flow_stats)
        assert features.shape == (1, EXPECTED_FEATURE_COUNT)

    def test_derived_features_computed(self):
        flow_stats = {
            'duration_sec': 10,
            'packet_count': 100,
            'byte_count': 50000,
            'ip_proto': 6,
            'icmp_code': 0,
            'icmp_type': 0,
        }
        features = extract_flow_features(flow_stats)
        f = features[0]
        # pps = 100/10 = 10.0
        assert f[3] == pytest.approx(10.0)
        # bps = 50000/10 = 5000.0
        assert f[4] == pytest.approx(5000.0)
        # avg_pkt_size = 50000/100 = 500.0
        assert f[5] == pytest.approx(500.0)

    def test_zero_duration_no_division_error(self):
        flow_stats = {
            'duration_sec': 0,
            'packet_count': 100,
            'byte_count': 50000,
            'ip_proto': 6,
            'icmp_code': 0,
            'icmp_type': 0,
        }
        features = extract_flow_features(flow_stats)
        f = features[0]
        assert f.shape[0] == EXPECTED_FEATURE_COUNT
        # With zero duration, pps and bps should be the raw counts
        assert f[3] == 100
        assert f[4] == 50000

    def test_zero_packets_no_division_error(self):
        flow_stats = {
            'duration_sec': 10,
            'packet_count': 0,
            'byte_count': 0,
            'ip_proto': 17,
            'icmp_code': 0,
            'icmp_type': 0,
        }
        features = extract_flow_features(flow_stats)
        # avg_pkt_size should be 0
        assert features[0][5] == 0

    def test_aggregate_features_included(self):
        flow_stats = {
            'duration_sec': 10,
            'packet_count': 100,
            'byte_count': 50000,
            'ip_proto': 6,
            'icmp_code': 0,
            'icmp_type': 0,
        }
        aggregates = {
            'flows_to_dst': 50,
            'unique_sources_to_dst': 20,
            'flow_creation_rate': 5.0,
        }
        features = extract_flow_features(flow_stats, aggregates=aggregates)
        f = features[0]
        assert f[9] == 50
        assert f[10] == 20
        assert f[11] == pytest.approx(5.0)

    def test_default_aggregates_are_zero(self):
        flow_stats = {
            'duration_sec': 10,
            'packet_count': 100,
            'byte_count': 50000,
            'ip_proto': 6,
            'icmp_code': 0,
            'icmp_type': 0,
        }
        features = extract_flow_features(flow_stats)
        f = features[0]
        assert f[9] == 0   # flows_to_dst
        assert f[10] == 0  # unique_sources_to_dst
        assert f[11] == 0  # flow_creation_rate


class TestValidateFeatures:
    """Test validate_features function."""

    def test_valid_features(self):
        features = np.array([[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]])
        is_valid, msg = validate_features(features)
        assert is_valid is True
        assert msg == ""

    def test_wrong_shape_invalid(self):
        features = np.array([[1, 2, 3]])
        is_valid, msg = validate_features(features)
        assert is_valid is False
        assert "shape" in msg.lower()

    def test_nan_features_invalid(self):
        features = np.array([[1, float('nan'), 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]])
        is_valid, _ = validate_features(features)
        assert is_valid is False

    def test_inf_features_invalid(self):
        features = np.array([[1, float('inf'), 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]])
        is_valid, _ = validate_features(features)
        assert is_valid is False

    def test_non_ndarray_invalid(self):
        is_valid, _ = validate_features([1, 2, 3])
        assert is_valid is False


class TestFeaturesToDict:
    """Test features_to_dict function."""

    def test_round_trip(self):
        features = np.array([10, 100, 50000, 10.0, 5000.0, 500.0, 6, 0, 0, 5, 3, 1.0]).reshape(1, -1)
        d = features_to_dict(features)
        assert len(d) == EXPECTED_FEATURE_COUNT
        for i, name in enumerate(FEATURE_NAMES):
            assert d[name] == features[0][i]

    def test_wrong_length_raises(self):
        with pytest.raises(ValueError):
            features_to_dict(np.array([1, 2, 3]).reshape(1, -1))
