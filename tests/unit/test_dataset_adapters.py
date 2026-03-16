"""Tests for sdn_ddos_detector.ml.dataset_adapters."""

import numpy as np
import pandas as pd
import pytest

from sdn_ddos_detector.ml.feature_engineering import FEATURE_NAMES
from sdn_ddos_detector.ml.dataset_adapters import (
    ADAPTER_REGISTRY,
    DatasetAdapter,
    CICIDS2017Adapter,
    CICDDoS2019Adapter,
    UNSWNB15Adapter,
)


# ── Synthetic fixture DataFrames ─────────────────────────────────────────────

@pytest.fixture
def cic_ids2017_df():
    return pd.DataFrame({
        "Flow Duration": [1_000_000, 500_000],
        "Total Fwd Packets": [10, 5000],
        "Total Backward Packets": [8, 100],
        "Total Length of Fwd Packets": [5000, 300_000],
        "Total Length of Bwd Packets": [4000, 50_000],
        "Protocol": [6, 17],
        "Label": ["BENIGN", "DoS Hulk"],
    })


@pytest.fixture
def cic_ddos2019_df():
    """Uses variant column names that CIC-DDoS2019 may produce."""
    return pd.DataFrame({
        "Flow Duration": [2_000_000, 100_000],
        "Tot Fwd Pkts": [20, 80000],
        "Tot Bwd Pkts": [15, 200],
        "TotLen Fwd Pkts": [10000, 5_000_000],
        "TotLen Bwd Pkts": [8000, 100_000],
        "Protocol": [6, 17],
        "Label": ["BENIGN", "DDoS-DNS"],
    })


@pytest.fixture
def unsw_nb15_df():
    return pd.DataFrame({
        "spkts": [5, 40000],
        "dpkts": [4, 100],
        "sbytes": [2000, 2_000_000],
        "dbytes": [1500, 50_000],
        "dur": [1.5, 0.01],
        "proto": ["tcp", "udp"],
        "label": [0, 1],
        "attack_cat": ["Normal", "DoS"],
    })


# ── AdapterRegistry ──────────────────────────────────────────────────────────

class TestAdapterRegistry:
    def test_registry_has_three_entries(self):
        assert len(ADAPTER_REGISTRY) == 3

    def test_all_adapters_are_dataset_adapter(self):
        for name, cls in ADAPTER_REGISTRY.items():
            assert issubclass(cls, DatasetAdapter), f"{name} is not a DatasetAdapter"


# ── CICIDS2017Adapter ────────────────────────────────────────────────────────

class TestCICIDS2017Adapter:
    def test_map_features_canonical_columns(self, cic_ids2017_df):
        adapter = CICIDS2017Adapter()
        result = adapter.map_features(cic_ids2017_df)
        for feat in FEATURE_NAMES:
            assert feat in result.columns, f"Missing column: {feat}"
        assert "label" in result.columns

    def test_get_labels_benign_vs_attack(self, cic_ids2017_df):
        adapter = CICIDS2017Adapter()
        binary, multiclass = adapter.get_labels(cic_ids2017_df)
        assert binary.iloc[0] == 0  # BENIGN
        assert binary.iloc[1] == 1  # DoS Hulk

    def test_get_citation_not_empty(self):
        adapter = CICIDS2017Adapter()
        assert len(adapter.get_citation()) > 0


# ── CICDDoS2019Adapter ──────────────────────────────────────────────────────

class TestCICDDoS2019Adapter:
    def test_map_features_canonical_columns(self, cic_ddos2019_df):
        adapter = CICDDoS2019Adapter()
        result = adapter.map_features(cic_ddos2019_df)
        for feat in FEATURE_NAMES:
            assert feat in result.columns, f"Missing column: {feat}"

    def test_find_column_variant_names(self, cic_ddos2019_df):
        adapter = CICDDoS2019Adapter()
        col = adapter._find_column(cic_ddos2019_df, ["Total Fwd Packets", "Tot Fwd Pkts"])
        assert col == "Tot Fwd Pkts"


# ── UNSWNB15Adapter ─────────────────────────────────────────────────────────

class TestUNSWNB15Adapter:
    def test_map_features_canonical_columns(self, unsw_nb15_df):
        adapter = UNSWNB15Adapter()
        result = adapter.map_features(unsw_nb15_df)
        for feat in FEATURE_NAMES:
            assert feat in result.columns, f"Missing column: {feat}"

    def test_has_predefined_split_detection(self, unsw_nb15_df):
        adapter = UNSWNB15Adapter()
        # No _split column
        assert adapter.has_predefined_split(unsw_nb15_df) is False
        # Add _split column
        df_with_split = unsw_nb15_df.copy()
        df_with_split["_split"] = ["train", "test"]
        assert adapter.has_predefined_split(df_with_split) is True


# ── Value Verification Tests (v3.1.0) ──────────────────────────────────────

class TestCICIDS2017ValueVerification:
    """Verify actual mapped values, not just column presence."""

    def test_duration_microsecond_conversion(self, cic_ids2017_df):
        """CIC-IDS2017 stores duration in microseconds; must convert to seconds."""
        adapter = CICIDS2017Adapter()
        result = adapter.map_features(cic_ids2017_df)
        # First row: 1_000_000 microseconds = 1.0 second
        assert abs(result["flow_duration_sec"].iloc[0] - 1.0) < 1e-6
        # Second row: 500_000 microseconds = 0.5 seconds
        assert abs(result["flow_duration_sec"].iloc[1] - 0.5) < 1e-6

    def test_packet_count_aggregation(self, cic_ids2017_df):
        """packet_count = Total Fwd Packets + Total Backward Packets."""
        adapter = CICIDS2017Adapter()
        result = adapter.map_features(cic_ids2017_df)
        # First row: 10 + 8 = 18
        assert result["packet_count"].iloc[0] == 18
        # Second row: 5000 + 100 = 5100
        assert result["packet_count"].iloc[1] == 5100

    def test_infinity_handling(self):
        """Infinity values in rate columns should be replaced, not propagated."""
        df = pd.DataFrame({
            "Flow Duration": [0, 1_000_000],
            "Total Fwd Packets": [100, 10],
            "Total Backward Packets": [0, 5],
            "Total Length of Fwd Packets": [5000, 3000],
            "Total Length of Bwd Packets": [0, 2000],
            "Protocol": [6, 6],
            "Flow Bytes/s": [np.inf, 5000.0],
            "Label": ["BENIGN", "BENIGN"],
        })
        adapter = CICIDS2017Adapter()
        result = adapter.map_features(df)
        # No infinities should remain
        assert not np.any(np.isinf(result.select_dtypes(include=[np.number]).values))


class TestUNSWNB15ValueVerification:

    def test_protocol_string_to_number(self, unsw_nb15_df):
        """UNSW-NB15 uses string protocol names that must map to numbers."""
        adapter = UNSWNB15Adapter()
        result = adapter.map_features(unsw_nb15_df)
        # First row: "tcp" → 6
        assert result["ip_proto"].iloc[0] == 6
        # Second row: "udp" → 17
        assert result["ip_proto"].iloc[1] == 17


class TestPPSCalculation:

    def test_pps_from_mapped_features(self, cic_ids2017_df):
        """packet_count_per_second = packet_count / duration_sec."""
        adapter = CICIDS2017Adapter()
        result = adapter.map_features(cic_ids2017_df)
        # Row 0: packets=18, duration=1.0s → pps=18.0
        expected_pps = 18.0 / 1.0
        assert abs(result["packet_count_per_second"].iloc[0] - expected_pps) < 1e-3
        # Row 1: packets=5100, duration=0.5s → pps=10200.0
        expected_pps2 = 5100.0 / 0.5
        assert abs(result["packet_count_per_second"].iloc[1] - expected_pps2) < 1e-3
