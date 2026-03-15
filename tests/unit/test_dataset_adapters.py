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
