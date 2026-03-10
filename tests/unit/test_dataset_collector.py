"""Tests for sdn_ddos_detector.utils.dataset_collector"""

import os
import csv
import tempfile
import pytest
from sdn_ddos_detector.ml.feature_engineering import CSV_HEADERS, EXPECTED_FEATURE_COUNT
from sdn_ddos_detector.utils.dataset_collector import DatasetCollector


@pytest.fixture
def tmp_csv(tmp_path):
    """Return a path for a temporary CSV file."""
    return str(tmp_path / 'test_dataset.csv')


@pytest.fixture
def collector(tmp_csv):
    """Return a DatasetCollector writing to a temp file."""
    return DatasetCollector(tmp_csv)


@pytest.fixture
def sample_normal_features():
    """Return a valid 12-feature normal flow vector."""
    return [15, 120, 84000, 8.0, 5600.0, 700.0, 6, 0, 0, 5, 3, 0.5]


@pytest.fixture
def sample_attack_features():
    """Return a valid 12-feature attack flow vector."""
    return [5, 50000, 3000000, 10000.0, 600000.0, 60.0, 1, 0, 8, 150, 80, 30.0]


class TestCollectorInit:
    """Test DatasetCollector initialization."""

    def test_creates_csv_file(self, tmp_csv):
        DatasetCollector(tmp_csv)
        assert os.path.isfile(tmp_csv)

    def test_csv_has_correct_headers(self, tmp_csv):
        DatasetCollector(tmp_csv)
        with open(tmp_csv, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader)
        assert headers == CSV_HEADERS

    def test_session_counts_start_at_zero(self, collector):
        assert collector.total_count == 0
        assert collector.normal_count == 0
        assert collector.attack_count == 0

    def test_default_path_used_when_none(self):
        # Just verify it doesn't crash with default path
        c = DatasetCollector()
        assert c.output_file.endswith('flow_dataset.csv')


class TestAddFlow:
    """Test adding individual flows."""

    def test_add_normal_flow(self, collector, sample_normal_features):
        collector.add_flow(sample_normal_features, label=0)
        assert collector.total_count == 1
        assert collector.normal_count == 1
        assert collector.attack_count == 0

    def test_add_attack_flow(self, collector, sample_attack_features):
        collector.add_flow(sample_attack_features, label=1)
        assert collector.total_count == 1
        assert collector.normal_count == 0
        assert collector.attack_count == 1

    def test_wrong_feature_count_raises(self, collector):
        with pytest.raises(ValueError, match="Expected"):
            collector.add_flow([1, 2, 3], label=0)

    def test_invalid_label_raises(self, collector, sample_normal_features):
        with pytest.raises(ValueError, match="Label must be"):
            collector.add_flow(sample_normal_features, label=2)

    def test_data_written_after_flush(self, collector, sample_normal_features):
        collector.add_flow(sample_normal_features, label=0)
        collector.flush()
        with open(collector.output_file, 'r') as f:
            rows = list(csv.reader(f))
        # Header + 1 data row
        assert len(rows) == 2


class TestAddFlowsBatch:
    """Test batch adding flows."""

    def test_batch_add(self, collector, sample_normal_features, sample_attack_features):
        batch = [
            (sample_normal_features, 0),
            (sample_attack_features, 1),
            (sample_normal_features, 0),
        ]
        collector.add_flows_batch(batch)
        assert collector.total_count == 3
        assert collector.normal_count == 2
        assert collector.attack_count == 1

    def test_batch_validation_error(self, collector, sample_normal_features):
        batch = [
            (sample_normal_features, 0),
            ([1, 2, 3], 0),  # Invalid
        ]
        with pytest.raises(ValueError):
            collector.add_flows_batch(batch)


class TestFlush:
    """Test buffer flushing."""

    def test_flush_empty_buffer_no_error(self, collector):
        collector.flush()  # Should not raise

    def test_flush_writes_all_buffered(self, collector, sample_normal_features):
        for _ in range(5):
            collector.add_flow(sample_normal_features, label=0)
        collector.flush()
        stats = collector.get_stats()
        assert stats['file_rows'] == 5


class TestGetStats:
    """Test statistics reporting."""

    def test_stats_after_adds(self, collector, sample_normal_features, sample_attack_features):
        collector.add_flow(sample_normal_features, label=0)
        collector.add_flow(sample_normal_features, label=0)
        collector.add_flow(sample_attack_features, label=1)
        collector.flush()
        stats = collector.get_stats()
        assert stats['total'] == 3
        assert stats['normal'] == 2
        assert stats['attack'] == 1
        assert stats['normal_pct'] == pytest.approx(66.7, abs=0.1)
        assert stats['attack_pct'] == pytest.approx(33.3, abs=0.1)
        assert stats['file_rows'] == 3

    def test_stats_zero_total(self, collector):
        stats = collector.get_stats()
        assert stats['total'] == 0
        assert stats['file_rows'] == 0


class TestReopenFile:
    """Test reopening existing CSV preserves data."""

    def test_reopen_preserves_rows(self, tmp_csv, sample_normal_features):
        c1 = DatasetCollector(tmp_csv)
        c1.add_flow(sample_normal_features, label=0)
        c1.add_flow(sample_normal_features, label=0)
        c1.flush()

        c2 = DatasetCollector(tmp_csv)
        stats = c2.get_stats()
        assert stats['file_rows'] == 2
        assert c2.total_count == 0  # Session resets
