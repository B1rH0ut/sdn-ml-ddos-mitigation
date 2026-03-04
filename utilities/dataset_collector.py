#!/usr/bin/env python3
"""
Dataset Collection Utility for DDoS Detection

Provides the DatasetCollector class for collecting flow statistics into
a CSV dataset suitable for training the Random Forest classifier. Flows
are appended incrementally, allowing real-time data collection from the
SDN controller during live network operation.

The CSV format produced by this module is consumed by:
    - ml_model/train_model.py (model training)
    - ml_model/create_roc.py (ROC curve generation)

CSV columns (11 total):
    flow_duration_sec, idle_timeout, hard_timeout, packet_count,
    byte_count, packet_count_per_second, byte_count_per_second,
    ip_proto, icmp_code, icmp_type, label

Usage:
    As module:
        from utilities.dataset_collector import DatasetCollector

        collector = DatasetCollector('../datasets/flow_dataset.csv')
        collector.add_flow([10, 5, 30, 100, 5000, 10.0, 500.0, 6, 0, 0], label=0)
        print(collector.get_stats())

    Standalone test:
        cd utilities
        python3 dataset_collector.py

"""

import csv
import os
import fcntl
from datetime import datetime


# CSV column headers — must match train_model.py FEATURE_COLUMNS + label
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

EXPECTED_FEATURE_COUNT = 10


class DatasetCollector:
    """
    Collect flow statistics into a CSV dataset for ML training.

    Manages a CSV file for incremental flow data collection. Creates
    the file with proper headers if it doesn't exist, appends flows
    atomically with file locking, and tracks collection statistics.

    Attributes:
        output_file (str): Absolute path to the output CSV file.
        total_count (int): Total number of flows added this session.
        normal_count (int): Number of normal flows (label=0) added.
        attack_count (int): Number of attack flows (label=1) added.
        created_at (datetime): Timestamp when this collector was initialized.
    """

    def __init__(self, output_file=None):
        """
        Initialize the DatasetCollector.

        Creates the output directory and CSV file with headers if they
        don't already exist.

        Args:
            output_file (str, optional): Path to the output CSV file.
                Defaults to ../datasets/flow_dataset.csv relative to
                this script's directory.

        Raises:
            IOError: If the output directory cannot be created or the
                     CSV file cannot be written.
        """
        # Resolve default path relative to this script's directory
        if output_file is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            output_file = os.path.join(
                script_dir, '..', 'datasets', 'flow_dataset.csv'
            )

        self.output_file = os.path.abspath(output_file)

        # Session statistics
        self.total_count = 0
        self.normal_count = 0
        self.attack_count = 0
        self.created_at = datetime.now()

        # Ensure output directory exists
        output_dir = os.path.dirname(self.output_file)
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            raise IOError(
                f"Cannot create output directory {output_dir}: {e}"
            )

        # Create CSV file with headers if it doesn't exist
        self._ensure_csv_exists()

    def _ensure_csv_exists(self):
        """
        Create the CSV file with headers if it doesn't already exist.

        Checks whether the file exists and contains the correct header
        row. If the file is missing or empty, creates it with the
        standard 11-column header.
        """
        if os.path.isfile(self.output_file):
            # Verify existing file has correct headers
            try:
                with open(self.output_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    existing_headers = next(reader, None)

                if existing_headers == CSV_HEADERS:
                    return  # File exists with correct headers
                elif existing_headers is not None:
                    print(
                        f"  WARNING: Existing CSV has different headers.\n"
                        f"    Expected: {CSV_HEADERS}\n"
                        f"    Found:    {existing_headers}\n"
                        f"    Appending with current format anyway."
                    )
                    return
            except (IOError, StopIteration):
                pass  # File exists but can't be read; recreate below

        # Create new file with headers
        try:
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADERS)
        except IOError as e:
            raise IOError(
                f"Cannot create CSV file {self.output_file}: {e}"
            )

    def add_flow(self, features, label):
        """
        Append a single flow record to the CSV dataset.

        Validates the feature list and label, then appends the flow
        as a new row to the CSV file using file locking to prevent
        corruption from concurrent writes.

        Args:
            features (list or array): List of 10 numeric feature values
                in the standard order:
                [flow_duration_sec, idle_timeout, hard_timeout,
                 packet_count, byte_count, packet_count_per_second,
                 byte_count_per_second, ip_proto, icmp_code, icmp_type]
            label (int): Flow classification label.
                0 = normal traffic, 1 = DDoS attack.

        Raises:
            ValueError: If features length is not 10 or label is not 0/1.
            IOError: If the CSV file cannot be written.
        """
        # Validate feature count
        if len(features) != EXPECTED_FEATURE_COUNT:
            raise ValueError(
                f"Expected {EXPECTED_FEATURE_COUNT} features, "
                f"got {len(features)}. "
                f"Features must be: {CSV_HEADERS[:EXPECTED_FEATURE_COUNT]}"
            )

        # Validate label
        if label not in (0, 1):
            raise ValueError(
                f"Label must be 0 (normal) or 1 (attack), got {label}"
            )

        # Build the complete row: 10 features + label
        row = list(features) + [label]

        # Append to CSV with file locking for concurrent write safety
        try:
            with open(self.output_file, 'a', newline='') as f:
                # Acquire exclusive lock to prevent concurrent corruption
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    writer = csv.writer(f)
                    writer.writerow(row)
                finally:
                    # Release lock
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except IOError as e:
            raise IOError(
                f"Failed to write to {self.output_file}: {e}"
            )

        # Update session statistics
        self.total_count += 1
        if label == 0:
            self.normal_count += 1
        else:
            self.attack_count += 1

    def add_flows_batch(self, flows):
        """
        Append multiple flow records to the CSV dataset in a single write.

        More efficient than calling add_flow() repeatedly when adding
        many flows at once, as it acquires the file lock only once.

        Args:
            flows (list): List of (features, label) tuples. Each features
                element must be a list of 10 numeric values, and each
                label must be 0 or 1.

        Raises:
            ValueError: If any flow has invalid features or label.
            IOError: If the CSV file cannot be written.
        """
        # Validate all flows before writing any
        rows = []
        for i, (features, label) in enumerate(flows):
            if len(features) != EXPECTED_FEATURE_COUNT:
                raise ValueError(
                    f"Flow {i}: expected {EXPECTED_FEATURE_COUNT} features, "
                    f"got {len(features)}"
                )
            if label not in (0, 1):
                raise ValueError(
                    f"Flow {i}: label must be 0 or 1, got {label}"
                )
            rows.append(list(features) + [label])

        # Write all rows with a single lock acquisition
        try:
            with open(self.output_file, 'a', newline='') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    writer = csv.writer(f)
                    writer.writerows(rows)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except IOError as e:
            raise IOError(
                f"Failed to write batch to {self.output_file}: {e}"
            )

        # Update session statistics
        for _, label in flows:
            self.total_count += 1
            if label == 0:
                self.normal_count += 1
            else:
                self.attack_count += 1

    def get_stats(self):
        """
        Return collection statistics for the current session.

        Returns:
            dict: Dictionary containing:
                - total (int): Total flows added this session
                - normal (int): Normal flows (label=0) added
                - attack (int): Attack flows (label=1) added
                - normal_pct (float): Percentage of normal flows
                - attack_pct (float): Percentage of attack flows
                - output_file (str): Path to the CSV file
                - file_size_kb (float): Current CSV file size in KB
                - file_rows (int): Total rows in CSV (excluding header)
                - session_start (str): When this collector was initialized
        """
        # Get file size
        try:
            file_size = os.path.getsize(self.output_file) / 1024
        except OSError:
            file_size = 0.0

        # Count total rows in the CSV file (excluding header)
        file_rows = 0
        try:
            with open(self.output_file, 'r') as f:
                file_rows = sum(1 for _ in f) - 1  # Subtract header row
                file_rows = max(file_rows, 0)
        except IOError:
            file_rows = 0

        # Calculate percentages
        total = max(self.total_count, 1)  # Avoid division by zero
        normal_pct = (self.normal_count / total) * 100
        attack_pct = (self.attack_count / total) * 100

        return {
            'total': self.total_count,
            'normal': self.normal_count,
            'attack': self.attack_count,
            'normal_pct': round(normal_pct, 1),
            'attack_pct': round(attack_pct, 1),
            'output_file': self.output_file,
            'file_size_kb': round(file_size, 2),
            'file_rows': file_rows,
            'session_start': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    def print_stats(self):
        """
        Print a formatted summary of collection statistics.

        Displays session counts, percentages, file information,
        and the target dataset composition for reference.
        """
        stats = self.get_stats()

        print("\n" + "=" * 55)
        print("  Dataset Collection Statistics")
        print("=" * 55)
        print(f"  Session start:  {stats['session_start']}")
        print(f"  Output file:    {stats['output_file']}")
        print(f"  File size:      {stats['file_size_kb']:.2f} KB")
        print(f"  Total in file:  {stats['file_rows']} rows")
        print(f"\n  This Session:")
        print(f"    Total added:  {stats['total']}")
        print(f"    Normal (0):   {stats['normal']} ({stats['normal_pct']}%)")
        print(f"    Attack (1):   {stats['attack']} ({stats['attack_pct']}%)")
        print(f"\n  Target composition: 65% normal / 35% attack")
        print("=" * 55 + "\n")


if __name__ == '__main__':
    """
    Demonstration and self-test for the DatasetCollector class.

    Creates a temporary CSV file, adds sample flows, verifies
    statistics, and cleans up.
    """
    import tempfile

    print("=" * 55)
    print("  DatasetCollector - Self Test")
    print("=" * 55)

    # Use a temporary file for testing
    test_file = os.path.join(tempfile.gettempdir(), 'test_dataset.csv')

    # Clean up any previous test file
    if os.path.exists(test_file):
        os.remove(test_file)

    # =========================================================================
    # Test 1: Initialization creates CSV with headers
    # =========================================================================
    print("\n  Test 1: Initialization")
    collector = DatasetCollector(test_file)
    assert os.path.isfile(test_file), "CSV file not created"

    with open(test_file, 'r') as f:
        header = f.readline().strip()
    expected_header = ','.join(CSV_HEADERS)
    assert header == expected_header, f"Wrong headers: {header}"
    print("    CSV created with correct headers")
    print("    PASSED")

    # =========================================================================
    # Test 2: Add normal flow
    # =========================================================================
    print("\n  Test 2: Add normal flow")
    normal_features = [15, 10, 30, 120, 84000, 8.0, 5600.0, 6, 0, 0]
    collector.add_flow(normal_features, label=0)
    assert collector.total_count == 1
    assert collector.normal_count == 1
    assert collector.attack_count == 0
    print("    Normal flow added successfully")
    print("    PASSED")

    # =========================================================================
    # Test 3: Add attack flow
    # =========================================================================
    print("\n  Test 3: Add attack flow")
    attack_features = [5, 0, 0, 50000, 3000000, 10000.0, 600000.0, 1, 0, 8]
    collector.add_flow(attack_features, label=1)
    assert collector.total_count == 2
    assert collector.normal_count == 1
    assert collector.attack_count == 1
    print("    Attack flow added successfully")
    print("    PASSED")

    # =========================================================================
    # Test 4: Batch add
    # =========================================================================
    print("\n  Test 4: Batch add")
    batch = [
        ([10, 5, 30, 80, 40000, 8.0, 4000.0, 17, 0, 0], 0),
        ([3, 0, 0, 80000, 5000000, 26666.7, 1666666.7, 17, 0, 0], 1),
        ([20, 10, 30, 200, 150000, 10.0, 7500.0, 6, 0, 0], 0),
    ]
    collector.add_flows_batch(batch)
    assert collector.total_count == 5
    assert collector.normal_count == 3
    assert collector.attack_count == 2
    print(f"    Batch of {len(batch)} flows added")
    print("    PASSED")

    # =========================================================================
    # Test 5: Statistics
    # =========================================================================
    print("\n  Test 5: Statistics")
    stats = collector.get_stats()
    assert stats['total'] == 5
    assert stats['normal'] == 3
    assert stats['attack'] == 2
    assert stats['normal_pct'] == 60.0
    assert stats['attack_pct'] == 40.0
    assert stats['file_rows'] == 5
    print(f"    Total: {stats['total']}, "
          f"Normal: {stats['normal']} ({stats['normal_pct']}%), "
          f"Attack: {stats['attack']} ({stats['attack_pct']}%)")
    print(f"    File rows: {stats['file_rows']}, "
          f"Size: {stats['file_size_kb']} KB")
    print("    PASSED")

    # =========================================================================
    # Test 6: Validation errors
    # =========================================================================
    print("\n  Test 6: Validation errors")

    # Wrong feature count
    try:
        collector.add_flow([1, 2, 3], label=0)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"    Wrong feature count: caught ValueError")

    # Invalid label
    try:
        collector.add_flow(normal_features, label=2)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"    Invalid label: caught ValueError")

    print("    PASSED")

    # =========================================================================
    # Test 7: Reopen existing file preserves data
    # =========================================================================
    print("\n  Test 7: Reopen existing file")
    collector2 = DatasetCollector(test_file)
    stats2 = collector2.get_stats()
    assert stats2['file_rows'] == 5, "Reopening lost data"
    assert collector2.total_count == 0, "Session count should reset"
    print(f"    File rows preserved: {stats2['file_rows']}")
    print(f"    Session count reset: {collector2.total_count}")
    print("    PASSED")

    # =========================================================================
    # Test 8: CSV content verification
    # =========================================================================
    print("\n  Test 8: CSV content verification")
    import pandas as pd
    df = pd.read_csv(test_file)
    assert len(df) == 5, f"Expected 5 rows, got {len(df)}"
    assert len(df.columns) == 11, f"Expected 11 columns, got {len(df.columns)}"
    assert list(df.columns) == CSV_HEADERS, "Column names don't match"
    assert df['label'].isin([0, 1]).all(), "Invalid labels in CSV"
    print(f"    Rows: {len(df)}, Columns: {len(df.columns)}")
    print(f"    Headers match: True")
    print(f"    Labels valid: True")
    print("    PASSED")

    # Print final stats
    collector.print_stats()

    # Cleanup
    os.remove(test_file)
    print("  Test file cleaned up")

    print("\n" + "=" * 55)
    print("  All 8 tests PASSED")
    print("=" * 55 + "\n")
