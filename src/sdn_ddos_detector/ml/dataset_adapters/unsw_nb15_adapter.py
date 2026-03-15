"""Adapter for UNSW-NB15 dataset.

Maps Argus/Bro-IDS 49 features to the canonical 12-feature format.
Supports the predefined train/test split (175,341 / 82,332).

Reference:
    Moustafa & Slay, "UNSW-NB15: a comprehensive data set for network
    intrusion detection systems", MilCIS 2015.
"""

import glob
import os
import warnings

import numpy as np
import pandas as pd

from sdn_ddos_detector.ml.feature_engineering import FEATURE_NAMES
from .base_adapter import DatasetAdapter

# Protocol name to number mapping for UNSW-NB15
PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "arp": 0,
    "ospf": 89,
    "igmp": 2,
    "sctp": 132,
    "gre": 47,
}


class UNSWNB15Adapter(DatasetAdapter):
    """Maps UNSW-NB15 Argus/Bro-IDS features to canonical 12 features."""

    def load_raw(self, path: str) -> pd.DataFrame:
        """Load UNSW-NB15 CSV files.

        Supports both the 4-part raw files and the predefined train/test split.
        Prefers the train/test split files if available.
        """
        # Check for predefined split files first
        train_file = os.path.join(path, "UNSW_NB15_training-set.csv")
        test_file = os.path.join(path, "UNSW_NB15_testing-set.csv")

        if os.path.exists(train_file) and os.path.exists(test_file):
            train_df = pd.read_csv(train_file, low_memory=False)
            test_df = pd.read_csv(test_file, low_memory=False)
            # Mark source for preserving predefined split
            train_df["_split"] = "train"
            test_df["_split"] = "test"
            return pd.concat([train_df, test_df], ignore_index=True)

        # Fall back to raw 4-part files
        csv_files = sorted(glob.glob(os.path.join(path, "UNSW-NB15_*.csv")))
        if not csv_files:
            # Try any CSV
            csv_files = sorted(glob.glob(os.path.join(path, "*.csv")))

        if not csv_files:
            raise FileNotFoundError(
                f"No CSV files found in {path}. "
                "Download from https://research.unsw.edu.au/projects/unsw-nb15-dataset"
            )

        dfs = []
        for f in csv_files:
            try:
                df = pd.read_csv(f, low_memory=False)
                dfs.append(df)
            except Exception as e:
                warnings.warn(f"Skipping {f}: {e}")

        if not dfs:
            raise ValueError(f"No valid CSV files could be loaded from {path}")

        return pd.concat(dfs, ignore_index=True)

    def map_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map UNSW-NB15 features to canonical 12-feature format."""
        df = df.copy()

        # Normalize column names to lowercase for consistency
        df.columns = df.columns.str.strip().str.lower()

        # Base features
        spkts = df["spkts"].fillna(0) if "spkts" in df.columns else pd.Series(0, index=df.index)
        dpkts = df["dpkts"].fillna(0) if "dpkts" in df.columns else pd.Series(0, index=df.index)
        packet_count = spkts + dpkts

        sbytes = df["sbytes"].fillna(0) if "sbytes" in df.columns else pd.Series(0, index=df.index)
        dbytes = df["dbytes"].fillna(0) if "dbytes" in df.columns else pd.Series(0, index=df.index)
        byte_count = sbytes + dbytes

        duration_sec = df["dur"].fillna(0) if "dur" in df.columns else pd.Series(0, index=df.index)

        # Rate features
        safe_duration = duration_sec.clip(lower=0.001)
        packets_per_second = packet_count / safe_duration
        bytes_per_second = byte_count / safe_duration
        avg_packet_size = byte_count / packet_count.clip(lower=1)

        # Protocol mapping: UNSW-NB15 uses string protocol names
        if "proto" in df.columns:
            ip_proto = df["proto"].astype(str).str.strip().str.lower().map(PROTO_MAP).fillna(0).astype(int)
        else:
            ip_proto = pd.Series(0, index=df.index, dtype=int)

        # ICMP fields
        icmp_code = pd.Series(0, index=df.index, dtype=int)
        icmp_type = pd.Series(0, index=df.index, dtype=int)
        icmp_mask = ip_proto == 1
        icmp_type = icmp_type.where(~icmp_mask, 8)

        # Aggregate features: approximate from source/destination IP groupings
        dst_col = None
        src_col = None
        for c in ["dstip", "dst_ip", "destination ip"]:
            if c in df.columns:
                dst_col = c
                break
        for c in ["srcip", "src_ip", "source ip"]:
            if c in df.columns:
                src_col = c
                break

        if dst_col:
            flows_to_dst = df.groupby(dst_col)[dst_col].transform("count")
            if src_col:
                unique_sources_to_dst = df.groupby(dst_col)[src_col].transform("nunique")
            else:
                unique_sources_to_dst = pd.Series(1, index=df.index)
        else:
            flows_to_dst = pd.Series(1, index=df.index)
            unique_sources_to_dst = pd.Series(1, index=df.index)

        # Flow creation rate: approximate from stime (start time) if available
        stime_col = None
        for c in ["stime", "start_time"]:
            if c in df.columns:
                stime_col = c
                break

        if stime_col and dst_col:
            try:
                stime = pd.to_numeric(df[stime_col], errors="coerce")
                flow_creation_rate = (
                    stime.groupby(df[dst_col])
                    .transform(lambda x: x.diff().clip(lower=0.001).rdiv(1).rolling(5, min_periods=1).mean())
                ).fillna(0)
            except Exception:
                flow_creation_rate = pd.Series(0, index=df.index)
        else:
            flow_creation_rate = pd.Series(0, index=df.index)

        binary_labels, _ = self.get_labels(df)

        result = pd.DataFrame({
            "flow_duration_sec": duration_sec.values,
            "packet_count": packet_count.values,
            "byte_count": byte_count.values,
            "packet_count_per_second": packets_per_second.values,
            "byte_count_per_second": bytes_per_second.values,
            "avg_packet_size": avg_packet_size.values,
            "ip_proto": ip_proto.values,
            "icmp_code": icmp_code.values,
            "icmp_type": icmp_type.values,
            "flows_to_dst": flows_to_dst.values,
            "unique_sources_to_dst": unique_sources_to_dst.values,
            "flow_creation_rate": flow_creation_rate.values,
            "label": binary_labels.values,
        })

        result = result.replace([np.inf, -np.inf], 0).dropna()
        return result

    def get_labels(self, df: pd.DataFrame) -> tuple:
        """Extract binary and multiclass labels.

        UNSW-NB15 has 'label' (binary: 0/1) and 'attack_cat' (multiclass).
        """
        # Binary label
        label_col = None
        for candidate in ["label", "Label"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col:
            binary = df[label_col].fillna(0).astype(int)
        else:
            binary = pd.Series(0, index=df.index, dtype=int)

        # Multiclass
        attack_col = None
        for candidate in ["attack_cat", "Attack_cat", "attack_category"]:
            if candidate in df.columns:
                attack_col = candidate
                break

        if attack_col:
            multiclass = df[attack_col].fillna("Normal").astype(str).str.strip()
        else:
            multiclass = binary.map({0: "Normal", 1: "Attack"})

        return binary, multiclass

    def has_predefined_split(self, df: pd.DataFrame) -> bool:
        """Check if the loaded data has predefined train/test split markers."""
        return "_split" in df.columns

    def get_predefined_split(self, df: pd.DataFrame) -> tuple:
        """Return train/test indices based on predefined split.

        Returns:
            Tuple of (train_indices, test_indices) as numpy arrays.
        """
        if "_split" not in df.columns:
            raise ValueError("No predefined split markers found. Load the "
                           "UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv files.")
        train_mask = df["_split"] == "train"
        test_mask = df["_split"] == "test"
        return df.index[train_mask].values, df.index[test_mask].values

    def get_citation(self) -> str:
        return """@inproceedings{moustafa2015unsw,
  title={UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems (UNSW-NB15 Network Data Set)},
  author={Moustafa, Nour and Slay, Jill},
  booktitle={Proceedings of the Military Communications and Information Systems Conference (MilCIS)},
  pages={1--6},
  year={2015},
  organization={IEEE},
  doi={10.1109/MilCIS.2015.7348942}
}"""
