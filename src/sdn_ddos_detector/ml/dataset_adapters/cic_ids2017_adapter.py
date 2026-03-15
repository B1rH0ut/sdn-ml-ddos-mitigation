"""Adapter for CIC-IDS2017 dataset.

Maps CICFlowMeter's ~80 features to the canonical 12-feature format.

Reference:
    Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset
    and Intrusion Traffic Characterization", ICISSP 2018.
"""

import glob
import os
import warnings

import numpy as np
import pandas as pd

from sdn_ddos_detector.ml.feature_engineering import FEATURE_NAMES, CSV_HEADERS
from .base_adapter import DatasetAdapter

# CIC-IDS2017 labels that map to attack (label=1)
ATTACK_LABELS = {
    "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest",
    "DDoS", "PortScan", "Bot", "Infiltration", "Web Attack - Brute Force",
    "Web Attack - XSS", "Web Attack - Sql Injection", "FTP-Patator",
    "SSH-Patator", "Heartbleed",
}


class CICIDS2017Adapter(DatasetAdapter):
    """Maps CIC-IDS2017 CICFlowMeter output to canonical 12 features."""

    def load_raw(self, path: str) -> pd.DataFrame:
        """Load all CIC-IDS2017 CSV files from a directory.

        Handles CICFlowMeter quirks:
        - Column names may have leading/trailing whitespace
        - Some numeric columns may be stored as strings
        - Infinity values in rate columns
        """
        csv_files = sorted(glob.glob(os.path.join(path, "*.csv")))
        if not csv_files:
            raise FileNotFoundError(
                f"No CSV files found in {path}. "
                "Download from https://www.unb.ca/cic/datasets/ids-2017.html"
            )

        dfs = []
        for f in csv_files:
            try:
                df = pd.read_csv(f, low_memory=False, encoding="utf-8")
                # Strip whitespace from column names (CICFlowMeter quirk)
                df.columns = df.columns.str.strip()
                dfs.append(df)
            except Exception as e:
                warnings.warn(f"Skipping {f}: {e}")

        if not dfs:
            raise ValueError(f"No valid CSV files could be loaded from {path}")

        combined = pd.concat(dfs, ignore_index=True)
        return combined

    def _clean_numeric(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert string-typed numeric columns and handle infinity."""
        numeric_cols = [
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Protocol", "Flow Bytes/s", "Flow Packets/s",
        ]
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        # Replace infinity with column max (finite values only)
        for col in df.select_dtypes(include=[np.number]).columns:
            finite_max = df[col][np.isfinite(df[col])].max()
            if pd.notna(finite_max):
                df[col] = df[col].replace([np.inf, -np.inf], finite_max)

        return df

    def map_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map CICFlowMeter features to canonical 12-feature format."""
        df = self._clean_numeric(df.copy())

        # Drop rows with NaN in critical columns
        critical = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                     "Total Length of Fwd Packets", "Total Length of Bwd Packets",
                     "Protocol"]
        df = df.dropna(subset=[c for c in critical if c in df.columns])

        # Base features
        packet_count = (
            df["Total Fwd Packets"].fillna(0) + df["Total Backward Packets"].fillna(0)
        )
        byte_count = (
            df["Total Length of Fwd Packets"].fillna(0)
            + df["Total Length of Bwd Packets"].fillna(0)
        )
        # CIC stores duration in microseconds
        duration_sec = df["Flow Duration"].fillna(0) / 1_000_000.0

        # Derived rate features
        safe_duration = duration_sec.clip(lower=0.001)
        packets_per_second = packet_count / safe_duration
        bytes_per_second = byte_count / safe_duration

        # Average packet size
        safe_packets = packet_count.clip(lower=1)
        avg_packet_size = byte_count / safe_packets

        # Protocol mapping (already numeric in CIC-IDS2017)
        ip_proto = df["Protocol"].fillna(0).astype(int)

        # ICMP fields: CIC doesn't separate icmp_code/icmp_type directly,
        # so we approximate from protocol number
        icmp_code = pd.Series(0, index=df.index, dtype=int)
        icmp_type = pd.Series(0, index=df.index, dtype=int)
        icmp_mask = ip_proto == 1
        icmp_type = icmp_type.where(~icmp_mask, 8)  # Echo request for ICMP

        # Aggregate features: computed from destination IP groupings
        if "Destination IP" in df.columns:
            flows_to_dst = df.groupby("Destination IP")["Destination IP"].transform("count")
            if "Source IP" in df.columns:
                unique_sources_to_dst = df.groupby("Destination IP")["Source IP"].transform("nunique")
            else:
                unique_sources_to_dst = pd.Series(1, index=df.index)
        else:
            flows_to_dst = pd.Series(1, index=df.index)
            unique_sources_to_dst = pd.Series(1, index=df.index)

        # Flow creation rate: estimated from timestamp ordering
        if "Timestamp" in df.columns:
            try:
                timestamps = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True)
                df["_ts_epoch"] = timestamps.astype(np.int64) / 1e9
                # Rate = flows per second to same destination in a rolling window
                if "Destination IP" in df.columns:
                    df_sorted = df.sort_values("_ts_epoch")
                    # Approximate: count of flows in last 5 seconds to same dst
                    flow_creation_rate = (
                        df_sorted.groupby("Destination IP")["_ts_epoch"]
                        .transform(lambda x: x.diff().clip(lower=0.001).rdiv(1).rolling(5, min_periods=1).mean())
                    )
                    flow_creation_rate = flow_creation_rate.reindex(df.index).fillna(0)
                else:
                    flow_creation_rate = pd.Series(0, index=df.index)
                df = df.drop(columns=["_ts_epoch"])
            except Exception:
                flow_creation_rate = pd.Series(0, index=df.index)
        else:
            flow_creation_rate = pd.Series(0, index=df.index)

        # Get labels
        binary_labels, _ = self.get_labels(df)

        # Assemble canonical DataFrame
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

        # Final cleanup
        result = result.replace([np.inf, -np.inf], 0)
        result = result.dropna()

        return result

    def get_labels(self, df: pd.DataFrame) -> tuple:
        """Extract binary and multiclass labels.

        CIC-IDS2017 uses a 'Label' column with values like 'BENIGN',
        'DoS Hulk', 'DDoS', etc.
        """
        label_col = None
        for candidate in ["Label", " Label", "label"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col is None:
            raise ValueError(
                f"No label column found. Available columns: {list(df.columns)[:10]}..."
            )

        multiclass = df[label_col].astype(str).str.strip()
        binary = (multiclass != "BENIGN").astype(int)

        return binary, multiclass

    def get_citation(self) -> str:
        return """@inproceedings{sharafaldin2018toward,
  title={Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization},
  author={Sharafaldin, Iman and Lashkari, Arash Habibi and Ghorbani, Ali A.},
  booktitle={Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)},
  pages={108--116},
  year={2018},
  organization={SciTePress},
  doi={10.5220/0006639801080116}
}"""
