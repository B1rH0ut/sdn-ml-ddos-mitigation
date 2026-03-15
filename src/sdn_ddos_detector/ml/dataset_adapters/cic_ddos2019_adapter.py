"""Adapter for CIC-DDoS2019 dataset.

Maps CICFlowMeter-V3 features to the canonical 12-feature format.
Supports 12+ DDoS attack types: DNS, NTP, LDAP, MSSQL, SNMP, SSDP,
UDP, SYN, TFTP, UDP-Lag, WebDDoS, NetBIOS.

Reference:
    Sharafaldin et al., "Developing Realistic Distributed Denial of Service
    (DDoS) Attack Dataset and Taxonomy", ICCST 2019.
"""

import glob
import os
import warnings

import numpy as np
import pandas as pd

from sdn_ddos_detector.ml.feature_engineering import FEATURE_NAMES
from .base_adapter import DatasetAdapter


class CICDDoS2019Adapter(DatasetAdapter):
    """Maps CIC-DDoS2019 CICFlowMeter-V3 output to canonical 12 features."""

    def load_raw(self, path: str) -> pd.DataFrame:
        """Load all CIC-DDoS2019 CSV files from a directory."""
        csv_files = sorted(glob.glob(os.path.join(path, "*.csv")))
        if not csv_files:
            raise FileNotFoundError(
                f"No CSV files found in {path}. "
                "Download from https://www.unb.ca/cic/datasets/ddos-2019.html"
            )

        dfs = []
        for f in csv_files:
            try:
                df = pd.read_csv(f, low_memory=False, encoding="utf-8")
                df.columns = df.columns.str.strip()
                dfs.append(df)
            except Exception as e:
                warnings.warn(f"Skipping {f}: {e}")

        if not dfs:
            raise ValueError(f"No valid CSV files could be loaded from {path}")

        return pd.concat(dfs, ignore_index=True)

    def _clean_numeric(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert string-typed numeric columns and handle infinity."""
        # CIC-DDoS2019 shares many column names with CIC-IDS2017
        # but may also use slightly different names
        for col in df.select_dtypes(include=["object"]).columns:
            if col.lower() not in ("label", "source ip", "destination ip",
                                    "timestamp", "src ip", "dst ip"):
                df[col] = pd.to_numeric(df[col], errors="coerce")

        for col in df.select_dtypes(include=[np.number]).columns:
            finite_max = df[col][np.isfinite(df[col])].max()
            if pd.notna(finite_max):
                df[col] = df[col].replace([np.inf, -np.inf], finite_max)

        return df

    def _find_column(self, df: pd.DataFrame, candidates: list) -> str | None:
        """Find the first matching column name from candidates."""
        for c in candidates:
            if c in df.columns:
                return c
        return None

    def map_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map CICFlowMeter-V3 features to canonical 12-feature format."""
        df = self._clean_numeric(df.copy())

        # Resolve column names (CIC-DDoS2019 may vary slightly)
        fwd_pkts_col = self._find_column(df, ["Total Fwd Packets", "Tot Fwd Pkts", "Fwd Packets"])
        bwd_pkts_col = self._find_column(df, ["Total Backward Packets", "Tot Bwd Pkts", "Bwd Packets"])
        fwd_len_col = self._find_column(df, ["Total Length of Fwd Packets", "TotLen Fwd Pkts", "Fwd Len"])
        bwd_len_col = self._find_column(df, ["Total Length of Bwd Packets", "TotLen Bwd Pkts", "Bwd Len"])
        duration_col = self._find_column(df, ["Flow Duration"])
        proto_col = self._find_column(df, ["Protocol"])
        dst_ip_col = self._find_column(df, ["Destination IP", "Dst IP"])
        src_ip_col = self._find_column(df, ["Source IP", "Src IP"])
        ts_col = self._find_column(df, ["Timestamp"])

        # Base features
        fwd_pkts = df[fwd_pkts_col].fillna(0) if fwd_pkts_col else pd.Series(0, index=df.index)
        bwd_pkts = df[bwd_pkts_col].fillna(0) if bwd_pkts_col else pd.Series(0, index=df.index)
        packet_count = fwd_pkts + bwd_pkts

        fwd_len = df[fwd_len_col].fillna(0) if fwd_len_col else pd.Series(0, index=df.index)
        bwd_len = df[bwd_len_col].fillna(0) if bwd_len_col else pd.Series(0, index=df.index)
        byte_count = fwd_len + bwd_len

        duration_sec = (df[duration_col].fillna(0) / 1_000_000.0) if duration_col else pd.Series(0, index=df.index)

        safe_duration = duration_sec.clip(lower=0.001)
        packets_per_second = packet_count / safe_duration
        bytes_per_second = byte_count / safe_duration
        avg_packet_size = byte_count / packet_count.clip(lower=1)

        ip_proto = df[proto_col].fillna(0).astype(int) if proto_col else pd.Series(0, index=df.index)
        icmp_code = pd.Series(0, index=df.index, dtype=int)
        icmp_type = pd.Series(0, index=df.index, dtype=int)
        if proto_col:
            icmp_type = icmp_type.where(ip_proto != 1, 8)

        # Aggregate features
        if dst_ip_col and dst_ip_col in df.columns:
            flows_to_dst = df.groupby(dst_ip_col)[dst_ip_col].transform("count")
            if src_ip_col and src_ip_col in df.columns:
                unique_sources_to_dst = df.groupby(dst_ip_col)[src_ip_col].transform("nunique")
            else:
                unique_sources_to_dst = pd.Series(1, index=df.index)
        else:
            flows_to_dst = pd.Series(1, index=df.index)
            unique_sources_to_dst = pd.Series(1, index=df.index)

        # Flow creation rate from timestamps
        if ts_col and ts_col in df.columns:
            try:
                timestamps = pd.to_datetime(df[ts_col], format="mixed", dayfirst=True)
                ts_epoch = timestamps.astype(np.int64) / 1e9
                if dst_ip_col and dst_ip_col in df.columns:
                    flow_creation_rate = (
                        ts_epoch.groupby(df[dst_ip_col])
                        .transform(lambda x: x.diff().clip(lower=0.001).rdiv(1).rolling(5, min_periods=1).mean())
                    ).fillna(0)
                else:
                    flow_creation_rate = pd.Series(0, index=df.index)
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

        CIC-DDoS2019 uses a 'Label' column. BENIGN → 0, all else → 1.
        """
        label_col = None
        for candidate in ["Label", " Label", "label"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col is None:
            raise ValueError(
                f"No label column found. Available: {list(df.columns)[:10]}..."
            )

        multiclass = df[label_col].astype(str).str.strip()
        binary = (multiclass != "BENIGN").astype(int)
        return binary, multiclass

    def get_citation(self) -> str:
        return """@inproceedings{sharafaldin2019developing,
  title={Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy},
  author={Sharafaldin, Iman and Lashkari, Arash Habibi and Sadeghzadeh, Saqib and Ghorbani, Ali A.},
  booktitle={Proceedings of the IEEE International Carnahan Conference on Security Technology (ICCST)},
  pages={1--8},
  year={2019},
  organization={IEEE},
  doi={10.1109/CCST.2019.8888419}
}"""
