"""Abstract base class for dataset adapters.

Each adapter maps a real-world dataset's features to the canonical
12-feature format defined in feature_engineering.py.
"""

from abc import ABC, abstractmethod

import pandas as pd


class DatasetAdapter(ABC):
    """Base class for mapping external datasets to the canonical feature set."""

    @abstractmethod
    def load_raw(self, path: str) -> pd.DataFrame:
        """Load raw CSV files from the dataset directory.

        Args:
            path: Directory containing the raw CSV files.

        Returns:
            Combined DataFrame with all raw records.
        """

    @abstractmethod
    def map_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map raw features to the canonical 12-feature format.

        Args:
            df: Raw DataFrame from load_raw().

        Returns:
            DataFrame with columns matching FEATURE_NAMES + 'label'.
        """

    @abstractmethod
    def get_labels(self, df: pd.DataFrame) -> tuple:
        """Extract binary and multiclass labels from raw data.

        Args:
            df: Raw DataFrame from load_raw().

        Returns:
            Tuple of (binary_labels, multiclass_labels) as pd.Series.
            binary_labels: 0 = normal, 1 = attack.
            multiclass_labels: original attack type strings.
        """

    @abstractmethod
    def get_citation(self) -> str:
        """Return BibTeX citation string for this dataset."""

    def load_and_map(self, path: str) -> pd.DataFrame:
        """Convenience method: load raw data and map to canonical features.

        Args:
            path: Directory containing the raw CSV files.

        Returns:
            DataFrame with canonical 12 features + 'label' column.
        """
        raw_df = self.load_raw(path)
        return self.map_features(raw_df)
