"""Dataset adapters for mapping real-world datasets to canonical features."""

from .base_adapter import DatasetAdapter
from .cic_ids2017_adapter import CICIDS2017Adapter
from .cic_ddos2019_adapter import CICDDoS2019Adapter
from .unsw_nb15_adapter import UNSWNB15Adapter

ADAPTER_REGISTRY = {
    "cic-ids2017": CICIDS2017Adapter,
    "cic-ddos2019": CICDDoS2019Adapter,
    "unsw-nb15": UNSWNB15Adapter,
}

__all__ = [
    "DatasetAdapter",
    "CICIDS2017Adapter",
    "CICDDoS2019Adapter",
    "UNSWNB15Adapter",
    "ADAPTER_REGISTRY",
]
