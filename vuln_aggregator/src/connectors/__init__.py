"""Scanner ingestion adapters."""

from src.connectors.base import BaseScannerConnector
from src.connectors.gvm import GVMConnector
from src.connectors.nessus import NessusConnector
from src.connectors.trivy import TrivyConnector

#: Registry mapping scanner name -> connector class.
CONNECTOR_REGISTRY: dict[str, type[BaseScannerConnector]] = {
    GVMConnector.scanner_name: GVMConnector,
    NessusConnector.scanner_name: NessusConnector,
    TrivyConnector.scanner_name: TrivyConnector,
}

__all__ = [
    "CONNECTOR_REGISTRY",
    "BaseScannerConnector",
    "GVMConnector",
    "NessusConnector",
    "TrivyConnector",
]
