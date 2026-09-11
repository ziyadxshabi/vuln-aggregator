"""Scanner ingestion adapters."""

from src.config import Settings
from src.connectors.base import BaseScannerConnector
from src.connectors.gvm import GVMConnector
from src.connectors.nessus import NessusConnector
from src.connectors.nmap import NmapConnector
from src.connectors.nuclei import NucleiConnector
from src.connectors.trivy import TrivyConnector

#: Registry mapping scanner name -> connector class.
CONNECTOR_REGISTRY: dict[str, type[BaseScannerConnector]] = {
    NmapConnector.scanner_name: NmapConnector,
    NucleiConnector.scanner_name: NucleiConnector,
    TrivyConnector.scanner_name: TrivyConnector,
    GVMConnector.scanner_name: GVMConnector,
    NessusConnector.scanner_name: NessusConnector,
}

DEFAULT_NETWORK_SCANNERS: tuple[str, ...] = ("nmap", "nuclei")
DEFAULT_IMAGE_SCANNERS: tuple[str, ...] = ("trivy",)
OPTIONAL_SCANNERS: frozenset[str] = frozenset({"gvm", "nessus"})


def scanner_is_ready(name: str, settings: Settings) -> bool:
    """Return True when a scanner can actually run with current settings."""
    if name == "gvm":
        return settings.gvm_enabled
    if name == "nessus":
        return bool(settings.nessus_access_key and settings.nessus_secret_key)
    return True


__all__ = [
    "CONNECTOR_REGISTRY",
    "DEFAULT_IMAGE_SCANNERS",
    "DEFAULT_NETWORK_SCANNERS",
    "OPTIONAL_SCANNERS",
    "BaseScannerConnector",
    "GVMConnector",
    "NessusConnector",
    "NmapConnector",
    "NucleiConnector",
    "TrivyConnector",
    "scanner_is_ready",
]
