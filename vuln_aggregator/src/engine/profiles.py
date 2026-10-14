"""Scan intensity presets for home LANs versus larger internal ranges."""

from __future__ import annotations

from dataclasses import dataclass

from src.models.enums import ScanProfile


@dataclass(frozen=True, slots=True)
class ScanProfileConfig:
    """Parameters consumed by nmap/Nuclei connectors and scope caps."""

    name: ScanProfile
    max_hosts: int
    nmap_top_ports: int
    nmap_timing: str
    nmap_host_timeout: str
    nmap_max_retries: int
    nuclei_rate_limit: int
    nuclei_concurrency: int
    include_default_login: bool
    chunk_prefix: int | None


_PROFILES: dict[ScanProfile, ScanProfileConfig] = {
    ScanProfile.HOME: ScanProfileConfig(
        name=ScanProfile.HOME,
        max_hosts=256,
        nmap_top_ports=1000,
        nmap_timing="T3",
        nmap_host_timeout="30s",
        nmap_max_retries=2,
        nuclei_rate_limit=50,
        nuclei_concurrency=10,
        include_default_login=False,
        chunk_prefix=None,
    ),
    ScanProfile.THOROUGH: ScanProfileConfig(
        name=ScanProfile.THOROUGH,
        max_hosts=1024,
        nmap_top_ports=1000,
        nmap_timing="T3",
        nmap_host_timeout="45s",
        nmap_max_retries=2,
        nuclei_rate_limit=40,
        nuclei_concurrency=8,
        include_default_login=True,
        chunk_prefix=None,
    ),
    ScanProfile.LARGE: ScanProfileConfig(
        name=ScanProfile.LARGE,
        max_hosts=4096,
        nmap_top_ports=100,
        nmap_timing="T3",
        nmap_host_timeout="20s",
        nmap_max_retries=1,
        nuclei_rate_limit=25,
        nuclei_concurrency=6,
        include_default_login=False,
        chunk_prefix=24,
    ),
}


def get_profile(name: ScanProfile | str) -> ScanProfileConfig:
    """Return the config for a profile name (enum or string)."""
    profile = name if isinstance(name, ScanProfile) else ScanProfile(str(name).lower())
    return _PROFILES[profile]
