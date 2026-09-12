"""Defensive target classification, allowlisting, and host-cap enforcement.

Network scans are restricted to an explicit CIDR allowlist (RFC1918 + loopback
by default). Public internet shotgun scans are rejected unless the operator
adds the range to ``SCAN_ALLOWLIST``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from src.engine.profiles import ScanProfileConfig
from src.models.enums import TargetKind

DEFAULT_ALLOWLIST: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "::1/128",
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_LOCAL_HOSTNAME_RE = re.compile(r"^(localhost|.*\.local)$", re.IGNORECASE)


class ScopeError(ValueError):
    """Target is outside the allowlist or exceeds the profile host cap."""


@dataclass(frozen=True, slots=True)
class PreparedScan:
    """Targets split by kind after scope validation."""

    network_targets: list[str] = field(default_factory=list)
    image_targets: list[str] = field(default_factory=list)
    nmap_chunks: list[str] = field(default_factory=list)
    estimated_hosts: int = 0


def parse_allowlist(
    entries: list[str] | tuple[str, ...] | None,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse CIDR strings into networks; fall back to the defensive default."""
    raw_entries = entries if entries else DEFAULT_ALLOWLIST
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in raw_entries:
        item = str(raw).strip()
        if not item:
            continue
        networks.append(ipaddress.ip_network(item, strict=False))
    if not networks:
        return [ipaddress.ip_network(item, strict=False) for item in DEFAULT_ALLOWLIST]
    return networks


def classify_target(raw: str) -> TargetKind:
    """Classify a user-supplied target as a network locator or a container image."""
    target = raw.strip()
    if not target:
        raise ScopeError("Empty scan target")

    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return TargetKind.NETWORK
        except ValueError:
            if ":" in target:
                return TargetKind.IMAGE
            return TargetKind.NETWORK

    try:
        ipaddress.ip_address(target)
        return TargetKind.NETWORK
    except ValueError:
        pass

    if ":" in target and not target.startswith("["):
        host, _, port = target.rpartition(":")
        if port.isdigit():
            host_clean = host.strip("[]")
            try:
                ipaddress.ip_address(host_clean)
                return TargetKind.NETWORK
            except ValueError:
                if _IPV4_RE.match(host_clean):
                    return TargetKind.NETWORK
        return TargetKind.IMAGE

    return TargetKind.NETWORK


def estimated_hosts(target: str) -> int:
    """Return the address count for a CIDR, or 1 for a single host/name."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
        return int(network.num_addresses)
    except ValueError:
        return 1


def chunk_network_targets(targets: list[str], profile: ScanProfileConfig) -> list[str]:
    """Split oversized CIDRs into prefix-sized chunks when the profile asks for it."""
    if profile.chunk_prefix is None:
        return list(targets)
    chunks: list[str] = []
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            chunks.append(target)
            continue
        if network.prefixlen >= profile.chunk_prefix:
            chunks.append(str(network))
            continue
        chunks.extend(str(subnet) for subnet in network.subnets(new_prefix=profile.chunk_prefix))
    return chunks


def _normalize_network_target(target: str) -> str:
    """Strip a trailing :port from IPv4/hostname targets so nmap receives a host/CIDR."""
    if "/" in target:
        return target
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        if port.isdigit():
            return host.strip("[]") or target
    return target


def _as_network(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        pass
    try:
        addr = ipaddress.ip_address(target.strip())
        return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
    except ValueError:
        return None


def _is_allowed(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    allowlist: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    for allowed in allowlist:
        if network.version != allowed.version:
            continue
        if network.subnet_of(allowed) or network == allowed:
            return True
    return False


def assert_network_in_allowlist(
    target: str,
    allowlist: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> None:
    """Raise :class:`ScopeError` if ``target`` is not fully inside the allowlist."""
    network = _as_network(target)
    if network is not None:
        if not _is_allowed(network, allowlist):
            raise ScopeError(
                f"Target {target!r} is outside the scan allowlist. "
                "Only RFC1918/loopback ranges are allowed by default; add public "
                "ranges you own to SCAN_ALLOWLIST."
            )
        return

    if _LOCAL_HOSTNAME_RE.match(target.strip()):
        return

    raise ScopeError(
        f"Hostname {target!r} cannot be verified against the CIDR allowlist. "
        "Use an IP or CIDR in SCAN_ALLOWLIST (private ranges by default)."
    )


def prepare_scan(
    targets: list[str],
    profile: ScanProfileConfig,
    allowlist_entries: list[str] | tuple[str, ...] | None = None,
) -> PreparedScan:
    """Classify, allowlist, cap, and (for large scans) chunk targets."""
    if not targets:
        raise ScopeError("At least one scan target is required")

    allowlist = parse_allowlist(allowlist_entries)
    network_targets: list[str] = []
    image_targets: list[str] = []

    for raw in targets:
        kind = classify_target(raw)
        cleaned = raw.strip()
        if kind is TargetKind.IMAGE:
            image_targets.append(cleaned)
        else:
            cleaned = _normalize_network_target(cleaned)
            assert_network_in_allowlist(cleaned, allowlist)
            network_targets.append(cleaned)

    host_count = sum(estimated_hosts(t) for t in network_targets)
    if host_count > profile.max_hosts:
        raise ScopeError(
            f"Estimated {host_count} addresses exceeds the {profile.name.value} "
            f"profile cap of {profile.max_hosts}. Use a smaller CIDR or a larger profile."
        )

    chunks = chunk_network_targets(network_targets, profile)
    return PreparedScan(
        network_targets=network_targets,
        image_targets=image_targets,
        nmap_chunks=chunks,
        estimated_hosts=host_count,
    )
