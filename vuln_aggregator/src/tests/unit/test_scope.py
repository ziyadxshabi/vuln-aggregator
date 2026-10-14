"""Unit tests for defensive scope classification, allowlisting, and host caps."""

from __future__ import annotations

import pytest

from src.engine.profiles import get_profile
from src.engine.scope import (
    ScopeError,
    classify_target,
    estimated_hosts,
    prepare_scan,
)
from src.models.enums import TargetKind


def test_classify_image_refs() -> None:
    assert classify_target("nginx:1.19") is TargetKind.IMAGE
    assert classify_target("ghcr.io/org/app:1.0") is TargetKind.IMAGE
    assert classify_target("python:3.9") is TargetKind.IMAGE


def test_classify_network_targets() -> None:
    assert classify_target("192.168.1.0/24") is TargetKind.NETWORK
    assert classify_target("10.0.0.5") is TargetKind.NETWORK
    assert classify_target("127.0.0.1") is TargetKind.NETWORK
    assert classify_target("router.local") is TargetKind.NETWORK
    assert classify_target("10.0.0.5:8080") is TargetKind.NETWORK


def test_prepare_scan_allows_rfc1918() -> None:
    prepared = prepare_scan(["192.168.1.0/24"], get_profile("home"))
    assert prepared.network_targets == ["192.168.1.0/24"]
    assert prepared.image_targets == []
    assert prepared.estimated_hosts == 256


def test_prepare_scan_rejects_public_ip() -> None:
    with pytest.raises(ScopeError, match="allowlist"):
        prepare_scan(["8.8.8.8"], get_profile("home"))


def test_prepare_scan_rejects_unspecified() -> None:
    with pytest.raises(ScopeError, match="allowlist"):
        prepare_scan(["0.0.0.0/0"], get_profile("home"))


def test_home_profile_rejects_slash_16() -> None:
    with pytest.raises(ScopeError, match="cap"):
        prepare_scan(["10.0.0.0/16"], get_profile("home"))


def test_thorough_allows_1024_hosts() -> None:
    prepared = prepare_scan(["10.0.0.0/22"], get_profile("thorough"))
    assert prepared.estimated_hosts == 1024


def test_large_chunks_to_slash_24() -> None:
    # /22 = 1024 hosts, four /24 chunks
    prepared = prepare_scan(["10.0.0.0/22"], get_profile("large"))
    assert prepared.estimated_hosts == 1024
    assert len(prepared.nmap_chunks) == 4
    assert prepared.nmap_chunks[0].endswith("/24")


def test_large_rejects_over_cap() -> None:
    with pytest.raises(ScopeError, match="cap"):
        prepare_scan(["10.0.0.0/16"], get_profile("large"))


def test_mixed_image_and_network() -> None:
    prepared = prepare_scan(["192.168.0.10", "nginx:1.19"], get_profile("home"))
    assert prepared.network_targets == ["192.168.0.10"]
    assert prepared.image_targets == ["nginx:1.19"]


def test_localhost_is_allowed() -> None:
    prepared = prepare_scan(["127.0.0.1"], get_profile("home"))
    assert prepared.network_targets == ["127.0.0.1"]


def test_custom_allowlist_permits_public() -> None:
    prepared = prepare_scan(
        ["8.8.8.8"],
        get_profile("home"),
        allowlist_entries=["8.8.8.8/32"],
    )
    assert prepared.network_targets == ["8.8.8.8"]


def test_estimated_hosts_single_ip() -> None:
    assert estimated_hosts("10.1.2.3") == 1


def test_image_only_skips_allowlist() -> None:
    prepared = prepare_scan(["nginx:1.19"], get_profile("home"))
    assert prepared.image_targets == ["nginx:1.19"]
    assert prepared.network_targets == []


def test_strips_port_from_ipv4_target() -> None:
    prepared = prepare_scan(["10.0.0.5:8080"], get_profile("home"))
    assert prepared.network_targets == ["10.0.0.5"]
