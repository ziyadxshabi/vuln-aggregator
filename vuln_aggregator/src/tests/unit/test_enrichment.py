"""Unit tests for the threat-intelligence enrichment pipeline."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.enrichment.cache import InMemoryTTLCache
from src.enrichment.cisa_kev import CISAKEVCatalog, _CACHE_KEY
from src.enrichment.epss import EPSSClient
from src.enrichment.exploit_intel import ExploitIntel
from src.enrichment.pipeline import EnrichmentPipeline


@pytest.mark.asyncio
async def test_cisa_kev_cache_hit() -> None:
    cache = InMemoryTTLCache()
    await cache.set_json(_CACHE_KEY, ["CVE-2021-44228", "CVE-2020-1234"], 3600)
    catalog = CISAKEVCatalog(cache)

    assert await catalog.is_known_exploited("CVE-2021-44228") is True
    assert await catalog.is_known_exploited("CVE-9999-0000") is False


@pytest.mark.asyncio
async def test_cisa_kev_download_populates_cache() -> None:
    cache = InMemoryTTLCache()
    catalog = CISAKEVCatalog(cache)

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, list[dict[str, str]]]:
            return {"vulnerabilities": [{"cveID": "CVE-2023-9999"}]}

    class FakeClient:
        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str) -> FakeResponse:
            return FakeResponse()

    with patch("src.enrichment.cisa_kev.httpx.AsyncClient", return_value=FakeClient()):
        count = await catalog.refresh()

    assert count == 1
    assert await catalog.is_known_exploited("CVE-2023-9999") is True


@pytest.mark.asyncio
async def test_epss_client_parses_response() -> None:
    client = EPSSClient()

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, list[dict[str, str]]]:
            return {
                "data": [
                    {"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.999"},
                ]
            }

    class FakeClient:
        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, params: dict[str, str] | None = None) -> FakeResponse:
            return FakeResponse()

    with patch("src.enrichment.epss.httpx.AsyncClient", return_value=FakeClient()):
        result = await client.fetch({"CVE-2021-44228"})

    assert result["CVE-2021-44228"] == (0.975, 0.999)


@pytest.mark.asyncio
async def test_enrichment_pipeline_uses_cache_on_second_call() -> None:
    cache = InMemoryTTLCache()
    kev = AsyncMock()
    kev.load = AsyncMock()
    kev.is_known_exploited = AsyncMock(return_value=False)
    epss = AsyncMock()
    epss.fetch = AsyncMock(return_value={"CVE-2021-44228": (0.5, 0.9)})
    exploit = AsyncMock()
    exploit.fetch_one = AsyncMock(return_value=ExploitIntel(sources=["nvd"]))

    pipeline = EnrichmentPipeline(cache=cache, kev=kev, epss=epss, exploit=exploit)

    await pipeline.enrich({"CVE-2021-44228"})
    await pipeline.enrich({"CVE-2021-44228"})

    epss.fetch.assert_called_once()


@pytest.mark.asyncio
async def test_enrichment_pipeline_kev_sets_weaponized_flag() -> None:
    cache = InMemoryTTLCache()
    kev = AsyncMock()
    kev.load = AsyncMock()
    kev.is_known_exploited = AsyncMock(return_value=True)
    epss = AsyncMock()
    epss.fetch = AsyncMock(return_value={})
    exploit = AsyncMock()
    exploit.fetch_one = AsyncMock(return_value=ExploitIntel())

    pipeline = EnrichmentPipeline(cache=cache, kev=kev, epss=epss, exploit=exploit)

    result = await pipeline.enrich({"CVE-2021-44228"})

    assert result["CVE-2021-44228"].is_known_exploited is True
    assert result["CVE-2021-44228"].has_weaponized_exploit is True
