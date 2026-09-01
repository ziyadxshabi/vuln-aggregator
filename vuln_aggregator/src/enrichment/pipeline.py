"""Async multi-feed enrichment pipeline implementing :class:`ThreatIntelPort`.

For a set of CVEs it combines:

* CISA KEV .... active-exploitation flag
* FIRST EPSS .. exploitation probability + percentile
* NVD/Vulners  CVSS v3.1 vector + weaponized-exploit signal

A TTL cache (per CVE) prevents redundant API calls when the same CVE appears on
many assets across many scans.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict

from src.config import Settings, get_settings
from src.enrichment.cache import InMemoryTTLCache
from src.enrichment.cisa_kev import CISAKEVCatalog
from src.enrichment.epss import EPSSClient
from src.enrichment.exploit_intel import ExploitIntelClient
from src.models.enrichment import EnrichmentData
from src.models.ports import CachePort

_MAX_CONCURRENCY = 8


class EnrichmentPipeline:
    """Coordinates all threat-intel feeds behind a single cache-aware call."""

    def __init__(
        self,
        cache: CachePort,
        kev: CISAKEVCatalog,
        epss: EPSSClient,
        exploit: ExploitIntelClient,
        settings: Settings | None = None,
    ) -> None:
        self._cache = cache
        self._kev = kev
        self._epss = epss
        self._exploit = exploit
        self._settings = settings or get_settings()
        self._semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)

    def _cache_key(self, cve_id: str) -> str:
        return f"enrichment:{cve_id.upper()}"

    async def enrich(self, cve_ids: set[str]) -> dict[str, EnrichmentData]:
        cleaned = {c.strip().upper() for c in cve_ids if c}
        if not cleaned:
            return {}

        results: dict[str, EnrichmentData] = {}
        uncached: set[str] = set()
        for cve in cleaned:
            cached = await self._cache.get_json(self._cache_key(cve))
            if cached is not None:
                results[cve] = EnrichmentData(**cached)
            else:
                uncached.add(cve)

        if not uncached:
            return results

        await self._kev.load()
        epss_map = await self._epss.fetch(uncached)

        async def _resolve(cve: str) -> tuple[str, EnrichmentData]:
            async with self._semaphore:
                data = EnrichmentData(cve_id=cve)
                if cve in epss_map:
                    data.epss_score, data.epss_percentile = epss_map[cve]
                    data.sources.append("first-epss")
                if await self._kev.is_known_exploited(cve):
                    data.is_known_exploited = True
                    data.has_weaponized_exploit = True
                    data.sources.append("cisa-kev")
                intel = await self._exploit.fetch_one(cve)
                data.cvss_v3_score = intel.cvss_v3_score
                data.cvss_v3_vector = intel.cvss_v3_vector
                data.has_weaponized_exploit = (
                    data.has_weaponized_exploit or intel.has_weaponized_exploit
                )
                for source in intel.sources or []:
                    if source not in data.sources:
                        data.sources.append(source)
                return cve, data

        resolved = await asyncio.gather(*(_resolve(cve) for cve in uncached))
        for cve, data in resolved:
            await self._cache.set_json(
                self._cache_key(cve),
                asdict(data),
                self._settings.enrichment_cache_ttl_seconds,
            )
            results[cve] = data

        return results


def build_default_pipeline(
    settings: Settings | None = None,
    cache: CachePort | None = None,
) -> EnrichmentPipeline:
    """Assemble a pipeline with the default feed clients."""
    resolved = settings or get_settings()
    cache_impl = cache or InMemoryTTLCache()
    return EnrichmentPipeline(
        cache=cache_impl,
        kev=CISAKEVCatalog(cache_impl, resolved),
        epss=EPSSClient(resolved),
        exploit=ExploitIntelClient(resolved),
        settings=resolved,
    )
