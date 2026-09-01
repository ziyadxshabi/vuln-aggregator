"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""

from __future__ import annotations

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.config import Settings, get_settings
from src.models.ports import CachePort

_CACHE_KEY = "cisa-kev:catalog"


class CISAKEVCatalog:
    """Downloads and caches the CISA KEV catalog; answers membership queries."""

    def __init__(self, cache: CachePort, settings: Settings | None = None) -> None:
        self._cache = cache
        self._settings = settings or get_settings()
        self._cve_ids: set[str] = set()
        self._loaded = False

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, max=30), reraise=True)
    async def _download(self) -> list[str]:
        async with httpx.AsyncClient(timeout=self._settings.http_timeout_seconds) as client:
            resp = await client.get(self._settings.cisa_kev_url)
            resp.raise_for_status()
            payload = resp.json()
        return [
            str(item["cveID"]).strip().upper()
            for item in payload.get("vulnerabilities", [])
            if item.get("cveID")
        ]

    async def refresh(self) -> int:
        """Force a re-download and repopulate the cache. Returns entry count."""
        cve_ids = await self._download()
        await self._cache.set_json(_CACHE_KEY, cve_ids, self._settings.kev_cache_ttl_seconds)
        self._cve_ids = set(cve_ids)
        self._loaded = True
        return len(self._cve_ids)

    async def load(self) -> None:
        """Populate from cache if available, otherwise download."""
        if self._loaded:
            return
        cached = await self._cache.get_json(_CACHE_KEY)
        if cached is not None:
            self._cve_ids = {str(cve).upper() for cve in cached}
            self._loaded = True
            return
        await self.refresh()

    async def is_known_exploited(self, cve_id: str) -> bool:
        await self.load()
        return cve_id.strip().upper() in self._cve_ids
