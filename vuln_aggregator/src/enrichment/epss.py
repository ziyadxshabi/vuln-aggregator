"""FIRST EPSS (Exploit Prediction Scoring System) client."""

from __future__ import annotations

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.config import Settings, get_settings

# The FIRST API accepts a comma separated list of CVEs; keep batches modest.
_BATCH_SIZE = 100


class EPSSClient:
    """Fetches EPSS probabilities and percentiles for CVEs."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, max=30), reraise=True)
    async def _fetch_batch(self, client: httpx.AsyncClient, cves: list[str]) -> dict[str, tuple[float, float]]:
        resp = await client.get(self._settings.epss_api_url, params={"cve": ",".join(cves)})
        resp.raise_for_status()
        out: dict[str, tuple[float, float]] = {}
        for item in resp.json().get("data", []):
            cve = str(item.get("cve", "")).upper()
            try:
                out[cve] = (float(item["epss"]), float(item["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
        return out

    async def fetch(self, cve_ids: set[str]) -> dict[str, tuple[float, float]]:
        """Return ``{cve: (epss_score, percentile)}`` for the requested CVEs."""
        cleaned = sorted({c.strip().upper() for c in cve_ids if c})
        if not cleaned:
            return {}
        results: dict[str, tuple[float, float]] = {}
        async with httpx.AsyncClient(timeout=self._settings.http_timeout_seconds) as client:
            for start in range(0, len(cleaned), _BATCH_SIZE):
                batch = cleaned[start : start + _BATCH_SIZE]
                results.update(await self._fetch_batch(client, batch))
        return results
