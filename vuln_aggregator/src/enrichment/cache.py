"""TTL cache adapters implementing :class:`CachePort`.

``InMemoryTTLCache`` is dependency-free (great for tests and single-process
runs). ``RedisTTLCache`` shares state across API and worker processes.
"""

from __future__ import annotations

import json
import time
from typing import Any


class InMemoryTTLCache:
    """Process-local cache with per-key expiry."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[float, Any]] = {}

    async def get_json(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at < time.monotonic():
            self._store.pop(key, None)
            return None
        return value

    async def set_json(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._store[key] = (time.monotonic() + ttl_seconds, value)


class RedisTTLCache:
    """Redis-backed JSON cache using ``redis.asyncio``."""

    def __init__(self, redis_url: str, namespace: str = "vuln") -> None:
        from redis.asyncio import Redis

        self._redis: Any = Redis.from_url(redis_url, decode_responses=True)
        self._namespace = namespace

    def _key(self, key: str) -> str:
        return f"{self._namespace}:{key}"

    async def get_json(self, key: str) -> Any | None:
        raw = await self._redis.get(self._key(key))
        if raw is None:
            return None
        return json.loads(raw)

    async def set_json(self, key: str, value: Any, ttl_seconds: int) -> None:
        await self._redis.set(self._key(key), json.dumps(value), ex=ttl_seconds)

    async def aclose(self) -> None:
        await self._redis.aclose()
