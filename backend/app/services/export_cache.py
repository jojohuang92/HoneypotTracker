"""Small in-process TTL cache for public feed bodies.

The IOC feeds are aggregate queries over the whole window, and their natural
consumers — pfSense, OPNsense, Pi-hole, fail2ban — poll on a timer from many
hosts at once. Without a cache every subscriber costs a full aggregate; with
one the cost is a single rebuild per ``ttl`` regardless of subscriber count.

Entries carry the body bytes and an ETag so the router can answer
``If-None-Match`` with 304 and skip the transfer as well as the query.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class CachedBody:
    body: bytes
    etag: str
    built_at: datetime
    expires_monotonic: float


class ExportCache:
    def __init__(self) -> None:
        self._entries: dict[tuple, CachedBody] = {}
        self._lock = threading.Lock()

    def get(self, key: tuple) -> CachedBody | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if time.monotonic() >= entry.expires_monotonic:
                del self._entries[key]
                return None
            return entry

    def put(self, key: tuple, body: bytes, ttl: float,
            built_at: datetime | None = None) -> CachedBody:
        entry = CachedBody(
            body=body,
            etag=self.etag_for(body),
            built_at=built_at or datetime.utcnow(),
            expires_monotonic=time.monotonic() + ttl,
        )
        if ttl > 0:
            with self._lock:
                self._entries[key] = entry
        return entry

    def get_or_build(self, key: tuple, ttl: float, build) -> CachedBody:
        """Return the cached body, or build it under the lock's protection.

        The build runs outside the lock (it is a database query); two
        concurrent misses may both build, which is harmless.
        """
        entry = self.get(key)
        if entry is not None:
            return entry
        return self.put(key, build(), ttl)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    @staticmethod
    def etag_for(body: bytes) -> str:
        return '"' + hashlib.sha256(body).hexdigest()[:32] + '"'


export_cache = ExportCache()
