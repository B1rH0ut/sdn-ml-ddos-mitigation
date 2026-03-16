"""
Bounded data structures for in-memory controller state.

Prevents OOM by capping the size of MAC tables, IP counters,
flood history, and flow stats buffers using TTLCache/LRUCache
from cachetools and collections.deque.

Audit findings addressed:
    - 6.3: _flood_history grows unbounded during MAC storms
    - 7.1: In-memory state (mac_to_port, blocked_ips, etc.) grows until OOM
"""

from __future__ import annotations

import collections
import time
from typing import Any

from cachetools import TTLCache, LRUCache


class BoundedMACTable:
    """
    Bounded MAC address table with TTL-based eviction.

    Wraps cachetools.TTLCache to provide automatic eviction of stale
    MAC entries and a hard cap on table size.

    Used for: mac_to_port, _port_macs
    """

    def __init__(self, maxsize: int = 4096, ttl: float = 120) -> None:
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    def __getitem__(self, key: Any) -> Any:
        return self._cache[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self._cache[key] = value

    def __contains__(self, key: object) -> bool:
        return key in self._cache

    def get(self, key: Any, default: Any = None) -> Any:
        return self._cache.get(key, default)

    def setdefault(self, key: Any, default: Any = None) -> Any:
        if key not in self._cache:
            self._cache[key] = default
        return self._cache[key]

    def items(self) -> Any:
        return self._cache.items()

    def keys(self) -> Any:
        return self._cache.keys()

    def pop(self, key: Any, *args: Any) -> Any:
        return self._cache.pop(key, *args)

    def __delitem__(self, key: Any) -> None:
        del self._cache[key]

    def __len__(self) -> int:
        return len(self._cache)


class BoundedIPCounter:
    """
    Bounded per-IP rate counter with TTL-based eviction.

    Wraps cachetools.TTLCache to track per-key counts with
    automatic expiry. Used for per-IP rate tracking and blocked_ips.
    """

    def __init__(self, maxsize: int = 10000, ttl: float = 300) -> None:
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    def increment(self, key: Any) -> int:
        """Increment counter for key, initializing to 0 if absent."""
        current = self._cache.get(key, 0)
        self._cache[key] = current + 1
        return self._cache[key]

    def get_count(self, key: Any) -> int:
        """Get current count for key (0 if absent or expired)."""
        return self._cache.get(key, 0)

    def __contains__(self, key: object) -> bool:
        return key in self._cache

    def __getitem__(self, key: Any) -> Any:
        return self._cache[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self._cache[key] = value

    def get(self, key: Any, default: Any = None) -> Any:
        return self._cache.get(key, default)

    def pop(self, key: Any, *args: Any) -> Any:
        return self._cache.pop(key, *args)

    def items(self) -> Any:
        return self._cache.items()

    def __len__(self) -> int:
        return len(self._cache)


class BoundedFloodHistory:
    """
    Bounded flood suppression history with LRU eviction.

    Wraps cachetools.LRUCache to track recent flood events.
    When the cache is full, the least-recently-used entry is evicted.
    """

    def __init__(self, maxsize: int = 512) -> None:
        self._cache: LRUCache = LRUCache(maxsize=maxsize)

    def record(self, key: Any, timestamp: float) -> None:
        """Record a flood event at the given timestamp."""
        self._cache[key] = timestamp

    def should_suppress(self, key: Any, window: float = 1.0) -> bool:
        """Check if a flood for this key occurred within the suppression window."""
        last = self._cache.get(key)
        if last is None:
            return False
        return (time.time() - last) < window

    def __contains__(self, key: object) -> bool:
        return key in self._cache

    def __getitem__(self, key: Any) -> Any:
        return self._cache[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self._cache[key] = value

    def pop(self, key: Any, *args: Any) -> Any:
        return self._cache.pop(key, *args)

    def items(self) -> Any:
        return self._cache.items()

    def __len__(self) -> int:
        return len(self._cache)


class FlowStatsBuffer:
    """
    Fixed-size buffer for per-switch previous flow statistics.

    Wraps collections.deque with a maximum length. When full,
    the oldest entry is automatically discarded.
    """

    def __init__(self, maxlen: int = 100) -> None:
        self._buffer: collections.deque = collections.deque(maxlen=maxlen)

    def append(self, stats: dict) -> None:
        """Append a stats snapshot, evicting the oldest if full."""
        self._buffer.append(stats)

    def get_previous(self) -> dict | None:
        """Get the most recent stats snapshot, or None if empty."""
        if self._buffer:
            return self._buffer[-1]
        return None

    def __len__(self) -> int:
        return len(self._buffer)
