"""Tests for sdn_ddos_detector.utils.bounded_cache."""

import time

import pytest
from cachetools import TTLCache

from sdn_ddos_detector.utils.bounded_cache import (
    BoundedMACTable,
    BoundedIPCounter,
    BoundedFloodHistory,
    FlowStatsBuffer,
)


# ── BoundedMACTable ──────────────────────────────────────────────────────────

class TestBoundedMACTable:
    def test_set_and_get_item(self):
        table = BoundedMACTable(maxsize=10, ttl=60)
        table["aa:bb:cc:dd:ee:ff"] = 3
        assert table["aa:bb:cc:dd:ee:ff"] == 3

    def test_contains_check(self):
        table = BoundedMACTable(maxsize=10, ttl=60)
        table["key1"] = 1
        assert "key1" in table
        assert "missing" not in table

    def test_ttl_eviction(self):
        table = BoundedMACTable(maxsize=10, ttl=0.1)
        table["key1"] = 42
        assert "key1" in table
        time.sleep(0.2)
        assert "key1" not in table

    def test_maxsize_eviction(self):
        table = BoundedMACTable(maxsize=3, ttl=60)
        for i in range(5):
            table[f"key{i}"] = i
        assert len(table) <= 3

    def test_setdefault_creates_missing(self):
        table = BoundedMACTable(maxsize=10, ttl=60)
        result = table.setdefault("newkey", 99)
        assert result == 99
        assert table["newkey"] == 99

    def test_pop_removes_entry(self):
        table = BoundedMACTable(maxsize=10, ttl=60)
        table["k"] = 7
        val = table.pop("k")
        assert val == 7
        assert "k" not in table


# ── BoundedIPCounter ─────────────────────────────────────────────────────────

class TestBoundedIPCounter:
    def test_increment_starts_at_one(self):
        counter = BoundedIPCounter(maxsize=100, ttl=60)
        result = counter.increment("10.0.0.1")
        assert result == 1

    def test_increment_accumulates(self):
        counter = BoundedIPCounter(maxsize=100, ttl=60)
        counter.increment("10.0.0.1")
        counter.increment("10.0.0.1")
        result = counter.increment("10.0.0.1")
        assert result == 3

    def test_get_count_returns_zero_if_missing(self):
        counter = BoundedIPCounter(maxsize=100, ttl=60)
        assert counter.get_count("unknown") == 0


# ── BoundedFloodHistory ──────────────────────────────────────────────────────

class TestBoundedFloodHistory:
    def test_record_and_should_suppress(self):
        history = BoundedFloodHistory(maxsize=100)
        history.record("ff:ff:ff:ff:ff:ff", time.time())
        assert history.should_suppress("ff:ff:ff:ff:ff:ff", window=1.0) is True

    def test_should_suppress_false_after_window(self):
        history = BoundedFloodHistory(maxsize=100)
        history.record("key", time.time() - 2.0)  # 2 seconds ago
        assert history.should_suppress("key", window=1.0) is False


# ── FlowStatsBuffer ──────────────────────────────────────────────────────────

class TestFlowStatsBuffer:
    def test_append_and_get_previous(self):
        buf = FlowStatsBuffer(maxlen=10)
        assert buf.get_previous() is None
        buf.append({"packets": 100})
        assert buf.get_previous() == {"packets": 100}


# ── TTLCache for ARP cache (v3.1.0) ────────────────────────────────────────

class TestTTLCacheForArp:
    """Verify TTLCache behaves correctly as ARP cache replacement."""

    def test_arp_cache_ttl_eviction(self):
        cache = TTLCache(maxsize=1024, ttl=0.1)
        cache["10.0.0.1"] = "aa:bb:cc:dd:ee:ff"
        assert "10.0.0.1" in cache
        time.sleep(0.2)
        assert "10.0.0.1" not in cache

    def test_arp_cache_maxsize_bounded(self):
        cache = TTLCache(maxsize=3, ttl=60)
        for i in range(10):
            cache[f"10.0.0.{i}"] = f"mac_{i}"
        assert len(cache) <= 3
