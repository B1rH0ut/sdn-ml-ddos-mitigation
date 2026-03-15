"""Tests for standalone classes/functions in ddos_controller.py.

Does NOT instantiate DDoSDetectionController (which requires Ryu runtime).
Tests PacketInRateLimiter, FloodRateLimiter, and _verify_model_integrity.

Mocks out Ryu imports at the module level so the controller module can be
imported without the full Ryu framework installed.
"""

import hashlib
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest


# ── Mock Ryu framework before importing ddos_controller ──────────────────────

def _setup_ryu_mocks():
    """Install mock Ryu modules so ddos_controller can be imported."""
    mock_modules = {}

    # ryu.base
    mock_modules["ryu"] = MagicMock()
    mock_modules["ryu.base"] = MagicMock()
    mock_modules["ryu.base.app_manager"] = MagicMock()
    mock_modules["ryu.controller"] = MagicMock()
    mock_modules["ryu.controller.ofp_event"] = MagicMock()
    mock_modules["ryu.controller.handler"] = MagicMock()
    mock_modules["ryu.ofproto"] = MagicMock()
    mock_modules["ryu.ofproto.ofproto_v1_3"] = MagicMock()
    mock_modules["ryu.lib"] = MagicMock()
    mock_modules["ryu.lib.hub"] = MagicMock()
    mock_modules["ryu.lib.packet"] = MagicMock()
    mock_modules["ryu.lib.packet.packet"] = MagicMock()
    mock_modules["ryu.lib.packet.ethernet"] = MagicMock()
    mock_modules["ryu.lib.packet.arp"] = MagicMock()
    mock_modules["ryu.lib.packet.ipv4"] = MagicMock()

    # ryu.cfg — needs CONF with register_opts and attribute access
    ryu_cfg = MagicMock()
    ryu_cfg.CONF = MagicMock()
    ryu_cfg.CONF.packet_in_rate_limit = 100
    ryu_cfg.IntOpt = MagicMock()
    ryu_cfg.FloatOpt = MagicMock()
    mock_modules["ryu.cfg"] = ryu_cfg

    for mod_name, mock_mod in mock_modules.items():
        if mod_name not in sys.modules:
            sys.modules[mod_name] = mock_mod


# Only install mocks if ryu is not actually available
try:
    import ryu  # noqa: F401
except ImportError:
    _setup_ryu_mocks()

from sdn_ddos_detector.controller.ddos_controller import (
    PacketInRateLimiter,
    FloodRateLimiter,
    _verify_model_integrity,
)


# ── PacketInRateLimiter ──────────────────────────────────────────────────────

class TestPacketInRateLimiter:
    def test_allows_under_limit(self):
        limiter = PacketInRateLimiter(rate_limit=5, window_sec=1.0)
        for _ in range(5):
            assert limiter.allow(dpid=1) is True

    def test_blocks_over_limit(self):
        limiter = PacketInRateLimiter(rate_limit=5, window_sec=1.0)
        for _ in range(5):
            limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False

    def test_window_reset_allows_again(self):
        limiter = PacketInRateLimiter(rate_limit=2, window_sec=0.1)
        limiter.allow(dpid=1)
        limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False
        time.sleep(0.15)
        assert limiter.allow(dpid=1) is True

    def test_independent_per_dpid(self):
        limiter = PacketInRateLimiter(rate_limit=2, window_sec=1.0)
        limiter.allow(dpid=1)
        limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False
        # dpid=2 should still be allowed
        assert limiter.allow(dpid=2) is True


# ── FloodRateLimiter ─────────────────────────────────────────────────────────

class TestFloodRateLimiter:
    def test_allows_under_limit(self):
        limiter = FloodRateLimiter(rate_limit=5, window_sec=1.0)
        for _ in range(5):
            assert limiter.allow(dpid=1) is True

    def test_blocks_over_limit(self):
        limiter = FloodRateLimiter(rate_limit=5, window_sec=1.0)
        for _ in range(5):
            limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False

    def test_independent_per_dpid(self):
        limiter = FloodRateLimiter(rate_limit=1, window_sec=1.0)
        limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False
        assert limiter.allow(dpid=2) is True


# ── _verify_model_integrity ──────────────────────────────────────────────────

class TestVerifyModelIntegrity:
    def test_returns_false_if_hash_file_missing(self, tmp_path, mock_logger):
        model_file = tmp_path / "flow_model.pkl"
        model_file.write_bytes(b"fake model data")
        result = _verify_model_integrity(
            str(model_file), str(tmp_path / "nonexistent"), mock_logger
        )
        assert result is False
        mock_logger.critical.assert_called()

    def test_returns_false_if_hash_mismatch(self, tmp_path, mock_logger):
        model_file = tmp_path / "flow_model.pkl"
        model_file.write_bytes(b"real model data")

        # Write hash file with wrong hash
        hash_file = tmp_path / "model_checksums.hmac"
        hash_file.write_text(json.dumps({"flow_model.pkl": "deadbeef" * 8}))

        result = _verify_model_integrity(str(model_file), str(tmp_path), mock_logger)
        assert result is False

    def test_returns_true_for_valid_sha256(self, tmp_path, mock_logger):
        model_data = b"valid model content"
        model_file = tmp_path / "flow_model.pkl"
        model_file.write_bytes(model_data)

        expected_hash = hashlib.sha256(model_data).hexdigest()
        hash_file = tmp_path / "model_checksums.hmac"
        hash_file.write_text(json.dumps({"flow_model.pkl": expected_hash}))

        with patch.dict(os.environ, {"SDN_MODEL_HMAC_KEY": ""}, clear=False):
            result = _verify_model_integrity(
                str(model_file), str(tmp_path), mock_logger
            )
        assert result is True

    def test_returns_true_for_valid_hmac(self, tmp_path, mock_logger):
        import hmac as hmac_mod

        model_data = b"hmac protected model"
        model_file = tmp_path / "flow_model.pkl"
        model_file.write_bytes(model_data)

        hmac_key = b"test-secret-key"
        expected_hash = hmac_mod.new(
            hmac_key, model_data, hashlib.sha256
        ).hexdigest()

        hash_file = tmp_path / "model_checksums.hmac"
        hash_file.write_text(json.dumps({"flow_model.pkl": expected_hash}))

        with patch.dict(
            os.environ, {"SDN_MODEL_HMAC_KEY": "test-secret-key"}, clear=False
        ):
            result = _verify_model_integrity(
                str(model_file), str(tmp_path), mock_logger
            )
        assert result is True
