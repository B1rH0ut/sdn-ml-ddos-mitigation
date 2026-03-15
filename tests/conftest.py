"""Shared pytest fixtures for SDN DDoS detection tests."""

import logging
from unittest.mock import MagicMock

import numpy as np
import pytest


@pytest.fixture
def sample_flow_stats():
    """Normal traffic flow stats dict."""
    return {
        "duration_sec": 10,
        "packet_count": 100,
        "byte_count": 50000,
        "ip_proto": 6,
        "icmp_code": 0,
        "icmp_type": 0,
    }


@pytest.fixture
def attack_flow_stats():
    """Attack traffic flow stats dict."""
    return {
        "duration_sec": 5,
        "packet_count": 50000,
        "byte_count": 3000000,
        "ip_proto": 1,
        "icmp_code": 0,
        "icmp_type": 8,
    }


@pytest.fixture
def normal_feature_vector():
    """Normal traffic feature vector, shape (1, 12)."""
    return np.array([[
        10.0,     # flow_duration_sec
        100.0,    # packet_count
        50000.0,  # byte_count
        10.0,     # packet_count_per_second
        5000.0,   # byte_count_per_second
        500.0,    # avg_packet_size
        6.0,      # ip_proto (TCP)
        0.0,      # icmp_code
        0.0,      # icmp_type
        5.0,      # flows_to_dst
        3.0,      # unique_sources_to_dst
        1.0,      # flow_creation_rate
    ]])


@pytest.fixture
def attack_feature_vector():
    """Attack traffic feature vector, shape (1, 12)."""
    return np.array([[
        2.0,          # flow_duration_sec
        50000.0,      # packet_count
        3000000.0,    # byte_count
        25000.0,      # packet_count_per_second
        1500000.0,    # byte_count_per_second
        60.0,         # avg_packet_size
        1.0,          # ip_proto (ICMP)
        0.0,          # icmp_code
        8.0,          # icmp_type
        500.0,        # flows_to_dst
        200.0,        # unique_sources_to_dst
        50.0,         # flow_creation_rate
    ]])


@pytest.fixture
def mock_logger():
    """Mock logger for testing code that logs."""
    return MagicMock(spec=logging.Logger)


@pytest.fixture
def mock_datapath():
    """Mock Ryu datapath object."""
    dp = MagicMock()
    dp.id = 1

    # ofproto constants
    dp.ofproto.OFPP_FLOOD = 0xFFFFFFFB
    dp.ofproto.OFPP_CONTROLLER = 0xFFFFFFFD
    dp.ofproto.OFPP_ANY = 0xFFFFFFFF
    dp.ofproto.OFPG_ANY = 0xFFFFFFFF
    dp.ofproto.OFPFC_ADD = 0
    dp.ofproto.OFP_NO_BUFFER = 0xFFFFFFFF

    # ofproto_parser mocks
    dp.ofproto_parser.OFPMatch = MagicMock()
    dp.ofproto_parser.OFPFlowMod = MagicMock()
    dp.ofproto_parser.OFPActionOutput = MagicMock()

    dp.send_msg = MagicMock()

    return dp
