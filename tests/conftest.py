"""Shared pytest fixtures for SDN DDoS detection tests."""

import sys
import os

# Add project root to path so utilities/ imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
