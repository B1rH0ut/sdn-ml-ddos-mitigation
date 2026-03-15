"""Tests for sdn_ddos_detector.controller.api_auth."""

from unittest.mock import MagicMock, patch

import pytest

# Import the module so patch() can resolve the attribute
import sdn_ddos_detector.controller.api_auth as api_auth_mod
from sdn_ddos_detector.controller.api_auth import BearerTokenAuth


class TestBearerTokenAuth:
    def _mock_app(self):
        """Create a mock WSGI app."""
        app = MagicMock()
        app.return_value = [b"OK"]
        return app

    def _mock_start_response(self):
        return MagicMock()

    def test_passthrough_when_no_token(self):
        with patch.object(api_auth_mod, "_API_TOKEN", ""):
            app = self._mock_app()
            mw = BearerTokenAuth(app)
            environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/stats"}
            start_response = self._mock_start_response()
            mw(environ, start_response)
            app.assert_called_once_with(environ, start_response)

    def test_rejects_missing_auth_header(self):
        with patch.object(api_auth_mod, "_API_TOKEN", "secret"):
            app = self._mock_app()
            mw = BearerTokenAuth(app)
            environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/stats"}
            start_response = self._mock_start_response()
            mw(environ, start_response)
            app.assert_not_called()

    def test_accepts_valid_bearer_token(self):
        with patch.object(api_auth_mod, "_API_TOKEN", "my-token"):
            app = self._mock_app()
            mw = BearerTokenAuth(app)
            environ = {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/stats",
                "HTTP_AUTHORIZATION": "Bearer my-token",
            }
            start_response = self._mock_start_response()
            mw(environ, start_response)
            app.assert_called_once_with(environ, start_response)
