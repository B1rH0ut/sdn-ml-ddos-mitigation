"""REST API bearer token authentication middleware (audit 3.1).

Reads SDN_API_TOKEN from environment. If set, all REST API requests
must include the header: Authorization: Bearer <token>

If SDN_API_TOKEN is not set, the middleware is a no-op (relies on
127.0.0.1 binding in ryu.conf for access control).
"""

import os
import hmac
import logging

from webob import Response

LOG = logging.getLogger(__name__)

# Read token once at import time
_API_TOKEN = os.environ.get('SDN_API_TOKEN', '')


class BearerTokenAuth:
    """WSGI middleware that enforces bearer token authentication."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        if not _API_TOKEN:
            # No token configured — pass through
            return self.app(environ, start_response)

        auth_header = environ.get('HTTP_AUTHORIZATION', '')

        if not auth_header.startswith('Bearer '):
            resp = Response(status=401, json_body={
                'error': 'Missing or invalid Authorization header. '
                         'Expected: Bearer <token>'
            })
            return resp(environ, start_response)

        provided_token = auth_header[7:]  # len('Bearer ') == 7

        if not hmac.compare_digest(provided_token, _API_TOKEN):
            resp = Response(status=401, json_body={
                'error': 'Invalid API token'
            })
            LOG.warning("REST API: invalid token from %s",
                        environ.get('REMOTE_ADDR', 'unknown'))
            return resp(environ, start_response)

        return self.app(environ, start_response)
