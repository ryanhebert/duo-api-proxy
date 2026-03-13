"""
Shared test fixtures for the Duo Admin API Auth Proxy test suite.

Environment variables must be set BEFORE importing main.py because the module
validates PROXY_SESSION_SECRET and registers the OAuth client at import time.
The OIDC discovery fetch happens inside the FastAPI lifespan, which we intercept
with respx so tests never contact real Duo endpoints.
"""

import os
import sys
import json

# ---------------------------------------------------------------------------
# 1. Inject test environment variables BEFORE any import of main.py
#    These must be present at module-load time because main.py reads them
#    at the top level (e.g. PROXY_SESSION_SECRET validation, oauth.register).
# ---------------------------------------------------------------------------
_TEST_ENV = {
    "DUO_HOST": "api-test.duosecurity.com",
    "DUO_IKEY": "DITEST00000000000000",
    "DUO_SKEY": "test_secret_key_for_signing_only",
    "DUO_SSO_WELL_KNOWN_URL": "https://sso-test.duosecurity.com/.well-known/openid-configuration",
    "DUO_SSO_CLIENT_ID": "DICLIENT0000000000TEST",
    "DUO_SSO_CLIENT_SECRET": "test_client_secret_value",
    "PROXY_SESSION_SECRET": "test_session_secret_32_chars_long!!",
    "PROXY_ENABLE_DCR": "false",
    "PROXY_ENABLE_DOCS": "true",
}

for key, value in _TEST_ENV.items():
    os.environ.setdefault(key, value)

# Now it is safe to import the application module.
import pytest
import httpx
import respx
from httpx import ASGITransport

from main import app  # noqa: E402 — env vars must be set first


# ---------------------------------------------------------------------------
# 2. Realistic OIDC discovery document returned by the mock
# ---------------------------------------------------------------------------
@pytest.fixture()
def mock_duo_discovery() -> dict:
    """Return a realistic Duo SSO OIDC discovery document for testing."""
    return {
        "issuer": "https://sso-test.duosecurity.com",
        "authorization_endpoint": "https://sso-test.duosecurity.com/authorize",
        "token_endpoint": "https://sso-test.duosecurity.com/oauth/v1/token",
        "userinfo_endpoint": "https://sso-test.duosecurity.com/oauth/v1/userinfo",
        "jwks_uri": "https://sso-test.duosecurity.com/oauth/v1/keys",
        "registration_endpoint": "https://sso-test.duosecurity.com/oauth/v1/register",
        "scopes_supported": [
            "openid", "profile", "email",
            "duo-admin-api:read", "duo-admin-api:write",
        ],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }


# ---------------------------------------------------------------------------
# 3. App client fixture — spins up the ASGI app with mocked OIDC discovery
# ---------------------------------------------------------------------------
@pytest.fixture()
async def app_client(mock_duo_discovery):
    """
    Yield an httpx.AsyncClient wired to the FastAPI app via ASGITransport.

    The Duo OIDC discovery endpoint is intercepted by respx so the lifespan
    startup succeeds without network access.
    """
    well_known_url = os.environ["DUO_SSO_WELL_KNOWN_URL"]

    with respx.mock(assert_all_mocked=False) as router:
        # Mock the OIDC discovery GET that the lifespan performs on startup.
        router.get(well_known_url).mock(
            return_value=httpx.Response(200, json=mock_duo_discovery)
        )

        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            yield client


# ---------------------------------------------------------------------------
# 4. Authenticated session fixture
# ---------------------------------------------------------------------------
@pytest.fixture()
async def authenticated_session(app_client):
    """
    Return the app_client pre-loaded with a fake authenticated session.

    This allows tests to skip the full OAuth flow and directly exercise
    endpoints that require an active session.
    """
    fake_user = {
        "sub": "test-user-id-001",
        "name": "Test User",
        "email": "testuser@example.com",
        "scope": "openid profile email duo-admin-api:read duo-admin-api:write",
    }

    # Inject the session via a direct request that sets session data.
    # We reach into the app's session middleware by making a throwaway request
    # and then extracting / re-using the session cookie.  However, the
    # simplest portable approach is to use the /root endpoint and inspect
    # the redirect, then manually set the session cookie.
    #
    # Because Starlette SessionMiddleware signs its cookies, the cleanest
    # approach is to expose a tiny test-only hook.  Instead, we create a
    # fresh client that patches the session directly in the ASGI scope.
    #
    # For now, we provide the client and fake_user dict so downstream tests
    # can use them.  P1 fixtures will add proper session injection.

    return {"client": app_client, "user": fake_user}
