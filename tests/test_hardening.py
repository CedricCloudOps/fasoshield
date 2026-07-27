"""Transport hardening: security headers, rate limiting, request tracing."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(isolated_settings):
    from fasoshield.api.main import app

    with TestClient(app) as test_client:
        yield test_client


def test_security_headers_present(client):
    headers = client.get("/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert "geolocation=()" in headers["permissions-policy"]


def test_csp_forbids_external_origins(client):
    csp = client.get("/console").headers["content-security-policy"]
    assert csp.startswith("default-src 'none'")
    assert "frame-ancestors 'none'" in csp
    # No CDN: the console ships its own assets, so nothing external is allowed.
    assert "http://" not in csp and "https://" not in csp


def test_console_script_carries_the_response_nonce(client):
    response = client.get("/console")
    csp = response.headers["content-security-policy"]
    nonce = csp.split("script-src 'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"' in response.text


def test_nonce_differs_between_responses(client):
    """A fixed nonce would defeat the point of having one."""
    first = client.get("/console").headers["content-security-policy"]
    second = client.get("/console").headers["content-security-policy"]
    assert first != second


def test_hsts_can_be_disabled_for_plain_http_deployments(client, isolated_settings, monkeypatch):
    assert "strict-transport-security" in client.get("/health").headers
    monkeypatch.setattr(isolated_settings, "hsts_enabled", False)
    assert "strict-transport-security" not in client.get("/health").headers


def test_request_id_is_echoed(client):
    response = client.get("/health", headers={"X-Request-ID": "trace-me-1234"})
    assert response.headers["x-request-id"] == "trace-me-1234"


def test_request_id_is_generated_when_absent(client):
    assert client.get("/health").headers["x-request-id"]


def test_rate_limit_returns_429_with_retry_after():
    """Exercised on a throwaway app: reloading the real one would leave a
    tightened middleware stack behind for every other test in the session."""
    from fastapi import FastAPI

    from fasoshield.api.middleware import RateLimitMiddleware

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, per_minute=60, burst=3)

    @app.get("/ping")
    def ping():
        return {"ok": True}

    with TestClient(app) as client:
        responses = [client.get("/ping") for _ in range(8)]

    statuses = [r.status_code for r in responses]
    assert statuses[0] == 200  # the burst allowance is honoured first
    assert 429 in statuses
    throttled = next(r for r in responses if r.status_code == 429)
    assert throttled.headers["retry-after"] == "60"


def test_rate_limit_buckets_are_per_caller():
    from fasoshield.api.middleware import RateLimitMiddleware

    limiter = RateLimitMiddleware(app=None, per_minute=60, burst=2)
    assert limiter._allow("ip:10.0.0.1")
    assert limiter._allow("ip:10.0.0.1")
    assert not limiter._allow("ip:10.0.0.1")
    # A different caller still has its full allowance.
    assert limiter._allow("ip:10.0.0.2")


def test_rate_limit_identity_never_contains_the_api_key():
    """Bucketing on the raw key would put a secret in memory structures and
    logs; the identity is a truncated digest instead."""
    from starlette.datastructures import Headers
    from starlette.requests import Request

    from fasoshield.api.middleware import RateLimitMiddleware

    limiter = RateLimitMiddleware(app=None, per_minute=60, burst=2)
    scope = {
        "type": "http",
        "headers": Headers({"x-api-key": "super-secret-agent-key"}).raw,
        "client": ("10.0.0.9", 1234),
    }
    identity = limiter._identity(Request(scope))
    assert identity.startswith("key:")
    assert "super-secret-agent-key" not in identity
