"""Transport-level hardening: security headers, rate limiting, request tracing.

These are the controls that apply to every request regardless of the endpoint,
and that an external security audit expects to find on a public-facing API.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..config import settings

logger = logging.getLogger("fasoshield.access")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id and emit one structured access log line per call.

    The log deliberately records the path but never the query string or the
    request body: an APK hash is not personal data, but a full URL from a
    misconfigured client might carry something that is.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "%s %s -> %s in %.1fms",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            extra={"request_id": request_id},
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline browser protections for the console.

    The Content-Security-Policy is strict — no external origin at all — which
    is possible because the console ships its own CSS and JavaScript inline
    with a per-response nonce rather than pulling a framework from a CDN.
    """

    async def dispatch(self, request: Request, call_next):
        nonce = uuid.uuid4().hex
        request.state.csp_nonce = nonce
        response: Response = await call_next(request)

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; "
            f"script-src 'nonce-{nonce}'; "
            f"style-src 'nonce-{nonce}'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'",
        )
        if settings.hsts_enabled:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token bucket per caller.

    The caller is the agent API key when one is presented, otherwise the client
    address — so one misbehaving device cannot exhaust the budget of a whole
    mobile network sharing a NAT address.
    """

    def __init__(self, app, per_minute: int, burst: int) -> None:
        super().__init__(app)
        self.rate = per_minute / 60.0  # tokens per second
        self.capacity = max(burst, 1)
        self._buckets: dict[str, tuple[float, float]] = defaultdict(
            lambda: (float(self.capacity), time.monotonic())
        )
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next):
        if self.rate <= 0:
            return await call_next(request)
        identity = self._identity(request)
        if not self._allow(identity):
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": "60"},
            )
        return await call_next(request)

    def _identity(self, request: Request) -> str:
        key = request.headers.get("x-api-key")
        if key:
            # Never key the bucket on the secret itself.
            import hashlib

            return "key:" + hashlib.sha256(key.encode()).hexdigest()[:16]
        return "ip:" + (request.client.host if request.client else "unknown")

    def _allow(self, identity: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets[identity]
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._buckets[identity] = (tokens, now)
                return False
            self._buckets[identity] = (tokens - 1.0, now)
            return True
