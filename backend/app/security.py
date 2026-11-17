"""Pure-ASGI security middleware: request size limits, rate limiting and
response security headers."""
import json
import threading
import time
from collections import defaultdict, deque


async def _send_json(send, status: int, detail: str, extra_headers=()):
    body = json.dumps({"detail": detail}).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), *extra_headers]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


class BodySizeLimit:
    """Reject request bodies above a per-path byte limit, whether or not the
    client sends an honest Content-Length."""

    def __init__(self, app, default_limit: int, limits: dict[str, int]):
        self.app, self.default_limit, self.limits = app, default_limit, limits

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            return await self.app(scope, receive, send)
        limit = self.limits.get(scope["path"], self.default_limit)
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    if int(value) > limit:
                        return await _send_json(send, 413, "Request is too large.")
                except ValueError:
                    return await _send_json(send, 400, "Invalid Content-Length.")

        received = 0
        started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _TooLarge
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await _send_json(send, 413, "Request is too large.")


class RateLimiter:
    """Sliding one-minute window per client IP, with a stricter limit for the
    expensive audio endpoints. In memory, so it applies per replica."""

    def __init__(self, app, per_minute: int, audio_per_minute: int, audio_paths: set[str]):
        self.app = app
        self.per_minute, self.audio_per_minute, self.audio_paths = per_minute, audio_per_minute, audio_paths
        self.hits: dict[tuple[str, bool], deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def _allow(self, key, limit) -> int:
        """Return 0 if allowed, otherwise seconds until the next slot frees."""
        now = time.monotonic()
        with self.lock:
            window = self.hits[key]
            while window and now - window[0] > 60:
                window.popleft()
            if len(window) >= limit:
                return int(60 - (now - window[0])) + 1
            window.append(now)
            if len(self.hits) > 20000:  # bound memory under a flood of IPs
                for k in [k for k, v in self.hits.items() if not v or now - v[-1] > 60]:
                    del self.hits[k]
            return 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        from .main import client_ip  # avoid an import cycle

        ip = client_ip(scope)
        is_audio = scope["path"] in self.audio_paths
        limit = self.audio_per_minute if is_audio else self.per_minute
        if limit > 0:
            wait = self._allow((ip, is_audio), limit)
            if wait:
                return await _send_json(
                    send, 429, "Too many requests. Try again in a minute.", [(b"retry-after", str(wait).encode())]
                )
        await self.app(scope, receive, send)


API_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cross-origin-resource-policy", b"cross-origin"),
]
# The JSON API never serves pages; /docs needs the Swagger UI assets.
STRICT_CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")


class SecurityHeaders:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        is_docs = scope["path"] in ("/docs", "/docs/oauth2-redirect", "/openapi.json")

        async def add_headers(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                headers += API_HEADERS
                if not is_docs:
                    headers.append(STRICT_CSP)
                if scope["method"] == "POST":
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, add_headers)
