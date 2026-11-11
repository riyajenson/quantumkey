"""Request guards for the relying party (R-10, SEC-07).

Every POST under /auth/ is counted per client IP and must declare a body size
within the cap. The counts live in this process's memory: with several worker
processes each keeps its own, and a restart resets them. The client IP is the
socket peer; X-Forwarded-For is not trusted, so behind a reverse proxy all
clients share the proxy's address.
"""

from __future__ import annotations

import math
import threading
import time
from typing import Callable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class RateLimiter:
    """Fixed window per key: at most `limit` hits in `window` seconds, the
    window starting at the key's first hit."""

    def __init__(
        self, limit: int, window: float = 60.0, clock: Callable[[], float] = time.time
    ) -> None:
        self.limit = limit
        self.window = window
        self.clock = clock
        self._windows: dict[str, list[float]] = {}  # key -> [start, count]
        self._last_sweep = float("-inf")
        self._lock = threading.Lock()

    def hit(self, key: str) -> float | None:
        """Count one request; return seconds until retry if over the limit."""
        now = self.clock()
        with self._lock:
            if now - self._last_sweep >= self.window:  # forget finished windows
                self._windows = {
                    k: v for k, v in self._windows.items() if now - v[0] < self.window
                }
                self._last_sweep = now
            entry = self._windows.get(key)
            if entry is None or now - entry[0] >= self.window:
                entry = self._windows[key] = [now, 0]
            entry[1] += 1
            if entry[1] > self.limit:
                return entry[0] + self.window - now
            return None


class RequestGuard:
    """ASGI middleware applying the rate limit and the body-size cap."""

    def __init__(self, app: ASGIApp, limiter: RateLimiter | None, max_body: int) -> None:
        self.app = app
        self.limiter = limiter
        self.max_body = max_body

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and scope["method"] == "POST"
            and scope["path"].startswith("/auth/")
        ):
            refusal = self._check(scope)
            if refusal is not None:
                await refusal(scope, receive, send)
                return
        await self.app(scope, receive, send)

    def _check(self, scope: Scope) -> JSONResponse | None:
        if self.limiter is not None:
            client = scope.get("client")
            retry = self.limiter.hit(client[0] if client else "unknown")
            if retry is not None:
                return JSONResponse(
                    {"error": "rate_limited"},
                    status_code=429,
                    headers={"Retry-After": str(max(1, math.ceil(retry)))},
                )
        length = dict(scope["headers"]).get(b"content-length")
        # The server enforces the declared length, so checking it bounds the body.
        if length is None or not length.isdigit():
            return JSONResponse({"error": "length_required"}, status_code=411)
        if int(length) > self.max_body:
            return JSONResponse({"error": "request_too_large"}, status_code=413)
        return None
