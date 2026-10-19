"""
ALPHA Rate Limiter
A simple in-memory request limiter for demonstrations.

Production applications should use a shared backend,
such as Redis, and enforce limits at the server/API layer.
"""

import time
from collections import defaultdict, deque
from threading import Lock


class RateLimiter:
    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: int = 60,
    ):
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("Limits must be positive.")

        self.max_requests = max_requests
        self.window_seconds = window_seconds

        self.requests = defaultdict(deque)
        self.lock = Lock()

    def allow_request(self, client_id: str) -> bool:
        """Return True if the client may make a request."""

        if not client_id:
            return False

        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self.lock:
            timestamps = self.requests[client_id]

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                return False

            timestamps.append(now)
            return True


if __name__ == "__main__":
    limiter = RateLimiter(
        max_requests=5,
        window_seconds=60,
    )

    demo_client = "demo-user"

    for attempt in range(1, 8):
        allowed = limiter.allow_request(demo_client)

        status = "ALLOWED" if allowed else "BLOCKED"

        print(f"Request {attempt}: {status}")
