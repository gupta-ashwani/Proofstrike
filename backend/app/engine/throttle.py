"""
Request throttling — a shared rate limiter for all engine stages.

The crawler and the Phase 4 detectors send traffic to the target. Against a
shared or production app that must stay polite: a minimum gap between requests
(so we don't hammer the server) and a cap on how many run at once.

One RateLimiter is created per scan (see app.engine.context) and passed to every
stage, so the whole scan shares a single budget rather than each stage pacing
itself independently.
"""

import asyncio
import time


class RateLimiter:
    """
    Paces async requests: at most `max_concurrency` in flight, and consecutive
    starts at least `delay` seconds apart.

    Hold it around the actual request so concurrency is counted correctly:

        async with limiter:
            await do_request()
    """

    def __init__(self, delay: float = 0.0, max_concurrency: int = 1):
        self.delay = max(0.0, float(delay))
        self.max_concurrency = max(1, int(max_concurrency))
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def __aenter__(self):
        await self._sem.acquire()
        if self.delay:
            # Serialize the gap calculation so concurrent waiters don't all fire at once
            async with self._lock:
                now = time.monotonic()
                wait = self._next_allowed - now
                if wait > 0:
                    await asyncio.sleep(wait)
                self._next_allowed = max(now, self._next_allowed) + self.delay
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self._sem.release()
        return False
