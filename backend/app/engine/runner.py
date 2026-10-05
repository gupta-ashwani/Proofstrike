"""
Background runner — executes long-running engine coroutines on a dedicated thread.

Playwright launches the browser as a subprocess, which needs an event loop that
supports subprocesses. On Windows, uvicorn's --reload mode runs the app on a
SelectorEventLoop that does not (every launch raises NotImplementedError), so each
job gets its own thread with a fresh loop — a ProactorEventLoop on Windows.

Because async DB connections are bound to the loop that created them, coroutines
run here must use their own DB engine (see app.database.make_engine).
"""

import asyncio
import logging
import sys
import threading
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger("proofstrike.engine.runner")


def _new_event_loop() -> asyncio.AbstractEventLoop:
    if sys.platform == "win32":
        return asyncio.ProactorEventLoop()
    return asyncio.new_event_loop()


def start_in_thread(
    name: str, coro_factory: Callable[[], Coroutine[Any, Any, Any]]
) -> threading.Thread:
    """Run coro_factory() to completion on a new daemon thread with its own event loop."""

    def _target():
        loop = _new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(coro_factory())
        except Exception:
            logger.exception("Background job %s crashed", name)
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                loop.close()

    thread = threading.Thread(target=_target, name=name, daemon=True)
    thread.start()
    return thread
