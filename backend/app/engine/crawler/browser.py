"""
Browser Manager — launch and manage Playwright Chromium for crawling.

Handles:
  - Browser lifecycle (launch / close)
  - Page creation with request interception
  - Capturing all network requests (XHR, fetch, document, etc.)
  - Cookie persistence for authenticated sessions
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

from playwright.async_api import (
    async_playwright, APIRequestContext, Browser, BrowserContext, Page, Request,
)

logger = logging.getLogger("proofstrike.crawler.browser")


def chromium_launch_args() -> list[str]:
    """Extra Chromium flags. In a container the browser runs as root and refuses to
    start without --no-sandbox; --disable-dev-shm-usage avoids crashes on a small
    /dev/shm. Gated on an env var so local (non-Docker) runs are unaffected."""
    if os.getenv("PROOFSTRIKE_BROWSER_NO_SANDBOX", "").lower() in ("1", "true", "yes"):
        return ["--no-sandbox", "--disable-dev-shm-usage"]
    return []


@dataclass
class CapturedRequest:
    """A network request captured by the browser interceptor."""
    url: str
    method: str
    resource_type: str  # xhr, fetch, document, script, stylesheet, etc.
    headers: dict = field(default_factory=dict)
    post_data: str | None = None


class BrowserManager:
    """
    Manages a Playwright Chromium browser instance for crawling.

    Usage:
        async with BrowserManager(headless=True) as bm:
            page = await bm.new_page()
            await page.goto("https://example.com")
            captured = bm.get_captured_requests()
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 30_000,
        viewport_width: int = 1280,
        viewport_height: int = 720,
        storage_state: dict | None = None,
    ):
        self.headless = headless
        self.timeout = timeout
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.storage_state = storage_state

        self._playwright = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._captured_requests: list[CapturedRequest] = []
        self._temp_state_path = None

    async def __aenter__(self):
        await self.launch()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def launch(self):
        """Launch Chromium browser and create a context."""
        logger.info("Launching Playwright Chromium (headless=%s)", self.headless)
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless, args=chromium_launch_args())
        context_args = dict(
            viewport={"width": self.viewport_width, "height": self.viewport_height},
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        self._temp_state_path = None
        if self.storage_state:
            # Reuse the crawl's authenticated session; accept a dict or fall back to a file
            try:
                self._context = await self._browser.new_context(
                    storage_state=self.storage_state, **context_args
                )
            except Exception:
                import json
                import os
                import tempfile
                fd, path = tempfile.mkstemp(suffix=".json")
                with os.fdopen(fd, "w") as f:
                    json.dump(self.storage_state, f)
                self._temp_state_path = path
                self._context = await self._browser.new_context(
                    storage_state=path, **context_args
                )
        else:
            self._context = await self._browser.new_context(**context_args)
        self._context.set_default_timeout(self.timeout)
        self._context.set_default_navigation_timeout(self.timeout)
        logger.info("Browser launched successfully")

    async def close(self):
        """Close browser and cleanup Playwright."""
        if self._temp_state_path:
            import os
            try:
                os.unlink(self._temp_state_path)
            except OSError:
                pass
            self._temp_state_path = None
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("Browser closed")

    async def new_page(self) -> Page:
        """
        Create a new page with network interception enabled.
        All XHR/fetch/document requests are captured automatically.
        """
        if not self._context:
            raise RuntimeError("Browser not launched. Call launch() first.")

        page = await self._context.new_page()

        # Intercept all network requests
        page.on("request", self._on_request)

        return page

    def _on_request(self, request: Request):
        """Callback for every network request — capture relevant ones."""
        resource_type = request.resource_type

        # Capture document navigations, XHR, fetch, and form submissions
        interesting_types = {"document", "xhr", "fetch", "form"}
        if resource_type in interesting_types:
            captured = CapturedRequest(
                url=request.url,
                method=request.method,
                resource_type=resource_type,
                headers=dict(request.headers) if request.headers else {},
                post_data=request.post_data,
            )
            self._captured_requests.append(captured)
            logger.debug(
                "Captured %s %s [%s]", request.method, request.url, resource_type
            )

    def get_captured_requests(self) -> list[CapturedRequest]:
        """Return all captured network requests."""
        return list(self._captured_requests)

    def clear_captured_requests(self):
        """Clear the captured requests buffer."""
        self._captured_requests.clear()

    def drain_captured_requests(self) -> list[CapturedRequest]:
        """Return and clear all captured requests (atomic drain)."""
        requests = list(self._captured_requests)
        self._captured_requests.clear()
        return requests

    async def new_anonymous_request_context(self) -> APIRequestContext:
        """
        Create a cookie-less HTTP client (separate from the crawling session),
        used to check which endpoints are reachable without logging in.
        Callers must dispose() it.
        """
        if not self._playwright:
            raise RuntimeError("Browser not launched. Call launch() first.")
        return await self._playwright.request.new_context(
            ignore_https_errors=True, timeout=10_000
        )

    async def get_storage_state(self) -> dict | None:
        """
        Export the context's session (cookies + localStorage) so a later stage can
        recreate an authenticated context. Contains secrets — keep in memory only.
        """
        if not self._context:
            return None
        return await self._context.storage_state()

    async def get_cookies(self) -> list[dict]:
        """Get all cookies from the browser context."""
        if not self._context:
            return []
        return await self._context.cookies()

    async def set_cookies(self, cookies: list[dict]):
        """Restore cookies into the browser context."""
        if self._context:
            await self._context.add_cookies(cookies)

    @property
    def context(self) -> BrowserContext | None:
        return self._context
