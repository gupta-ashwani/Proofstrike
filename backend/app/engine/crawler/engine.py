"""
Crawl stage — browser-based discovery of the target's attack surface.

Runs as the first stage of the scan pipeline (app.engine.pipeline). Given a
ScanContext it:
  1. Launches the browser
  2. Authenticates (if configured), re-authenticating if the session is lost
  3. Spiders the app (BFS), skipping logout/destructive URLs, paced by the limiter
  4. Extracts endpoints from the DOM + network traffic
  5. Marks which endpoints need authentication (anonymous re-check)
  6. Captures the authenticated session so later stages can reuse it
  7. Stores endpoints in the DB (credentials masked)

It writes metrics to ctx.stats and the session to ctx.storage_state. It does NOT
set terminal scan status — the pipeline owns completed/failed/stopped.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from app.engine.crawler.browser import BrowserManager
from app.engine.crawler.auth import AuthHandler
from app.engine.crawler.spider import Spider, UrlExcluder
from app.engine.crawler.seeds import discover_seeds
from app.engine.crawler.endpoint_extractor import (
    EndpointExtractor,
    DiscoveredEndpoint,
    mask_sensitive_params,
)

if TYPE_CHECKING:
    from app.engine.context import ScanContext

logger = logging.getLogger("proofstrike.crawler.engine")

# Give up re-authenticating after this many lost sessions in one crawl
MAX_RELOGINS = 3


def _path_key(url: str) -> str:
    """host + path, for comparing pages regardless of query/fragment/trailing slash."""
    parsed = urlparse(url)
    return parsed.netloc.lower() + (parsed.path.rstrip("/") or "/")


def _probe_params(params: dict | None) -> dict:
    """Flatten stored params (plain values, lists, form-field descriptors) for a GET probe."""
    flat = {}
    for name, value in (params or {}).items():
        if isinstance(value, dict) and "value" in value:
            value = value["value"]
        elif isinstance(value, list):
            value = value[0] if value else ""
        if isinstance(value, (str, int, float, bool)):
            flat[name] = value
    return flat


class CrawlStage:
    """Discovers endpoints for a scan. One instance per scan run."""

    name = "crawl"

    def __init__(self):
        self._cancelled = False
        self._spider: Spider | None = None
        self._relogins = 0

    def cancel(self):
        self._cancelled = True
        if self._spider:
            self._spider.cancel()

    def _stopped(self) -> bool:
        return self._cancelled

    async def run(self, ctx: ScanContext):
        """Crawl the target and store endpoints. Raises on a fatal crawl error."""
        ctx.stats.setdefault("errors", [])
        ctx.stats.update(pages_visited=0, endpoints_found=0,
                         max_depth=ctx.max_depth, max_pages=ctx.max_pages)

        logger.info(
            "Starting crawl: scan=%s url=%s depth=%d pages=%d delay=%.2fs",
            ctx.scan_id[:8], ctx.base_url, ctx.max_depth, ctx.max_pages, ctx.limiter.delay,
        )

        all_discovered: list[DiscoveredEndpoint] = []
        unique_endpoints: list[DiscoveredEndpoint] = []

        async with BrowserManager(headless=ctx.headless) as browser:
            page = await browser.new_page()
            session_guard = None

            # ── Authentication ──
            if ctx.auth_config:
                logger.info("Auth config detected — performing login")
                auth_handler = AuthHandler(page)
                auth_success = await auth_handler.login(ctx.auth_config)
                ctx.stats["auth_success"] = auth_success
                # The login traffic (incl. the credential POST) is not app attack surface
                browser.clear_captured_requests()

                if auth_success:
                    session_guard = self._make_session_guard(auth_handler, ctx, browser)
                else:
                    logger.warning("Auth failed — continuing with unauthenticated crawl")
                    ctx.stats["errors"].append("Authentication failed")
            else:
                logger.info("No auth config — crawling without authentication")
                ctx.stats["auth_success"] = None

            # ── Seed discovery (sitemap.xml / robots.txt) ──
            seed_urls = []
            if ctx.use_sitemap and not self._stopped():
                seed_urls = await discover_seeds(
                    browser.context.request, ctx.base_url, ctx.scope, ctx.excluder, ctx.limiter
                )
                ctx.stats["seed_urls"] = len(seed_urls)

            # ── Spider ──
            self._spider = Spider(
                page=page,
                base_url=ctx.base_url,
                max_depth=ctx.max_depth,
                max_pages=ctx.max_pages,
                excluder=ctx.excluder,
                session_guard=session_guard,
                limiter=ctx.limiter,
                scope=ctx.scope,
                extra_seeds=seed_urls,
            )
            if self._stopped():
                self._spider.cancel()

            extractor = EndpointExtractor(page=page, scope=ctx.scope)
            pages_visited = 0
            pages_failed = 0

            async for crawl_result in self._spider.crawl():
                if self._stopped():
                    break

                pages_visited += 1

                if crawl_result.error:
                    pages_failed += 1
                    ctx.stats["errors"].append(f"{crawl_result.url}: {crawl_result.error}")
                    browser.clear_captured_requests()
                    continue

                dom_endpoints = await extractor.extract_from_dom()
                all_discovered.extend(dom_endpoints)

                captured = browser.drain_captured_requests()
                net_endpoints = extractor.extract_from_network(captured)
                all_discovered.extend(net_endpoints)

                if pages_visited % 10 == 0:
                    await self._update_stats(ctx, pages_visited, len(all_discovered))

                logger.info(
                    "Page %d: %d DOM endpoints, %d network endpoints",
                    pages_visited, len(dom_endpoints), len(net_endpoints),
                )

            ctx.stats["pages_visited"] = pages_visited
            ctx.stats["excluded_urls"] = list(self._spider.excluded_urls)
            if self._relogins:
                ctx.stats["relogins"] = self._relogins

            if pages_visited and pages_failed == pages_visited and not self._stopped():
                raise RuntimeError("Every page failed to load — is the target URL reachable?")

            # ── Deduplicate, mark auth-required, capture the session ──
            unique_endpoints = EndpointExtractor.deduplicate(all_discovered)
            if ctx.authenticated and not self._stopped():
                await self._mark_auth_required(
                    browser, unique_endpoints, ctx.auth_config["login_url"], ctx
                )
                # Hand the logged-in session to later stages (kept in memory only)
                ctx.storage_state = await browser.get_storage_state()

        # ── Store endpoints (credentials masked) ──
        for ep in unique_endpoints:
            ep.params = mask_sensitive_params(ep.params, ctx.secret_values)
        ctx.stats["endpoints_found"] = len(unique_endpoints)
        await self._store_endpoints(ctx, unique_endpoints)

        logger.info(
            "Crawl stage done: %d pages, %d endpoints",
            ctx.stats["pages_visited"], ctx.stats["endpoints_found"],
        )

    def _make_session_guard(self, auth_handler: AuthHandler, ctx: ScanContext, browser):
        """
        When a page (other than the login page itself) lands on the login page, the
        session was lost — log in again.
        """
        login_key = _path_key(ctx.auth_config["login_url"])

        async def guard(requested_url: str, landed_url: str) -> bool:
            if _path_key(landed_url) != login_key or _path_key(requested_url) == login_key:
                return False
            if self._relogins >= MAX_RELOGINS:
                return False

            self._relogins += 1
            logger.warning(
                "Session lost at %s — re-authenticating (%d/%d)",
                requested_url, self._relogins, MAX_RELOGINS,
            )
            success = await auth_handler.login(ctx.auth_config)
            browser.clear_captured_requests()
            if not success:
                ctx.stats["errors"].append(f"Re-authentication failed at {requested_url}")
            return success

        return guard

    async def _mark_auth_required(
        self,
        browser: BrowserManager,
        endpoints: list[DiscoveredEndpoint],
        login_url: str,
        ctx: ScanContext,
    ):
        """
        Re-request each GET endpoint without cookies. A 401/403 or a redirect to the
        login page means it needs auth. POSTs are left unchecked (replaying is unsafe)
        and excluded URLs are skipped. Paced by the shared limiter.
        """
        login_key = _path_key(login_url)
        context = await browser.new_anonymous_request_context()
        try:
            for ep in endpoints:
                if self._stopped():
                    break
                if ep.method.upper() != "GET" or ctx.excluder.is_excluded(ep.url):
                    continue
                if _path_key(ep.url) == login_key:
                    continue
                try:
                    async with ctx.limiter:
                        response = await context.get(
                            ep.url, params=_probe_params(ep.params), max_redirects=0
                        )
                except Exception as e:
                    logger.debug("Auth probe failed for %s: %s", ep.url, e)
                    continue

                status = response.status
                location = response.headers.get("location", "")
                redirected_to_login = (
                    300 <= status < 400
                    and location
                    and _path_key(urljoin(ep.url, location)) == login_key
                )
                ep.auth_required = status in (401, 403) or bool(redirected_to_login)
                await response.dispose()
        finally:
            await context.dispose()

    async def _store_endpoints(self, ctx: ScanContext, endpoints: list[DiscoveredEndpoint]):
        from app.models.endpoint import Endpoint

        async with ctx.session_factory() as db:
            for ep in endpoints:
                db.add(Endpoint(
                    scan_id=ctx.scan_id,
                    url=ep.url,
                    method=ep.method,
                    params=ep.params,
                    auth_required=ep.auth_required,
                    source=ep.source,
                ))
            await db.commit()
        logger.info("Stored %d endpoints in DB", len(endpoints))

    async def _update_stats(self, ctx: ScanContext, pages_visited: int, endpoints_found: int):
        """Periodic progress write during a long crawl."""
        from sqlalchemy import select
        from app.models.scan import Scan

        async with ctx.session_factory() as db:
            scan = (await db.execute(select(Scan).where(Scan.id == ctx.scan_id))).scalar_one_or_none()
            if scan:
                scan.stats = {**ctx.stats, "pages_visited": pages_visited, "endpoints_found": endpoints_found}
                await db.commit()
