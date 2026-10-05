"""
Crawler Engine — orchestrator that ties browser, auth, spider, and extractor.

This is the main entry point for Phase 3.
Given a scan_id, it:
  1. Loads the target and scan from DB
  2. Launches browser
  3. Performs authentication (if configured), re-authenticating if the session is lost
  4. Spiders the application (BFS), skipping logout/destructive URLs
  5. Extracts endpoints from DOM + network traffic
  6. Marks which endpoints need authentication (anonymous re-check)
  7. Stores everything in the Endpoint table (credentials masked)
  8. Updates scan status and stats
"""

import logging
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database import async_session
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.models.endpoint import Endpoint
from app.models.finding import Finding

from app.engine.crawler.browser import BrowserManager
from app.engine.crawler.auth import AuthHandler, AuthConfig
from app.engine.crawler.spider import Spider, UrlExcluder
from app.engine.crawler.endpoint_extractor import (
    EndpointExtractor,
    DiscoveredEndpoint,
    mask_sensitive_params,
)

logger = logging.getLogger("proofstrike.crawler.engine")

# Give up re-authenticating after this many lost sessions in one crawl
MAX_RELOGINS = 3


def _config_value(config: dict, keys: tuple[str, ...], default: int, minimum: int) -> int:
    """
    First of `keys` present in config, as an int clamped to `minimum`.

    Checks for presence rather than truthiness, so an explicit 0 is respected.
    """
    for key in keys:
        value = config.get(key)
        if value is not None:
            try:
                return max(minimum, int(value))
            except (TypeError, ValueError):
                logger.warning("Ignoring invalid scan config %s=%r", key, value)
    return default


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


class CrawlerEngine:
    """
    Main crawler orchestrator.

    Usage:
        engine = CrawlerEngine(scan_id="...")
        await engine.run()
    """

    def __init__(
        self,
        scan_id: str,
        headless: bool = True,
        max_depth: int = 5,
        max_pages: int = 100,
    ):
        self.scan_id = scan_id
        self.headless = headless
        self.max_depth = max_depth
        self.max_pages = max_pages

        # State
        self._cancelled = False
        self._spider: Spider | None = None
        self._relogins = 0

    def cancel(self):
        """Cancel a running crawl."""
        self._cancelled = True
        if self._spider:
            self._spider.cancel()

    async def run(self, session_factory: async_sessionmaker[AsyncSession] | None = None) -> dict:
        """
        Execute the full crawl pipeline.

        session_factory must be bound to the event loop this runs on; it defaults
        to the app's shared factory (only valid on the API's own loop).
        Returns a stats dict with crawl metrics.
        """
        self._session = session_factory or async_session

        stats = {
            "pages_visited": 0,
            "endpoints_found": 0,
            "auth_success": None,
            "errors": [],
            "duration_seconds": 0,
        }

        start_time = datetime.now(timezone.utc)

        # ── 1. Load scan and target from DB ──
        async with self._session() as db:
            scan, target = await self._load_scan_and_target(db)
            if not scan or not target:
                return stats
            if self._cancelled:
                # Stopped before the crawl got going — keep the STOPPED status
                return stats

            # Update scan status to CRAWLING
            scan.status = ScanStatus.CRAWLING.value
            scan.started_at = start_time
            scan.completed_at = None
            scan.stats = None

            # Re-crawl: replace endpoints from any previous run of this scan
            await db.execute(
                update(Finding).where(Finding.scan_id == self.scan_id).values(endpoint_id=None)
            )
            await db.execute(delete(Endpoint).where(Endpoint.scan_id == self.scan_id))
            await db.commit()

        # NOTE: We can access scan and target after the session closes because
        # expire_on_commit=False is set in our async_sessionmaker in database.py.
        base_url = target.base_url.rstrip("/")
        base_domain = urlparse(base_url).netloc
        auth_config = target.auth_config
        if AuthConfig.is_configured(auth_config):
            # Allow a login_url relative to the target ("/login")
            auth_config = {**auth_config, "login_url": urljoin(target.base_url, auth_config["login_url"])}

        # Apply scan config overrides
        scan_config = scan.config or {}
        max_depth = _config_value(scan_config, ("max_depth", "crawl_depth"), self.max_depth, minimum=0)
        max_pages = _config_value(scan_config, ("max_pages", "request_budget"), self.max_pages, minimum=1)
        headless = scan_config.get("headless", self.headless)
        excluder = UrlExcluder(scan_config.get("exclude_patterns"))
        stats["max_depth"] = max_depth
        stats["max_pages"] = max_pages

        # Credentials that must never be stored, even if they show up in captured traffic
        secret_values = set()
        if auth_config:
            secret_values.add(str(auth_config.get("password", "")))
            for user in auth_config.get("users") or []:
                if isinstance(user, dict) and user.get("password"):
                    secret_values.add(str(user["password"]))
            secret_values.discard("")

        logger.info(
            "Starting crawl: scan=%s target=%s url=%s depth=%d pages=%d",
            self.scan_id[:8], target.name, base_url, max_depth, max_pages,
        )

        all_discovered: list[DiscoveredEndpoint] = []
        unique_endpoints: list[DiscoveredEndpoint] = []

        try:
            # ── 2. Launch browser ──
            async with BrowserManager(headless=headless) as browser:
                page = await browser.new_page()
                session_guard = None

                # ── 3. Authentication ──
                if AuthConfig.is_configured(auth_config):
                    logger.info("Auth config detected — performing login")
                    auth_handler = AuthHandler(page)
                    auth_success = await auth_handler.login(auth_config)
                    stats["auth_success"] = auth_success
                    # The login traffic (incl. the credential POST) is not app attack surface
                    browser.clear_captured_requests()

                    if auth_success:
                        session_guard = self._make_session_guard(
                            auth_handler, auth_config, browser, stats
                        )
                    else:
                        logger.warning("Auth failed — continuing with unauthenticated crawl")
                        stats["errors"].append("Authentication failed")
                else:
                    logger.info("No auth config — crawling without authentication")
                    stats["auth_success"] = None

                # ── 4. Spider ──
                self._spider = Spider(
                    page=page,
                    base_url=base_url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    excluder=excluder,
                    session_guard=session_guard,
                )
                if self._cancelled:
                    self._spider.cancel()

                extractor = EndpointExtractor(page=page, base_domain=base_domain)
                pages_visited = 0
                pages_failed = 0

                async for crawl_result in self._spider.crawl():
                    if self._cancelled:
                        break

                    pages_visited += 1

                    if crawl_result.error:
                        pages_failed += 1
                        stats["errors"].append(
                            f"{crawl_result.url}: {crawl_result.error}"
                        )
                        browser.clear_captured_requests()
                        continue

                    # ── 5a. Extract endpoints from DOM ──
                    dom_endpoints = await extractor.extract_from_dom()
                    all_discovered.extend(dom_endpoints)

                    # ── 5b. Extract endpoints from network traffic ──
                    captured = browser.drain_captured_requests()
                    net_endpoints = extractor.extract_from_network(captured)
                    all_discovered.extend(net_endpoints)

                    # Periodic DB update (every 10 pages)
                    if pages_visited % 10 == 0:
                        async with self._session() as db:
                            await self._update_scan_stats(
                                db, pages_visited, len(all_discovered)
                            )

                    logger.info(
                        "Page %d: %d DOM endpoints, %d network endpoints",
                        pages_visited, len(dom_endpoints), len(net_endpoints),
                    )

                stats["pages_visited"] = pages_visited
                stats["excluded_urls"] = list(self._spider.excluded_urls)

                if pages_visited and pages_failed == pages_visited and not self._cancelled:
                    raise RuntimeError("Every page failed to load — is the target URL reachable?")

                # ── 6. Deduplicate, then mark endpoints that need a login ──
                unique_endpoints = EndpointExtractor.deduplicate(all_discovered)
                if stats["auth_success"] and not self._cancelled:
                    await self._mark_auth_required(
                        browser, unique_endpoints, auth_config["login_url"], excluder
                    )

        except Exception as e:
            logger.error("Crawler error: %s", str(e), exc_info=True)
            stats["errors"].append(f"Crawler error: {type(e).__name__}: {e}")

            # Set scan to FAILED
            async with self._session() as db:
                result = await db.execute(
                    select(Scan).where(Scan.id == self.scan_id)
                )
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED.value
                    scan.completed_at = datetime.now(timezone.utc)
                    stats["duration_seconds"] = (scan.completed_at - start_time).total_seconds()
                    scan.stats = stats
                    await db.commit()
            return stats

        # ── 7. Store endpoints (credentials masked) ──
        for ep in unique_endpoints:
            ep.params = mask_sensitive_params(ep.params, secret_values)
        stats["endpoints_found"] = len(unique_endpoints)

        async with self._session() as db:
            await self._store_endpoints(db, unique_endpoints)

            # ── 8. Finalize scan ──
            end_time = datetime.now(timezone.utc)
            stats["duration_seconds"] = (end_time - start_time).total_seconds()

            result = await db.execute(
                select(Scan).where(Scan.id == self.scan_id)
            )
            scan = result.scalar_one_or_none()
            if scan:
                if self._cancelled:
                    scan.status = ScanStatus.STOPPED.value
                else:
                    # Stay in CRAWLING until detection phase moves it forward
                    # For now, mark as COMPLETED since we don't have detectors yet
                    scan.status = ScanStatus.COMPLETED.value

                scan.completed_at = end_time
                scan.stats = stats
                await db.commit()

        logger.info(
            "Crawl complete: %d pages, %d endpoints in %.1fs",
            stats["pages_visited"],
            stats["endpoints_found"],
            stats["duration_seconds"],
        )

        return stats

    def _make_session_guard(self, auth_handler: AuthHandler, auth_config: dict, browser, stats: dict):
        """
        Build the Spider's session guard: when a page (other than the login page
        itself) lands on the login page, the session was lost — log in again.
        """
        login_key = _path_key(auth_config["login_url"])

        async def guard(requested_url: str, landed_url: str) -> bool:
            if _path_key(landed_url) != login_key or _path_key(requested_url) == login_key:
                return False
            if self._relogins >= MAX_RELOGINS:
                return False

            self._relogins += 1
            stats["relogins"] = self._relogins
            logger.warning(
                "Session lost at %s — re-authenticating (%d/%d)",
                requested_url, self._relogins, MAX_RELOGINS,
            )
            success = await auth_handler.login(auth_config)
            browser.clear_captured_requests()
            if not success:
                stats["errors"].append(f"Re-authentication failed at {requested_url}")
            return success

        return guard

    async def _mark_auth_required(
        self,
        browser: BrowserManager,
        endpoints: list[DiscoveredEndpoint],
        login_url: str,
        excluder: UrlExcluder,
    ):
        """
        Re-request each GET endpoint without cookies. If the anonymous request is
        refused (401/403) or redirected to the login page, it requires auth.

        Only GET endpoints are checked (replaying POSTs is not safe), and URLs the
        crawler is not allowed to visit are skipped.
        """
        login_key = _path_key(login_url)
        context = await browser.new_anonymous_request_context()
        try:
            for ep in endpoints:
                if self._cancelled:
                    break
                if ep.method.upper() != "GET" or excluder.is_excluded(ep.url):
                    continue
                if _path_key(ep.url) == login_key:
                    continue
                try:
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

    async def _load_scan_and_target(
        self, db: AsyncSession
    ) -> tuple[Scan | None, Target | None]:
        """Load the scan and its associated target from DB."""
        result = await db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = result.scalar_one_or_none()

        if not scan:
            logger.error("Scan %s not found", self.scan_id)
            return None, None

        result = await db.execute(
            select(Target).where(Target.id == scan.target_id)
        )
        target = result.scalar_one_or_none()

        if not target:
            logger.error("Target %s not found for scan %s", scan.target_id, self.scan_id)
            return None, None

        return scan, target

    async def _store_endpoints(
        self, db: AsyncSession, endpoints: list[DiscoveredEndpoint]
    ):
        """Store discovered endpoints in the database."""
        count = 0
        for ep in endpoints:
            endpoint = Endpoint(
                scan_id=self.scan_id,
                url=ep.url,
                method=ep.method,
                params=ep.params,
                auth_required=ep.auth_required,
                source=ep.source,
            )
            db.add(endpoint)
            count += 1

        await db.commit()
        logger.info("Stored %d endpoints in DB", count)

    async def _update_scan_stats(
        self, db: AsyncSession, pages_visited: int, endpoints_found: int
    ):
        """Update scan stats in DB (called periodically during crawl)."""
        result = await db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = result.scalar_one_or_none()
        if scan:
            scan.stats = {
                "pages_visited": pages_visited,
                "endpoints_found": endpoints_found,
            }
            await db.commit()
