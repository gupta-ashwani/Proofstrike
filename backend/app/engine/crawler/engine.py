"""
Crawler Engine — orchestrator that ties browser, auth, spider, and extractor.

This is the main entry point for Phase 3.
Given a scan_id, it:
  1. Loads the target and scan from DB
  2. Launches browser
  3. Performs authentication (if configured)
  4. Spiders the application (BFS)
  5. Extracts endpoints from DOM + network traffic
  6. Stores everything in the Endpoint table
  7. Updates scan status and stats
"""

import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.models.endpoint import Endpoint

from app.engine.crawler.browser import BrowserManager
from app.engine.crawler.auth import AuthHandler, AuthConfig
from app.engine.crawler.spider import Spider
from app.engine.crawler.endpoint_extractor import EndpointExtractor, DiscoveredEndpoint

logger = logging.getLogger("proofstrike.crawler.engine")




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

    def cancel(self):
        """Cancel a running crawl."""
        self._cancelled = True
        if self._spider:
            self._spider.cancel()

    async def run(self) -> dict:
        """
        Execute the full crawl pipeline.

        Returns a stats dict with crawl metrics.
        """
        stats = {
            "pages_visited": 0,
            "endpoints_found": 0,
            "auth_success": None,
            "errors": [],
            "duration_seconds": 0,
        }

        start_time = datetime.now(timezone.utc)

        # ── 1. Load scan and target from DB ──
        async with async_session() as db:
            scan, target = await self._load_scan_and_target(db)
            if not scan or not target:
                return stats

            # Update scan status to CRAWLING
            scan.status = ScanStatus.CRAWLING.value
            scan.started_at = start_time
            await db.commit()

        # NOTE: We can access scan and target after the session closes because
        # expire_on_commit=False is set in our async_sessionmaker in database.py.
        base_url = target.base_url.rstrip("/")
        auth_config = target.auth_config
        base_domain = urlparse(base_url).netloc

        # Apply scan config overrides
        scan_config = scan.config or {}
        max_depth = scan_config.get("max_depth") or scan_config.get("crawl_depth") or self.max_depth
        max_pages = scan_config.get("max_pages") or scan_config.get("request_budget") or self.max_pages
        headless = scan_config.get("headless", self.headless)

        logger.info(
            "Starting crawl: scan=%s target=%s url=%s depth=%d pages=%d",
            self.scan_id[:8], target.name, base_url, max_depth, max_pages,
        )

        all_discovered: list[DiscoveredEndpoint] = []

        try:
            # ── 2. Launch browser ──
            async with BrowserManager(headless=headless) as browser:
                page = await browser.new_page()

                # ── 3. Authentication ──
                if AuthConfig.is_configured(auth_config):
                    logger.info("Auth config detected — performing login")
                    auth_handler = AuthHandler(page)
                    auth_success = await auth_handler.login(auth_config)
                    stats["auth_success"] = auth_success

                    if not auth_success:
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
                )

                extractor = EndpointExtractor(page=page, base_domain=base_domain)
                pages_visited = 0

                async for crawl_result in self._spider.crawl():
                    if self._cancelled:
                        break

                    pages_visited += 1

                    if crawl_result.error:
                        stats["errors"].append(
                            f"{crawl_result.url}: {crawl_result.error}"
                        )
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
                        async with async_session() as db:
                            await self._update_scan_stats(
                                db, pages_visited, len(all_discovered)
                            )

                    logger.info(
                        "Page %d: %d DOM endpoints, %d network endpoints",
                        pages_visited, len(dom_endpoints), len(net_endpoints),
                    )

                stats["pages_visited"] = pages_visited

        except Exception as e:
            logger.error("Crawler error: %s", str(e), exc_info=True)
            stats["errors"].append(f"Crawler error: {str(e)}")

            # Set scan to FAILED
            async with async_session() as db:
                result = await db.execute(
                    select(Scan).where(Scan.id == self.scan_id)
                )
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED.value
                    scan.completed_at = datetime.now(timezone.utc)
                    scan.stats = stats
                    await db.commit()
            return stats

        # ── 6. Deduplicate and store endpoints ──
        unique_endpoints = EndpointExtractor.deduplicate(all_discovered)
        stats["endpoints_found"] = len(unique_endpoints)

        async with async_session() as db:
            await self._store_endpoints(db, unique_endpoints)

            # ── 7. Finalize scan ──
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
