"""
Scan pipeline — orchestrates the stages of a scan.

    crawl  →  detect  →  verify  →  completed
  (CRAWLING)  (TESTING)  (VERIFYING)

The pipeline owns scan lifecycle: it sets started_at, moves the status to each
stage's phase, and writes the terminal status (completed / failed / stopped). Each
stage does its work against the shared ScanContext and raises on fatal errors.

Detect and verify are stubs for now — Phase 4 and Phase 5 fill them in.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import delete, select, update

from app.database import async_session
from app.engine.context import ScanContext
from app.engine.crawler.engine import CrawlStage
from app.engine.detect import DetectStage
from app.engine.verify import VerifyStage
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.models.endpoint import Endpoint
from app.models.finding import Finding

logger = logging.getLogger("proofstrike.engine.pipeline")


# Stage class → the status the scan should show while it runs
STAGE_STATUS = {
    "crawl": ScanStatus.CRAWLING.value,
    "detect": ScanStatus.TESTING.value,
    "verify": ScanStatus.VERIFYING.value,
}


class ScanPipeline:
    """Runs all stages of one scan. One instance per run; register it for cancellation."""

    def __init__(self, scan_id: str, session_factory=None):
        self.scan_id = scan_id
        self.session_factory = session_factory or async_session
        self._cancelled = False
        self._current_stage = None

    def cancel(self):
        self._cancelled = True
        if self._current_stage:
            self._current_stage.cancel()

    async def run(self) -> dict:
        start_time = datetime.now(timezone.utc)

        ctx = await self._begin(start_time)
        if ctx is None:
            return {}

        stages = [CrawlStage(), DetectStage(), VerifyStage()]
        try:
            for stage in stages:
                if self._cancelled:
                    break
                self._current_stage = stage
                await self._set_status(STAGE_STATUS[stage.name])
                await stage.run(ctx)
        except Exception as e:
            logger.error("Scan %s failed in %s stage: %s",
                         self.scan_id[:8], getattr(self._current_stage, "name", "?"), e,
                         exc_info=True)
            ctx.stats.setdefault("errors", []).append(f"{type(e).__name__}: {e}")
            await self._finalize(ctx, ScanStatus.FAILED.value, start_time)
            return ctx.stats

        final = ScanStatus.STOPPED.value if self._cancelled else ScanStatus.COMPLETED.value
        await self._finalize(ctx, final, start_time)
        logger.info("Scan %s finished: %s", self.scan_id[:8], final)
        return ctx.stats

    async def _begin(self, start_time) -> ScanContext | None:
        """Load scan+target, reset prior results, mark started. Returns the context."""
        async with self.session_factory() as db:
            scan = (await db.execute(select(Scan).where(Scan.id == self.scan_id))).scalar_one_or_none()
            if not scan:
                logger.error("Scan %s not found", self.scan_id)
                return None
            target = (await db.execute(select(Target).where(Target.id == scan.target_id))).scalar_one_or_none()
            if not target:
                logger.error("Target %s not found for scan %s", scan.target_id, self.scan_id)
                return None

            ctx = ScanContext.build(self.scan_id, self.session_factory, target, scan.config)

            # Fresh run: clear previous results of this scan
            await db.execute(delete(Finding).where(Finding.scan_id == self.scan_id))
            await db.execute(delete(Endpoint).where(Endpoint.scan_id == self.scan_id))

            scan.status = ScanStatus.CRAWLING.value
            scan.started_at = start_time
            scan.completed_at = None
            scan.stats = None
            await db.commit()

        return ctx

    async def _set_status(self, status: str):
        async with self.session_factory() as db:
            scan = (await db.execute(select(Scan).where(Scan.id == self.scan_id))).scalar_one_or_none()
            if scan:
                scan.status = status
                await db.commit()

    async def _finalize(self, ctx: ScanContext, status: str, start_time):
        end_time = datetime.now(timezone.utc)
        ctx.stats["duration_seconds"] = (end_time - start_time).total_seconds()
        async with self.session_factory() as db:
            scan = (await db.execute(select(Scan).where(Scan.id == self.scan_id))).scalar_one_or_none()
            if scan:
                scan.status = status
                scan.completed_at = end_time
                scan.stats = ctx.stats
                await db.commit()
