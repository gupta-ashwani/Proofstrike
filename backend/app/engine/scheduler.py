"""
Continuous scanning scheduler.

This is the "continuous" half of ProofStrike: give it a target with a schedule and
it re-runs the full VAPT pipeline at a fixed interval, so findings stay current and
each run can be diffed against the last.

It runs as a background asyncio task on the API server's own event loop (started in
app.main's lifespan). On each tick it finds targets whose schedule is enabled and
due, mints a new Scan row, and hands it to `launch` — the same launch_scan() the API
uses, which runs the pipeline on its own Proactor thread. The scheduler itself never
launches Playwright, so it is safe on the server's SelectorEventLoop (Windows).

Rules:
  - A target is *due* when schedule_enabled is set and next_scan_at has passed.
  - A target that already has a non-terminal scan is skipped this tick so runs never
    pile up; next_scan_at is only advanced once a run is actually launched, so the
    deferred run fires on a later tick once the previous one finishes.
  - A missed window (server was down past next_scan_at) is simply due on the next
    tick — it fires once, not once per window missed.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database import async_session
from app.models.scan import Scan, ScanStatus
from app.models.target import Target

logger = logging.getLogger("proofstrike.engine.scheduler")

# How often the scheduler wakes to look for due targets.
TICK_SECONDS = 30

# Scan statuses that count as "still running" — a target with one of these is not
# launched again until it clears.
_ACTIVE_STATUSES = (
    ScanStatus.QUEUED.value,
    ScanStatus.CRAWLING.value,
    ScanStatus.TESTING.value,
    ScanStatus.VERIFYING.value,
)


async def _due_targets(db) -> list[Target]:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(Target).where(
            Target.schedule_enabled.is_(True),
            Target.scan_interval_minutes.is_not(None),
            Target.next_scan_at.is_not(None),
            Target.next_scan_at <= now,
        )
    )
    return list(result.scalars().all())


async def _has_active_scan(db, target_id: str) -> bool:
    result = await db.execute(
        select(Scan.id)
        .where(Scan.target_id == target_id, Scan.status.in_(_ACTIVE_STATUSES))
        .limit(1)
    )
    return result.first() is not None


async def tick(launch) -> int:
    """
    Run one scheduler pass. `launch` is a callable(scan_id) that starts the scan
    pipeline (normally app.routers.crawler.launch_scan). Returns how many scans were
    launched — handy for tests.
    """
    launched = 0
    async with async_session() as db:
        for target in await _due_targets(db):
            if await _has_active_scan(db, target.id):
                logger.debug(
                    "Target %s is due but a scan is already active; deferring",
                    target.id[:8],
                )
                continue

            now = datetime.now(timezone.utc)
            scan = Scan(
                target_id=target.id,
                status=ScanStatus.QUEUED.value,
                config=target.schedule_config,
            )
            db.add(scan)
            target.last_scheduled_scan_at = now
            target.next_scan_at = now + timedelta(
                minutes=target.scan_interval_minutes
            )
            await db.commit()
            await db.refresh(scan)

            logger.info(
                "Scheduler launched scan %s for target %s; next run due %s",
                scan.id[:8], target.id[:8], target.next_scan_at.isoformat(),
            )
            launch(scan.id)
            launched += 1
    return launched


async def run_scheduler(stop_event: asyncio.Event, launch) -> None:
    """
    Tick every TICK_SECONDS until `stop_event` is set. A failing tick is logged and
    the loop continues — a bad target never kills the scheduler.
    """
    logger.info("Continuous scan scheduler started (tick=%ss)", TICK_SECONDS)
    try:
        while not stop_event.is_set():
            try:
                await tick(launch)
            except Exception:
                logger.exception("Scheduler tick failed")
            # Sleep until the next tick, but wake immediately on shutdown.
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=TICK_SECONDS)
            except asyncio.TimeoutError:
                pass
    finally:
        logger.info("Continuous scan scheduler stopped")
