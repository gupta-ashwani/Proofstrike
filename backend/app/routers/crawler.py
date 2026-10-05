"""
Crawler router — trigger and monitor crawl jobs for scans.
"""

import logging
import threading

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db, make_engine, make_session_factory
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.engine.crawler.engine import CrawlerEngine
from app.engine.runner import start_in_thread

logger = logging.getLogger("proofstrike.routers.crawler")

router = APIRouter(prefix="/api/scans", tags=["Crawler"])

# Track running crawlers for cancellation (accessed from request handlers and crawler threads)
_active_crawlers: dict[str, CrawlerEngine] = {}
_active_lock = threading.Lock()

# Scan states from which a (re-)crawl may be started
RECRAWLABLE_STATUSES = (
    ScanStatus.QUEUED.value,
    ScanStatus.COMPLETED.value,
    ScanStatus.FAILED.value,
    ScanStatus.STOPPED.value,
)


async def _run_crawler(engine: CrawlerEngine):
    """Runs on the crawler's own thread/event loop, so it needs its own DB engine."""
    db_engine = make_engine()
    try:
        stats = await engine.run(make_session_factory(db_engine))
        logger.info("Crawl finished for scan %s: %s", engine.scan_id[:8], stats)
    except Exception as e:
        logger.error("Crawl failed for scan %s: %s", engine.scan_id[:8], e, exc_info=True)
    finally:
        await db_engine.dispose()
        with _active_lock:
            _active_crawlers.pop(engine.scan_id, None)


def launch_crawler(scan_id: str) -> bool:
    """
    Start the crawler for a scan on a background thread.

    Returns False if a crawler is already running for this scan.
    """
    with _active_lock:
        if scan_id in _active_crawlers:
            return False
        engine = CrawlerEngine(scan_id=scan_id)
        _active_crawlers[scan_id] = engine

    start_in_thread(f"crawler-{scan_id[:8]}", lambda: _run_crawler(engine))
    return True


@router.post("/{scan_id}/crawl", status_code=202)
async def start_crawl(scan_id: str, db: AsyncSession = Depends(get_db)):
    """
    Trigger (or re-run) the crawler for a scan.

    The crawler runs in the background — this endpoint returns immediately.
    Endpoints from a previous crawl of this scan are replaced.
    Monitor progress via GET /api/scans/{scan_id}/progress.
    """
    # Verify scan exists and is in a valid state
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in RECRAWLABLE_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Scan is in '{scan.status}' state — can only crawl from "
                   f"{', '.join(repr(s) for s in RECRAWLABLE_STATUSES)}",
        )

    # Verify target exists
    result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if not launch_crawler(scan_id):
        raise HTTPException(status_code=409, detail="Crawler already running for this scan")

    return {
        "message": "Crawler started",
        "scan_id": scan_id,
        "target_url": target.base_url,
        "config": scan.config,
    }


def cancel_crawler(scan_id: str) -> bool:
    with _active_lock:
        engine = _active_crawlers.get(scan_id)
    if engine:
        engine.cancel()
        return True
    return False

@router.post("/{scan_id}/crawl/stop", status_code=200)
async def stop_crawl(scan_id: str):
    """Stop a running crawler."""
    if not cancel_crawler(scan_id):
        raise HTTPException(status_code=404, detail="No active crawler for this scan")

    return {"message": "Crawler stop signal sent", "scan_id": scan_id}
