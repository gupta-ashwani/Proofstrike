"""
Crawler router — trigger and monitor crawl jobs for scans.
"""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.engine.crawler.engine import CrawlerEngine

logger = logging.getLogger("proofstrike.routers.crawler")

router = APIRouter(prefix="/api/scans", tags=["Crawler"])

# Track running crawlers for cancellation
_active_crawlers: dict[str, CrawlerEngine] = {}


async def run_crawler(scan_id: str, config: dict | None = None):
    """Background task that runs the crawler engine."""
    max_depth = (config or {}).get("max_depth", 5)
    max_pages = (config or {}).get("max_pages", 100)
    headless = (config or {}).get("headless", True)

    engine = CrawlerEngine(
        scan_id=scan_id,
        headless=headless,
        max_depth=max_depth,
        max_pages=max_pages,
    )
    _active_crawlers[scan_id] = engine

    try:
        stats = await engine.run()
        logger.info("Crawl finished for scan %s: %s", scan_id[:8], stats)
    except Exception as e:
        logger.error("Crawl failed for scan %s: %s", scan_id[:8], e)
    finally:
        _active_crawlers.pop(scan_id, None)


@router.post("/{scan_id}/crawl", status_code=202)
async def start_crawl(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger the crawler for a scan.

    The crawler runs as a background task — this endpoint returns immediately.
    Monitor progress via GET /api/scans/{scan_id}/progress.
    """
    # Verify scan exists and is in a valid state
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in (ScanStatus.QUEUED.value, ScanStatus.COMPLETED.value):
        raise HTTPException(
            status_code=400,
            detail=f"Scan is in '{scan.status}' state — can only crawl from 'queued' or 'completed'",
        )

    # Check if already running
    if scan_id in _active_crawlers:
        raise HTTPException(status_code=409, detail="Crawler already running for this scan")

    # Verify target exists
    result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Launch crawler in background
    background_tasks.add_task(run_crawler, scan_id, scan.config)

    return {
        "message": "Crawler started",
        "scan_id": scan_id,
        "target_url": target.base_url,
        "config": scan.config,
    }


def cancel_crawler(scan_id: str) -> bool:
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
