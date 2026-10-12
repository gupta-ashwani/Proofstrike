"""
Crawler router — trigger and monitor scan runs (crawl → detect → verify).
"""

import logging
import threading

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db, make_engine, make_session_factory
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.engine.pipeline import ScanPipeline
from app.engine.runner import start_in_thread

logger = logging.getLogger("proofstrike.routers.crawler")

router = APIRouter(prefix="/api/scans", tags=["Crawler"])

# Track running scans for cancellation (accessed from request handlers and scan threads)
_active_scans: dict[str, ScanPipeline] = {}
_active_lock = threading.Lock()

# Scan states from which a (re-)run may be started
RERUNNABLE_STATUSES = (
    ScanStatus.QUEUED.value,
    ScanStatus.COMPLETED.value,
    ScanStatus.FAILED.value,
    ScanStatus.STOPPED.value,
)


async def _run_pipeline(pipeline: ScanPipeline):
    """Runs on the scan's own thread/event loop, so it needs its own DB engine."""
    db_engine = make_engine()
    try:
        pipeline.session_factory = make_session_factory(db_engine)
        stats = await pipeline.run()
        logger.info("Scan finished for %s: %s", pipeline.scan_id[:8], stats)
    except Exception as e:
        logger.error("Scan failed for %s: %s", pipeline.scan_id[:8], e, exc_info=True)
    finally:
        await db_engine.dispose()
        with _active_lock:
            _active_scans.pop(pipeline.scan_id, None)


def launch_scan(scan_id: str) -> bool:
    """
    Start the scan pipeline on a background thread.

    Returns False if the scan is already running.
    """
    with _active_lock:
        if scan_id in _active_scans:
            return False
        pipeline = ScanPipeline(scan_id=scan_id)
        _active_scans[scan_id] = pipeline

    start_in_thread(f"scan-{scan_id[:8]}", lambda: _run_pipeline(pipeline))
    return True


def cancel_scan(scan_id: str) -> bool:
    with _active_lock:
        pipeline = _active_scans.get(scan_id)
    if pipeline:
        pipeline.cancel()
        return True
    return False


@router.post("/{scan_id}/crawl", status_code=202)
async def start_crawl(scan_id: str, db: AsyncSession = Depends(get_db)):
    """
    Trigger (or re-run) the full scan pipeline for a scan.

    Runs in the background — this endpoint returns immediately. Results from a
    previous run of this scan are replaced. Monitor via GET /api/scans/{id}/progress.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in RERUNNABLE_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Scan is in '{scan.status}' state — can only run from "
                   f"{', '.join(repr(s) for s in RERUNNABLE_STATUSES)}",
        )

    result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if not launch_scan(scan_id):
        raise HTTPException(status_code=409, detail="Scan already running")

    return {
        "message": "Scan started",
        "scan_id": scan_id,
        "target_url": target.base_url,
        "config": scan.config,
    }


@router.post("/{scan_id}/crawl/stop", status_code=200)
async def stop_crawl(scan_id: str):
    """Stop a running scan."""
    if not cancel_scan(scan_id):
        raise HTTPException(status_code=404, detail="No active scan to stop")

    return {"message": "Scan stop signal sent", "scan_id": scan_id}
