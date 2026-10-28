"""
Diff router — serve the scan-to-scan differential (what changed since last run).

Diffs are computed by the pipeline when a scan completes (app.engine.diff) and
stored in the scan_diffs table; these endpoints just read them back.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.scan_diff import ScanDiff
from app.schemas.scan import ScanDiffResponse

router = APIRouter(prefix="/api", tags=["Diff"])


def _to_response(diff: ScanDiff) -> ScanDiffResponse:
    data = diff.data or {}
    return ScanDiffResponse(
        scan_id=diff.scan_id,
        target_id=diff.target_id,
        previous_scan_id=diff.previous_scan_id,
        is_baseline=diff.is_baseline,
        new_count=diff.new_count,
        fixed_count=diff.fixed_count,
        unchanged_count=diff.unchanged_count,
        new=data.get("new", []),
        fixed=data.get("fixed", []),
        unchanged=data.get("unchanged", []),
        created_at=diff.created_at,
    )


@router.get("/scans/{scan_id}/diff", response_model=ScanDiffResponse)
async def get_scan_diff(scan_id: str, db: AsyncSession = Depends(get_db)):
    """The differential for one scan (vs the target's previous completed scan)."""
    diff = (
        await db.execute(select(ScanDiff).where(ScanDiff.scan_id == scan_id))
    ).scalar_one_or_none()
    if not diff:
        raise HTTPException(
            status_code=404,
            detail="No diff for this scan (it may not have completed yet)",
        )
    return _to_response(diff)


@router.get("/targets/{target_id}/diff/latest", response_model=ScanDiffResponse)
async def get_latest_target_diff(target_id: str, db: AsyncSession = Depends(get_db)):
    """The diff for this target's most recently completed scan — the dashboard view."""
    diff = (
        await db.execute(
            select(ScanDiff)
            .join(Scan, Scan.id == ScanDiff.scan_id)
            .where(
                ScanDiff.target_id == target_id,
                Scan.status == ScanStatus.COMPLETED.value,
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if not diff:
        raise HTTPException(status_code=404, detail="No completed scan to diff yet")
    return _to_response(diff)
