"""
Dashboard router — aggregated stats for the overview page.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database import get_db
from app.models.target import Target
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding, FindingStatus, Severity
from app.schemas.dashboard import DashboardStats, SeverityBreakdown

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get aggregated stats for the dashboard overview."""

    # Total targets
    total_targets = (
        await db.execute(select(func.count()).select_from(Target))
    ).scalar() or 0

    # Total scans
    total_scans = (
        await db.execute(select(func.count()).select_from(Scan))
    ).scalar() or 0

    # Active scans (queued, crawling, testing, verifying)
    active_statuses = [
        ScanStatus.QUEUED.value,
        ScanStatus.CRAWLING.value,
        ScanStatus.TESTING.value,
        ScanStatus.VERIFYING.value,
    ]
    active_scans = (
        await db.execute(
            select(func.count()).where(Scan.status.in_(active_statuses))
        )
    ).scalar() or 0

    # Total findings
    total_findings = (
        await db.execute(select(func.count()).select_from(Finding))
    ).scalar() or 0

    # Confirmed findings
    confirmed_findings = (
        await db.execute(
            select(func.count()).where(
                Finding.status == FindingStatus.CONFIRMED.value
            )
        )
    ).scalar() or 0

    # Severity breakdown (all findings, not just confirmed)
    severity_counts = {}
    for sev in Severity:
        count = (
            await db.execute(
                select(func.count()).where(Finding.severity == sev.value)
            )
        ).scalar() or 0
        severity_counts[sev.value] = count

    return DashboardStats(
        total_targets=total_targets,
        total_scans=total_scans,
        active_scans=active_scans,
        total_findings=total_findings,
        confirmed_findings=confirmed_findings,
        severity_breakdown=SeverityBreakdown(
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
            info=severity_counts.get("info", 0),
        ),
    )
