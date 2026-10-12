"""
Scans router — create, list, inspect, and control scan jobs.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timezone

from app.database import get_db
from app.models.target import Target
from app.models.scan import Scan, ScanStatus
from app.models.endpoint import Endpoint
from app.models.finding import Finding
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse, ScanProgress
from app.schemas.finding import (
    FindingResponse,
    FindingListResponse,
    EndpointResponse,
    EndpointListResponse,
)
from app.routers.crawler import launch_scan, cancel_scan

router = APIRouter(prefix="/api/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db)
):
    """Start a new scan against a target."""
    # Verify target exists
    result = await db.execute(select(Target).where(Target.id == payload.target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = Scan(
        target_id=payload.target_id,
        status=ScanStatus.QUEUED.value,
        config=payload.config,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch the crawler on its own background thread (see app.engine.runner).
    # The scan row is committed above, so the crawler thread can load it.
    launch_scan(scan.id)

    return ScanResponse(
        id=scan.id,
        target_id=scan.target_id,
        status=scan.status,
        config=scan.config,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        stats=scan.stats,
        created_at=scan.created_at,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(
    target_id: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all scans, optionally filtered by target or status."""
    query = select(Scan).order_by(Scan.created_at.desc())

    if target_id:
        query = query.where(Scan.target_id == target_id)
    if status:
        query = query.where(Scan.status == status)

    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(
        scans=[
            ScanResponse(
                id=s.id,
                target_id=s.target_id,
                status=s.status,
                config=s.config,
                started_at=s.started_at,
                completed_at=s.completed_at,
                stats=s.stats,
                created_at=s.created_at,
            )
            for s in scans
        ],
        total=len(scans),
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get details for a single scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse(
        id=scan.id,
        target_id=scan.target_id,
        status=scan.status,
        config=scan.config,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        stats=scan.stats,
        created_at=scan.created_at,
    )


@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get real-time progress for a running scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    endpoint_count = await db.execute(
        select(func.count()).where(Endpoint.scan_id == scan_id)
    )
    finding_count = await db.execute(
        select(func.count()).where(Finding.scan_id == scan_id)
    )

    elapsed = None
    if scan.started_at:
        end = scan.completed_at or datetime.now(timezone.utc)
        elapsed = (end - scan.started_at).total_seconds()

    return ScanProgress(
        id=scan.id,
        status=scan.status,
        endpoints_found=endpoint_count.scalar() or 0,
        findings_count=finding_count.scalar() or 0,
        elapsed_seconds=elapsed,
    )


@router.get("/{scan_id}/endpoints", response_model=EndpointListResponse)
async def get_scan_endpoints(scan_id: str, db: AsyncSession = Depends(get_db)):
    """List all endpoints discovered in a scan."""
    result = await db.execute(
        select(Endpoint)
        .where(Endpoint.scan_id == scan_id)
        .order_by(Endpoint.created_at)
    )
    endpoints = result.scalars().all()

    return EndpointListResponse(
        endpoints=[
            EndpointResponse(
                id=e.id,
                scan_id=e.scan_id,
                url=e.url,
                method=e.method,
                params=e.params,
                auth_required=e.auth_required,
                source=e.source,
                created_at=e.created_at,
            )
            for e in endpoints
        ],
        total=len(endpoints),
    )


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
async def get_scan_findings(scan_id: str, db: AsyncSession = Depends(get_db)):
    """List all findings for a scan."""
    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at.desc())
    )
    findings = result.scalars().all()

    return FindingListResponse(
        findings=[
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                endpoint_id=f.endpoint_id,
                type=f.type,
                severity=f.severity,
                status=f.status,
                title=f.title,
                description=f.description,
                reproduction_steps=f.reproduction_steps,
                remediation=f.remediation,
                created_at=f.created_at,
                evidence_items=[],
            )
            for f in findings
        ],
        total=len(findings),
    )


@router.post("/{scan_id}/stop", response_model=ScanResponse)
async def stop_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Stop a running scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    active_statuses = [
        ScanStatus.QUEUED.value,
        ScanStatus.CRAWLING.value,
        ScanStatus.TESTING.value,
        ScanStatus.VERIFYING.value,
    ]
    if scan.status not in active_statuses:
        raise HTTPException(status_code=400, detail="Scan is not active")

    scan.status = ScanStatus.STOPPED.value
    scan.completed_at = datetime.now(timezone.utc)
    
    # Cancel crawler if it's currently running
    cancel_scan(scan_id)
    
    await db.flush()
    await db.refresh(scan)

    return ScanResponse(
        id=scan.id,
        target_id=scan.target_id,
        status=scan.status,
        config=scan.config,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        stats=scan.stats,
        created_at=scan.created_at,
    )
