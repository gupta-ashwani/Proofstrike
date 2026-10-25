"""
Findings router — list, inspect, and update vulnerability findings.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.finding import Finding, FindingStatus, Severity
from app.models.evidence import Evidence
from app.schemas.finding import (
    FindingResponse,
    FindingListResponse,
    FindingUpdate,
    EvidenceResponse,
)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get("", response_model=FindingListResponse)
async def list_findings(
    type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all findings with optional filters."""
    query = select(Finding).order_by(Finding.created_at.desc())

    if type:
        query = query.where(Finding.type == type)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)

    result = await db.execute(query)
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


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single finding with all its evidence."""
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.evidence_items))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        endpoint_id=finding.endpoint_id,
        type=finding.type,
        severity=finding.severity,
        status=finding.status,
        title=finding.title,
        description=finding.description,
        reproduction_steps=finding.reproduction_steps,
        remediation=finding.remediation,
        created_at=finding.created_at,
        evidence_items=[
            EvidenceResponse(
                id=e.id,
                type=e.type,
                content=e.content,
                file_path=e.file_path,
                created_at=e.created_at,
            )
            for e in finding.evidence_items
        ],
    )


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str, payload: FindingUpdate, db: AsyncSession = Depends(get_db)
):
    """Update a finding's status or severity (e.g. mark as false positive)."""
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.evidence_items))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if payload.status is not None:
        allowed = {s.value for s in FindingStatus}
        if payload.status not in allowed:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status '{payload.status}'. Allowed: {sorted(allowed)}",
            )
        finding.status = payload.status
    if payload.severity is not None:
        allowed_sev = {s.value for s in Severity}
        if payload.severity not in allowed_sev:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity '{payload.severity}'. Allowed: {sorted(allowed_sev)}",
            )
        finding.severity = payload.severity

    await db.flush()
    await db.refresh(finding)

    return FindingResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        endpoint_id=finding.endpoint_id,
        type=finding.type,
        severity=finding.severity,
        status=finding.status,
        title=finding.title,
        description=finding.description,
        reproduction_steps=finding.reproduction_steps,
        remediation=finding.remediation,
        created_at=finding.created_at,
        evidence_items=[
            EvidenceResponse(
                id=e.id,
                type=e.type,
                content=e.content,
                file_path=e.file_path,
                created_at=e.created_at,
            )
            for e in finding.evidence_items
        ],
    )
