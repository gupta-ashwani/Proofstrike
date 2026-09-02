"""
Reports router — export scan results as JSON/HTML/PDF.
(Placeholder for Phase 6 — currently returns JSON only.)
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.evidence import Evidence

router = APIRouter(prefix="/api/scans", tags=["Reports"])


@router.get("/{scan_id}/report")
async def export_scan_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export a scan report. Currently supports JSON; HTML/PDF coming in Phase 6."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get findings with evidence
    findings_result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.evidence_items))
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at)
    )
    findings = findings_result.scalars().all()

    report = {
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "status": scan.status,
        "started_at": str(scan.started_at) if scan.started_at else None,
        "completed_at": str(scan.completed_at) if scan.completed_at else None,
        "stats": scan.stats,
        "findings": [
            {
                "id": f.id,
                "type": f.type,
                "severity": f.severity,
                "status": f.status,
                "title": f.title,
                "description": f.description,
                "reproduction_steps": f.reproduction_steps,
                "remediation": f.remediation,
                "evidence": [
                    {
                        "type": e.type,
                        "content": e.content,
                        "file_path": e.file_path,
                    }
                    for e in f.evidence_items
                ],
            }
            for f in findings
        ],
        "total_findings": len(findings),
    }

    if format == "json":
        return JSONResponse(content=report)

    # HTML and PDF will be implemented in Phase 6
    raise HTTPException(
        status_code=501,
        detail=f"{format.upper()} export not yet implemented. Coming in Phase 6.",
    )
