"""
Reports router — export a scan's results as JSON, HTML, or PDF (Phase 6).

All three share one data shape built by app.services.report_service. HTML is a
self-contained printable document; PDF is that HTML rendered by headless Chromium
(already a dependency), produced on its own event loop via a worker thread so it
never blocks the server loop.
"""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.evidence import Evidence  # noqa: F401  (ensures mapper is registered)
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.services import report_service

logger = logging.getLogger("proofstrike.routers.reports")

router = APIRouter(prefix="/api/scans", tags=["Reports"])


@router.get("/{scan_id}/report")
async def export_scan_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export a scan report as JSON (default), HTML, or PDF."""
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target = None
    if scan.target_id:
        target = (await db.execute(
            select(Target).where(Target.id == scan.target_id)
        )).scalar_one_or_none()

    findings = (await db.execute(
        select(Finding)
        .options(selectinload(Finding.evidence_items))
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at)
    )).scalars().all()

    report = report_service.build_report(scan, findings, target)

    if format == "json":
        return JSONResponse(content=report)

    html_doc = report_service.render_html(report)
    short = scan.id[:8]

    if format == "html":
        return HTMLResponse(
            content=html_doc,
            headers={"Content-Disposition": f'inline; filename="proofstrike-report-{short}.html"'},
        )

    # format == "pdf": render the HTML with Chromium on a worker thread (off the server loop).
    try:
        pdf_bytes = await asyncio.to_thread(report_service.render_pdf, html_doc)
    except Exception as e:  # Chromium missing/launch failure, etc.
        logger.exception("PDF render failed for scan %s", scan_id)
        raise HTTPException(
            status_code=500,
            detail=("PDF rendering failed. Ensure Chromium is installed for Playwright "
                    "(`python -m playwright install chromium`). "
                    f"Underlying error: {type(e).__name__}: {e}"),
        )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="proofstrike-report-{short}.pdf"'},
    )
