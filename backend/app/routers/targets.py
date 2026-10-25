"""
Targets router — CRUD for web applications being tested.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database import get_db
from app.models.target import Target
from app.models.scan import Scan
from app.schemas.target import (
    TargetCreate,
    TargetUpdate,
    ScheduleUpdate,
    TargetResponse,
    TargetListResponse,
)
from app.services.credentials import mask_auth_config, merge_masked_secrets

router = APIRouter(prefix="/api/targets", tags=["Targets"])


async def _scan_count(db: AsyncSession, target_id: str) -> int:
    result = await db.execute(
        select(func.count()).where(Scan.target_id == target_id)
    )
    return result.scalar() or 0


def _to_response(target: Target, scan_count: int) -> TargetResponse:
    """Build the API view of a target (masking auth secrets, exposing the schedule)."""
    return TargetResponse(
        id=target.id,
        name=target.name,
        base_url=target.base_url,
        auth_config=mask_auth_config(target.auth_config),
        created_at=target.created_at,
        updated_at=target.updated_at,
        scan_count=scan_count,
        schedule_enabled=target.schedule_enabled,
        scan_interval_minutes=target.scan_interval_minutes,
        schedule_config=target.schedule_config,
        last_scheduled_scan_at=target.last_scheduled_scan_at,
        next_scan_at=target.next_scan_at,
    )


@router.get("", response_model=TargetListResponse)
async def list_targets(db: AsyncSession = Depends(get_db)):
    """List all registered targets."""
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    targets = result.scalars().all()

    target_responses = [
        _to_response(t, await _scan_count(db, t.id)) for t in targets
    ]

    return TargetListResponse(targets=target_responses, total=len(target_responses))


@router.post("", response_model=TargetResponse, status_code=201)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)):
    """Register a new target application."""
    target = Target(
        name=payload.name,
        base_url=payload.base_url,
        auth_config=payload.auth_config,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)

    return _to_response(target, 0)


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single target by ID."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    return _to_response(target, await _scan_count(db, target.id))


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: str, payload: TargetUpdate, db: AsyncSession = Depends(get_db)
):
    """Update a target's details."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if payload.name is not None:
        target.name = payload.name
    if payload.base_url is not None:
        target.base_url = payload.base_url
    # auth_config may be explicitly set to null to remove authentication
    if "auth_config" in payload.model_fields_set:
        target.auth_config = merge_masked_secrets(payload.auth_config, target.auth_config)

    await db.flush()
    await db.refresh(target)

    return _to_response(target, await _scan_count(db, target.id))


@router.put("/{target_id}/schedule", response_model=TargetResponse)
async def set_schedule(
    target_id: str, payload: ScheduleUpdate, db: AsyncSession = Depends(get_db)
):
    """
    Turn continuous scanning on or off for a target, and set its interval.

    Enabling schedules the first run to fire on the scheduler's next tick (so the
    user sees it start right away) and every `interval_minutes` thereafter;
    disabling clears the next-run time so nothing further is launched. In-flight
    scans are never interrupted here.
    """
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if payload.enabled:
        interval = payload.interval_minutes or target.scan_interval_minutes
        if interval is None:
            raise HTTPException(
                status_code=400,
                detail="interval_minutes is required to enable a schedule",
            )
        target.schedule_enabled = True
        target.scan_interval_minutes = interval
        if "config" in payload.model_fields_set:
            target.schedule_config = payload.config
        # Due immediately — the next scheduler tick launches the baseline run.
        target.next_scan_at = datetime.now(timezone.utc)
    else:
        target.schedule_enabled = False
        target.next_scan_at = None
        # Keep scan_interval_minutes / schedule_config so re-enabling is one click.

    await db.flush()
    await db.refresh(target)

    return _to_response(target, await _scan_count(db, target.id))


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a target and all associated scans."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    await db.delete(target)
