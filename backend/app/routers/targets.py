"""
Targets router — CRUD for web applications being tested.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database import get_db
from app.models.target import Target
from app.models.scan import Scan
from app.schemas.target import (
    TargetCreate,
    TargetUpdate,
    TargetResponse,
    TargetListResponse,
)

router = APIRouter(prefix="/api/targets", tags=["Targets"])


@router.get("", response_model=TargetListResponse)
async def list_targets(db: AsyncSession = Depends(get_db)):
    """List all registered targets."""
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    targets = result.scalars().all()

    target_responses = []
    for t in targets:
        # Count scans for this target
        count_result = await db.execute(
            select(func.count()).where(Scan.target_id == t.id)
        )
        scan_count = count_result.scalar() or 0

        target_responses.append(
            TargetResponse(
                id=t.id,
                name=t.name,
                base_url=t.base_url,
                auth_config=t.auth_config,
                created_at=t.created_at,
                updated_at=t.updated_at,
                scan_count=scan_count,
            )
        )

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

    return TargetResponse(
        id=target.id,
        name=target.name,
        base_url=target.base_url,
        auth_config=target.auth_config,
        created_at=target.created_at,
        updated_at=target.updated_at,
        scan_count=0,
    )


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single target by ID."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    count_result = await db.execute(
        select(func.count()).where(Scan.target_id == target.id)
    )
    scan_count = count_result.scalar() or 0

    return TargetResponse(
        id=target.id,
        name=target.name,
        base_url=target.base_url,
        auth_config=target.auth_config,
        created_at=target.created_at,
        updated_at=target.updated_at,
        scan_count=scan_count,
    )


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
    if payload.auth_config is not None:
        target.auth_config = payload.auth_config

    await db.flush()
    await db.refresh(target)

    count_result = await db.execute(
        select(func.count()).where(Scan.target_id == target.id)
    )
    scan_count = count_result.scalar() or 0

    return TargetResponse(
        id=target.id,
        name=target.name,
        base_url=target.base_url,
        auth_config=target.auth_config,
        created_at=target.created_at,
        updated_at=target.updated_at,
        scan_count=scan_count,
    )


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a target and all associated scans."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    await db.delete(target)
