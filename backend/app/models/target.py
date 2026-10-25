"""
Target model — represents a web application being tested.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Text, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.sqlite import JSON

from app.database import Base, UTCDateTime


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    auth_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # ── Continuous scanning schedule ──
    # When enabled, the background scheduler (app.engine.scheduler) re-runs a scan
    # against this target every `scan_interval_minutes`. schedule_config is the
    # Scan.config each scheduled run is launched with (detectors, crawl limits).
    # next_scan_at is when the next scheduled run is due; the scheduler advances it
    # by one interval after each launch. These are the only fields the scheduler
    # reads/writes — secrets still live only in auth_config / in-memory sessions.
    schedule_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    scan_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    schedule_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_scheduled_scan_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    next_scan_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Target {self.name} ({self.base_url})>"
