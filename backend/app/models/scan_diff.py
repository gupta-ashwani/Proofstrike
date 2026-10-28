"""
ScanDiff model — the delta between a completed scan and the target's previous one.

This is the "differential" half of ProofStrike: after each scan completes, its
confirmed findings are compared against the previous completed scan for the same
target, and the result is persisted here as NEW / FIXED / UNCHANGED sets. The
dashboard reads this to show "what changed since last time" instead of the full
list every run.

One row per scan (scan_id is unique). `data` holds the three lists of finding
summaries; the counts are duplicated as columns so a target's trend can be listed
cheaply without unpacking JSON. `is_baseline` is True when there was no previous
completed scan to diff against (the first run establishes the inventory).
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Integer, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.sqlite import JSON

from app.database import Base, UTCDateTime


class ScanDiff(Base):
    __tablename__ = "scan_diffs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False, unique=True,
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    # The scan this one was compared against (None on the baseline run).
    previous_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    is_baseline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    new_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fixed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unchanged_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # {"new": [item...], "fixed": [item...], "unchanged": [item...]}
    # each item: {fingerprint, type, severity, title, finding_id}
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return (
            f"<ScanDiff scan={self.scan_id[:8]} +{self.new_count}"
            f" -{self.fixed_count} ={self.unchanged_count}>"
        )
