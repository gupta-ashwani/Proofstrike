"""
Evidence model — proof artifacts attached to a finding.
"""

import uuid
from datetime import datetime, timezone
import enum

from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EvidenceType(str, enum.Enum):
    SCREENSHOT = "screenshot"
    REQUEST = "request"
    RESPONSE = "response"
    CURL = "curl"
    DOM_SNAPSHOT = "dom_snapshot"


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[str] = mapped_column(String(30), nullable=False)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    finding = relationship("Finding", back_populates="evidence_items")

    def __repr__(self) -> str:
        return f"<Evidence {self.type} for finding={self.finding_id[:8]}>"
