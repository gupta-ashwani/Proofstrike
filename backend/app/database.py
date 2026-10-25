"""
Database engine, session factory, and base model for SQLAlchemy.
Uses async SQLite for development.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import TypeDecorator

from app.config import settings


def make_engine():
    """
    Create an async engine for settings.DATABASE_URL.

    Async DB connections are bound to the event loop that created them, so the
    background scan threads (see app.engine.runner) each build their own engine.
    """
    connect_args = {}
    if settings.DATABASE_URL.startswith("sqlite"):
        # API and crawler threads write concurrently — wait for locks instead of failing
        connect_args["timeout"] = 30
    return create_async_engine(
        settings.DATABASE_URL, echo=settings.DEBUG, connect_args=connect_args
    )


def make_session_factory(db_engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)


engine = make_engine()

async_session = make_session_factory(engine)


class UTCDateTime(TypeDecorator):
    """
    Timezone-aware UTC datetime column.

    SQLite has no timezone support: DateTime(timezone=True) silently returns naive
    values, which breaks arithmetic against aware datetimes and makes the API emit
    timestamps without an offset (browsers then read UTC as local time).
    Values are stored as naive UTC and always returned as aware UTC.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is not None and value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value: datetime | None, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


async def get_db():
    """FastAPI dependency — yields an async database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db():
    """Create all tables on startup (dev convenience)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# Columns added to existing tables after the DB was first created. create_all()
# only creates missing *tables*, not missing *columns*, and dev has no Alembic
# migration step — so on startup we ALTER TABLE ADD COLUMN any that a pre-existing
# proofstrike.db is missing. Keep each DDL additive and give non-null columns a
# DEFAULT so existing rows migrate cleanly.
_SCHEMA_ADDITIONS: dict[str, dict[str, str]] = {
    "targets": {
        "schedule_enabled": "BOOLEAN NOT NULL DEFAULT 0",
        "scan_interval_minutes": "INTEGER",
        "schedule_config": "JSON",
        "last_scheduled_scan_at": "DATETIME",
        "next_scan_at": "DATETIME",
    },
}


def _apply_schema_additions(sync_conn):
    for table, columns in _SCHEMA_ADDITIONS.items():
        rows = sync_conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
        if not rows:
            continue  # table doesn't exist yet (create_all handles fresh DBs)
        existing = {r[1] for r in rows}
        for col, ddl in columns.items():
            if col not in existing:
                sync_conn.exec_driver_sql(
                    f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"
                )


async def ensure_schema():
    """Add any columns a pre-existing SQLite DB is missing (see _SCHEMA_ADDITIONS)."""
    async with engine.begin() as conn:
        await conn.run_sync(_apply_schema_additions)
