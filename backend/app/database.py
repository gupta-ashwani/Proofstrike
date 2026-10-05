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
