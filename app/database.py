"""
AEGIS Database Module
SQLAlchemy async engine and session management.
Supports SQLite (dev) and PostgreSQL (prod).
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool
from .config import settings


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


# Create async engine with appropriate settings for SQLite or PostgreSQL
if settings.database_url.startswith("sqlite"):
    # SQLite needs special handling for async
    engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # Single connection for SQLite
    )
else:
    # PostgreSQL or other databases
    engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )

# Async session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncSession:
    """
    Dependency that provides a database session.
    Automatically closes session after request completes.
    """
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """
    Initialize database tables.
    Called on application startup.
    """
    async with engine.begin() as conn:
        # Import models to ensure they're registered with Base
        from . import models  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)
        await _apply_sqlite_migrations(conn)


async def _apply_sqlite_migrations(conn):
    """Lightweight column adds for existing SQLite dev databases."""
    if not settings.database_url.startswith("sqlite"):
        return

    from sqlalchemy import text

    def migrate(sync_conn):
        rows = sync_conn.execute(text("PRAGMA table_info(chat_sessions)")).fetchall()
        columns = {row[1] for row in rows}
        if "security_threshold_preset" not in columns:
            sync_conn.execute(
                text(
                    "ALTER TABLE chat_sessions "
                    "ADD COLUMN security_threshold_preset VARCHAR(20) DEFAULT 'balanced'"
                )
            )
        if "completion_mode" not in columns:
            sync_conn.execute(
                text(
                    "ALTER TABLE chat_sessions "
                    "ADD COLUMN completion_mode VARCHAR(20) DEFAULT 'balanced'"
                )
            )
        if "workflow_meta" not in columns:
            sync_conn.execute(
                text(
                    "ALTER TABLE chat_sessions "
                    "ADD COLUMN workflow_meta TEXT DEFAULT '{}'"
                )
            )

    await conn.run_sync(migrate)


async def close_db():
    """
    Close database connections.
    Called on application shutdown.
    """
    await engine.dispose()
