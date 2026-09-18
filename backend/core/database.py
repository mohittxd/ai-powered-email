"""
SQLAlchemy async engine and session factory.
"""
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from core.config import settings


engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create all tables on startup."""
    async with engine.begin() as conn:
        from core import models  # noqa — import to register models
        await conn.run_sync(Base.metadata.create_all)
        # Keep existing local/PostgreSQL installations upgradeable without
        # dropping data or requiring a destructive rebuild.
        if "sqlite" in settings.database_url:
            columns = await conn.exec_driver_sql("PRAGMA table_info(emails)")
            names = {row[1] for row in columns}
            if "owner_id" not in names:
                await conn.exec_driver_sql("ALTER TABLE emails ADD COLUMN owner_id VARCHAR(36)")
            for column, definition in (
                ("gmail_message_id", "VARCHAR(255)"),
                ("gmail_thread_id", "VARCHAR(255)"),
                ("gmail_labels", "JSON"),
            ):
                if column not in names:
                    await conn.exec_driver_sql(
                        f"ALTER TABLE emails ADD COLUMN {column} {definition}"
                    )

            user_columns = await conn.exec_driver_sql("PRAGMA table_info(users)")
            user_names = {row[1] for row in user_columns}
            for column, definition in (
                ("google_id", "VARCHAR(255)"),
                ("profile_picture", "TEXT"),
                ("is_active", "BOOLEAN NOT NULL DEFAULT 1"),
                ("last_login", "DATETIME"),
            ):
                if column not in user_names:
                    await conn.exec_driver_sql(
                        f"ALTER TABLE users ADD COLUMN {column} {definition}"
                    )

            gmail_columns = await conn.exec_driver_sql("PRAGMA table_info(gmail_connections)")
            gmail_names = {row[1] for row in gmail_columns}
            for column, definition in (
                ("last_sync_at", "DATETIME"),
                ("last_sync_stats", "JSON"),
            ):
                if column not in gmail_names:
                    await conn.exec_driver_sql(
                        f"ALTER TABLE gmail_connections ADD COLUMN {column} {definition}"
                    )
        else:
            # Existing PostgreSQL deployments may predate the additive auth and
            # Gmail metadata migration. Add only missing columns/indexes.
            await conn.exec_driver_sql(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255)"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture TEXT"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP"
            )
            await conn.exec_driver_sql(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_google_id ON users (google_id)"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE emails ADD COLUMN IF NOT EXISTS gmail_message_id VARCHAR(255)"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE emails ADD COLUMN IF NOT EXISTS gmail_thread_id VARCHAR(255)"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE emails ADD COLUMN IF NOT EXISTS gmail_labels JSON"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE emails ADD COLUMN IF NOT EXISTS owner_id VARCHAR(36)"
            )
            await conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_emails_owner_id ON emails (owner_id)"
            )
            await conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_emails_gmail_message_id ON emails (gmail_message_id)"
            )
            await conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_emails_gmail_thread_id ON emails (gmail_thread_id)"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE gmail_connections ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMP"
            )
            await conn.exec_driver_sql(
                "ALTER TABLE gmail_connections ADD COLUMN IF NOT EXISTS last_sync_stats JSON"
            )
