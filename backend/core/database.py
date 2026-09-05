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
    """Create all tables on startup and seed demo users."""
    from core import models
    from core.rbac import hash_password
    from sqlalchemy import select

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        demo_users = [
            {
                "id": "u-001",
                "email": "admin@forensics.local",
                "name": "Admin User",
                "role": "admin",
                "password": "admin123",
            },
            {
                "id": "u-002",
                "email": "analyst@forensics.local",
                "name": "Demo Analyst",
                "role": "analyst",
                "password": "analyst123",
            },
            {
                "id": "u-003",
                "email": "investigator@forensics.local",
                "name": "IR Investigator",
                "role": "investigator",
                "password": "ir2026",
            },
        ]

        for demo in demo_users:
            result = await session.execute(
                select(models.User).where(models.User.id == demo["id"])
            )
            user = result.scalar_one_or_none()

            if user is None:
                session.add(
                    models.User(
                        id=demo["id"],
                        email=demo["email"],
                        name=demo["name"],
                        role=demo["role"],
                        hashed_password=hash_password(demo["password"]),
                    )
                )

        await session.commit()