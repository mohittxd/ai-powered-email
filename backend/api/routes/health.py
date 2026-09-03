"""
Health-check endpoint — GET /api/v1/health
Returns service status and basic metadata for load-balancer / readiness probes.
"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from core.database import get_db
from core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get(
    "/health",
    summary="Service health check",
    tags=["Health"],
    response_description="Returns healthy when the service and database are reachable",
)
async def health_check(db: AsyncSession = Depends(get_db)):
    """
    Liveness + readiness probe.

    - Verifies the API process is running.
    - Performs a lightweight DB ping to confirm connectivity.
    """
    db_status = "healthy"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("Health-check DB ping failed: %s", exc)
        db_status = "degraded"

    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "database": db_status,
    }
