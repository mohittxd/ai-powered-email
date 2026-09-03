"""
FastAPI application entrypoint — ForensicAI v3.0.0
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.database import init_db
from core.logging_config import setup_logging
from api.routes import emails, cases, reports, iocs, audit, auth, users, campaigns, health


logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("ForensicAI starting up…")
    await init_db()
    os.makedirs(settings.upload_dir, exist_ok=True)
    logger.info("Database ready. Upload dir: %s", settings.upload_dir)
    yield
    logger.info("ForensicAI shutting down.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    description=(
        "AI-powered email threat detection, geolocation tracing, and forensic intelligence. "
        "For defensive security use only — SOC teams, email admins, law enforcement support."
    ),
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global exception handlers ────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url)
    # Safe error handling, only expose details if debug=True
    err_msg = str(exc) if settings.debug else "Internal server error occurred."
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": err_msg},
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Not found", "detail": str(request.url)},
    )

# ── Routers ───────────────────────────────────────────────────────────────────

API_PREFIX = "/api/v1"

app.include_router(health.router,    prefix=API_PREFIX, tags=["Health"])
app.include_router(emails.router,    prefix=API_PREFIX, tags=["Email Analysis"])
app.include_router(cases.router,     prefix=API_PREFIX, tags=["Case Management"])
app.include_router(reports.router,   prefix=API_PREFIX, tags=["Reports"])
app.include_router(iocs.router,      prefix=API_PREFIX, tags=["IOC Database"])
app.include_router(audit.router,     prefix=API_PREFIX, tags=["Audit Log"])
app.include_router(auth.router,      prefix=API_PREFIX, tags=["Auth"])
app.include_router(users.router,     prefix=API_PREFIX, tags=["User & System Management"])
app.include_router(campaigns.router, prefix=API_PREFIX, tags=["Campaigns"])



# ── Root ──────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Root"])
async def root():
    return {
        "platform": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "docs": "/docs",
        "health": "/api/v1/health",
    }


@app.get("/health", tags=["Root"])
async def root_health():
    """Legacy root-level health probe — kept for backward compat."""
    return {"status": "ok"}
