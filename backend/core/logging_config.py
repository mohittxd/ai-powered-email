"""
Centralised logging configuration for ForensicAI.
Call setup_logging() once at application startup.
"""
import logging
import sys
from core.config import settings


def setup_logging() -> None:
    """
    Configure root logger with a structured, coloured console handler.
    Level is controlled by LOG_LEVEL in .env (default: INFO).
    """
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(level)
    # Avoid duplicate handlers on hot-reload
    if not root.handlers:
        root.addHandler(handler)
    else:
        root.handlers.clear()
        root.addHandler(handler)

    # Quieten noisy third-party loggers
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.debug else logging.WARNING
    )
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    logging.getLogger(__name__).info(
        "Logging initialised — level=%s  service=%s  version=%s",
        settings.log_level.upper(),
        settings.app_name,
        settings.app_version,
    )
