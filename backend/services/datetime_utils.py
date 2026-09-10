"""
Datetime parsing and normalization utilities for forensic services.

normalize_datetime(value) -> Optional[datetime]
- Accepts datetime objects or strings.
- Returns a timezone-aware UTC datetime on success, or None on failure.

Behavior:
- If value is a datetime and tzinfo is None, it is treated as UTC and tzinfo set to timezone.utc.
- If value is a datetime with tzinfo, it's converted to UTC.
- If value is a string, attempts email.utils.parsedate_to_datetime first (RFC-5322), then
  falls back to datetime.fromisoformat for ISO-like strings.
- Any parse errors return None.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)


def normalize_datetime(value: Optional[object]) -> Optional[datetime]:
    """Normalize various datetime inputs to a timezone-aware UTC datetime.

    Args:
        value: datetime, str, or None

    Returns:
        datetime with tzinfo=timezone.utc, or None if parsing fails / value is None.
    """
    if value is None:
        return None

    # If already a datetime, normalise tzinfo
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            # Treat naive datetimes as UTC
            return dt.replace(tzinfo=timezone.utc)
        try:
            return dt.astimezone(timezone.utc)
        except Exception:
            logger.debug("Failed to convert datetime to UTC: %r", dt)
            return None

    # If value is a string, try RFC-5322 parsing then ISO parsing
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            dt = parsedate_to_datetime(s)
            # parsedate_to_datetime may return None in edge cases
            if dt is None:
                raise ValueError("parsedate_to_datetime returned None")
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            # Fallback: try ISO format parsing
            try:
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                logger.debug("Unable to parse datetime string: %r", s)
                return None

    # Unsupported type
    logger.debug("Unsupported datetime input type: %r", type(value))
    return None
