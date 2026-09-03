"""
Phase 6 — Threat Intelligence Service.
Integrates AbuseIPDB.
Gracefully degrades if API key is missing or request fails.
"""
import ipaddress
import logging
import requests
from typing import Optional

from core.config import settings

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 5.0


def is_valid_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private and not ip_obj.is_loopback
    except ValueError:
        return False


def get_threat_intel(ip: Optional[str]) -> dict:
    """
    Lookup threat intelligence for an IP using AbuseIPDB.
    Returns graceful fallback if IP is None, private, API key missing, or error.
    """
    fallback = {
        "ip": ip,
        "reputation": "unknown",
        "abuse_confidence": None,
        "source": "AbuseIPDB",
        "status": "unavailable"
    }

    if not ip or not is_valid_public_ip(ip):
        if not ip:
            fallback["status"] = "invalid_ip"
        return fallback

    api_key = settings.abuseipdb_api_key
    if not api_key:
        logger.debug("Threat Intel not available (abuseipdb_api_key missing).")
        return fallback

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        
        reputation = "clean"
        if score > 0:
            reputation = "suspicious"
        if score > 50:
            reputation = "malicious"

        return {
            "ip": ip,
            "reputation": reputation,
            "abuse_confidence": score,
            "source": "AbuseIPDB",
            "status": "success",
        }
    except requests.RequestException as exc:
        logger.error(f"Threat Intel lookup failed for {ip}: {exc}")
        return fallback
    except ValueError as exc:
        logger.error(f"Threat Intel invalid JSON for {ip}: {exc}")
        return fallback
