"""
Phase 6 — IP Geolocation Service.
Uses MaxMind GeoLite2 if a path is configured and the database exists.
If unavailable, returns a graceful fallback.
"""
import ipaddress
import logging
import os
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

from core.config import settings

logger = logging.getLogger(__name__)


def is_valid_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not ip_obj.is_private and not ip_obj.is_loopback
    except ValueError:
        return False


def get_geolocation(ip: Optional[str]) -> dict:
    """
    Lookup geolocation for an IP address.
    Returns graceful fallback if IP is None, invalid, private, or DB unavailable.
    """
    fallback = {"status": "unavailable"}

    if not ip or not is_valid_public_ip(ip):
        return fallback

    if not GEOIP_AVAILABLE:
        logger.debug("GeoIP not available (geoip2 not installed).")
        return fallback

    db_path = settings.maxmind_db_path
    if not db_path or not os.path.exists(db_path):
        logger.debug("GeoIP not available (database path not configured or file missing).")
        return fallback

    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)
            return {
                "ip": ip,
                "country": response.country.iso_code,
                "region": response.subdivisions.most_specific.iso_code if response.subdivisions else None,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                # ASN and ISP are in a separate DB usually (GeoLite2-ASN), we just put None or extract if available
                "asn": None,
                "isp": None,
                "status": "success",
            }
    except geoip2.errors.AddressNotFoundError:
        return {"status": "not_found", "ip": ip}
    except Exception as exc:
        logger.error(f"GeoIP lookup failed for {ip}: {exc}")
        return fallback
