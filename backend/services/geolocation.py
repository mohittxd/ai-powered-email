"""
IP Geolocation & Origin Traceability Service.

Walks the Received header chain, filters private IPs,
geolocates each public IP via ipinfo.io, and flags VPN/Tor/hosting.
"""
import re
import httpx
from typing import Optional
from utils.ip_utils import is_private_ip, is_tor_exit, is_hosting_asn
from core.config import settings


IPINFO_BASE = "https://ipinfo.io"


async def _geolocate_ip(ip: str) -> dict:
    """
    Query ipinfo.io for geolocation data.
    Falls back to empty dict on failure.
    """
    try:
        headers = {}
        url = f"{IPINFO_BASE}/{ip}/json"
        params = {}
        if settings.ipinfo_token:
            params["token"] = settings.ipinfo_token

        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {}


def _parse_loc(loc_str: Optional[str]) -> tuple[Optional[float], Optional[float]]:
    """Parse 'lat,lon' string into floats."""
    if not loc_str:
        return None, None
    try:
        parts = loc_str.split(",")
        return float(parts[0]), float(parts[1])
    except Exception:
        return None, None


async def geolocate_hop(hop: dict) -> dict:
    """
    Enrich a single hop dict with geolocation data.
    Returns a new dict merging hop + geo info.
    """
    ip = hop.get("ip_address")

    if not ip or is_private_ip(ip):
        return {
            **hop,
            "is_private": True,
            "is_vpn_tor": False,
            "is_hosting": False,
            "country": None,
            "country_code": None,
            "city": None,
            "region": None,
            "isp": None,
            "asn": None,
            "lat": None,
            "lon": None,
            "threat_flags": [],
        }

    geo = await _geolocate_ip(ip)

    country = geo.get("country", "")
    city = geo.get("city", "")
    region = geo.get("region", "")
    org = geo.get("org", "")  # "AS12345 ISP Name"

    # Parse ASN and ISP from org field
    asn = ""
    isp = org
    if org:
        parts = org.split(" ", 1)
        asn = parts[0] if parts[0].startswith("AS") else ""
        isp = parts[1] if len(parts) > 1 else org

    loc_str = geo.get("loc", "")
    lat, lon = _parse_loc(loc_str)

    threat_flags = []
    is_tor = is_tor_exit(ip)
    is_host = is_hosting_asn(asn)

    if is_tor:
        threat_flags.append("tor_exit_node")
    if is_host:
        threat_flags.append("known_hosting_provider")

    # Heuristic VPN/proxy detection from org name
    vpn_keywords = {"vpn", "proxy", "anonymize", "private layer", "mullvad", "nordvpn", "expressvpn"}
    if any(k in isp.lower() for k in vpn_keywords):
        threat_flags.append("vpn_provider")
        is_tor = True  # treat as anonymized

    return {
        **hop,
        "is_private": False,
        "is_vpn_tor": is_tor or "vpn_provider" in threat_flags,
        "is_hosting": is_host,
        "country": country,
        "country_code": country,
        "city": city,
        "region": region,
        "isp": isp,
        "asn": asn,
        "lat": lat,
        "lon": lon,
        "threat_flags": threat_flags,
        "raw_geo": geo,
    }


async def trace_origin(parsed_email: dict, auth_analysis: dict) -> dict:
    """
    Walk the received hop chain, geolocate each public IP,
    and identify the most likely origin hop.

    Returns:
      {
        hops: [...enriched hops...],
        origin_hop: {...},
        origin_ip: str,
        geo_path: [{lat, lon, city, country, ...}]
      }
    """
    raw_hops = auth_analysis.get("received_hops", [])

    enriched = []
    for hop in raw_hops:
        geo_hop = await geolocate_hop(hop)
        enriched.append(geo_hop)

    # Find earliest (lowest hop_index) public, non-private hop
    origin_hop = None
    for hop in enriched:
        if not hop.get("is_private") and hop.get("ip_address"):
            origin_hop = hop
            break

    # Build geo path for map rendering (skip hops without coordinates)
    geo_path = [
        {
            "hop_index": h["hop_index"],
            "ip": h.get("ip_address"),
            "lat": h.get("lat"),
            "lon": h.get("lon"),
            "city": h.get("city"),
            "country": h.get("country"),
            "isp": h.get("isp"),
            "threat_flags": h.get("threat_flags", []),
        }
        for h in enriched
        if h.get("lat") is not None and h.get("lon") is not None
    ]

    return {
        "hops": enriched,
        "origin_hop": origin_hop,
        "origin_ip": origin_hop.get("ip_address") if origin_hop else None,
        "geo_path": geo_path,
    }
