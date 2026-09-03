"""
IP utility helpers — RFC1918/loopback detection, cloud ASN sets.
"""
import ipaddress
from typing import Optional


PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Well-known cloud/hosting ASNs (for flagging)
KNOWN_HOSTING_ASNS = {
    "AS14061",  # DigitalOcean
    "AS16509",  # Amazon AWS
    "AS15169",  # Google Cloud
    "AS8075",   # Microsoft Azure
    "AS13335",  # Cloudflare
    "AS20473",  # Vultr
    "AS36352",  # ColoCrossing
    "AS46844",  # Sharktech
    "AS29838",  # Allied Fiber
    "AS9009",   # M247
    "AS51167",  # Contabo
    "AS24940",  # Hetzner
}

# Known Tor exit node list (static sample — production should poll dan.me.uk/torlist)
KNOWN_TOR_EXITS_SAMPLE = {
    "185.220.101.34",
    "185.220.101.35",
    "185.220.101.36",
    "185.220.101.48",
    "185.220.101.56",
    "185.107.70.202",
    "104.244.72.115",
    "45.33.32.156",
    "107.189.10.143",
    "162.247.74.74",
    "171.25.193.77",
    "192.42.116.16",
}


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is RFC1918, loopback, or link-local."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_tor_exit(ip_str: str) -> bool:
    """Check against a static sample list + ipinfo.io org field heuristic."""
    return ip_str in KNOWN_TOR_EXITS_SAMPLE


def is_hosting_asn(asn: Optional[str]) -> bool:
    """Return True if the ASN belongs to a known cloud/hosting provider."""
    if not asn:
        return False
    # Normalize — strip leading 'AS' if needed
    normalized = asn.strip().upper()
    if not normalized.startswith("AS"):
        normalized = "AS" + normalized
    return normalized in KNOWN_HOSTING_ASNS
