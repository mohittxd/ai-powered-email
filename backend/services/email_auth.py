"""
Phase 4 — Email Authentication Analysis Service.

Provides independent SPF, DKIM, and DMARC analysis for a parsed .eml.

IMPORTANT LIMITATIONS — clearly stated:
  • SPF is evaluated at SMTP delivery time using the envelope sender (MAIL FROM),
    which is not always present in a saved .eml. This service performs a DNS
    lookup and a best-effort mechanism check against the visible From domain
    and the earliest observed public sender IP. It is NOT a definitive SPF result.
  • DKIM verification requires fetching the public key from DNS. Results depend
    on DNS availability and whether the signing domain still publishes its key.
  • Full DMARC evaluation requires both SMTP-time SPF and a cryptographic DKIM
    result. From a standalone .eml, a definitive DMARC verdict is often impossible.

No fabricated results are returned. When evaluation is impossible, the status
UNAVAILABLE or UNKNOWN is used with a clear explanation.

Statuses used:
  PASS         — authentication succeeded
  FAIL         — authentication failed
  SOFTFAIL     — SPF ~all (soft fail)
  NEUTRAL      — SPF ?all or inconclusive
  NONE         — no record published / mechanism absent
  UNKNOWN      — record exists but result cannot be determined
  UNAVAILABLE  — verification cannot be attempted (missing data, library error)
"""
import ipaddress
import logging
import re
from typing import Optional

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# Valid status constants
PASS        = "PASS"
FAIL        = "FAIL"
SOFTFAIL    = "SOFTFAIL"
NEUTRAL     = "NEUTRAL"
NONE_STATUS = "NONE"
UNKNOWN     = "UNKNOWN"
UNAVAILABLE = "UNAVAILABLE"


# ── DNS helpers ────────────────────────────────────────────────────────────────

def _txt_records(domain: str, timeout: float = 5.0) -> list[str]:
    """Return TXT records for a domain. Returns [] on any failure."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except (dns.exception.DNSException, Exception):
        return []


def _get_spf_record(domain: str) -> Optional[str]:
    """Return the first SPF TXT record found for domain, or None."""
    for txt in _txt_records(domain):
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def _get_dmarc_record(domain: str) -> Optional[str]:
    """Return the DMARC TXT record at _dmarc.<domain>, or None."""
    for txt in _txt_records(f"_dmarc.{domain}"):
        if txt.lower().startswith("v=dmarc1"):
            return txt
    return None


def _get_dkim_pubkey_record(selector: str, domain: str) -> Optional[str]:
    """Return the DKIM public key TXT record at <selector>._domainkey.<domain>."""
    query = f"{selector}._domainkey.{domain}"
    records = _txt_records(query)
    for r in records:
        if "p=" in r.lower():
            return r
    return None


# ── SPF analysis ───────────────────────────────────────────────────────────────

def _ip_in_cidr(ip_str: str, cidr: str) -> bool:
    """Return True if ip_str is within cidr (e.g. '1.2.3.0/24')."""
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _evaluate_spf_record(record: str, sender_ip: Optional[str]) -> tuple[str, str]:
    """
    Best-effort evaluation of an SPF record against a sender IP.
    Only evaluates ip4: and ip6: mechanisms directly.
    Returns (status, detail).
    """
    if sender_ip is None:
        return UNKNOWN, (
            "SPF record found but no sender IP available for evaluation. "
            "Definitive SPF result requires the SMTP envelope sender IP."
        )

    mechanisms = record.split()
    evaluated_mechanisms: list[str] = []
    has_complex = False

    for mech in mechanisms:
        m_lower = mech.lower()

        # ip4:/ip6: — direct IP match
        if m_lower.startswith("ip4:"):
            cidr = mech[4:]
            evaluated_mechanisms.append(mech)
            if _ip_in_cidr(sender_ip, cidr):
                return PASS, f"Sender IP {sender_ip} matches SPF mechanism '{mech}'."

        elif m_lower.startswith("ip6:"):
            cidr = mech[4:]
            evaluated_mechanisms.append(mech)
            try:
                if ipaddress.ip_address(sender_ip) in ipaddress.ip_network(cidr, strict=False):
                    return PASS, f"Sender IP {sender_ip} matches SPF mechanism '{mech}'."
            except ValueError:
                pass

        # Complex mechanisms that require recursive DNS resolution
        elif m_lower.startswith(("include:", "a:", "a", "mx:", "mx", "ptr:", "exists:")):
            has_complex = True

        # All qualifiers
        elif m_lower in ("-all", "~all", "?all", "+all"):
            if not has_complex:
                # No ip4/ip6 matched and no complex mechanisms — IP not authorised
                if m_lower == "-all":
                    return FAIL, (
                        f"Sender IP {sender_ip} did not match any SPF ip4/ip6 mechanism "
                        f"and the record uses hard-fail (-all). "
                        f"Note: include/a/mx mechanisms were not evaluated."
                    )
                elif m_lower == "~all":
                    return SOFTFAIL, (
                        f"Sender IP {sender_ip} did not match evaluated ip4/ip6 mechanisms; "
                        f"record ends with soft-fail (~all). Full evaluation may differ."
                    )
                elif m_lower == "?all":
                    return NEUTRAL, (
                        f"SPF record uses neutral qualifier (?all). "
                        f"Sender IP {sender_ip} not matched by evaluated mechanisms."
                    )
                elif m_lower == "+all":
                    return PASS, "SPF +all — any sender is permitted (dangerous policy)."

    if has_complex:
        return UNKNOWN, (
            f"SPF record contains include/a/mx mechanisms that require recursive DNS "
            f"resolution which was not performed. Sender IP: {sender_ip}. "
            "This is not a definitive SPF result — only SMTP-time evaluation is authoritative."
        )

    return UNKNOWN, f"SPF record could not be conclusively evaluated for IP {sender_ip}."


def analyze_spf(
    from_domain: str,
    earliest_public_sender_ip: Optional[str] = None,
    auth_results_header: Optional[str] = None,
) -> dict:
    """
    SPF analysis for a From domain.

    Returns:
      status       — one of the defined status constants
      record       — raw SPF TXT record (if found)
      domain       — domain queried
      sender_ip    — IP used for evaluation (if available)
      detail       — human-readable explanation
      mta_reported — SPF result extracted from Authentication-Results header (if present)
      note         — limitation disclaimer
    """
    result: dict = {
        "status":        NONE_STATUS,
        "record":        None,
        "domain":        from_domain,
        "sender_ip":     earliest_public_sender_ip,
        "detail":        "",
        "mta_reported":  None,
        "note":          (
            "SPF is evaluated at SMTP time using the envelope MAIL FROM address. "
            "This result is based on a DNS lookup of the visible From domain and "
            "best-effort IP matching — it is NOT equivalent to an authoritative SMTP SPF check."
        ),
    }

    # Extract MTA-reported result from Authentication-Results header
    if auth_results_header:
        spf_match = re.search(r'\bspf=(\w+)', auth_results_header, re.IGNORECASE)
        if spf_match:
            result["mta_reported"] = spf_match.group(1).upper()

    if not from_domain:
        result["detail"] = "No sender domain available."
        return result

    record = _get_spf_record(from_domain)
    if not record:
        result["status"] = NONE_STATUS
        result["detail"] = f"No SPF TXT record found for '{from_domain}'."
        return result

    result["record"] = record
    status, detail = _evaluate_spf_record(record, earliest_public_sender_ip)
    result["status"] = status
    result["detail"] = detail
    return result


# ── DKIM analysis ──────────────────────────────────────────────────────────────

def _parse_dkim_signature(sig: str) -> dict:
    """Parse key=value pairs from a DKIM-Signature header value."""
    parsed = {}
    for pair in re.findall(r'([a-z]+)=([^;]+)', sig, re.IGNORECASE):
        parsed[pair[0].strip().lower()] = pair[1].strip()
    return parsed


def analyze_dkim(raw_bytes: bytes, parsed: dict) -> dict:
    """
    DKIM analysis.

    Attempts verification via dkimpy if available.
    If the signing domain's DNS key is unavailable or expired, returns UNAVAILABLE.
    Never treats unavailable verification as FAIL.

    Returns:
      status         — PASS / FAIL / NONE / UNAVAILABLE / UNKNOWN
      signing_domain — d= value from DKIM-Signature
      selector       — s= value
      detail         — explanation
      mta_reported   — result from Authentication-Results header (if present)
      pubkey_found   — whether the DNS public key record was located
    """
    headers = parsed.get("headers", {})
    auth_results = parsed.get("auth_results", "") or ""

    result: dict = {
        "status":         NONE_STATUS,
        "signing_domain": None,
        "selector":       None,
        "detail":         "No DKIM-Signature header found.",
        "mta_reported":   None,
        "pubkey_found":   None,
    }

    # MTA-reported result
    dkim_match = re.search(r'\bdkim=(\w+)', auth_results, re.IGNORECASE)
    if dkim_match:
        result["mta_reported"] = dkim_match.group(1).upper()

    sig_value = headers.get("dkim-signature") or headers.get("DKIM-Signature")
    if not sig_value:
        return result

    sig_str = sig_value if isinstance(sig_value, str) else sig_value[0]
    sig_tags = _parse_dkim_signature(sig_str)

    signing_domain = sig_tags.get("d")
    selector       = sig_tags.get("s")
    result["signing_domain"] = signing_domain
    result["selector"]       = selector

    if not signing_domain or not selector:
        result["status"] = UNKNOWN
        result["detail"] = "DKIM-Signature present but d= or s= tags are missing."
        return result

    # Check DNS key availability first (no verification if key is gone)
    pubkey_record = _get_dkim_pubkey_record(selector, signing_domain)
    result["pubkey_found"] = pubkey_record is not None

    if not pubkey_record:
        result["status"] = UNAVAILABLE
        result["detail"] = (
            f"DKIM-Signature present (d={signing_domain}, s={selector}) but the "
            f"public key record '{selector}._domainkey.{signing_domain}' could not "
            "be retrieved from DNS. Verification is unavailable — this is NOT treated as FAIL. "
            "The key may have been rotated or the domain may no longer publish it."
        )
        return result

    # Attempt dkimpy verification
    try:
        import dkim as dkimlib
        valid = dkimlib.verify(raw_bytes)
        if valid:
            result["status"] = PASS
            result["detail"] = (
                f"DKIM signature verified successfully "
                f"(d={signing_domain}, s={selector})."
            )
        else:
            result["status"] = FAIL
            result["detail"] = (
                f"DKIM signature verification FAILED "
                f"(d={signing_domain}, s={selector}). "
                "The message body or signed headers may have been modified in transit."
            )
    except ImportError:
        result["status"] = UNAVAILABLE
        result["detail"] = (
            f"DKIM-Signature found (d={signing_domain}, s={selector}) "
            "but dkimpy is not installed. Install with: pip install dkimpy"
        )
    except Exception as exc:
        logger.debug("DKIM verification error: %s", exc)
        result["status"] = UNAVAILABLE
        result["detail"] = (
            f"DKIM-Signature found (d={signing_domain}, s={selector}) "
            f"but verification raised an exception: {type(exc).__name__}. "
            "This is NOT treated as a failure."
        )

    return result


# ── DMARC analysis ─────────────────────────────────────────────────────────────

def _parse_dmarc_tags(record: str) -> dict:
    """Parse v=DMARC1; tag=value; ... into a dict."""
    tags = {}
    for pair in re.findall(r'([a-z]+)=([^;]+)', record, re.IGNORECASE):
        tags[pair[0].strip().lower()] = pair[1].strip()
    return tags


def _domains_aligned(domain_a: Optional[str], domain_b: Optional[str], strict: bool) -> bool:
    """
    Check DMARC alignment.
    Strict: exact match. Relaxed: one is an organisational subdomain of the other.
    """
    if not domain_a or not domain_b:
        return False
    a, b = domain_a.lower(), domain_b.lower()
    if strict:
        return a == b
    # Relaxed: check if they share the same registered domain (last 2 labels)
    a_parts = a.split(".")
    b_parts = b.split(".")
    return a_parts[-2:] == b_parts[-2:]


def analyze_dmarc(
    from_domain: str,
    spf_status: str,
    spf_domain: Optional[str],
    dkim_status: str,
    dkim_signing_domain: Optional[str],
    auth_results_header: Optional[str] = None,
) -> dict:
    """
    DMARC analysis.

    Returns:
      status       — PASS / FAIL / NONE / UNKNOWN / UNAVAILABLE
      policy       — p= value (none, quarantine, reject)
      record       — raw DMARC TXT record
      domain       — From domain queried
      spf_aligned  — whether SPF domain aligns with From domain
      dkim_aligned — whether DKIM signing domain aligns with From domain
      detail       — explanation
      mta_reported — result from Authentication-Results header (if present)
      note         — limitation disclaimer
    """
    result: dict = {
        "status":       NONE_STATUS,
        "policy":       None,
        "record":       None,
        "domain":       from_domain,
        "spf_aligned":  None,
        "dkim_aligned": None,
        "detail":       "",
        "mta_reported": None,
        "note":         (
            "Complete DMARC evaluation from a standalone .eml is not always possible. "
            "Authoritative DMARC evaluation is performed by the receiving MTA at delivery time. "
            "This result reflects DNS lookup and best-effort alignment checking."
        ),
    }

    # MTA-reported result
    if auth_results_header:
        dmarc_match = re.search(r'\bdmarc=(\w+)', auth_results_header, re.IGNORECASE)
        if dmarc_match:
            result["mta_reported"] = dmarc_match.group(1).upper()

    if not from_domain:
        result["detail"] = "No From domain available for DMARC lookup."
        return result

    record = _get_dmarc_record(from_domain)
    if not record:
        result["status"] = NONE_STATUS
        result["detail"] = f"No DMARC record found at '_dmarc.{from_domain}'."
        return result

    result["record"] = record
    tags = _parse_dmarc_tags(record)

    policy = tags.get("p", "none").lower()
    result["policy"] = policy

    adkim_strict = tags.get("adkim", "r").lower() == "s"  # default relaxed
    aspf_strict  = tags.get("aspf",  "r").lower() == "s"

    # Alignment checks
    dkim_aligned = _domains_aligned(dkim_signing_domain, from_domain, adkim_strict)
    spf_aligned  = _domains_aligned(spf_domain, from_domain, aspf_strict)
    result["dkim_aligned"] = dkim_aligned
    result["spf_aligned"]  = spf_aligned

    # DMARC passes if at least one of SPF or DKIM passes AND is aligned
    spf_passes  = spf_status  in (PASS, SOFTFAIL) and spf_aligned
    dkim_passes = dkim_status == PASS              and dkim_aligned

    # Cannot definitively evaluate if both SPF and DKIM are unavailable/unknown
    if spf_status in (UNAVAILABLE, UNKNOWN) and dkim_status in (UNAVAILABLE, UNKNOWN, NONE_STATUS):
        result["status"] = UNAVAILABLE
        result["detail"] = (
            f"DMARC record found (p={policy}) but neither SPF nor DKIM provided a "
            "definitive result. A definitive DMARC verdict is not possible from this .eml alone."
        )
        return result

    if dkim_passes or spf_passes:
        result["status"] = PASS
        passing = []
        if dkim_passes:
            passing.append(f"DKIM (d={dkim_signing_domain}, aligned)")
        if spf_passes:
            passing.append(f"SPF (domain={spf_domain}, aligned)")
        result["detail"] = (
            f"DMARC PASS — p={policy}. Passing identifiers: {', '.join(passing)}."
        )
    else:
        result["status"] = FAIL
        reasons = []
        if dkim_status == FAIL:
            reasons.append("DKIM failed")
        elif not dkim_aligned and dkim_status == PASS:
            reasons.append(f"DKIM passed but not aligned (d={dkim_signing_domain})")
        elif dkim_status in (NONE_STATUS, UNAVAILABLE):
            reasons.append(f"DKIM not available ({dkim_status})")
        if spf_status in (FAIL, SOFTFAIL, NEUTRAL, NONE_STATUS):
            reasons.append(f"SPF {spf_status.lower()}")
        elif not spf_aligned and spf_status == PASS:
            reasons.append(f"SPF passed but not aligned (domain={spf_domain})")
        result["detail"] = (
            f"DMARC FAIL — p={policy}. Reasons: {'; '.join(reasons) or 'unknown'}. "
            "Note: this may not reflect the actual delivery outcome."
        )

    return result


# ── Main entry point ───────────────────────────────────────────────────────────

def analyze_authentication(
    raw_bytes: bytes,
    parsed: dict,
    earliest_public_sender_ip: Optional[str] = None,
) -> dict:
    """
    Run SPF, DKIM, and DMARC analysis on a parsed email.

    Args:
      raw_bytes               — original .eml bytes (needed for DKIM verification)
      parsed                  — output of email_ingestor.parse_eml()
      earliest_public_sender_ip — from Phase 3 header forensics (optional)

    Returns:
      {spf, dkim, dmarc, auth_results_header, summary}
    """
    from_addr   = parsed.get("from_address", "")
    from_domain = from_addr.split("@")[-1].strip().lower() if "@" in from_addr else ""
    auth_results_hdr = parsed.get("auth_results", "") or ""

    spf  = analyze_spf(from_domain, earliest_public_sender_ip, auth_results_hdr)
    dkim = analyze_dkim(raw_bytes, parsed)
    dmarc = analyze_dmarc(
        from_domain=from_domain,
        spf_status=spf["status"],
        spf_domain=from_domain if spf["status"] == PASS else None,
        dkim_status=dkim["status"],
        dkim_signing_domain=dkim.get("signing_domain"),
        auth_results_header=auth_results_hdr,
    )

    # Summary
    statuses = f"SPF={spf['status']} DKIM={dkim['status']} DMARC={dmarc['status']}"
    any_fail = any(
        s["status"] == FAIL for s in (spf, dkim, dmarc)
    )
    any_critical = dmarc["status"] == FAIL and dmarc.get("policy") in ("quarantine", "reject")
    if any_critical:
        summary = f"Authentication FAILED with enforcing DMARC policy. {statuses}."
    elif any_fail:
        summary = f"One or more authentication checks failed. {statuses}."
    elif all(s["status"] == PASS for s in (spf, dkim, dmarc)):
        summary = f"All authentication checks passed. {statuses}."
    else:
        summary = f"Authentication results are partial or inconclusive. {statuses}."

    return {
        "spf":                  spf,
        "dkim":                 dkim,
        "dmarc":                dmarc,
        "auth_results_header":  auth_results_hdr or None,
        "summary":              summary,
    }
