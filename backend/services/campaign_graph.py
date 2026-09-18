"""
Phase 21 — NetworkX Campaign Correlation & Shared Infrastructure Graph Service.

Constructs an interactive NetworkX multigraph mapping relationships between:
- Email Evidence Nodes
- Sender Addresses
- Reply-To Addresses
- Domains
- IP Addresses
- URLs
- ASNs (Autonomous System Numbers)
- Message-IDs
- Infrastructure (ISP / Hosting Providers)

Calculates a Campaign Correlation Score (0-100) based on shared indicator density
and formats graph data for frontend visualization.

DISCLAIMER: Shared technical infrastructure indicators represent structural correlations.
They do NOT establish definitive proof of common human authorship.
"""

import logging
from typing import Dict, List, Any, Set
from collections import defaultdict
import networkx as nx
from sqlalchemy import text

logger = logging.getLogger(__name__)

ATTRIBUTION_DISCLAIMER = (
    "Technical indicators represent observed structural correlations (shared IPs, domains, ASNs, URLs). "
    "Shared infrastructure does NOT by itself establish definitive proof of common human authorship or organizational identity."
)


def _extract_domain(email_or_url: str) -> str:
    if not email_or_url:
        return ""
    val = email_or_url.strip().lower()
    if "@" in val:
        return val.split("@")[-1]
    if "://" in val:
        val = val.split("://")[-1]
    return val.split("/")[0].split(":")[0]


async def build_global_campaign_graph(db, owner_id: str | None = None) -> nx.Graph:
    """
    Queries all emails, trace hops, and IOCs from PostgreSQL using raw SQL
    for maximum performance, building a NetworkX Graph representation.
    """
    owner_filter = ""
    params = {}
    if owner_id:
        owner_filter = "WHERE e.owner_id = :owner_id"
        params["owner_id"] = owner_id

    emails_rows = (await db.execute(
        text(f"SELECT id, subject, from_address, reply_to, message_id, "
             f"fraud_score, classification, analyzed_at FROM emails e {owner_filter}"),
        params
    )).fetchall()

    email_ids = [r[0] for r in emails_rows]
    if not email_ids:
        return nx.Graph()

    placeholders = ",".join(f":eid{i}" for i in range(len(email_ids)))
    hop_params = {f"eid{i}": eid for i, eid in enumerate(email_ids)}

    hops_rows = (await db.execute(
        text(f"SELECT email_id, ip_address, is_private, asn, isp FROM trace_hops "
             f"WHERE email_id IN ({placeholders})"),
        hop_params
    )).fetchall()

    ioc_params = {f"eid{i}": eid for i, eid in enumerate(email_ids)}
    ioc_rows = (await db.execute(
        text(f"SELECT email_id, ioc_type, value FROM iocs "
             f"WHERE email_id IN ({placeholders})"),
        ioc_params
    )).fetchall()

    hops_by_email = {}
    for row in hops_rows:
        hops_by_email.setdefault(row[0], []).append(row)

    iocs_by_email = {}
    for row in ioc_rows:
        iocs_by_email.setdefault(row[0], []).append(row)

    G = nx.Graph()

    for email in emails_rows:
        eid, subject, from_addr, reply_to, msg_id, fraud_score, classification, analyzed_at = email
        e_node = f"email:{eid}"
        fs = fraud_score or 0
        score = round(fs * 100) if fs <= 1.0 else round(fs)
        G.add_node(
            e_node, node_type="email", id=eid,
            label=subject or f"Email {eid[:8]}",
            from_address=from_addr or "", reply_to=reply_to or "",
            fraud_score=score,
            classification=classification or "LEGITIMATE",
            analyzed_at=analyzed_at.isoformat() if analyzed_at else None
        )

        if from_addr:
            fa = from_addr.strip().lower()
            s_node = f"sender:{fa}"
            G.add_node(s_node, node_type="sender", label=fa, value=fa)
            G.add_edge(e_node, s_node, relation="SENT_BY")
            s_dom = _extract_domain(fa)
            if s_dom and len(s_dom) > 3:
                d_node = f"domain:{s_dom}"
                G.add_node(d_node, node_type="domain", label=s_dom, value=s_dom)
                G.add_edge(s_node, d_node, relation="USES_DOMAIN")

        if reply_to:
            ra = reply_to.strip().lower()
            r_node = f"reply_to:{ra}"
            G.add_node(r_node, node_type="reply_to", label=ra, value=ra)
            G.add_edge(e_node, r_node, relation="HAS_REPLY_TO")
            r_dom = _extract_domain(ra)
            if r_dom and len(r_dom) > 3:
                rd_node = f"domain:{r_dom}"
                G.add_node(rd_node, node_type="domain", label=r_dom, value=r_dom)
                G.add_edge(r_node, rd_node, relation="USES_DOMAIN")

        if msg_id:
            mid = msg_id.strip()
            m_node = f"message_id:{mid}"
            G.add_node(m_node, node_type="message_id", label=mid[:30], value=mid)
            G.add_edge(e_node, m_node, relation="HAS_MESSAGE_ID")

        for hop in hops_by_email.get(eid, []):
            _, ip_addr, is_private, asn, isp = hop
            if ip_addr and not is_private:
                ip_val = ip_addr.strip()
                ip_node = f"ip:{ip_val}"
                G.add_node(ip_node, node_type="ip", label=ip_val, value=ip_val)
                G.add_edge(e_node, ip_node, relation="ORIGINATED_FROM")
                if asn:
                    asn_val = asn.strip()
                    asn_node = f"asn:{asn_val}"
                    G.add_node(asn_node, node_type="asn", label=asn_val, value=asn_val)
                    G.add_edge(ip_node, asn_node, relation="BELONGS_TO_ASN")
                if isp:
                    isp_val = isp.strip()
                    infra_node = f"infrastructure:{isp_val}"
                    G.add_node(infra_node, node_type="infrastructure", label=isp_val, value=isp_val)
                    if asn:
                        G.add_edge(f"asn:{asn.strip()}", infra_node, relation="USES_INFRASTRUCTURE")
                    else:
                        G.add_edge(ip_node, infra_node, relation="USES_INFRASTRUCTURE")

        for ioc in iocs_by_email.get(eid, []):
            _, ioc_type, ioc_val_raw = ioc
            ioc_val = ioc_val_raw.strip().lower()
            if ioc_type == "url":
                u_node = f"url:{ioc_val}"
                G.add_node(u_node, node_type="url", label=ioc_val[:35], value=ioc_val)
                G.add_edge(e_node, u_node, relation="CONTAINS_URL")
                u_dom = _extract_domain(ioc_val)
                if u_dom and len(u_dom) > 3:
                    ud_node = f"domain:{u_dom}"
                    G.add_node(ud_node, node_type="domain", label=u_dom, value=u_dom)
                    G.add_edge(u_node, ud_node, relation="HOSTED_ON_DOMAIN")
            elif ioc_type == "domain":
                d_node = f"domain:{ioc_val}"
                G.add_node(d_node, node_type="domain", label=ioc_val, value=ioc_val)
                G.add_edge(e_node, d_node, relation="CONTAINS_DOMAIN")
            elif ioc_type == "ip":
                ip_node = f"ip:{ioc_val}"
                G.add_node(ip_node, node_type="ip", label=ioc_val, value=ioc_val)
                G.add_edge(e_node, ip_node, relation="CONTAINS_IP")

    return G


INFRA_TYPES = {"domain", "ip", "url", "asn", "infrastructure"}


def compute_campaign_correlation(G: nx.Graph) -> List[Dict[str, Any]]:
    """
    Performs NetworkX connected component analysis to group email evidence
    into campaign clusters based on shared infrastructure and indicators.

    Performance: single-pass edge scan to build infrastructure-to-email
    reverse index, then groups by connected components. O(V+E) total.
    """
    components = list(nx.connected_components(G))
    campaigns = []
    cluster_idx = 1

    for comp_nodes in components:
        subgraph = G.subgraph(comp_nodes)

        email_nodes = [n for n in comp_nodes if G.nodes[n].get("node_type") == "email"]
        if len(email_nodes) < 2:
            continue

        email_set = set(email_nodes)

        email_list = []
        for en in email_nodes:
            nd = G.nodes[en]
            email_list.append({
                "id": nd.get("id"),
                "subject": nd.get("label"),
                "from_address": nd.get("from_address"),
                "reply_to": nd.get("reply_to"),
                "fraud_score": nd.get("fraud_score", 0),
                "classification": nd.get("classification", "LEGITIMATE"),
                "analyzed_at": nd.get("analyzed_at")
            })

        infra_email_map: Dict[str, Set[str]] = defaultdict(set)

        ip_asn_map: Dict[str, Set[str]] = defaultdict(set)
        asn_infra_map: Dict[str, Set[str]] = defaultdict(set)
        sender_domain_map: Dict[str, Set[str]] = defaultdict(set)

        for u, v in subgraph.edges():
            ut = subgraph.nodes[u].get("node_type")
            vt = subgraph.nodes[v].get("node_type")
            if ut == "ip" and vt == "asn":
                ip_asn_map[u].add(v)
            elif vt == "ip" and ut == "asn":
                ip_asn_map[v].add(u)
            elif ut == "asn" and vt == "infrastructure":
                asn_infra_map[u].add(v)
            elif vt == "asn" and ut == "infrastructure":
                asn_infra_map[v].add(u)
            elif ut == "sender" and vt == "domain":
                sender_domain_map[u].add(v)
            elif vt == "sender" and ut == "domain":
                sender_domain_map[v].add(u)
            elif ut == "reply_to" and vt == "domain":
                sender_domain_map[u].add(v)
            elif vt == "reply_to" and ut == "domain":
                sender_domain_map[v].add(u)

        for u, v in subgraph.edges():
            ut = subgraph.nodes[u].get("node_type")
            vt = subgraph.nodes[v].get("node_type")

            if ut == "email" and u in email_set:
                if vt in INFRA_TYPES:
                    infra_email_map[v].add(u)
                if vt in ("sender", "reply_to"):
                    for dom in sender_domain_map.get(v, set()):
                        infra_email_map[dom].add(u)
                if vt == "ip":
                    for asn in ip_asn_map.get(v, set()):
                        infra_email_map[asn].add(u)
                        for inf in asn_infra_map.get(asn, set()):
                            infra_email_map[inf].add(u)
            elif vt == "email" and v in email_set:
                if ut in INFRA_TYPES:
                    infra_email_map[u].add(v)
                if ut in ("sender", "reply_to"):
                    for dom in sender_domain_map.get(u, set()):
                        infra_email_map[dom].add(v)
                if ut == "ip":
                    for asn in ip_asn_map.get(u, set()):
                        infra_email_map[asn].add(v)
                        for inf in asn_infra_map.get(asn, set()):
                            infra_email_map[inf].add(v)

        shared_domains: Set[str] = set()
        shared_ips: Set[str] = set()
        shared_urls: Set[str] = set()
        shared_asns: Set[str] = set()
        shared_infra: Set[str] = set()

        for node, reachable_emails in infra_email_map.items():
            if len(reachable_emails) < 2:
                continue
            ntype = G.nodes[node].get("node_type")
            val = G.nodes[node].get("value") or G.nodes[node].get("label") or node
            if ntype == "domain":
                shared_domains.add(val)
            elif ntype == "ip":
                shared_ips.add(val)
            elif ntype == "url":
                shared_urls.add(val)
            elif ntype == "asn":
                shared_asns.add(val)
            elif ntype == "infrastructure":
                shared_infra.add(val)

        raw_score = (
            35 * len(shared_ips) +
            30 * len(shared_urls) +
            20 * len(shared_domains) +
            15 * len(shared_asns) +
            10 * len(shared_infra)
        )

        if raw_score == 0:
            correlation_score = min(100, 15 + (len(email_nodes) * 5))
        else:
            correlation_score = min(100, max(25, raw_score))

        if correlation_score >= 75:
            correlation_level = "CRITICAL"
        elif correlation_score >= 50:
            correlation_level = "HIGH"
        elif correlation_score >= 25:
            correlation_level = "MEDIUM"
        else:
            correlation_level = "LOW"

        avg_fraud_score = round(sum(e["fraud_score"] for e in email_list) / len(email_list)) if email_list else 0

        campaigns.append({
            "campaign_id": f"CAMP-{cluster_idx:03d}",
            "campaign_name": f"Infrastructure Cluster #{cluster_idx} ({len(email_list)} Emails)",
            "correlation_score": correlation_score,
            "correlation_level": correlation_level,
            "avg_fraud_score": avg_fraud_score,
            "email_count": len(email_list),
            "related_emails": email_list,
            "shared_domains": sorted(list(shared_domains)),
            "shared_ips": sorted(list(shared_ips)),
            "shared_urls": sorted(list(shared_urls)),
            "shared_infrastructure": sorted(list(shared_infra | shared_asns)),
            "graph_representation": {
                "node_count": len(comp_nodes),
                "edge_count": subgraph.number_of_edges(),
            },
            "attribution_disclaimer": ATTRIBUTION_DISCLAIMER
        })
        cluster_idx += 1

    campaigns.sort(key=lambda c: c["correlation_score"], reverse=True)
    return campaigns
