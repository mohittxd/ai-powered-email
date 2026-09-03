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
from typing import Dict, List, Any, Tuple, Set
import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from core.models import Email, TraceHop, IOC

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


async def build_global_campaign_graph(db) -> nx.Graph:
    """
    Queries all emails, trace hops, and IOCs from PostgreSQL,
    building a comprehensive NetworkX Graph representation.
    """
    stmt = select(Email).options(
        selectinload(Email.trace_hops),
        selectinload(Email.iocs)
    )
    res = await db.execute(stmt)
    emails = res.scalars().all()

    G = nx.Graph()

    for email in emails:
        e_node = f"email:{email.id}"
        score = round((email.fraud_score or 0) * 100) if email.fraud_score <= 1.0 else round(email.fraud_score or 0)
        G.add_node(
            e_node,
            node_type="email",
            id=email.id,
            label=email.subject or f"Email {email.id[:8]}",
            from_address=email.from_address or "",
            reply_to=email.reply_to or "",
            fraud_score=score,
            classification=email.classification or "LEGITIMATE",
            analyzed_at=email.analyzed_at.isoformat() if email.analyzed_at else None
        )

        # 1. Sender Node & Domain
        if email.from_address:
            from_addr = email.from_address.strip().lower()
            s_node = f"sender:{from_addr}"
            G.add_node(s_node, node_type="sender", label=from_addr, value=from_addr)
            G.add_edge(e_node, s_node, relation="SENT_BY")

            s_dom = _extract_domain(from_addr)
            if s_dom and len(s_dom) > 3:
                d_node = f"domain:{s_dom}"
                G.add_node(d_node, node_type="domain", label=s_dom, value=s_dom)
                G.add_edge(s_node, d_node, relation="USES_DOMAIN")

        # 2. Reply-To Node & Domain
        if email.reply_to:
            reply_addr = email.reply_to.strip().lower()
            r_node = f"reply_to:{reply_addr}"
            G.add_node(r_node, node_type="reply_to", label=reply_addr, value=reply_addr)
            G.add_edge(e_node, r_node, relation="HAS_REPLY_TO")

            r_dom = _extract_domain(reply_addr)
            if r_dom and len(r_dom) > 3:
                rd_node = f"domain:{r_dom}"
                G.add_node(rd_node, node_type="domain", label=r_dom, value=r_dom)
                G.add_edge(r_node, rd_node, relation="USES_DOMAIN")

        # 3. Message-ID Node
        if email.message_id:
            msg_id = email.message_id.strip()
            m_node = f"message_id:{msg_id}"
            G.add_node(m_node, node_type="message_id", label=msg_id[:30], value=msg_id)
            G.add_edge(e_node, m_node, relation="HAS_MESSAGE_ID")

        # 4. Trace Hops (IPs, ASNs, Infrastructure)
        for hop in email.trace_hops:
            if hop.ip_address and not hop.is_private:
                ip_val = hop.ip_address.strip()
                ip_node = f"ip:{ip_val}"
                G.add_node(ip_node, node_type="ip", label=ip_val, value=ip_val)
                G.add_edge(e_node, ip_node, relation="ORIGINATED_FROM")

                if hop.asn:
                    asn_val = hop.asn.strip()
                    asn_node = f"asn:{asn_val}"
                    G.add_node(asn_node, node_type="asn", label=asn_val, value=asn_val)
                    G.add_edge(ip_node, asn_node, relation="BELONGS_TO_ASN")

                if hop.isp:
                    isp_val = hop.isp.strip()
                    infra_node = f"infrastructure:{isp_val}"
                    G.add_node(infra_node, node_type="infrastructure", label=isp_val, value=isp_val)
                    if hop.asn:
                        G.add_edge(f"asn:{hop.asn.strip()}", infra_node, relation="USES_INFRASTRUCTURE")
                    else:
                        G.add_edge(ip_node, infra_node, relation="USES_INFRASTRUCTURE")

        # 5. IOC Nodes (URLs, Domains, IPs)
        for ioc in email.iocs:
            ioc_val = ioc.value.strip().lower()
            if ioc.ioc_type == "url":
                u_node = f"url:{ioc_val}"
                G.add_node(u_node, node_type="url", label=ioc_val[:35], value=ioc_val)
                G.add_edge(e_node, u_node, relation="CONTAINS_URL")

                u_dom = _extract_domain(ioc_val)
                if u_dom and len(u_dom) > 3:
                    ud_node = f"domain:{u_dom}"
                    G.add_node(ud_node, node_type="domain", label=u_dom, value=u_dom)
                    G.add_edge(u_node, ud_node, relation="HOSTED_ON_DOMAIN")

            elif ioc.ioc_type == "domain":
                d_node = f"domain:{ioc_val}"
                G.add_node(d_node, node_type="domain", label=ioc_val, value=ioc_val)
                G.add_edge(e_node, d_node, relation="CONTAINS_DOMAIN")

            elif ioc.ioc_type == "ip":
                ip_node = f"ip:{ioc_val}"
                G.add_node(ip_node, node_type="ip", label=ioc_val, value=ioc_val)
                G.add_edge(e_node, ip_node, relation="CONTAINS_IP")

    return G


def compute_campaign_correlation(G: nx.Graph) -> List[Dict[str, Any]]:
    """
    Performs NetworkX connected component analysis to group email evidence
    into campaign clusters based on shared infrastructure and indicators.
    """
    components = list(nx.connected_components(G))
    campaigns = []
    cluster_idx = 1

    for comp_nodes in components:
        subgraph = G.subgraph(comp_nodes)

        # Gather email nodes in this component
        email_nodes = [n for n in comp_nodes if G.nodes[n].get("node_type") == "email"]

        # Only process clusters containing 2+ related emails (or singletons if desired)
        if len(email_nodes) < 2:
            continue

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

        # Identify shared entities (connected to >= 2 email nodes in this component)
        shared_domains: Set[str] = set()
        shared_ips: Set[str] = set()
        shared_urls: Set[str] = set()
        shared_asns: Set[str] = set()
        shared_infra: Set[str] = set()

        for node in comp_nodes:
            ntype = G.nodes[node].get("node_type")
            if ntype in ("email", "sender", "reply_to", "message_id"):
                continue

            # Check how many emails in this subgraph connect to `node` via a 1 or 2 hop path
            connected_emails = 0
            for en in email_nodes:
                if nx.has_path(subgraph, en, node):
                    path_len = nx.shortest_path_length(subgraph, en, node)
                    if path_len <= 3:
                        connected_emails += 1

            if connected_emails >= 2:
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

        # Calculate Campaign Correlation Score (0-100)
        # Weighted by indicator specificity and overlap density
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

        # Construct D3 / Cytoscape compatible graph JSON for frontend visualization
        nodes_json = []
        for n in comp_nodes:
            nd = G.nodes[n]
            nodes_json.append({
                "id": n,
                "label": nd.get("label", n),
                "type": nd.get("node_type", "unknown"),
                "value": nd.get("value", "")
            })

        edges_json = []
        for u, v, edata in subgraph.edges(data=True):
            edges_json.append({
                "source": u,
                "target": v,
                "relation": edata.get("relation", "CONNECTED_TO")
            })

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
                "node_count": len(nodes_json),
                "edge_count": len(edges_json),
                "nodes": nodes_json,
                "edges": edges_json,
            },
            "attribution_disclaimer": ATTRIBUTION_DISCLAIMER
        })
        cluster_idx += 1

    # Sort campaigns by correlation score descending
    campaigns.sort(key=lambda c: c["correlation_score"], reverse=True)
    return campaigns
