"""
Attribution & Correlation Engine — NetworkX-based graph analysis.

Builds a graph linking domains, IPs, sender aliases, and reply-to addresses
across multiple emails to identify campaign infrastructure.
"""
import json
from datetime import datetime
from typing import Optional
import networkx as nx


# ─────────────────────────── Graph Construction ───────────────────────────────

def build_campaign_graph(emails: list[dict]) -> dict:
    """
    Build an attribution graph from a list of email analysis dicts.

    Nodes: domains, IPs, sender email addresses, reply-to addresses
    Edges: co-occurrence in same email (with weight)

    Returns a serializable graph dict.
    """
    G = nx.Graph()

    for em in emails:
        nodes_in_email = []

        # Add sender nodes
        from_addr = em.get("from_address", "")
        from_domain = from_addr.split("@")[-1].lower() if "@" in (from_addr or "") else ""

        if from_addr:
            G.add_node(from_addr, node_type="email_addr", label=from_addr)
            nodes_in_email.append(from_addr)

        if from_domain:
            G.add_node(from_domain, node_type="domain", label=from_domain)
            nodes_in_email.append(from_domain)

        reply_to = em.get("reply_to", "")
        if reply_to and reply_to != from_addr:
            G.add_node(reply_to, node_type="email_addr", label=reply_to)
            nodes_in_email.append(reply_to)
            rt_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
            if rt_domain and rt_domain != from_domain:
                G.add_node(rt_domain, node_type="domain", label=rt_domain)
                nodes_in_email.append(rt_domain)

        # Add IP nodes from received hops
        for hop in em.get("origin_trace", []):
            ip = hop.get("ip")
            if ip and not hop.get("is_private"):
                G.add_node(ip, node_type="ip", label=ip,
                           country=hop.get("country", ""),
                           isp=hop.get("isp", ""),
                           threat_flags=hop.get("threat_flags", []))
                nodes_in_email.append(ip)

        # Add IOC domain/IP nodes
        for ioc in em.get("iocs", []):
            if ioc.get("ioc_type") in ("domain", "ip"):
                val = ioc["value"]
                G.add_node(val, node_type=ioc["ioc_type"],
                           risk_level=ioc.get("risk_level", "medium"),
                           label=val)
                nodes_in_email.append(val)

        # Connect all nodes in this email (co-occurrence edges)
        for i in range(len(nodes_in_email)):
            for j in range(i + 1, len(nodes_in_email)):
                n1, n2 = nodes_in_email[i], nodes_in_email[j]
                if G.has_edge(n1, n2):
                    G[n1][n2]["weight"] = G[n1][n2].get("weight", 1) + 1
                else:
                    G.add_edge(n1, n2, weight=1,
                               email_id=em.get("email_id", ""))

    return _serialize_graph(G)


def _serialize_graph(G: nx.Graph) -> dict:
    """Convert NetworkX graph to JSON-serializable dict."""
    nodes = []
    for node_id, data in G.nodes(data=True):
        nodes.append({
            "id": str(node_id),
            "label": data.get("label", str(node_id)),
            "node_type": data.get("node_type", "unknown"),
            "risk_level": data.get("risk_level", "low"),
            "country": data.get("country", ""),
            "isp": data.get("isp", ""),
            "threat_flags": data.get("threat_flags", []),
            "degree": G.degree(node_id),
        })

    edges = []
    for u, v, data in G.edges(data=True):
        edges.append({
            "source": str(u),
            "target": str(v),
            "weight": data.get("weight", 1),
            "email_id": data.get("email_id", ""),
        })

    # Compute confidence signals
    stats = {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "ip_nodes": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "ip"),
        "domain_nodes": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "domain"),
        "email_nodes": sum(1 for _, d in G.nodes(data=True) if d.get("node_type") == "email_addr"),
        "shared_infra_edges": sum(1 for _, _, d in G.edges(data=True) if d.get("weight", 1) > 1),
    }

    # Attribution confidence
    if stats["shared_infra_edges"] > 2:
        attribution = "shared_infrastructure"
        confidence = min(0.5 + stats["shared_infra_edges"] * 0.1, 0.95)
    elif stats["ip_nodes"] > 0:
        attribution = "direct_actor_infrastructure"
        confidence = 0.6
    else:
        attribution = "spoofed_domain"
        confidence = 0.4

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": stats,
        "attribution": attribution,
        "confidence": round(confidence, 2),
        "generated_at": datetime.utcnow().isoformat(),
    }


def score_attribution(graph_data: dict) -> dict:
    """
    Score confidence levels for attribution categories.
    Returns confidence scores for each scenario.
    """
    stats = graph_data.get("stats", {})
    shared = stats.get("shared_infra_edges", 0)
    ips = stats.get("ip_nodes", 0)
    domains = stats.get("domain_nodes", 0)

    return {
        "compromised_account": round(max(0, 0.3 - shared * 0.05), 2),
        "spoofed_domain":       round(min(0.3 + domains * 0.1, 0.8), 2),
        "anonymized_infra":     round(min(ips * 0.15, 0.7), 2),
        "direct_actor_infra":   round(min(shared * 0.12, 0.9), 2),
    }
