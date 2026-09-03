"""
Phase 21 — Campaign Correlation & Shared Infrastructure Service.
Leverages NetworkX multigraph analytics to cluster email evidence based on
shared Senders, Reply-Tos, Domains, IPs, URLs, ASNs, and Infrastructure.
"""
import logging
from typing import List, Dict, Any
from services.campaign_graph import build_global_campaign_graph, compute_campaign_correlation

logger = logging.getLogger(__name__)


async def cluster_emails_by_iocs(db) -> List[Dict[str, Any]]:
    """
    Executes Phase 21 NetworkX campaign correlation algorithm.
    Groups related email evidence and identifies shared infrastructure components.
    """
    try:
        G = await build_global_campaign_graph(db)
        campaigns = compute_campaign_correlation(G)
        return campaigns
    except Exception as exc:
        logger.exception("Error executing NetworkX campaign correlation: %s", exc)
        return []
