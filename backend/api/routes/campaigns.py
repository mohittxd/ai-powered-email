"""
Phase 21 — Campaign Correlation API Routes.
Exposes NetworkX email relationship clusters, shared infrastructure, and correlation scores.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_db
from services.campaign import cluster_emails_by_iocs

router = APIRouter()


@router.get("/campaigns", summary="List auto-correlated email campaigns (NetworkX)")
async def list_campaigns(db: AsyncSession = Depends(get_db)):
    """
    Executes Phase 21 NetworkX campaign correlation across all analyzed emails.
    Identifies shared infrastructure (Senders, Reply-Tos, Domains, IPs, URLs, ASNs).
    """
    campaigns = await cluster_emails_by_iocs(db)
    return {
        "total_campaigns": len(campaigns),
        "campaigns": campaigns,
        "disclaimer": "Technical correlations represent shared network infrastructure, domain registrants, or indicator overlap. Shared infrastructure does NOT establish definitive proof of common human authorship."
    }


@router.get("/campaigns/summary", summary="Campaign threat summary")
async def campaign_summary(db: AsyncSession = Depends(get_db)):
    campaigns = await cluster_emails_by_iocs(db)
    return {
        "total_campaigns": len(campaigns),
        "critical": sum(1 for c in campaigns if c.get("correlation_level") == "CRITICAL"),
        "high": sum(1 for c in campaigns if c.get("correlation_level") == "HIGH"),
        "medium": sum(1 for c in campaigns if c.get("correlation_level") == "MEDIUM"),
        "total_emails_correlated": sum(c.get("email_count", 0) for c in campaigns),
        "top_campaigns": campaigns[:3],
    }


@router.get("/campaigns/{campaign_id}", summary="Get campaign details & NetworkX graph")
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    campaigns = await cluster_emails_by_iocs(db)
    target = next((c for c in campaigns if c["campaign_id"] == campaign_id or c.get("id") == campaign_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found.")
    return target
