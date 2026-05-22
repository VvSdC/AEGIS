"""
AEGIS Dashboard Routes
Statistics and overview endpoints.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta

from ..database import get_db
from ..schemas import DashboardStats, DashboardResponse, RiskHeatmapEntry
from ..models import RiskAssessment, FilterLog, AuditLog, Playbook

router = APIRouter()


@router.get("/dashboard/stats", response_model=DashboardResponse)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
):
    """
    Get dashboard statistics.
    
    Returns:
    - Total systems tracked
    - High risk system count
    - Filter request statistics
    - Policy compliance rate
    - Recent audit activity
    - Active playbooks
    """
    # Total unique systems
    result = await db.execute(
        select(func.count(func.distinct(RiskAssessment.system_name)))
    )
    total_systems = result.scalar_one() or 0
    
    # High risk systems
    result = await db.execute(
        select(func.count(func.distinct(RiskAssessment.system_name)))
        .where(RiskAssessment.level.in_(["HIGH", "CRITICAL"]))
    )
    high_risk_systems = result.scalar_one() or 0
    
    # Filter statistics
    result = await db.execute(select(func.count(FilterLog.id)))
    total_filter_requests = result.scalar_one() or 0
    
    result = await db.execute(
        select(func.count(FilterLog.id))
        .where(FilterLog.blocked == True)
    )
    blocked_requests = result.scalar_one() or 0
    
    # Recent audits (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(hours=24)
    result = await db.execute(
        select(func.count(AuditLog.id))
        .where(AuditLog.timestamp >= yesterday)
    )
    recent_audits = result.scalar_one() or 0
    
    # Active playbooks (not ATTESTED)
    result = await db.execute(
        select(func.count(Playbook.id))
        .where(Playbook.current_stage != "ATTESTED")
    )
    active_playbooks = result.scalar_one() or 0
    
    # Calculate compliance rate (simplified)
    compliance_rate = 0.0
    if total_systems > 0:
        compliance_rate = max(0, (total_systems - high_risk_systems) / total_systems * 100)
    
    # Risk heatmap - latest assessment per system
    result = await db.execute(
        select(RiskAssessment)
        .order_by(RiskAssessment.assessed_at.desc())
        .limit(20)
    )
    assessments = result.scalars().all()
    
    # Dedupe by system name, keep latest
    seen = set()
    risk_heatmap = []
    for a in assessments:
        if a.system_name not in seen:
            seen.add(a.system_name)
            risk_heatmap.append(RiskHeatmapEntry(
                system_name=a.system_name,
                risk_level=a.level,
                score=a.score,
                last_assessed=a.assessed_at,
            ))
    
    # Recent activity
    result = await db.execute(
        select(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(10)
    )
    recent_logs = result.scalars().all()
    
    recent_activity = [
        {
            "timestamp": log.timestamp.isoformat(),
            "event_type": log.event_type,
            "actor": log.actor,
            "system_name": log.system_name,
        }
        for log in recent_logs
    ]
    
    return DashboardResponse(
        stats=DashboardStats(
            total_systems=total_systems,
            high_risk_systems=high_risk_systems,
            total_filter_requests=total_filter_requests,
            blocked_requests=blocked_requests,
            policy_compliance_rate=round(compliance_rate, 1),
            recent_audits=recent_audits,
            active_playbooks=active_playbooks,
        ),
        risk_heatmap=risk_heatmap,
        recent_activity=recent_activity,
    )


@router.get("/dashboard/filter-stats")
async def get_filter_stats(
    days: int = 7,
    db: AsyncSession = Depends(get_db),
):
    """Get filter statistics over time."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    result = await db.execute(
        select(FilterLog)
        .where(FilterLog.timestamp >= cutoff)
        .order_by(FilterLog.timestamp.desc())
    )
    logs = result.scalars().all()
    
    # Group by day
    daily_stats = {}
    for log in logs:
        day = log.timestamp.date().isoformat()
        if day not in daily_stats:
            daily_stats[day] = {"total": 0, "blocked": 0, "pii_detected": 0}
        daily_stats[day]["total"] += 1
        if log.blocked:
            daily_stats[day]["blocked"] += 1
        if any("pii" in f.lower() for f in log.filters_triggered):
            daily_stats[day]["pii_detected"] += 1
    
    return {
        "period_days": days,
        "daily_stats": daily_stats,
    }
