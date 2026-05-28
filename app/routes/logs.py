"""
Admin telemetry log routes.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import AuditLog, ChatMessage, ChatSession, FilterLog
from ..schemas import (
    LogsActorCount,
    LogsDashboardRates,
    LogsDashboardResponse,
    LogsDashboardSummary,
    LogsTrafficDay,
)
from ..security import require_admin_user
from ..telemetry import pii_type_from_filter, threat_category_from_filter

router = APIRouter()

_ANALYZE_EVENTS = frozenset({
    "analyze_success",
    "analyze_blocked_tier1",
    "analyze_blocked_tier2",
})


def _audit_entry(row: AuditLog) -> dict:
    return {
        "id": row.id,
        "timestamp": row.timestamp.isoformat(),
        "event_type": row.event_type,
        "actor": row.actor,
        "system_name": row.system_name,
        "details": row.details,
        "hash": row.hash,
        "prev_hash": row.prev_hash,
    }


@router.get("/logs/dashboard", response_model=LogsDashboardResponse)
async def get_logs_dashboard(
    days: int = 7,
    user=Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
):
    days = max(1, min(days, 90))
    cutoff = datetime.utcnow() - timedelta(days=days)

    audit_rows = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.timestamp >= cutoff)
            .order_by(AuditLog.timestamp.desc())
        )
    ).scalars().all()

    filter_rows = (
        await db.execute(
            select(FilterLog).where(FilterLog.timestamp >= cutoff)
        )
    ).scalars().all()

    actor_counts: dict[str, int] = defaultdict(int)
    event_type_counts: dict[str, int] = defaultdict(int)
    pii_by_type: dict[str, int] = defaultdict(int)
    threat_by_category: dict[str, int] = defaultdict(int)
    inference_by_provider: dict[str, int] = defaultdict(int)
    region_breakdown: dict[str, int] = defaultdict(int)
    direction_breakdown: dict[str, int] = defaultdict(int)

    analyze_total = 0
    analyze_allowed = 0
    analyze_blocked = 0
    pii_detections = 0
    jailbreak_detections = 0
    injection_detections = 0
    toxicity_detections = 0

    daily_audit: dict[str, int] = defaultdict(int)
    daily_filter: dict[str, int] = defaultdict(int)
    daily_blocked: dict[str, int] = defaultdict(int)
    daily_pii: dict[str, int] = defaultdict(int)

    for row in audit_rows:
        event_type_counts[row.event_type] += 1
        actor_counts[row.actor or "unknown"] += 1
        day = row.timestamp.date().isoformat()
        daily_audit[day] += 1

        details = row.details or {}
        if row.event_type in _ANALYZE_EVENTS:
            analyze_total += 1
            if row.event_type == "analyze_success":
                analyze_allowed += 1
            else:
                analyze_blocked += 1
            provider = details.get("inference_provider")
            if provider:
                inference_by_provider[str(provider)] += 1
            region = details.get("region")
            if region:
                region_breakdown[str(region)] += 1

        for pii_label in details.get("pii_types") or []:
            pii_by_type[str(pii_label)] += 1
            pii_detections += 1
        for cat, count in (details.get("threat_counts") or {}).items():
            threat_by_category[str(cat)] += int(count)
            if cat == "jailbreak":
                jailbreak_detections += int(count)
            elif cat == "injection":
                injection_detections += int(count)
            elif cat == "toxicity":
                toxicity_detections += int(count)

    blocked_filter_requests = 0

    for log in filter_rows:
        day = log.timestamp.date().isoformat()
        daily_filter[day] += 1
        if log.blocked:
            daily_blocked[day] += 1
            blocked_filter_requests += 1
        if log.direction:
            direction_breakdown[log.direction] += 1

        day_had_pii = False
        for fname in log.filters_triggered or []:
            pii_label = pii_type_from_filter(fname)
            if pii_label:
                pii_by_type[pii_label] += 1
                if not day_had_pii:
                    daily_pii[day] += 1
                    day_had_pii = True
                pii_detections += 1
            cat = threat_category_from_filter(fname)
            if cat:
                threat_by_category[cat] += 1
                if cat == "jailbreak":
                    jailbreak_detections += 1
                elif cat == "injection":
                    injection_detections += 1
                elif cat == "toxicity":
                    toxicity_detections += 1

    all_days = sorted(set(daily_audit) | set(daily_filter) | set(daily_blocked) | set(daily_pii))
    if not all_days:
        all_days = [
            (datetime.utcnow() - timedelta(days=i)).date().isoformat()
            for i in range(days - 1, -1, -1)
        ]

    traffic_by_day = [
        LogsTrafficDay(
            date=day,
            audit_events=daily_audit.get(day, 0),
            filter_requests=daily_filter.get(day, 0),
            blocked=daily_blocked.get(day, 0),
            pii_hits=daily_pii.get(day, 0),
        )
        for day in all_days
    ]

    recent_entries = [_audit_entry(row) for row in audit_rows[:50]]

    chat_sessions_count = (
        await db.execute(
            select(func.count(ChatSession.id)).where(ChatSession.created_at >= cutoff)
        )
    ).scalar_one() or 0
    chat_messages_count = (
        await db.execute(
            select(func.count(ChatMessage.id)).where(ChatMessage.created_at >= cutoff)
        )
    ).scalar_one() or 0

    filter_total = len(filter_rows)
    analyze_block_rate = round((analyze_blocked / analyze_total) * 100, 1) if analyze_total else 0.0
    filter_block_rate = round((blocked_filter_requests / filter_total) * 100, 1) if filter_total else 0.0
    traffic_denominator = filter_total + analyze_total
    pii_hit_rate = round((pii_detections / traffic_denominator) * 100, 1) if traffic_denominator else 0.0

    top_actors = [
        LogsActorCount(actor=actor, count=count)
        for actor, count in sorted(actor_counts.items(), key=lambda x: -x[1])[:8]
    ]

    return LogsDashboardResponse(
        viewer=user["username"],
        period_days=days,
        generated_at=datetime.utcnow(),
        rates=LogsDashboardRates(
            analyze_block_rate=analyze_block_rate,
            filter_block_rate=filter_block_rate,
            pii_hit_rate=pii_hit_rate,
        ),
        top_actors=top_actors,
        summary=LogsDashboardSummary(
            period_days=days,
            total_audit_events=len(audit_rows),
            total_filter_requests=len(filter_rows),
            blocked_filter_requests=blocked_filter_requests,
            analyze_total=analyze_total,
            analyze_allowed=analyze_allowed,
            analyze_blocked=analyze_blocked,
            pii_detections=pii_detections,
            jailbreak_detections=jailbreak_detections,
            injection_detections=injection_detections,
            toxicity_detections=toxicity_detections,
            chat_sessions=chat_sessions_count,
            chat_messages=chat_messages_count,
        ),
        event_type_counts=dict(sorted(event_type_counts.items(), key=lambda x: -x[1])),
        pii_by_type=dict(sorted(pii_by_type.items(), key=lambda x: -x[1])),
        threat_by_category=dict(sorted(threat_by_category.items(), key=lambda x: -x[1])),
        traffic_by_day=traffic_by_day,
        inference_by_provider=dict(sorted(inference_by_provider.items(), key=lambda x: -x[1])),
        region_breakdown=dict(sorted(region_breakdown.items(), key=lambda x: -x[1])),
        direction_breakdown=dict(sorted(direction_breakdown.items(), key=lambda x: -x[1])),
        recent_entries=recent_entries,
    )


@router.get("/logs")
async def get_logs(
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    system_name: Optional[str] = None,
    user=Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)
    count_query = select(func.count(AuditLog.id))

    if event_type:
        query = query.where(AuditLog.event_type == event_type)
        count_query = count_query.where(AuditLog.event_type == event_type)
    if system_name:
        query = query.where(AuditLog.system_name == system_name)
        count_query = count_query.where(AuditLog.system_name == system_name)

    rows = (await db.execute(query)).scalars().all()
    total = (await db.execute(count_query)).scalar_one() or 0

    return {
        "viewer": user["username"],
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [_audit_entry(row) for row in rows],
    }
