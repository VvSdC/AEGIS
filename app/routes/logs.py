"""
Admin telemetry log routes.
"""

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import AuditLog
from ..security import require_admin_user

router = APIRouter()


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
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if system_name:
        query = query.where(AuditLog.system_name == system_name)

    rows = (await db.execute(query)).scalars().all()
    return {
        "viewer": user["username"],
        "entries": [
            {
                "id": row.id,
                "timestamp": row.timestamp.isoformat(),
                "event_type": row.event_type,
                "actor": row.actor,
                "system_name": row.system_name,
                "details": row.details,
                "hash": row.hash,
                "prev_hash": row.prev_hash,
            }
            for row in rows
        ],
    }
