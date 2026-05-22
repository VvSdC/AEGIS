"""
AEGIS Audit Routes
Hash-chained audit logging endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from datetime import datetime

from ..database import get_db
from ..schemas import AuditLogRequest, AuditLogResponse, AuditTrailResponse, AuditVerifyResponse
from ..engines.audit_vault import get_audit_vault

router = APIRouter()


@router.post("/audit/log", response_model=AuditLogResponse)
async def log_event(
    request: AuditLogRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Log an audit event with hash chain integrity.
    
    Each entry is cryptographically linked to the previous entry
    using SHA-256 hashes, creating a tamper-evident audit trail.
    """
    audit = get_audit_vault()
    
    entry = await audit.log(
        db=db,
        event_type=request.event_type,
        actor=request.actor,
        system_name=request.system_name,
        details=request.details,
    )
    
    return AuditLogResponse(
        id=entry.id,
        timestamp=entry.timestamp,
        event_type=entry.event_type,
        actor=entry.actor,
        system_name=entry.system_name,
        details=entry.details,
        hash=entry.hash,
        prev_hash=entry.prev_hash,
    )


@router.get("/audit/trail", response_model=AuditTrailResponse)
async def get_audit_trail(
    system_name: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve audit trail with optional filters.
    
    Returns entries in reverse chronological order with
    chain verification status.
    """
    audit = get_audit_vault()
    
    entries, total = await audit.get_trail(
        db=db,
        system_name=system_name,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )
    
    # Verify chain integrity
    verification = await audit.verify_chain(db, system_name=system_name)
    
    return AuditTrailResponse(
        entries=[
            AuditLogResponse(
                id=e.id,
                timestamp=e.timestamp,
                event_type=e.event_type,
                actor=e.actor,
                system_name=e.system_name,
                details=e.details,
                hash=e.hash,
                prev_hash=e.prev_hash,
            )
            for e in entries
        ],
        total=total,
        verified=verification.verified,
        verification_message=verification.message,
    )


@router.get("/audit/verify", response_model=AuditVerifyResponse)
async def verify_audit_chain(
    system_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify the integrity of the audit chain.
    
    Recomputes all hashes from genesis and compares to stored hashes.
    Any mismatch indicates tampering.
    """
    audit = get_audit_vault()
    
    result = await audit.verify_chain(db, system_name=system_name)
    
    return AuditVerifyResponse(
        verified=result.verified,
        total_entries=result.total_entries,
        first_entry_hash=result.first_entry_hash,
        last_entry_hash=result.last_entry_hash,
        message=result.message,
        tampered_entries=result.tampered_entries,
    )


@router.get("/audit/entry/{hash}")
async def get_entry_by_hash(
    hash: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific audit entry by its hash."""
    audit = get_audit_vault()
    
    entry = await audit.get_entry_by_hash(db, hash)
    
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    
    return AuditLogResponse(
        id=entry.id,
        timestamp=entry.timestamp,
        event_type=entry.event_type,
        actor=entry.actor,
        system_name=entry.system_name,
        details=entry.details,
        hash=entry.hash,
        prev_hash=entry.prev_hash,
    )
