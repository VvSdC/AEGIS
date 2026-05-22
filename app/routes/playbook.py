"""
AEGIS Playbook Routes
Governance workflow endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from ..database import get_db
from ..schemas import PlaybookRunRequest, PlaybookStatusResponse, PlaybookAdvanceRequest
from ..engines.playbook_runner import get_playbook_runner, STAGE_ORDER
from ..engines.audit_vault import get_audit_vault

router = APIRouter()


@router.post("/playbook/run", response_model=PlaybookStatusResponse)
async def create_playbook(
    request: PlaybookRunRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Start a new governance playbook for a system.
    
    Creates a new playbook starting at INTAKE stage and tracks
    progression through:
    
    INTAKE → RISK_ASSESSMENT → POLICY_CHECK → REVIEW → APPROVED → ATTESTED
    """
    runner = get_playbook_runner()
    
    status = await runner.create(
        db=db,
        system_name=request.system_name,
        owner=request.owner,
        region=request.region,
        extra_data=request.extra_data,
    )
    
    # Log to audit vault
    audit = get_audit_vault()
    await audit.log(
        db=db,
        event_type="playbook_created",
        actor=request.owner,
        system_name=request.system_name,
        details={
            "playbook_id": status.id,
            "region": request.region,
        }
    )
    
    return PlaybookStatusResponse(
        id=status.id,
        system_name=status.system_name,
        owner=status.owner,
        region=status.region,
        current_stage=status.current_stage,
        stages_completed={
            k: {
                "completed_at": v.completed_at.isoformat(),
                "completed_by": v.completed_by,
            }
            for k, v in status.stages_completed.items()
        },
        next_stage=status.next_stage,
        created_at=status.created_at,
        updated_at=status.updated_at,
    )


@router.get("/playbook/{playbook_id}", response_model=PlaybookStatusResponse)
async def get_playbook_status(
    playbook_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get the current status of a playbook."""
    runner = get_playbook_runner()
    
    status = await runner.get_status(db, playbook_id)
    
    if not status:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    return PlaybookStatusResponse(
        id=status.id,
        system_name=status.system_name,
        owner=status.owner,
        region=status.region,
        current_stage=status.current_stage,
        stages_completed={
            k: {
                "completed_at": v.completed_at.isoformat(),
                "completed_by": v.completed_by,
            }
            for k, v in status.stages_completed.items()
        },
        next_stage=status.next_stage,
        created_at=status.created_at,
        updated_at=status.updated_at,
    )


@router.post("/playbook/{playbook_id}/advance", response_model=PlaybookStatusResponse)
async def advance_playbook(
    playbook_id: int,
    request: PlaybookAdvanceRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Advance a playbook to the next stage.
    
    Some stages (RISK_ASSESSMENT, POLICY_CHECK) run automatically.
    Others (REVIEW, APPROVED, ATTESTED) require manual completion.
    """
    runner = get_playbook_runner()
    
    # Get current status
    current = await runner.get_status(db, playbook_id)
    if not current:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    # Advance
    status = await runner.advance(
        db=db,
        playbook_id=playbook_id,
        completed_by=request.approved_by or "api",
        notes=request.notes,
    )
    
    if not status:
        raise HTTPException(status_code=500, detail="Failed to advance playbook")
    
    # Log to audit vault
    audit = get_audit_vault()
    await audit.log(
        db=db,
        event_type="playbook_advanced",
        actor=request.approved_by or "api",
        system_name=current.system_name,
        details={
            "playbook_id": playbook_id,
            "from_stage": current.current_stage,
            "to_stage": status.current_stage,
        }
    )
    
    return PlaybookStatusResponse(
        id=status.id,
        system_name=status.system_name,
        owner=status.owner,
        region=status.region,
        current_stage=status.current_stage,
        stages_completed={
            k: {
                "completed_at": v.completed_at.isoformat(),
                "completed_by": v.completed_by,
            }
            for k, v in status.stages_completed.items()
        },
        next_stage=status.next_stage,
        created_at=status.created_at,
        updated_at=status.updated_at,
    )


@router.get("/playbooks")
async def list_playbooks(
    system_name: Optional[str] = None,
    owner: Optional[str] = None,
    stage: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List playbooks with optional filters."""
    runner = get_playbook_runner()
    
    statuses = await runner.list_playbooks(
        db=db,
        system_name=system_name,
        owner=owner,
        stage=stage,
        limit=limit,
        offset=offset,
    )
    
    return {
        "playbooks": [s.to_dict() for s in statuses],
        "total": len(statuses),
    }


@router.get("/playbook/stages")
async def list_stages():
    """List all playbook stages."""
    return {
        "stages": [s.value for s in STAGE_ORDER],
        "descriptions": {
            "INTAKE": "Initial system information collection",
            "RISK_ASSESSMENT": "Automated risk scoring",
            "POLICY_CHECK": "Policy compliance evaluation",
            "REVIEW": "Human review of assessment",
            "APPROVED": "Approval granted",
            "ATTESTED": "Final attestation complete",
        }
    }
