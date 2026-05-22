"""
AEGIS Playbook Runner
Governance workflow state machine for AI system approval process.

Workflow Stages:
INTAKE → RISK_ASSESSMENT → POLICY_CHECK → REVIEW → APPROVED → ATTESTED
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Playbook
from .risk_scorer import get_risk_scorer
from .policy_engine import get_policy_engine


class PlaybookStage(str, Enum):
    INTAKE = "INTAKE"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    POLICY_CHECK = "POLICY_CHECK"
    REVIEW = "REVIEW"
    APPROVED = "APPROVED"
    ATTESTED = "ATTESTED"


# Stage progression order
STAGE_ORDER = [
    PlaybookStage.INTAKE,
    PlaybookStage.RISK_ASSESSMENT,
    PlaybookStage.POLICY_CHECK,
    PlaybookStage.REVIEW,
    PlaybookStage.APPROVED,
    PlaybookStage.ATTESTED,
]


@dataclass
class StageResult:
    """Result of completing a stage."""
    stage: str
    completed_at: datetime
    completed_by: str
    notes: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlaybookStatus:
    """Current status of a playbook."""
    id: int
    system_name: str
    owner: str
    region: str
    current_stage: str
    stages_completed: Dict[str, StageResult]
    next_stage: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "system_name": self.system_name,
            "owner": self.owner,
            "region": self.region,
            "current_stage": self.current_stage,
            "stages_completed": {
                k: {
                    "completed_at": v.completed_at.isoformat(),
                    "completed_by": v.completed_by,
                    "notes": v.notes,
                    "data": v.data,
                }
                for k, v in self.stages_completed.items()
            },
            "next_stage": self.next_stage,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class PlaybookRunner:
    """
    Governance workflow state machine.
    
    Manages the lifecycle of AI system governance from intake to attestation.
    """
    
    def __init__(self):
        """Initialize the playbook runner."""
        self._risk_scorer = get_risk_scorer()
        self._policy_engine = get_policy_engine()
    
    def _get_next_stage(self, current: str) -> Optional[str]:
        """Get the next stage after current."""
        try:
            current_enum = PlaybookStage(current)
            current_idx = STAGE_ORDER.index(current_enum)
            if current_idx < len(STAGE_ORDER) - 1:
                return STAGE_ORDER[current_idx + 1].value
        except (ValueError, IndexError):
            pass
        return None
    
    async def create(
        self,
        db: AsyncSession,
        system_name: str,
        owner: str,
        region: str,
        extra_data: Dict[str, Any] = None,
    ) -> PlaybookStatus:
        """
        Create a new playbook for a system.
        
        Args:
            db: Database session
            system_name: Name of the AI system
            owner: Owner/requestor
            region: Deployment region
            extra_data: Additional data
        
        Returns:
            PlaybookStatus for the new playbook
        """
        extra_data = extra_data or {}
        
        playbook = Playbook(
            system_name=system_name,
            owner=owner,
            region=region,
            current_stage=PlaybookStage.INTAKE.value,
            stages_completed={},
            extra_data=extra_data,
        )
        
        db.add(playbook)
        await db.flush()
        
        return PlaybookStatus(
            id=playbook.id,
            system_name=playbook.system_name,
            owner=playbook.owner,
            region=playbook.region,
            current_stage=playbook.current_stage,
            stages_completed={},
            next_stage=self._get_next_stage(playbook.current_stage),
            created_at=playbook.created_at,
            updated_at=playbook.updated_at,
        )
    
    async def get_status(
        self,
        db: AsyncSession,
        playbook_id: int,
    ) -> Optional[PlaybookStatus]:
        """Get the current status of a playbook."""
        result = await db.execute(
            select(Playbook).where(Playbook.id == playbook_id)
        )
        playbook = result.scalar_one_or_none()
        
        if not playbook:
            return None
        
        # Parse stages_completed
        stages = {}
        for stage_name, stage_data in playbook.stages_completed.items():
            stages[stage_name] = StageResult(
                stage=stage_name,
                completed_at=datetime.fromisoformat(stage_data["completed_at"]),
                completed_by=stage_data["completed_by"],
                notes=stage_data.get("notes"),
                data=stage_data.get("data", {}),
            )
        
        return PlaybookStatus(
            id=playbook.id,
            system_name=playbook.system_name,
            owner=playbook.owner,
            region=playbook.region,
            current_stage=playbook.current_stage,
            stages_completed=stages,
            next_stage=self._get_next_stage(playbook.current_stage),
            created_at=playbook.created_at,
            updated_at=playbook.updated_at,
        )
    
    async def advance(
        self,
        db: AsyncSession,
        playbook_id: int,
        completed_by: str,
        notes: Optional[str] = None,
        data: Dict[str, Any] = None,
    ) -> Optional[PlaybookStatus]:
        """
        Advance a playbook to the next stage.
        
        Some stages run automatically (RISK_ASSESSMENT, POLICY_CHECK).
        Others require manual completion (REVIEW, APPROVED, ATTESTED).
        
        Args:
            db: Database session
            playbook_id: Playbook ID
            completed_by: User completing the stage
            notes: Optional notes
            data: Optional additional data
        
        Returns:
            Updated PlaybookStatus
        """
        result = await db.execute(
            select(Playbook).where(Playbook.id == playbook_id)
        )
        playbook = result.scalar_one_or_none()
        
        if not playbook:
            return None
        
        data = data or {}
        current_stage = playbook.current_stage
        next_stage = self._get_next_stage(current_stage)
        
        if not next_stage:
            # Already at final stage
            return await self.get_status(db, playbook_id)
        
        # Run automatic stages
        if next_stage == PlaybookStage.RISK_ASSESSMENT.value:
            # Run risk assessment automatically
            risk_data = data.get("risk_input", {})
            risk_score = self._risk_scorer.score(
                system_name=playbook.system_name,
                **risk_data
            )
            data["risk_score"] = risk_score.to_dict()
        
        elif next_stage == PlaybookStage.POLICY_CHECK.value:
            # Run policy check automatically
            system_details = data.get("system_details", {})
            evaluation = self._policy_engine.evaluate(
                system_name=playbook.system_name,
                region=playbook.region,
                system_details=system_details,
            )
            data["policy_evaluation"] = evaluation.to_dict()
        
        # Record stage completion
        stages_completed = dict(playbook.stages_completed)
        stages_completed[current_stage] = {
            "completed_at": datetime.utcnow().isoformat(),
            "completed_by": completed_by,
            "notes": notes,
            "data": data,
        }
        
        # Update playbook
        playbook.stages_completed = stages_completed
        playbook.current_stage = next_stage
        playbook.updated_at = datetime.utcnow()
        
        await db.flush()
        
        return await self.get_status(db, playbook_id)
    
    async def list_playbooks(
        self,
        db: AsyncSession,
        system_name: Optional[str] = None,
        owner: Optional[str] = None,
        stage: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PlaybookStatus]:
        """List playbooks with optional filters."""
        query = select(Playbook)
        
        if system_name:
            query = query.where(Playbook.system_name == system_name)
        if owner:
            query = query.where(Playbook.owner == owner)
        if stage:
            query = query.where(Playbook.current_stage == stage)
        
        query = query.order_by(Playbook.updated_at.desc()).offset(offset).limit(limit)
        
        result = await db.execute(query)
        playbooks = result.scalars().all()
        
        statuses = []
        for pb in playbooks:
            stages = {}
            for stage_name, stage_data in pb.stages_completed.items():
                stages[stage_name] = StageResult(
                    stage=stage_name,
                    completed_at=datetime.fromisoformat(stage_data["completed_at"]),
                    completed_by=stage_data["completed_by"],
                    notes=stage_data.get("notes"),
                    data=stage_data.get("data", {}),
                )
            
            statuses.append(PlaybookStatus(
                id=pb.id,
                system_name=pb.system_name,
                owner=pb.owner,
                region=pb.region,
                current_stage=pb.current_stage,
                stages_completed=stages,
                next_stage=self._get_next_stage(pb.current_stage),
                created_at=pb.created_at,
                updated_at=pb.updated_at,
            ))
        
        return statuses


# Singleton
_playbook_runner: Optional[PlaybookRunner] = None


def get_playbook_runner() -> PlaybookRunner:
    """Get or create the playbook runner singleton."""
    global _playbook_runner
    if _playbook_runner is None:
        _playbook_runner = PlaybookRunner()
    return _playbook_runner
