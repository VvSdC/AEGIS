"""
AEGIS Risk Scoring Routes
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from ..database import get_db
from ..schemas import RiskScoreRequest, RiskScoreResponse, RiskBreakdown
from ..engines.risk_scorer import get_risk_scorer
from ..engines.audit_vault import get_audit_vault
from ..models import RiskAssessment

router = APIRouter()


@router.post("/risk/score", response_model=RiskScoreResponse)
async def score_risk(
    request: RiskScoreRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Score an AI system's risk level.
    
    Uses 40+ weighted signals across 6 categories:
    - Data Sensitivity (25%)
    - Autonomy Level (20%)
    - Impact Scope (20%)
    - Model Risk (15%)
    - Regulatory Exposure (10%)
    - Organizational Readiness (10%)
    
    Returns a 0-100 score with level classification and recommendations.
    """
    scorer = get_risk_scorer()
    
    result = scorer.score(
        system_name=request.system_name,
        pii_involved=request.pii_involved,
        pii_types=request.pii_types,
        data_volume=request.data_volume,
        cross_border_transfer=request.cross_border_transfer,
        autonomy_level=request.autonomy_level,
        decision_type=request.decision_type,
        affected_users=request.affected_users,
        vulnerable_populations=request.vulnerable_populations,
        critical_infrastructure=request.critical_infrastructure,
        model_type=request.model_type,
        training_data_provenance=request.training_data_provenance,
        applicable_regulations=request.applicable_regulations,
        high_risk_classification=request.high_risk_classification,
        existing_controls=request.existing_controls,
        team_training=request.team_training,
        incident_response_plan=request.incident_response_plan,
    )
    
    # Save to database
    assessment = RiskAssessment(
        system_name=result.system_name,
        score=result.score,
        level=result.level.value,
        breakdown=result.breakdown.to_dict(),
        recommendations=result.recommendations,
        input_data=result.input_data,
        assessed_at=result.assessed_at,
    )
    db.add(assessment)
    
    # Log to audit vault
    audit = get_audit_vault()
    await audit.log(
        db=db,
        event_type="risk_score",
        actor="api",
        system_name=request.system_name,
        details={
            "score": result.score,
            "level": result.level.value,
        }
    )
    
    return RiskScoreResponse(
        system_name=result.system_name,
        score=result.score,
        level=result.level.value,
        breakdown=RiskBreakdown(
            data_sensitivity=result.breakdown.data_sensitivity,
            autonomy_level=result.breakdown.autonomy_level,
            impact_scope=result.breakdown.impact_scope,
            model_risk=result.breakdown.model_risk,
            regulatory_exposure=result.breakdown.regulatory_exposure,
            organizational_readiness=result.breakdown.organizational_readiness,
        ),
        recommendations=result.recommendations,
        assessed_at=result.assessed_at,
    )


@router.get("/risk/history/{system_name}")
async def get_risk_history(
    system_name: str,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """Get risk assessment history for a system."""
    from sqlalchemy import select
    
    result = await db.execute(
        select(RiskAssessment)
        .where(RiskAssessment.system_name == system_name)
        .order_by(RiskAssessment.assessed_at.desc())
        .limit(limit)
    )
    assessments = result.scalars().all()
    
    return {
        "system_name": system_name,
        "assessments": [
            {
                "id": a.id,
                "score": a.score,
                "level": a.level,
                "assessed_at": a.assessed_at.isoformat(),
            }
            for a in assessments
        ]
    }
