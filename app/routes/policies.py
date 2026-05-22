"""
AEGIS Policy Routes
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from ..database import get_db
from ..schemas import PolicyEvaluateRequest, PolicyEvaluateResponse, PolicyEvaluationResult
from ..engines.policy_engine import get_policy_engine
from ..engines.audit_vault import get_audit_vault

router = APIRouter()


@router.get("/policies")
async def list_policies(
    region: Optional[str] = None,
):
    """
    List all available policy templates.
    
    Optionally filter by region to see applicable policies.
    """
    engine = get_policy_engine()
    
    if region:
        policies = engine.get_policies_for_region(region)
        return {
            "region": region,
            "policies": [p.to_dict() for p in policies]
        }
    
    return {
        "policies": engine.list_policies()
    }


@router.get("/policies/{policy_name}")
async def get_policy(policy_name: str):
    """Get a specific policy template by name."""
    engine = get_policy_engine()
    policy = engine.get_policy(policy_name)
    
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_name}' not found")
    
    return policy.to_dict()


@router.post("/policies/evaluate", response_model=PolicyEvaluateResponse)
async def evaluate_policies(
    request: PolicyEvaluateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Evaluate a system against applicable policies.
    
    Automatically selects policies based on region and evaluates
    all rules against the provided system details.
    
    Returns pass/fail for each rule with compliance status.
    """
    engine = get_policy_engine()
    
    result = engine.evaluate(
        system_name=request.system_name,
        region=request.region,
        system_details=request.system_details,
    )
    
    # Log to audit vault
    audit = get_audit_vault()
    await audit.log(
        db=db,
        event_type="policy_check",
        actor="api",
        system_name=request.system_name,
        details={
            "region": request.region,
            "policies_evaluated": result.policies_evaluated,
            "passed": len(result.passed_rules),
            "failed": len(result.failed_rules),
            "compliant": result.overall_compliant,
        }
    )
    
    return PolicyEvaluateResponse(
        system_name=result.system_name,
        region=result.region,
        policies_evaluated=result.policies_evaluated,
        passed_rules=[
            PolicyEvaluationResult(
                rule_id=r.rule_id,
                rule_name=r.rule_name,
                passed=r.passed,
                severity=r.severity,
                message=r.message,
            )
            for r in result.passed_rules
        ],
        failed_rules=[
            PolicyEvaluationResult(
                rule_id=r.rule_id,
                rule_name=r.rule_name,
                passed=r.passed,
                severity=r.severity,
                message=r.message,
            )
            for r in result.failed_rules
        ],
        warnings=result.warnings,
        overall_compliant=result.overall_compliant,
    )


@router.get("/policies/regions")
async def list_regions():
    """List all supported regions and their associated policies."""
    engine = get_policy_engine()
    return {
        "regions": engine.REGION_POLICIES
    }
