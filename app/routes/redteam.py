"""
AEGIS Red Team Routes
Adversarial testing endpoints.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from ..database import get_db
from ..schemas import RedTeamRequest, RedTeamResponse, RedTeamProbeResult
from ..engines.redteam_kit import get_redteam_kit
from ..engines.audit_vault import get_audit_vault

router = APIRouter()


@router.post("/redteam/run", response_model=RedTeamResponse)
async def run_redteam(
    request: RedTeamRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Run red team adversarial tests.
    
    Tests the target model against probes in 5 categories:
    - **Jailbreak**: Bypass safety measures
    - **PII**: Extract sensitive information
    - **Bias**: Demographic bias detection
    - **Hallucination**: Factual accuracy
    - **Injection**: Prompt manipulation
    
    Returns pass/fail for each probe with risk assessment.
    """
    kit = get_redteam_kit()
    
    report = await kit.run(
        categories=request.categories,
        target_model=request.target_model,
    )
    
    # Log to audit vault
    audit = get_audit_vault()
    await audit.log(
        db=db,
        event_type="redteam",
        actor="api",
        system_name=request.system_name,
        details={
            "target_model": report.target_model,
            "categories": report.categories_tested,
            "total_probes": report.total_probes,
            "passed": report.passed,
            "failed": report.failed,
        }
    )
    
    return RedTeamResponse(
        target_model=report.target_model,
        categories_tested=report.categories_tested,
        total_probes=report.total_probes,
        passed=report.passed,
        failed=report.failed,
        results=[
            RedTeamProbeResult(
                category=r.category,
                probe=r.probe,
                response=r.response[:500],  # Truncate
                passed=r.passed,
                risk_level=r.risk_level.value,
                details=r.details,
            )
            for r in report.results
        ],
        run_at=report.run_at,
    )


@router.get("/redteam/categories")
async def list_categories():
    """List available red team test categories."""
    return {
        "categories": [
            {
                "id": "jailbreak",
                "name": "Jailbreak Tests",
                "description": "Attempts to bypass safety measures",
                "probe_count": 4,
            },
            {
                "id": "pii",
                "name": "PII Extraction",
                "description": "Attempts to extract sensitive information",
                "probe_count": 3,
            },
            {
                "id": "bias",
                "name": "Bias Detection",
                "description": "Tests for demographic bias",
                "probe_count": 3,
            },
            {
                "id": "hallucination",
                "name": "Hallucination Tests",
                "description": "Tests factual accuracy",
                "probe_count": 3,
            },
            {
                "id": "injection",
                "name": "Prompt Injection",
                "description": "Attempts to manipulate system prompts",
                "probe_count": 3,
            },
        ]
    }
