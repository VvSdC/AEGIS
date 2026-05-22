"""
AEGIS Two-Tier Analysis Route

Progressive two-tier guardrail analysis:
1. Tier 1 (Basic): Fast regex/pattern matching (<30ms)
2. Tier 2 (Advanced): LLM-based analysis + region policy enforcement (~5s)

Returns structured Pydantic response with allow/response format.
"""

import time
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    Tier1Result,
    Tier2Result,
    FilterMatch,
    OutputGuardrailResult,
    OutputTier1Result,
    OutputTier2Result,
    OutputFinding,
)
from ..engines.guardrails import get_guardrail_engine
from ..engines.policy_engine import get_policy_engine
from ..engines.audit_vault import get_audit_vault
from ..engines.gemini_cli import get_gemini_cli
from ..engines.region_policies import build_compliance_header, get_policies_for_region

router = APIRouter()

REGION_MAP = {
    "india": "INDIA",
    "china": "APAC",
    "europe": "EU",
    "usa": "US",
    "australia": "AUSTRALIA",
}


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(
    request: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Two-tier progressive analysis endpoint.

    Flow:
    1. Run Tier 1 (fast pattern matching) - results returned immediately
    2. If not hard-blocked and mode is 'advanced':
       - Run Tier 2 LLM analysis
       - Apply region-based policies
       - Generate model response
    3. Return structured response: {allow, response}
    """
    start_time = time.perf_counter()
    guardrail_engine = get_guardrail_engine()
    policy_engine = get_policy_engine()
    audit = get_audit_vault()

    internal_region = REGION_MAP.get(request.region, "GLOBAL")

    # --- Tier 1: Fast pattern scan ---
    tier1_start = time.perf_counter()
    tier1_filter = await guardrail_engine.filter(
        text=request.prompt,
        direction="prompt",
        tier="1",
        region=internal_region,
    )
    tier1_latency = time.perf_counter() - tier1_start

    tier1 = Tier1Result(
        blocked=tier1_filter.blocked,
        block_reason=getattr(tier1_filter, "block_reason", None),
        matches=[
            FilterMatch(
                filter_name=m.filter_name,
                category=m.category,
                matched_text=m.matched_text,
                replacement=m.replacement,
                confidence=m.confidence,
                tier=m.tier,
            )
            for m in tier1_filter.matches
        ],
        filtered_text=tier1_filter.filtered_text,
        latency_seconds=round(tier1_latency, 4),
    )

    if tier1.blocked:
        total_latency = time.perf_counter() - start_time
        await audit.log(
            db=db,
            event_type="analyze_blocked_tier1",
            actor="api",
            system_name="aegis-ui",
            details={
                "region": request.region,
                "reason": tier1.block_reason,
                "latency_s": round(total_latency, 4),
            },
        )
        return AnalyzeResponse(
            allow=False,
            response=f"Request blocked by Tier 1 guardrails: {tier1.block_reason}",
            original_prompt=request.prompt,
            tier1=tier1,
            tier2=None,
            output_guardrail=None,
            total_latency_seconds=round(total_latency, 4),
        )

    # --- Tier 2: Advanced analysis (if mode is advanced) ---
    tier2 = None
    if request.guardrail_mode == "advanced":
        tier2_start = time.perf_counter()

        tier2_filter = await guardrail_engine.filter(
            text=tier1.filtered_text,
            direction="prompt",
            tier="2",
            region=internal_region,
        )

        policies = policy_engine.get_policies_for_region(internal_region)
        policy_names = get_policies_for_region(request.region)

        tier2_blocked = tier2_filter.blocked
        tier2_reason = getattr(tier2_filter, "block_reason", None)
        tier2_latency = time.perf_counter() - tier2_start

        tier2 = Tier2Result(
            blocked=tier2_blocked,
            block_reason=tier2_reason,
            policies_applied=policy_names,
            region=request.region,
            latency_seconds=round(tier2_latency, 4),
        )

        if tier2_blocked:
            total_latency = time.perf_counter() - start_time
            await audit.log(
                db=db,
                event_type="analyze_blocked_tier2",
                actor="api",
                system_name="aegis-ui",
                details={
                    "region": request.region,
                    "reason": tier2_reason,
                    "policies": policy_names,
                    "latency_s": round(total_latency, 4),
                },
            )
            return AnalyzeResponse(
                allow=False,
                response=f"Request blocked by Tier 2 analysis: {tier2_reason}",
                original_prompt=request.prompt,
                tier1=tier1,
                tier2=tier2,
                output_guardrail=None,
                total_latency_seconds=round(total_latency, 4),
            )
    else:
        policy_names = get_policies_for_region(request.region)
        tier2 = Tier2Result(
            blocked=False,
            block_reason=None,
            policies_applied=policy_names,
            region=request.region,
            latency_seconds=0.0,
        )

    # --- Generate model response ---
    compliance_header = build_compliance_header(request.region)
    governed_prompt = compliance_header + tier1.filtered_text

    cli = get_gemini_cli()
    if not cli or not cli.is_available():
        total_latency = time.perf_counter() - start_time
        return AnalyzeResponse(
            allow=False,
            response="Model unavailable. Gemini CLI is not configured or not reachable.",
            original_prompt=request.prompt,
            tier1=tier1,
            tier2=tier2,
            output_guardrail=None,
            total_latency_seconds=round(total_latency, 4),
        )

    try:
        model_response = await cli.generate_content_async(governed_prompt)
    except Exception as e:
        total_latency = time.perf_counter() - start_time
        return AnalyzeResponse(
            allow=False,
            response=f"Model failed to respond. Error: {str(e)}",
            original_prompt=request.prompt,
            tier1=tier1,
            tier2=tier2,
            output_guardrail=None,
            total_latency_seconds=round(total_latency, 4),
        )

    # --- Output Guardrails (warn-only assessment) ---
    output_guardrail_mode = getattr(request, 'output_guardrail_mode', 'tier1')
    output_guardrail_result = None
    
    if output_guardrail_mode != "none":
        output_assessment = await guardrail_engine.assess_output(
            original_prompt=request.prompt,
            response_text=model_response,
            region=request.region,
            tier=output_guardrail_mode,
        )
        
        tier1_data = output_assessment.get("tier1")
        tier2_data = output_assessment.get("tier2")
        
        output_tier1 = None
        if tier1_data:
            output_tier1 = OutputTier1Result(
                findings=[OutputFinding(**f) for f in tier1_data.get("findings", [])],
                has_warnings=tier1_data.get("has_warnings", False),
                warning_summary=tier1_data.get("warning_summary"),
                latency_ms=tier1_data.get("latency_ms", 0),
            )
        
        output_tier2 = None
        if tier2_data:
            output_tier2 = OutputTier2Result(
                compliant=tier2_data.get("compliant", True),
                safety_score=tier2_data.get("safety_score", 1.0),
                compliance_findings=[OutputFinding(**f) for f in tier2_data.get("compliance_findings", [])],
                region=tier2_data.get("region", request.region),
                policies_checked=tier2_data.get("policies_checked", []),
                assessment=tier2_data.get("assessment", ""),
                recommendations=tier2_data.get("recommendations", []),
                latency_ms=tier2_data.get("latency_ms", 0),
            )
        
        output_guardrail_result = OutputGuardrailResult(
            tier1=output_tier1,
            tier2=output_tier2,
            safe_to_use=output_assessment.get("safe_to_use", True),
            action_required=output_assessment.get("action_required", False),
            summary=output_assessment.get("summary", "Output passed all checks."),
        )

    total_latency = time.perf_counter() - start_time

    await audit.log(
        db=db,
        event_type="analyze_success",
        actor="api",
        system_name="aegis-ui",
        details={
            "region": request.region,
            "guardrail_mode": request.guardrail_mode,
            "output_guardrail_mode": output_guardrail_mode,
            "output_safe_to_use": output_guardrail_result.safe_to_use if output_guardrail_result else True,
            "latency_s": round(total_latency, 4),
        },
    )

    return AnalyzeResponse(
        allow=True,
        response=model_response,
        original_prompt=request.prompt,
        tier1=tier1,
        tier2=tier2,
        output_guardrail=output_guardrail_result,
        total_latency_seconds=round(total_latency, 4),
    )
