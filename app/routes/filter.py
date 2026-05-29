"""
AEGIS Filter Routes
Guardrail filtering endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..schemas import FilterRequest, FilterResponse, FilterMatch
from ..engines.guardrails import get_guardrail_engine
from ..engines.audit_vault import get_audit_vault

router = APIRouter()


@router.post("/filter", response_model=FilterResponse)
async def filter_text(
    request: FilterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Filter text through AEGIS guardrails.
    
    **Tier 1** (<30ms): Regex + YARA pattern matching for:
    - PII detection & redaction
    - Jailbreak detection
    - Prompt injection detection
    - Toxicity blocklist
    
    **Tier 2** (async): LLM-based deep classification for:
    - Jailbreak and policy issues (when tier 2 enabled)
    - Novel jailbreak variants
    - Bias detection
    
    Returns filtered text with match details and latency metrics.
    """
    engine = get_guardrail_engine()
    
    # Run filters
    tier_map = {"1": "1", "2": "2", "both": "both"}
    tier = tier_map.get(str(request.tier), "both")
    
    result = await engine.filter(
        text=request.text,
        direction=request.direction,
        tier=tier,
        filters=request.filters,
    )
    
    # Log to audit vault
    audit = get_audit_vault()
    await audit.log(
        db=db,
        event_type="filter",
        actor="api",
        system_name=request.system_name,
        details={
            "direction": request.direction,
            "blocked": result.blocked,
            "matches_count": len(result.matches),
            "tier1_latency_ms": result.tier1_latency_ms,
            "tier2_latency_ms": result.tier2_latency_ms,
        }
    )
    
    return FilterResponse(
        original_text=result.original_text,
        filtered_text=result.filtered_text,
        blocked=result.blocked,
        block_reason=result.block_reason,
        matches=[
            FilterMatch(
                filter_name=m.filter_name,
                category=m.category,
                matched_text=m.matched_text,
                replacement=m.replacement,
                confidence=m.confidence,
                tier=m.tier,
            )
            for m in result.matches
        ],
        tier1_latency_ms=result.tier1_latency_ms,
        tier2_latency_ms=result.tier2_latency_ms,
        total_latency_ms=result.total_latency_ms,
    )


@router.post("/filter/batch")
async def filter_batch(
    texts: list[FilterRequest],
    db: AsyncSession = Depends(get_db),
):
    """
    Filter multiple texts in batch.
    
    Useful for filtering multiple prompts or responses at once.
    """
    engine = get_guardrail_engine()
    results = []
    
    for request in texts:
        result = await engine.filter(
            text=request.text,
            direction=request.direction,
            tier=str(request.tier),
            filters=request.filters,
        )
        results.append(FilterResponse(
            original_text=result.original_text,
            filtered_text=result.filtered_text,
            blocked=result.blocked,
            block_reason=result.block_reason,
            matches=[
                FilterMatch(
                    filter_name=m.filter_name,
                    category=m.category,
                    matched_text=m.matched_text,
                    replacement=m.replacement,
                    confidence=m.confidence,
                    tier=m.tier,
                )
                for m in result.matches
            ],
            tier1_latency_ms=result.tier1_latency_ms,
            tier2_latency_ms=result.tier2_latency_ms,
            total_latency_ms=result.total_latency_ms,
        ))
    
    return {"results": results}
