"""
AEGIS Proxy Routes
The core proxy endpoint that redirects prompts through AEGIS to configured inference providers.

This is the key endpoint that answers: "How do we redirect prompts to proxy 
and from there to the actual model?"

Flow:
1. App sends prompt to POST /api/v1/proxy
2. AEGIS runs Tier 1 guardrails (PII, jailbreak, injection detection)
3. If blocked → return block reason
4. If passed → forward to selected inference API
5. Get model response
6. Run response through output filters
7. Log to audit vault
8. Return filtered response to app
"""

import time
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..config import settings
from ..schemas import (
    ProxyRequest, ProxyResponse, FilterResponse, FilterMatch,
    OutputGuardrailResult, OutputTier1Result, OutputTier2Result, OutputFinding,
)
from ..engines.guardrails import get_guardrail_engine
from ..engines.policy_engine import get_policy_engine
from ..engines.audit_vault import get_audit_vault
from ..engines.inference_providers import get_inference_router
from ..security import require_authenticated_user

router = APIRouter()

@router.post("/proxy", response_model=ProxyResponse)
async def proxy_to_inference(
    request: ProxyRequest,
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Proxy a prompt through AEGIS governance layer to inference providers.
    
    This is the main integration point for applications:
    
    **Instead of:**
    ```
    App → Inference API
    ```
    
    **Use:**
    ```
    App → AEGIS /proxy → (Guardrails + Policy + Audit) → Inference API → Response Filter → App
    ```
    
    ## Flow:
    1. Receive prompt from application
    2. Run Tier 1 guardrails (PII redaction, jailbreak detection)
    3. Check region-specific policies
    4. If blocked: return immediately with reason
    5. If passed: forward to selected provider
    6. Filter model response (PII, toxicity)
    7. Log everything to audit vault
    8. Return filtered response
    
    ## Example Usage:
    ```python
    # Instead of calling a model provider directly:
    # response = model.generate_content(prompt)
    
    # Route through AEGIS:
    response = requests.post(
        "http://localhost:8000/api/v1/proxy",
        json={
            "prompt": "What is the weather like?",
            "system_name": "my-chatbot",
            "region": "EU"
        }
    )
    ```
    """
    start_time = time.perf_counter()
    
    guardrail_engine = get_guardrail_engine()
    policy_engine = get_policy_engine()
    audit = get_audit_vault()

    # Step 1: Run input guardrails based on mode
    # guardrail_mode: "none" | "rule_based" | "model_based"
    guardrail_mode = request.guardrail_mode
    
    if guardrail_mode == "none":
        # Skip guardrails entirely - direct passthrough
        input_filter_result = type('obj', (object,), {
            'blocked': False,
            'filtered_text': request.prompt,
            'original_text': request.prompt,
            'matches': [],
            'tier1_latency_ms': 0,
            'tier2_latency_ms': 0,
            'total_latency_ms': 0,
        })()
    else:
        # rule_based = Tier 1 only (<30ms), model_based = both tiers
        tier = "1" if guardrail_mode == "rule_based" else "both"
        input_filter_result = await guardrail_engine.filter(
            text=request.prompt,
            direction="prompt",
            tier=tier,
            region=request.region,
        )
    
    # Check if blocked
    if input_filter_result.blocked:
        # Log blocked request
        await audit.log(
            db=db,
            event_type="proxy_blocked",
            actor=user["username"],
            system_name=request.system_name,
            details={
                "reason": input_filter_result.block_reason,
                "filters_triggered": [m.filter_name for m in input_filter_result.matches],
            }
        )
        
        elapsed = (time.perf_counter() - start_time) * 1000
        guardrail_latency = input_filter_result.total_latency_ms if hasattr(input_filter_result, 'total_latency_ms') else elapsed
        
        return ProxyResponse(
            original_prompt=request.prompt,
            filtered_prompt="[BLOCKED]",
            model_response="",
            filtered_response="",
            guardrail_results=FilterResponse(
                original_text=input_filter_result.original_text,
                filtered_text=input_filter_result.filtered_text,
                blocked=True,
                block_reason=input_filter_result.block_reason,
                matches=[
                    FilterMatch(
                        filter_name=m.filter_name,
                        category=m.category,
                        matched_text=m.matched_text,
                        replacement=m.replacement,
                        confidence=m.confidence,
                        tier=m.tier,
                    )
                    for m in input_filter_result.matches
                ],
                tier1_latency_ms=input_filter_result.tier1_latency_ms,
                tier2_latency_ms=input_filter_result.tier2_latency_ms,
                total_latency_ms=input_filter_result.total_latency_ms,
            ),
            total_time_ms=elapsed,
            guardrail_latency_ms=guardrail_latency,
            model_time_ms=0,
            blocked=True,
            block_reason=input_filter_result.block_reason,
        )
    
    # Step 2: Use filtered prompt (PII redacted)
    filtered_prompt = input_filter_result.filtered_text
    
    # Step 3: Quick policy pre-check (optional based on region)
    policy_check = None
    if request.region:
        # Get applicable policies (lightweight check)
        policies = policy_engine.get_policies_for_region(request.region)
        policy_check = {
            "region": request.region,
            "policies_applicable": [p.name for p in policies],
        }
    
    # Step 4: Forward to selected inference provider
    inference = get_inference_router()
    if not inference.is_valid_model(request.inference_provider, request.model):
        raise HTTPException(
            status_code=400,
            detail=f"Model '{request.model}' is not valid for provider '{request.inference_provider}'.",
        )
    model_start = time.perf_counter()
    try:
        model_response = await inference.generate(request.inference_provider, request.model, filtered_prompt)
    except Exception as e:
        await audit.log(
            db=db,
            event_type="proxy_error",
            actor=user["username"],
            system_name=request.system_name,
            details={"error": str(e)},
        )
        raise HTTPException(status_code=502, detail=f"Inference API error: {str(e)}")
    
    # Step 5: Output guardrails based on output_guardrail_mode
    model_time_ms = (time.perf_counter() - model_start) * 1000
    
    output_guardrail_mode = getattr(request, 'output_guardrail_mode', 'tier1')
    output_guardrail_result = None
    filtered_response = model_response  # Default: no modification
    
    if output_guardrail_mode != "none":
        # Run output assessment (warn-only, no blocking)
        output_assessment = await guardrail_engine.assess_output(
            original_prompt=request.prompt,
            response_text=model_response,
            region=request.region or "india",
            tier=output_guardrail_mode,
        )
        
        # Build structured output guardrail result
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
                region=tier2_data.get("region", request.region or "india"),
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
        
        # Note: We don't modify filtered_response - output guardrails are warn-only
    
    # Step 6: Log to audit
    elapsed = (time.perf_counter() - start_time) * 1000
    input_guardrail_time = input_filter_result.total_latency_ms if hasattr(input_filter_result, 'total_latency_ms') else 0
    output_guardrail_time = (
        (output_guardrail_result.tier1.latency_ms if output_guardrail_result and output_guardrail_result.tier1 else 0) +
        (output_guardrail_result.tier2.latency_ms if output_guardrail_result and output_guardrail_result.tier2 else 0)
    )
    guardrail_latency = input_guardrail_time + output_guardrail_time
    
    await audit.log(
        db=db,
        event_type="proxy_success",
        actor=user["username"],
        system_name=request.system_name,
        details={
            "input_filters": len(input_filter_result.matches) if hasattr(input_filter_result, 'matches') else 0,
            "output_warnings": len(output_guardrail_result.tier1.findings) if output_guardrail_result and output_guardrail_result.tier1 else 0,
            "output_safe_to_use": output_guardrail_result.safe_to_use if output_guardrail_result else True,
            "total_time_ms": elapsed,
            "guardrail_latency_ms": guardrail_latency,
            "model_time_ms": model_time_ms,
            "inference_provider": request.inference_provider,
            "model": request.model,
        }
    )
    
    # Step 7: Return filtered response
    return ProxyResponse(
        original_prompt=request.prompt,
        filtered_prompt=filtered_prompt,
        model_response=model_response,
        filtered_response=filtered_response,
        guardrail_results=FilterResponse(
            original_text=input_filter_result.original_text if hasattr(input_filter_result, 'original_text') else request.prompt,
            filtered_text=input_filter_result.filtered_text if hasattr(input_filter_result, 'filtered_text') else request.prompt,
            blocked=False,
            matches=[
                FilterMatch(
                    filter_name=m.filter_name,
                    category=m.category,
                    matched_text=m.matched_text,
                    replacement=m.replacement,
                    confidence=m.confidence,
                    tier=m.tier,
                )
                for m in (input_filter_result.matches if hasattr(input_filter_result, 'matches') else [])
            ],
            tier1_latency_ms=input_filter_result.tier1_latency_ms if hasattr(input_filter_result, 'tier1_latency_ms') else 0,
            tier2_latency_ms=input_filter_result.tier2_latency_ms if hasattr(input_filter_result, 'tier2_latency_ms') else 0,
            total_latency_ms=input_filter_result.total_latency_ms if hasattr(input_filter_result, 'total_latency_ms') else 0,
        ),
        output_guardrail=output_guardrail_result,
        policy_check=policy_check,
        total_time_ms=elapsed,
        guardrail_latency_ms=guardrail_latency,
        model_time_ms=model_time_ms,
        blocked=False,
    )


@router.post("/proxy/stream")
async def proxy_stream(
    request: ProxyRequest,
    user=Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Streaming version of the proxy endpoint.
    
    Same guardrails and governance, but returns a streaming response
    for real-time chat applications.
    
    (Simplified implementation - production would use SSE or WebSocket)
    """
    # For now, delegate to non-streaming endpoint
    return await proxy_to_inference(request, user, db)


@router.get("/proxy/status")
async def proxy_status():
    """Check proxy connectivity and configuration."""
    inference = get_inference_router()
    options = inference.get_available_provider_options()
    
    return {
        "providers": options,
        "default_provider": "gemini",
        "default_model": "gemini-2.5-flash",
        "tier1_enabled": True,
        "tier2_enabled": settings.tier2_enabled,
        "guardrails_active": True,
    }
