"""
Governed multi-turn chat: guardrails, storage policy, inference, audit.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..chat_storage import resolve_user_storage
from ..models import ChatMessage, ChatSession
from ..schemas import (
    ChatMessageResponse,
    ChatSendMessageResponse,
    OutputFinding,
    OutputGuardrailResult,
    OutputTier1Result,
    OutputTier2Result,
    PipelineStepState,
    Tier1Result,
    Tier2Result,
    FilterMatch,
)
from ..telemetry import summarize_guardrail_matches, entities_from_matches
from .audit_vault import get_audit_vault
from .guardrails import get_guardrail_engine
from .inference_providers import get_inference_router, refresh_gemini_catalog, refresh_mistral_catalog
from .region_policies import build_compliance_header, get_policies_for_region

REGION_MAP = {
    "india": "INDIA",
    "china": "APAC",
    "europe": "EU",
    "usa": "US",
    "australia": "AUSTRALIA",
}


def _build_tier1_result(tier1_filter, latency_seconds: float) -> Tier1Result:
    entities = entities_from_matches(tier1_filter.matches)
    matches = [
        FilterMatch(
            filter_name=m.filter_name,
            category=m.category,
            matched_text="" if tier1_filter.blocked else m.matched_text,
            replacement=m.replacement,
            confidence=m.confidence,
            tier=m.tier,
        )
        for m in tier1_filter.matches
    ]
    return Tier1Result(
        blocked=tier1_filter.blocked,
        block_reason=getattr(tier1_filter, "block_reason", None),
        matches=matches,
        identified_entities=entities,
        filtered_text="" if tier1_filter.blocked else tier1_filter.filtered_text,
        latency_seconds=round(latency_seconds, 4),
    )


def build_pipeline_steps(
    *,
    guardrail_mode: str,
    tier1: Tier1Result,
    tier2: Optional[Tier2Result],
    allow: bool,
    model_done: bool,
    output_done: bool,
    output_skipped: bool,
) -> List[PipelineStepState]:
    tier2_skipped = guardrail_mode != "advanced"
    tier2_state = "skipped"
    tier2_detail = "Skipped (basic mode)"
    if not tier2_skipped and tier2:
        if tier2.blocked:
            tier2_state = "blocked"
            tier2_detail = tier2.block_reason or "Blocked"
        else:
            tier2_state = "done"
            tier2_detail = f"{len(tier2.policies_applied)} policies applied"

    model_state = "done" if model_done and allow else ("blocked" if not allow and tier2 and tier2.blocked else "blocked" if not allow else "waiting")
    if not allow:
        if tier1.blocked:
            model_state = "skipped"
        elif tier2 and tier2.blocked:
            model_state = "skipped"

    output_state = "skipped" if output_skipped else ("done" if output_done else "skipped")
    if not allow:
        output_state = "skipped"

    return [
        PipelineStepState(
            id="tier1",
            label="Fast screening",
            state="blocked" if tier1.blocked else "done",
            detail=tier1.block_reason if tier1.blocked else "No threats detected",
            latency_ms=round(tier1.latency_seconds * 1000, 1),
        ),
        PipelineStepState(
            id="tier2",
            label="Deep policy review",
            state=tier2_state,
            detail=tier2_detail,
            latency_ms=round(tier2.latency_seconds * 1000, 1) if tier2 and not tier2_skipped else None,
        ),
        PipelineStepState(
            id="model",
            label="Model response",
            state=model_state if allow else ("skipped" if tier1.blocked or (tier2 and tier2.blocked) else "blocked"),
            detail="Response generated" if allow and model_done else None,
        ),
        PipelineStepState(
            id="output",
            label="Output safety check",
            state=output_state,
            detail="Assessment complete" if output_done else "Skipped",
        ),
    ]


def _message_to_response(msg: ChatMessage, ephemeral: Optional[str] = None) -> ChatMessageResponse:
    meta = msg.meta or {}
    pipeline = [PipelineStepState(**s) for s in (msg.pipeline or [])]
    output_guardrail = None
    og_raw = meta.get("output_guardrail")
    if og_raw:
        output_guardrail = OutputGuardrailResult(**og_raw)
    return ChatMessageResponse(
        id=msg.id,
        role=msg.role,
        content=msg.content,
        storage_mode=msg.storage_mode,
        allow=msg.allow,
        pipeline=pipeline,
        identified_entities=meta.get("identified_entities", []),
        output_guardrail=output_guardrail,
        created_at=msg.created_at,
        ephemeral_display=ephemeral,
    )


async def get_session_for_user(db: AsyncSession, session_id: int, username: str) -> ChatSession:
    result = await db.execute(
        select(ChatSession).where(ChatSession.id == session_id, ChatSession.user_id == username)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise PermissionError("Chat session not found")
    return session


async def list_session_messages(db: AsyncSession, session_id: int) -> List[ChatMessage]:
    result = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.created_at.asc(), ChatMessage.id.asc())
    )
    return list(result.scalars().all())


def _history_for_inference(messages: List[ChatMessage]) -> List[Dict[str, str]]:
    history: List[Dict[str, str]] = []
    for msg in messages:
        if not msg.content:
            continue
        if msg.role == "user":
            history.append({"role": "user", "content": msg.content})
        elif msg.role == "assistant" and msg.allow:
            history.append({"role": "assistant", "content": msg.content})
    return history


async def process_chat_message(
    db: AsyncSession,
    session: ChatSession,
    user_text: str,
    username: str,
) -> ChatSendMessageResponse:
    start_time = time.perf_counter()
    guardrail_engine = get_guardrail_engine()
    audit = get_audit_vault()
    internal_region = REGION_MAP.get(session.region, "GLOBAL")

    prior_messages = await list_session_messages(db, session.id)

    tier1_start = time.perf_counter()
    tier1_filter = await guardrail_engine.filter(
        text=user_text,
        direction="prompt",
        tier="1",
        region=internal_region,
    )
    tier1_latency = time.perf_counter() - tier1_start
    tier1 = _build_tier1_result(tier1_filter, tier1_latency)
    tier1_telemetry = summarize_guardrail_matches(tier1_filter.matches)

    stored_content, storage_mode, _ = resolve_user_storage(tier1_filter)
    entities = entities_from_matches(tier1_filter.matches)

    user_msg = ChatMessage(
        session_id=session.id,
        role="user",
        content=stored_content,
        storage_mode=storage_mode,
        allow=None,
        pipeline=[],
        meta={"identified_entities": entities if tier1.blocked else []},
    )
    db.add(user_msg)
    await db.flush()

    ephemeral_user = user_text if storage_mode == "withheld" else None

    async def _audit(event_type: str, extra: dict):
        await audit.log(
            db=db,
            event_type=event_type,
            actor=username,
            system_name="aegis-chat",
            details={
                "session_id": session.id,
                "message_id": user_msg.id,
                "region": session.region,
                "storage_mode": storage_mode,
                **tier1_telemetry,
                **extra,
            },
        )

    tier2: Optional[Tier2Result] = None
    output_guardrail_result: Optional[OutputGuardrailResult] = None
    allow = True
    assistant_text = ""
    output_skipped = session.output_guardrail_mode == "none"

    if tier1.blocked:
        allow = False
        assistant_text = f"Request blocked by screening: {tier1.block_reason}"
        pipeline = build_pipeline_steps(
            guardrail_mode=session.guardrail_mode,
            tier1=tier1,
            tier2=None,
            allow=False,
            model_done=False,
            output_done=False,
            output_skipped=True,
        )
        await _audit("chat_blocked_tier1", {"reason": tier1.block_reason})
    else:
        if session.guardrail_mode == "advanced":
            tier2_start = time.perf_counter()
            tier2_filter = await guardrail_engine.filter(
                text=tier1.filtered_text,
                direction="prompt",
                tier="2",
                region=internal_region,
            )
            tier2_latency = time.perf_counter() - tier2_start
            policy_names = get_policies_for_region(session.region)
            tier2 = Tier2Result(
                blocked=tier2_filter.blocked,
                block_reason=getattr(tier2_filter, "block_reason", None),
                policies_applied=policy_names,
                region=session.region,
                latency_seconds=round(tier2_latency, 4),
            )
            if tier2.blocked:
                allow = False
                assistant_text = f"Request blocked by policy review: {tier2.block_reason}"
                pipeline = build_pipeline_steps(
                    guardrail_mode=session.guardrail_mode,
                    tier1=tier1,
                    tier2=tier2,
                    allow=False,
                    model_done=False,
                    output_done=False,
                    output_skipped=True,
                )
                await _audit("chat_blocked_tier2", {"reason": tier2.block_reason})
            else:
                pass
        else:
            policy_names = get_policies_for_region(session.region)
            tier2 = Tier2Result(
                blocked=False,
                block_reason=None,
                policies_applied=policy_names,
                region=session.region,
                latency_seconds=0.0,
            )

        if allow:
            await refresh_gemini_catalog()
            await refresh_mistral_catalog()
            inference = get_inference_router()
            history = _history_for_inference(prior_messages)
            if stored_content:
                history.append({"role": "user", "content": stored_content})
            compliance_header = build_compliance_header(session.region)
            try:
                assistant_text = await inference.generate_messages(
                    session.inference_provider,
                    session.model,
                    history,
                    compliance_header=compliance_header,
                )
            except Exception as exc:
                allow = False
                assistant_text = f"Model failed to respond: {exc}"

            if allow and session.output_guardrail_mode != "none":
                output_assessment = await guardrail_engine.assess_output(
                    original_prompt=user_text,
                    response_text=assistant_text,
                    region=session.region,
                    tier=session.output_guardrail_mode,
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
                        compliance_findings=[
                            OutputFinding(**f) for f in tier2_data.get("compliance_findings", [])
                        ],
                        region=tier2_data.get("region", session.region),
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

            pipeline = build_pipeline_steps(
                guardrail_mode=session.guardrail_mode,
                tier1=tier1,
                tier2=tier2,
                allow=allow,
                model_done=allow,
                output_done=allow and not output_skipped,
                output_skipped=output_skipped,
            )
            if allow:
                await _audit(
                    "chat_message_success",
                    {
                        "guardrail_mode": session.guardrail_mode,
                        "inference_provider": session.inference_provider,
                        "model": session.model,
                        "latency_s": round(time.perf_counter() - start_time, 4),
                    },
                )

    assistant_meta: Dict = {
        "identified_entities": tier1.identified_entities if not allow else [],
        "total_latency_s": round(time.perf_counter() - start_time, 4),
    }
    if output_guardrail_result is not None:
        assistant_meta["output_guardrail"] = output_guardrail_result.model_dump()

    assistant_msg = ChatMessage(
        session_id=session.id,
        role="assistant",
        content=assistant_text if allow or not allow else assistant_text,
        storage_mode="full",
        allow=allow,
        pipeline=[s.model_dump() for s in pipeline],
        meta=assistant_meta,
    )
    db.add(assistant_msg)

    if not session.title or session.title == "New chat":
        session.title = (user_text[:48] + "…") if len(user_text) > 48 else user_text
    session.updated_at = datetime.utcnow()

    await db.flush()

    return ChatSendMessageResponse(
        session_id=session.id,
        user_message=_message_to_response(user_msg, ephemeral=ephemeral_user),
        assistant_message=_message_to_response(assistant_msg),
    )
