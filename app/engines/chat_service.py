"""
Governed multi-turn chat: guardrails, storage policy, inference, audit.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..output_review import (
    MAX_REGENERATIONS,
    apply_pii_redaction,
    build_regeneration_instruction,
    collect_recommendations,
    evaluate_output_review,
)
from ..security_threshold import resolve_security_threshold
from ..chat_storage import resolve_user_storage
from ..models import ChatMessage, ChatSession
from ..schemas import (
    ChatMessageResponse,
    ChatSendMessageResponse,
    OutputFinding,
    OutputGuardrailResult,
    OutputTier1Result,
    OutputTier2Result,
    OutputReviewState,
    ChatMessageResolveRequest,
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


def _assessment_to_output_guardrail(output_assessment: dict, session_region: str) -> OutputGuardrailResult:
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
            region=tier2_data.get("region", session_region),
            policies_checked=tier2_data.get("policies_checked", []),
            assessment=tier2_data.get("assessment", ""),
            recommendations=tier2_data.get("recommendations", []),
            latency_ms=tier2_data.get("latency_ms", 0),
        )
    return OutputGuardrailResult(
        tier1=output_tier1,
        tier2=output_tier2,
        safe_to_use=output_assessment.get("safe_to_use", True),
        action_required=output_assessment.get("action_required", False),
        summary=output_assessment.get("summary", "Output passed all checks."),
    )


async def _assess_model_output(
    guardrail_engine,
    user_text: str,
    assistant_text: str,
    session: ChatSession,
) -> Optional[OutputGuardrailResult]:
    if session.output_guardrail_mode == "none":
        return None
    output_assessment = await guardrail_engine.assess_output(
        original_prompt=user_text,
        response_text=assistant_text,
        region=session.region,
        tier=session.output_guardrail_mode,
    )
    return _assessment_to_output_guardrail(output_assessment, session.region)


def _message_to_response(msg: ChatMessage, ephemeral: Optional[str] = None) -> ChatMessageResponse:
    meta = msg.meta or {}
    pipeline = [PipelineStepState(**s) for s in (msg.pipeline or [])]
    output_guardrail = None
    og_raw = meta.get("output_guardrail")
    if og_raw:
        output_guardrail = OutputGuardrailResult(**og_raw)
    output_review = None
    rv_raw = meta.get("output_review")
    if rv_raw:
        output_review = OutputReviewState(**rv_raw)

    content = msg.content
    preview_content = None
    if meta.get("review_status") == "pending_review" and msg.role == "assistant":
        preview_content = meta.get("raw_content") or msg.content
        content = None

    return ChatMessageResponse(
        id=msg.id,
        role=msg.role,
        content=content,
        storage_mode=msg.storage_mode,
        allow=msg.allow,
        pipeline=pipeline,
        identified_entities=meta.get("identified_entities", []),
        output_guardrail=output_guardrail,
        output_review=output_review,
        preview_content=preview_content,
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
            meta = msg.meta or {}
            if meta.get("review_status") == "pending_review":
                continue
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
                output_guardrail_result = await _assess_model_output(
                    guardrail_engine, user_text, assistant_text, session
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

    if allow and output_guardrail_result is not None:
        threshold = resolve_security_threshold(session.security_threshold_preset)
        review_state, _ = evaluate_output_review(
            assistant_text,
            output_guardrail_result,
            threshold,
            session.region,
            regenerations_used=0,
        )
        assistant_meta["output_review"] = review_state.model_dump()
        assistant_meta["raw_content"] = assistant_text
        assistant_meta["regenerations_used"] = 0
        assistant_meta["review_status"] = review_state.status
        assistant_meta["source_user_prompt"] = user_text
    elif allow:
        assistant_meta["review_status"] = "delivered"

    assistant_msg = ChatMessage(
        session_id=session.id,
        role="assistant",
        content=assistant_text,
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

    if allow and assistant_meta.get("review_status") == "pending_review":
        await audit.log(
            db=db,
            event_type="chat_output_review_required",
            actor=username,
            system_name="aegis-chat",
            details={
                "session_id": session.id,
                "message_id": assistant_msg.id,
                "trigger_reasons": assistant_meta.get("output_review", {}).get("trigger_reasons", []),
                "security_threshold": resolve_security_threshold(session.security_threshold_preset),
            },
        )

    return ChatSendMessageResponse(
        session_id=session.id,
        user_message=_message_to_response(user_msg, ephemeral=ephemeral_user),
        assistant_message=_message_to_response(assistant_msg),
    )


async def get_message_for_user(
    db: AsyncSession,
    session_id: int,
    message_id: int,
    username: str,
) -> ChatMessage:
    await get_session_for_user(db, session_id, username)
    result = await db.execute(
        select(ChatMessage).where(
            ChatMessage.id == message_id,
            ChatMessage.session_id == session_id,
        )
    )
    msg = result.scalar_one_or_none()
    if not msg:
        raise PermissionError("Message not found")
    return msg


async def _finalize_review_state(
    msg: ChatMessage,
    session: ChatSession,
    text: str,
    user_text: str,
    guardrail_engine,
    regenerations_used: int,
) -> None:
    meta = msg.meta or {}
    threshold = resolve_security_threshold(session.security_threshold_preset)
    output_guardrail_result = await _assess_model_output(
        guardrail_engine, user_text, text, session
    )
    if output_guardrail_result:
        meta["output_guardrail"] = output_guardrail_result.model_dump()
    review_state, _ = evaluate_output_review(
        text,
        output_guardrail_result,
        threshold,
        session.region,
        regenerations_used=regenerations_used,
    )
    meta["output_review"] = review_state.model_dump()
    meta["raw_content"] = text
    meta["regenerations_used"] = regenerations_used
    meta["review_status"] = review_state.status
    msg.meta = meta
    msg.content = text if review_state.status == "delivered" else text


async def resolve_chat_message(
    db: AsyncSession,
    session: ChatSession,
    message_id: int,
    body: ChatMessageResolveRequest,
    username: str,
) -> ChatMessageResponse:
    msg = await get_message_for_user(db, session.id, message_id, username)
    if msg.role != "assistant":
        raise ValueError("Only assistant messages can be resolved")

    meta = dict(msg.meta or {})
    if meta.get("review_status") != "pending_review":
        raise ValueError("Message is not pending review")

    review = OutputReviewState(**meta["output_review"])
    raw = meta.get("raw_content") or msg.content or ""
    findings = review.findings
    allowed = set(body.allowed_pii_finding_ids)
    guardrail_engine = get_guardrail_engine()
    audit = get_audit_vault()
    user_text = meta.get("source_user_prompt", "")
    threshold = review.security_threshold
    regen_used = int(meta.get("regenerations_used", 0))

    og_raw = meta.get("output_guardrail")
    og = OutputGuardrailResult(**og_raw) if og_raw else None

    async def _audit(event_type: str, extra: dict):
        await audit.log(
            db=db,
            event_type=event_type,
            actor=username,
            system_name="aegis-chat",
            details={
                "session_id": session.id,
                "message_id": msg.id,
                "action": body.action,
                "region": session.region,
                **extra,
            },
        )

    if body.action == "accept":
        text = apply_pii_redaction(raw, findings, allowed)
        meta["review_status"] = "delivered"
        review.status = "delivered"
        review.requires_user_action = False
        meta["output_review"] = review.model_dump()
        meta["raw_content"] = text
        msg.content = text
        msg.meta = meta
        await _audit(
            "chat_output_accepted",
            {
                "allowed_pii_ids": list(allowed),
                "max_code_confidence": review.max_code_confidence,
            },
        )

    elif body.action == "apply_pii_redaction":
        text = apply_pii_redaction(raw, findings, allowed)
        await _finalize_review_state(
            msg, session, text, user_text, guardrail_engine, regen_used
        )
        await _audit(
            "chat_output_pii_redacted",
            {"allowed_pii_ids": list(allowed), "review_status": msg.meta.get("review_status")},
        )

    elif body.action == "regenerate":
        if regen_used >= MAX_REGENERATIONS:
            raise ValueError("No regenerations remaining")
        if "regenerate" not in review.allowed_actions:
            raise ValueError("Regeneration is not available for this message")

        code_findings = [f for f in findings if f.category == "insecure_code"]
        instruction = build_regeneration_instruction(
            code_findings,
            collect_recommendations(og),
        )

        prior = await list_session_messages(db, session.id)
        prior = [m for m in prior if m.id < msg.id]
        history = _history_for_inference(prior)
        history.append({"role": "assistant", "content": raw})
        history.append({"role": "user", "content": instruction})

        await refresh_gemini_catalog()
        await refresh_mistral_catalog()
        inference = get_inference_router()
        compliance_header = build_compliance_header(session.region)
        new_text = await inference.generate_messages(
            session.inference_provider,
            session.model,
            history,
            compliance_header=compliance_header,
        )

        regen_used += 1
        await _finalize_review_state(
            msg, session, new_text, user_text, guardrail_engine, regen_used
        )
        await _audit(
            "chat_output_regenerated",
            {
                "regenerations_used": regen_used,
                "review_status": msg.meta.get("review_status"),
            },
        )
    else:
        raise ValueError(f"Unknown action: {body.action}")

    session.updated_at = datetime.utcnow()
    await db.flush()
    return _message_to_response(msg)
