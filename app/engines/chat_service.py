"""
Governed multi-turn chat: guardrails, storage policy, inference, audit.
"""

import time
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..input_pii_consent import (
    PII_CATEGORIES,
    apply_input_pii_redaction,
    chat_needs_pii_consent,
    consent_state_for_api,
    ensure_consent_findings,
    format_input_pii_consent_message,
    prepare_tier1_for_pii_consent,
    scan_pii_for_consent,
    tier1_has_pii,
    has_non_pii_block,
)
from ..output_review import (
    MAX_REGENERATIONS,
    apply_pii_redaction,
    build_regeneration_instruction,
    collect_recommendations,
    evaluate_output_review,
)
from ..security_threshold import resolve_security_threshold
from ..clarification_assessment import assess_prompt_clarity
from ..task_workflow import (
    append_regen_lesson,
    build_brief_header,
    build_clarification_header,
    build_execution_plan,
    extract_brief_from_message,
    format_clarification_message,
    get_workflow,
    merge_clarification_answers,
    save_workflow,
    task_brief_model,
    total_planned_llm_calls,
)
from ..schemas import (
    ChatMessageResponse,
    ChatSendMessageResponse,
    ClarificationQuestion,
    ExecutionPlanStep,
    OutputFinding,
    OutputGuardrailResult,
    OutputTier1Result,
    OutputTier2Result,
    OutputReviewState,
    ChatInputPiiConsentRequest,
    ChatMessageResolveRequest,
    InputPiiEntity,
    PipelineStepState,
    TaskBrief,
    Tier1Result,
    Tier2Result,
    FilterMatch,
)
from ..chat_storage import resolve_user_storage
from ..models import ChatMessage, ChatSession
from ..telemetry import summarize_guardrail_matches, entities_from_matches
from .audit_vault import get_audit_vault
from .guardrails import get_guardrail_engine
from .inference_providers import get_inference_router
from ..response_cleanup import strip_visible_compliance_boilerplate
from .region_policies import build_governance_system_instruction, get_policies_for_region

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


def session_workflow_envelope(session: ChatSession) -> dict:
    workflow = get_workflow(session)
    phase = workflow.get("phase") or "idle"
    clar = workflow.get("clarification") or {}
    questions = [
        ClarificationQuestion(**q) for q in (clar.get("questions") or [])
    ]
    plan = build_execution_plan(
        guardrail_mode=session.guardrail_mode,
        output_guardrail_mode=session.output_guardrail_mode,
        completion_mode=getattr(session, "completion_mode", "balanced") or "balanced",
        phase=phase,
        clarifying=phase == "clarifying",
    )
    return {
        "phase": phase,
        "task_brief": task_brief_model(workflow),
        "execution_plan": plan,
        "planned_llm_calls": total_planned_llm_calls(plan),
        "clarification_questions": questions,
    }


def _compliance_with_brief(session: ChatSession, workflow: dict) -> str:
    parts = []
    clar_header = build_clarification_header(workflow)
    if clar_header:
        parts.append(clar_header)
    brief_header = build_brief_header(workflow)
    if brief_header:
        parts.append(brief_header)
    parts.append(build_governance_system_instruction(session.region))
    return "\n\n".join(parts)


def _friendly_tier1_pipeline_detail(tier1: Tier1Result) -> str:
    if not tier1.blocked:
        return "Looks OK"
    reason = (tier1.block_reason or "").lower()
    if "hard block" in reason or "pii" in reason or "pan" in reason or "aadhaar" in reason:
        return "Personal details found — waiting for your choice"
    return "Message not allowed"


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
    tier2_detail = "Not used (standard checking only)"
    if not tier2_skipped and tier2:
        if tier2.blocked:
            tier2_state = "blocked"
            tier2_detail = tier2.block_reason or "Message not allowed"
        else:
            tier2_state = "done"
            tier2_detail = "Extra review passed"

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
            label="Checked your message",
            state="blocked" if tier1.blocked else "done",
            detail=_friendly_tier1_pipeline_detail(tier1),
            latency_ms=round(tier1.latency_seconds * 1000, 1),
        ),
        PipelineStepState(
            id="tier2",
            label="Extra safety review",
            state=tier2_state,
            detail=tier2_detail,
            latency_ms=round(tier2.latency_seconds * 1000, 1) if tier2 and not tier2_skipped else None,
        ),
        PipelineStepState(
            id="model",
            label="Prepared the answer",
            state=model_state if allow else ("skipped" if tier1.blocked or (tier2 and tier2.blocked) else "blocked"),
            detail="Answer ready" if allow and model_done else None,
        ),
        PipelineStepState(
            id="output",
            label="Checked the answer",
            state=output_state,
            detail="Review complete" if output_done else "Not needed",
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


def _clean_assistant_reply(text: str) -> str:
    """Remove governance boilerplate models sometimes echo into the visible reply."""
    return strip_visible_compliance_boilerplate(text or "")


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

    clar_questions = [
        ClarificationQuestion(**q) for q in (meta.get("clarification_questions") or [])
    ]
    input_pii_consent = consent_state_for_api(meta, msg.id) if msg.role == "user" else None
    return ChatMessageResponse(
        id=msg.id,
        role=msg.role,
        content=content,
        storage_mode=msg.storage_mode,
        allow=msg.allow,
        pipeline=pipeline,
        requires_clarification=bool(meta.get("requires_clarification")),
        clarification_questions=clar_questions,
        identified_entities=meta.get("identified_entities", []),
        input_pii_consent=input_pii_consent,
        requires_input_pii_consent=bool(meta.get("requires_input_pii_consent")),
        input_pii_user_message_id=meta.get("input_pii_user_message_id"),
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


async def _execute_after_tier1_pass(
    *,
    db: AsyncSession,
    session: ChatSession,
    username: str,
    user_text: str,
    stored_content: Optional[str],
    prior_messages: List[ChatMessage],
    tier1: Tier1Result,
    guardrail_engine,
    internal_region: str,
    start_time: float,
    audit,
    user_msg: ChatMessage,
    _audit,
    pii_consent_granted: bool = False,
) -> dict:
    """Run clarification gate, tier2, model, and output checks after tier1 passed."""
    output_skipped = session.output_guardrail_mode == "none"
    policy_names = get_policies_for_region(session.region)
    tier2: Optional[Tier2Result] = None
    output_guardrail_result: Optional[OutputGuardrailResult] = None
    allow = True
    assistant_text = ""
    clarification_deferred = False
    pipeline: List[PipelineStepState] = []

    workflow = get_workflow(session)
    completion_mode = getattr(session, "completion_mode", "balanced") or "balanced"
    prompt_for_model = stored_content or user_text
    inference = get_inference_router()

    is_clear, questions = await assess_prompt_clarity(
        inference_router=inference,
        provider=session.inference_provider,
        model=session.model,
        user_text=user_text,
        completion_mode=completion_mode,
        workflow=workflow,
    )

    if not is_clear and questions:
        workflow["phase"] = "clarifying"
        workflow["pending_user_prompt"] = prompt_for_model
        if not (workflow.get("task_brief") or {}).get("goal"):
            workflow["task_brief"] = extract_brief_from_message(user_text)
        workflow["clarification"] = {
            "round": int((workflow.get("clarification") or {}).get("round", 0)),
            "questions": [q.model_dump() for q in questions],
            "answers": {},
            "original_prompt": prompt_for_model,
        }
        save_workflow(session, workflow)
        clarification_deferred = True
        assistant_text = format_clarification_message(questions)
        tier2 = Tier2Result(
            blocked=False,
            block_reason=None,
            policies_applied=policy_names,
            region=session.region,
            latency_seconds=0.0,
        )
        pipeline = [
            PipelineStepState(
                id="tier1",
                label="Checked your message",
                state="done",
                detail="Looks OK",
                latency_ms=round(tier1.latency_seconds * 1000, 1),
            ),
            PipelineStepState(
                id="clarify",
                label="Asked a few questions",
                state="done",
                detail="Waiting for your answers",
            ),
            PipelineStepState(
                id="tier2",
                label="Extra safety review",
                state="skipped",
                detail="Continues after you answer",
            ),
            PipelineStepState(
                id="model",
                label="Prepared the answer",
                state="skipped",
                detail="Waiting for your answers",
            ),
            PipelineStepState(
                id="output",
                label="Checked the answer",
                state="skipped",
                detail="After the answer is ready",
            ),
        ]
        await _audit(
            "chat_clarification_requested",
            {
                "question_count": len(questions),
                "completion_mode": completion_mode,
                "source": "llm_clarity_check",
            },
        )
    else:
        brief = workflow.get("task_brief") or {}
        if not brief.get("goal"):
            workflow["task_brief"] = extract_brief_from_message(user_text)
        workflow["phase"] = "ready"
        save_workflow(session, workflow)

        if session.guardrail_mode == "advanced":
            tier2_start = time.perf_counter()
            tier2_filter = await guardrail_engine.filter(
                text=prompt_for_model,
                direction="prompt",
                tier="2",
                region=internal_region,
            )
            tier2_latency = time.perf_counter() - tier2_start
            tier2 = Tier2Result(
                blocked=tier2_filter.blocked,
                block_reason=getattr(tier2_filter, "block_reason", None),
                policies_applied=policy_names,
                region=session.region,
                latency_seconds=round(tier2_latency, 4),
            )
            if tier2.blocked:
                allow = False
                assistant_text = (
                    "We could not send your message because it did not pass our safety review."
                )
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
            tier2 = Tier2Result(
                blocked=False,
                block_reason=None,
                policies_applied=policy_names,
                region=session.region,
                latency_seconds=0.0,
            )

        if allow:
            history = _history_for_inference(prior_messages)
            if prompt_for_model:
                history.append({"role": "user", "content": prompt_for_model})
            compliance_header = _compliance_with_brief(session, workflow)
            try:
                assistant_text = _clean_assistant_reply(
                    await inference.generate_messages(
                        session.inference_provider,
                        session.model,
                        history,
                        compliance_header=compliance_header,
                        refresh_catalog=not pii_consent_granted,
                    )
                )
            except Exception as exc:
                allow = False
                assistant_text = f"We could not get an answer right now: {exc}"

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
            workflow["phase"] = "executing"
            save_workflow(session, workflow)
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

    return {
        "allow": allow,
        "assistant_text": assistant_text,
        "pipeline": pipeline,
        "tier2": tier2,
        "output_guardrail_result": output_guardrail_result,
        "clarification_deferred": clarification_deferred,
    }


async def _find_clarification_assistant(
    db: AsyncSession, session_id: int
) -> Optional[ChatMessage]:
    """Last assistant message still waiting for clarification answers."""
    messages = await list_session_messages(db, session_id)
    for msg in reversed(messages):
        if msg.role != "assistant":
            continue
        meta = msg.meta or {}
        if meta.get("requires_clarification"):
            return msg
    return None


async def _find_pii_consent_assistant(
    db: AsyncSession, session_id: int, user_message_id: int
) -> Optional[ChatMessage]:
    messages = await list_session_messages(db, session_id)
    for msg in reversed(messages):
        if msg.role != "assistant":
            continue
        meta = msg.meta or {}
        if meta.get("input_pii_user_message_id") == user_message_id:
            return msg
    return None


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
    tier1_filter = guardrail_engine.run_tier1(
        user_text,
        direction="prompt",
        region=internal_region,
        input_pii_consent=True,
    )
    tier1_latency = time.perf_counter() - tier1_start
    # Chat must never hard-block PII alone — always ask the user first.
    needs_pii_consent = False
    if not has_non_pii_block(tier1_filter):
        if tier1_has_pii(tier1_filter) or chat_needs_pii_consent(
            tier1_filter, original_text=user_text
        ):
            needs_pii_consent = True
            prepare_tier1_for_pii_consent(tier1_filter, user_text)

    tier1 = _build_tier1_result(tier1_filter, tier1_latency)
    if needs_pii_consent:
        tier1 = tier1.model_copy(
            update={
                "blocked": False,
                "block_reason": None,
                "filtered_text": user_text,
                "identified_entities": [],
            },
        )
    tier1_telemetry = summarize_guardrail_matches(tier1_filter.matches)

    stored_content, storage_mode, _ = resolve_user_storage(
        tier1_filter,
        pii_consent_pending=needs_pii_consent,
        chat_input=True,
    )
    if needs_pii_consent:
        pii_entities, internal_findings = ensure_consent_findings(
            guardrail_engine, user_text, internal_region, tier1_filter.matches
        )
        entity_names = [e.entity_name for e in pii_entities]
        user_meta = {
            "identified_entities": entity_names,
            "pii_consent": {
                "status": "pending",
                "entities": [e.model_dump() for e in pii_entities],
                "pending_prompt": user_text,
                "findings_internal": internal_findings,
            },
        }
    else:
        user_meta = {
            "identified_entities": entities_from_matches(tier1_filter.matches)
            if tier1.blocked
            else [],
        }

    user_msg = ChatMessage(
        session_id=session.id,
        role="user",
        content=stored_content,
        storage_mode=storage_mode,
        allow=None,
        pipeline=[],
        meta=user_meta,
    )
    db.add(user_msg)
    await db.flush()

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
    clarification_deferred = False
    input_pii_consent_pending = False

    if needs_pii_consent:
        input_pii_consent_pending = True
        allow = False
        assistant_text = format_input_pii_consent_message(pii_entities)
        pipeline = [
            PipelineStepState(
                id="tier1",
                label="Checked your message",
                state="done",
                detail="Personal details found — waiting for your choice",
                latency_ms=round(tier1.latency_seconds * 1000, 1),
            ),
            PipelineStepState(
                id="tier2",
                label="Extra safety review",
                state="skipped",
                detail="After you choose what to share",
            ),
            PipelineStepState(
                id="model",
                label="Prepared the answer",
                state="skipped",
                detail="After you choose what to share",
            ),
            PipelineStepState(
                id="output",
                label="Checked the answer",
                state="skipped",
                detail="After you choose what to share",
            ),
        ]
        await _audit(
            "chat_input_pii_consent_required",
            {"entity_count": len(pii_entities), "entities": entity_names},
        )
    elif tier1.blocked and tier1_has_pii(tier1_filter):
        prepare_tier1_for_pii_consent(tier1_filter, user_text)
        pii_entities, internal_findings = ensure_consent_findings(
            guardrail_engine, user_text, internal_region, tier1_filter.matches
        )
        entity_names = [e.entity_name for e in pii_entities]
        user_meta = dict(user_msg.meta or {})
        user_meta["identified_entities"] = entity_names
        user_meta["pii_consent"] = {
            "status": "pending",
            "entities": [e.model_dump() for e in pii_entities],
            "pending_prompt": user_text,
            "findings_internal": internal_findings,
        }
        user_msg.meta = user_meta
        user_msg.storage_mode = "withheld"
        user_msg.content = None
        input_pii_consent_pending = True
        allow = False
        assistant_text = format_input_pii_consent_message(pii_entities)
        pipeline = [
            PipelineStepState(
                id="tier1",
                label="Checked your message",
                state="done",
                detail="Personal details found — waiting for your choice",
                latency_ms=round(tier1.latency_seconds * 1000, 1),
            ),
            PipelineStepState(
                id="tier2",
                label="Extra safety review",
                state="skipped",
                detail="After you choose what to share",
            ),
            PipelineStepState(
                id="model",
                label="Prepared the answer",
                state="skipped",
                detail="After you choose what to share",
            ),
            PipelineStepState(
                id="output",
                label="Checked the answer",
                state="skipped",
                detail="After you choose what to share",
            ),
        ]
        await _audit(
            "chat_input_pii_consent_required",
            {"entity_count": len(pii_entities), "entities": entity_names, "fallback": True},
        )
    elif tier1.blocked:
        allow = False
        assistant_text = (
            "We could not send your message because it did not pass our safety checks."
        )
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
        turn = await _execute_after_tier1_pass(
            db=db,
            session=session,
            username=username,
            user_text=user_text,
            stored_content=stored_content,
            prior_messages=prior_messages,
            tier1=tier1,
            guardrail_engine=guardrail_engine,
            internal_region=internal_region,
            start_time=start_time,
            audit=audit,
            user_msg=user_msg,
            _audit=_audit,
        )
        allow = turn["allow"]
        assistant_text = turn["assistant_text"]
        pipeline = turn["pipeline"]
        tier2 = turn["tier2"]
        output_guardrail_result = turn["output_guardrail_result"]
        clarification_deferred = turn["clarification_deferred"]

    workflow = get_workflow(session)
    ephemeral_user = user_text if user_msg.storage_mode == "withheld" else None

    assistant_meta: Dict = {
        "identified_entities": tier1.identified_entities if not allow else [],
        "total_latency_s": round(time.perf_counter() - start_time, 4),
    }
    if input_pii_consent_pending:
        assistant_meta["requires_input_pii_consent"] = True
        assistant_meta["input_pii_user_message_id"] = user_msg.id
    if clarification_deferred:
        clar = workflow.get("clarification") or {}
        assistant_meta["requires_clarification"] = True
        assistant_meta["clarification_questions"] = clar.get("questions") or []
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

    envelope = session_workflow_envelope(session)
    return ChatSendMessageResponse(
        session_id=session.id,
        user_message=_message_to_response(user_msg, ephemeral=ephemeral_user),
        assistant_message=_message_to_response(assistant_msg),
        phase=envelope["phase"],
        execution_plan=envelope["execution_plan"],
        planned_llm_calls=envelope["planned_llm_calls"],
        task_brief=envelope["task_brief"],
    )


async def continue_after_clarification(
    db: AsyncSession,
    session: ChatSession,
    answers: Dict[str, str],
    username: str,
) -> ChatSendMessageResponse:
    """Merge clarification answers and run tier2 → model → output review."""
    start_time = time.perf_counter()
    workflow = get_workflow(session)
    pending = workflow.get("pending_user_prompt")
    if workflow.get("phase") != "clarifying" or not pending:
        raise ValueError("This chat is not waiting for clarification answers")

    workflow = merge_clarification_answers(workflow, answers, pending)
    save_workflow(session, workflow)

    guardrail_engine = get_guardrail_engine()
    audit = get_audit_vault()
    internal_region = REGION_MAP.get(session.region, "GLOBAL")
    prior_messages = await list_session_messages(db, session.id)
    user_text = pending

    tier2: Optional[Tier2Result] = None
    output_guardrail_result: Optional[OutputGuardrailResult] = None
    allow = True
    assistant_text = ""
    output_skipped = session.output_guardrail_mode == "none"
    policy_names = get_policies_for_region(session.region)

    tier1 = Tier1Result(
        blocked=False,
        block_reason=None,
        matches=[],
        identified_entities=[],
        filtered_text=pending,
        latency_seconds=0.0,
    )

    if session.guardrail_mode == "advanced":
        tier2_start = time.perf_counter()
        tier2_filter = await guardrail_engine.filter(
            text=pending,
            direction="prompt",
            tier="2",
            region=internal_region,
        )
        tier2_latency = time.perf_counter() - tier2_start
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
    else:
        tier2 = Tier2Result(
            blocked=False,
            block_reason=None,
            policies_applied=policy_names,
            region=session.region,
            latency_seconds=0.0,
        )

    if allow:
        inference = get_inference_router()
        history = _history_for_inference(prior_messages)
        clar_header = build_clarification_header(workflow)
        user_payload = user_text.strip()
        if clar_header:
            user_payload = f"{user_text.strip()}\n\n{clar_header}"
        if user_payload:
            history.append({"role": "user", "content": user_payload})
        compliance_header = _compliance_with_brief(session, workflow)
        try:
            assistant_text = _clean_assistant_reply(
                await inference.generate_messages(
                    session.inference_provider,
                    session.model,
                    history,
                    compliance_header=compliance_header,
                    refresh_catalog=False,
                )
            )
        except Exception as exc:
            allow = False
            assistant_text = f"We could not get an answer right now: {exc}"

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
    workflow["phase"] = "executing" if allow else workflow.get("phase", "ready")
    save_workflow(session, workflow)

    clarification_msg = await _find_clarification_assistant(db, session.id)
    if clarification_msg:
        assistant_msg = clarification_msg
        assistant_msg.content = assistant_text
        assistant_msg.allow = allow
        assistant_msg.pipeline = [s.model_dump() for s in pipeline]
        assistant_meta = dict(assistant_msg.meta or {})
        assistant_meta.pop("requires_clarification", None)
        assistant_meta.pop("clarification_questions", None)
        assistant_meta["total_latency_s"] = round(time.perf_counter() - start_time, 4)
    else:
        assistant_meta = {"total_latency_s": round(time.perf_counter() - start_time, 4)}
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

    assistant_msg.meta = assistant_meta
    session.updated_at = datetime.utcnow()
    await db.flush()

    await audit.log(
        db=db,
        event_type="chat_clarification_completed",
        actor=username,
        system_name="aegis-chat",
        details={"session_id": session.id, "message_id": assistant_msg.id},
    )

    envelope = session_workflow_envelope(session)
    last_user = prior_messages[-1] if prior_messages else None
    user_resp = _message_to_response(last_user) if last_user and last_user.role == "user" else ChatMessageResponse(
        id=0,
        role="user",
        content=None,
        created_at=datetime.utcnow(),
    )
    return ChatSendMessageResponse(
        session_id=session.id,
        user_message=user_resp,
        assistant_message=_message_to_response(assistant_msg),
        phase=envelope["phase"],
        execution_plan=envelope["execution_plan"],
        planned_llm_calls=envelope["planned_llm_calls"],
        task_brief=envelope["task_brief"],
    )


async def update_session_brief(session: ChatSession, body) -> TaskBrief:
    workflow = get_workflow(session)
    brief = dict(workflow.get("task_brief") or {})
    data = body.model_dump(exclude_unset=True)
    for key, value in data.items():
        if value is not None:
            brief[key] = value
    workflow["task_brief"] = brief
    workflow["phase"] = "ready"
    save_workflow(session, workflow)
    return task_brief_model(workflow)


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


async def resolve_input_pii_consent(
    db: AsyncSession,
    session: ChatSession,
    user_message_id: int,
    body: ChatInputPiiConsentRequest,
    username: str,
) -> ChatSendMessageResponse:
    """Apply the user's choice for detected input PII and continue or block the turn."""
    start_time = time.perf_counter()
    user_msg = await get_message_for_user(db, session.id, user_message_id, username)
    if user_msg.role != "user":
        raise ValueError("Only user messages can receive PII consent")

    meta = dict(user_msg.meta or {})
    consent = meta.get("pii_consent") or {}
    if consent.get("status") != "pending":
        raise ValueError("This message is not waiting for your choice about personal details")

    assistant_msg = await _find_pii_consent_assistant(db, session.id, user_msg.id)
    if not assistant_msg:
        raise ValueError("Could not find the related assistant message")

    pending_prompt = consent.get("pending_prompt") or ""
    internal = consent.get("findings_internal") or []
    guardrail_engine = get_guardrail_engine()
    audit = get_audit_vault()
    internal_region = REGION_MAP.get(session.region, "GLOBAL")

    prior_messages = [
        m for m in await list_session_messages(db, session.id) if m.id < user_msg.id
    ]

    async def _audit(event_type: str, extra: dict):
        await audit.log(
            db=db,
            event_type=event_type,
            actor=username,
            system_name="aegis-chat",
            details={
                "session_id": session.id,
                "message_id": user_msg.id,
                "action": body.action,
                "region": session.region,
                **extra,
            },
        )

    tier1 = Tier1Result(
        blocked=False,
        block_reason=None,
        matches=[],
        identified_entities=[],
        filtered_text=pending_prompt,
        latency_seconds=0.0,
    )

    if body.action == "deny":
        meta["pii_consent"] = {
            "status": "denied",
            "entities": consent.get("entities") or [],
        }
        user_msg.meta = meta
        user_msg.allow = False
        user_msg.storage_mode = "withheld"
        user_msg.content = None

        assistant_msg.content = (
            "You chose not to send this message. Nothing was shared with the AI."
        )
        assistant_msg.allow = False
        assistant_msg.pipeline = [
            PipelineStepState(
                id="tier1",
                label="Checked your message",
                state="blocked",
                detail="You chose not to share personal details",
            ).model_dump()
        ]
        ameta = dict(assistant_msg.meta or {})
        ameta.pop("requires_input_pii_consent", None)
        assistant_msg.meta = ameta
        await _audit("chat_input_pii_denied", {"entity_count": len(consent.get("entities") or [])})
    else:
        if body.action == "allow_all":
            text_to_send = pending_prompt
            consent_status = "allowed_all"
            allowed_ids = {f["id"] for f in internal}
        elif body.action == "allow_some":
            if not body.allowed_pii_finding_ids:
                raise ValueError("Select at least one type of personal detail to allow, or choose Allow all")
            allowed_ids = set(body.allowed_pii_finding_ids)
            all_finding_ids = {f["id"] for f in internal}
            if allowed_ids >= all_finding_ids:
                text_to_send = pending_prompt
            else:
                if pending_prompt and not any(f.get("spans") for f in internal):
                    _, internal = scan_pii_for_consent(
                        guardrail_engine, pending_prompt, internal_region
                    )[1]
                text_to_send = apply_input_pii_redaction(pending_prompt, internal, allowed_ids)
            consent_status = "allowed_some"
        else:
            raise ValueError(f"Unknown action: {body.action}")

        has_redaction = text_to_send != pending_prompt
        user_msg.content = text_to_send
        user_msg.storage_mode = "redacted" if has_redaction else "full"
        user_msg.allow = True
        meta["identified_entities"] = []
        meta["pii_consent"] = {
            "status": consent_status,
            "entities": consent.get("entities") or [],
        }
        user_msg.meta = meta

        tier1.filtered_text = text_to_send
        turn = await _execute_after_tier1_pass(
            db=db,
            session=session,
            username=username,
            user_text=pending_prompt,
            stored_content=text_to_send,
            prior_messages=prior_messages,
            tier1=tier1,
            guardrail_engine=guardrail_engine,
            internal_region=internal_region,
            start_time=start_time,
            audit=audit,
            user_msg=user_msg,
            _audit=_audit,
            pii_consent_granted=True,
        )

        assistant_msg.content = turn["assistant_text"]
        assistant_msg.allow = turn["allow"]
        assistant_msg.pipeline = [s.model_dump() for s in turn["pipeline"]]
        ameta = dict(assistant_msg.meta or {})
        ameta.pop("requires_input_pii_consent", None)
        ameta.pop("input_pii_user_message_id", None)
        ameta["total_latency_s"] = round(time.perf_counter() - start_time, 4)
        if turn["clarification_deferred"]:
            clar = get_workflow(session).get("clarification") or {}
            ameta["requires_clarification"] = True
            ameta["clarification_questions"] = clar.get("questions") or []
        if turn["output_guardrail_result"] is not None:
            ameta["output_guardrail"] = turn["output_guardrail_result"].model_dump()
        if turn["allow"] and turn["output_guardrail_result"] is not None:
            threshold = resolve_security_threshold(session.security_threshold_preset)
            review_state, _ = evaluate_output_review(
                turn["assistant_text"],
                turn["output_guardrail_result"],
                threshold,
                session.region,
                regenerations_used=0,
            )
            ameta["output_review"] = review_state.model_dump()
            ameta["raw_content"] = turn["assistant_text"]
            ameta["regenerations_used"] = 0
            ameta["review_status"] = review_state.status
            ameta["source_user_prompt"] = pending_prompt
            if review_state.status == "delivered":
                assistant_msg.content = turn["assistant_text"]
            else:
                assistant_msg.content = turn["assistant_text"]
        elif turn["allow"]:
            ameta["review_status"] = "delivered"
        assistant_msg.meta = ameta

        await _audit(
            "chat_input_pii_allowed",
            {
                "action": body.action,
                "allowed_entity_ids": list(body.allowed_pii_finding_ids),
                "redacted": has_redaction,
            },
        )

        if turn["allow"] and ameta.get("review_status") == "pending_review":
            await audit.log(
                db=db,
                event_type="chat_output_review_required",
                actor=username,
                system_name="aegis-chat",
                details={
                    "session_id": session.id,
                    "message_id": assistant_msg.id,
                    "trigger_reasons": ameta.get("output_review", {}).get("trigger_reasons", []),
                },
            )

    session.updated_at = datetime.utcnow()
    await db.flush()

    envelope = session_workflow_envelope(session)
    ephemeral = pending_prompt if user_msg.storage_mode == "withheld" else None
    return ChatSendMessageResponse(
        session_id=session.id,
        user_message=_message_to_response(user_msg, ephemeral=ephemeral),
        assistant_message=_message_to_response(assistant_msg),
        phase=envelope["phase"],
        execution_plan=envelope["execution_plan"],
        planned_llm_calls=envelope["planned_llm_calls"],
        task_brief=envelope["task_brief"],
    )


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

        workflow = get_workflow(session)
        if code_findings:
            top = max(code_findings, key=lambda f: f.confidence)
            append_regen_lesson(
                workflow,
                issue=top.description or top.label or "insecure code",
                fix="; ".join(collect_recommendations(og)[:3]) or instruction[:200],
                attempt=regen_used + 1,
            )
            save_workflow(session, workflow)

        prior = await list_session_messages(db, session.id)
        prior = [m for m in prior if m.id < msg.id]
        history = _history_for_inference(prior)
        history.append({"role": "assistant", "content": raw})
        history.append({"role": "user", "content": instruction})

        inference = get_inference_router()
        compliance_header = _compliance_with_brief(session, get_workflow(session))
        new_text = _clean_assistant_reply(
            await inference.generate_messages(
                session.inference_provider,
                session.model,
                history,
                compliance_header=compliance_header,
                refresh_catalog=False,
            )
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
