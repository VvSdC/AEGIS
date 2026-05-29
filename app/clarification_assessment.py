"""LLM-assisted prompt clarity check before the main chat generation."""

from __future__ import annotations

import json
import re
from typing import List, Tuple

from .schemas import ClarificationQuestion
from .task_workflow import (
    build_clarification_questions,
    references_ambiguous_term,
    should_clarify,
)

_CLARITY_JSON_RE = re.compile(r"\{[\s\S]*\}", re.MULTILINE)

_CLARITY_PROMPT = """You decide whether a user message is clear enough to answer in one helpful reply.

Reply with ONLY valid JSON (no markdown fences).

If the message is clear and specific enough:
{"clear": true}

If important details are missing:
{"clear": false, "questions": [
  {"id": "short_snake_case_id", "text": "One short question about what is missing", "choices": []}
]}

Rules:
- Specific tasks (math, facts, code with context, clear how-to) → clear true.
- Single unclear names with no context (e.g. "Explain how Strix works", "What is Mercury?") → clear false; ask which product, domain, or version they mean.
- Homonyms, brand names, or acronyms without scope → clear false.
- Ask at most 3 questions, each about THIS message only — no generic boilerplate.
- Use choices only when a small fixed set helps; otherwise use an empty choices array.
- Do not ask about personal data the user already provided."""


def _parse_clarity_payload(raw: str) -> dict:
    text = (raw or "").strip()
    match = _CLARITY_JSON_RE.search(text)
    if match:
        text = match.group()
    return json.loads(text)


def _questions_from_payload(data: dict) -> List[ClarificationQuestion]:
    out: List[ClarificationQuestion] = []
    for i, item in enumerate(data.get("questions") or []):
        if not isinstance(item, dict):
            continue
        qid = str(item.get("id") or f"q{i + 1}").strip() or f"q{i + 1}"
        qtext = str(item.get("text") or "").strip()
        if not qtext:
            continue
        choices = [str(c).strip() for c in (item.get("choices") or []) if str(c).strip()]
        out.append(ClarificationQuestion(id=qid, text=qtext, choices=choices[:6]))
    return out[:3]


def heuristic_is_clear(text: str, completion_mode: str, workflow: dict) -> bool:
    """Fast path: skip LLM when rules say the prompt is ready."""
    if completion_mode == "fast":
        return True
    clarification = workflow.get("clarification") or {}
    if int(clarification.get("round", 0)) >= 1:
        return True
    brief = workflow.get("task_brief") or {}
    if brief.get("goal") and workflow.get("phase") == "ready":
        return True
    return not should_clarify(text, completion_mode, workflow)


async def assess_prompt_clarity(
    *,
    inference_router,
    provider: str,
    model: str,
    user_text: str,
    completion_mode: str,
    workflow: dict,
) -> Tuple[bool, List[ClarificationQuestion]]:
    """
    Return (is_clear, questions).
    questions is non-empty only when the model (or fallback) needs clarification.
    """
    if references_ambiguous_term(user_text):
        return False, build_clarification_questions(user_text)

    if heuristic_is_clear(user_text, completion_mode, workflow):
        return True, []

    if not inference_router or not provider or not model:
        if should_clarify(user_text, completion_mode, workflow):
            return False, build_clarification_questions(user_text)
        return True, []

    prompt = f"{_CLARITY_PROMPT}\n\nUser message:\n{user_text.strip()[:4000]}"
    try:
        raw = await inference_router.generate(
            provider,
            model,
            prompt,
            refresh_catalog=False,
        )
        data = _parse_clarity_payload(raw)
        if data.get("clear") is True:
            if references_ambiguous_term(user_text):
                return False, build_clarification_questions(user_text)
            return True, []
        questions = _questions_from_payload(data)
        if questions:
            return False, questions
        return False, build_clarification_questions(user_text)
    except Exception:
        if should_clarify(user_text, completion_mode, workflow):
            return False, build_clarification_questions(user_text)
        return True, []
