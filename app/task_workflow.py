"""
Task workflow: completion modes, clarification gate, task brief, execution planning.

State machine (no agents) — session.workflow_meta JSON on ChatSession.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from .schemas import ExecutionPlanStep, TaskBrief, ClarificationQuestion


DEFAULT_WORKFLOW: Dict[str, Any] = {
    "phase": "idle",
    "pending_user_prompt": None,
    "task_brief": {
        "goal": "",
        "constraints": [],
        "must_not": [],
        "acceptance": "",
        "stack": "",
        "lessons": [],
    },
    "clarification": {
        "round": 0,
        "questions": [],
        "answers": {},
    },
}

GOAL_VERBS = re.compile(
    r"\b(build|create|implement|fix|debug|add|remove|migrate|refactor|explain|design|write|deploy|test)\b",
    re.I,
)
VAGUE_PHRASES = re.compile(
    r"\b(help me with this|make it better|fix this|do something|not sure|something like)\b",
    re.I,
)
CODE_HINTS = re.compile(
    r"\b(api|endpoint|auth|jwt|database|sql|react|python|function|class|script|deploy|docker)\b",
    re.I,
)


def empty_workflow() -> Dict[str, Any]:
    return deepcopy(DEFAULT_WORKFLOW)


def get_workflow(session) -> Dict[str, Any]:
    raw = getattr(session, "workflow_meta", None) or {}
    merged = empty_workflow()
    if isinstance(raw, dict):
        for key in merged:
            if key in raw:
                merged[key] = raw[key]
        if isinstance(raw.get("task_brief"), dict):
            merged["task_brief"] = {**merged["task_brief"], **raw["task_brief"]}
        if isinstance(raw.get("clarification"), dict):
            merged["clarification"] = {**merged["clarification"], **raw["clarification"]}
    return merged


def save_workflow(session, workflow: Dict[str, Any]) -> None:
    session.workflow_meta = workflow


def task_brief_model(workflow: Dict[str, Any]) -> TaskBrief:
    return TaskBrief(**(workflow.get("task_brief") or {}))


def estimate_llm_calls(
    *,
    guardrail_mode: str,
    output_guardrail_mode: str,
    blocked_at_input: bool = False,
    includes_main: bool = True,
) -> int:
    """Upper-bound LLM calls for one governed user turn (after clarification)."""
    if blocked_at_input:
        if guardrail_mode == "advanced":
            return 1
        return 0
    calls = 0
    if guardrail_mode == "advanced":
        calls += 1
    if includes_main:
        calls += 1
    if output_guardrail_mode == "tier2":
        calls += 1
    return calls


def build_execution_plan(
    *,
    guardrail_mode: str,
    output_guardrail_mode: str,
    completion_mode: str,
    phase: str,
    clarifying: bool = False,
) -> List[ExecutionPlanStep]:
    """Planned steps for the next governed turn (shown in Planning panel)."""
    steps: List[ExecutionPlanStep] = []

    if clarifying or phase == "clarifying":
        steps.append(
            ExecutionPlanStep(
                id="clarify",
                label="Clarification",
                kind="local",
                state="active",
                detail="Ask targeted questions (no main model yet)",
                llm_calls=0,
            )
        )
        steps.append(
            ExecutionPlanStep(
                id="tier1",
                label="Fast screening",
                kind="local",
                state="waiting",
                detail="After you confirm the brief",
                llm_calls=0,
            )
        )
        if guardrail_mode == "advanced":
            steps.append(
                ExecutionPlanStep(
                    id="tier2",
                    label="Llama Guard",
                    kind="llm",
                    state="waiting",
                    detail="Semantic safety (Hugging Face)",
                    llm_calls=1,
                )
            )
        steps.append(
            ExecutionPlanStep(
                id="model",
                label="Model response",
                kind="llm",
                state="waiting",
                detail="Single governed generation",
                llm_calls=1,
            )
        )
        if output_guardrail_mode == "tier2":
            steps.append(
                ExecutionPlanStep(
                    id="output",
                    label="Output compliance review",
                    kind="llm",
                    state="waiting",
                    detail="Reviews the reply",
                    llm_calls=1,
                )
            )
        elif output_guardrail_mode == "tier1":
            steps.append(
                ExecutionPlanStep(
                    id="output",
                    label="Output safety check",
                    kind="local",
                    state="waiting",
                    detail="Pattern scan on reply",
                    llm_calls=0,
                )
            )
        return steps

    steps.append(
        ExecutionPlanStep(
            id="tier1",
            label="Fast screening",
            kind="local",
            state="planned",
            detail="Regex, YARA, PII on your message",
            llm_calls=0,
        )
    )
    if guardrail_mode == "advanced":
        steps.append(
            ExecutionPlanStep(
                id="tier2",
                label="Llama Guard",
                kind="llm",
                state="planned",
                detail="Llama Guard 3 on Hugging Face (semantic, multilingual)",
                llm_calls=1,
            )
        )
    else:
        steps.append(
            ExecutionPlanStep(
                id="tier2",
                label="Llama Guard",
                kind="local",
                state="skipped",
                detail="Skipped (basic input — PII only)",
                llm_calls=0,
            )
        )

    steps.append(
        ExecutionPlanStep(
            id="model",
            label="Model response",
            kind="llm",
            state="planned",
            detail="Main chat generation with task brief",
            llm_calls=1,
        )
    )

    if output_guardrail_mode == "tier2":
        steps.append(
            ExecutionPlanStep(
                id="output",
                label="Output compliance review",
                kind="llm",
                state="planned",
                detail="LLM reviews the reply",
                llm_calls=1,
            )
        )
    elif output_guardrail_mode == "tier1":
        steps.append(
            ExecutionPlanStep(
                id="output",
                label="Output safety check",
                kind="local",
                state="planned",
                detail="Pattern scan on reply",
                llm_calls=0,
            )
        )
    else:
        steps.append(
            ExecutionPlanStep(
                id="output",
                label="Output safety check",
                kind="local",
                state="skipped",
                detail="Off for this session",
                llm_calls=0,
            )
        )

    mode_note = {
        "fast": "Fast mode — skip upfront clarification",
        "balanced": "Balanced — clarify only when the prompt is vague",
        "clarify_first": "Clarify-first — questions before first generation",
    }.get(completion_mode, "")
    if mode_note and steps:
        steps[0].detail = (steps[0].detail or "") + f" · {mode_note}"

    return steps


def total_planned_llm_calls(steps: List[ExecutionPlanStep]) -> int:
    countable = {"planned", "active", "waiting", "done"}
    return sum(s.llm_calls for s in steps if s.state in countable and s.llm_calls > 0)


def intent_confidence(text: str) -> float:
    """Rule-based 0–1 score; higher = ready to generate without clarifying."""
    t = (text or "").strip()
    if not t:
        return 0.0
    score = 0.45
    if len(t) >= 80:
        score += 0.2
    elif len(t) >= 40:
        score += 0.1
    if GOAL_VERBS.search(t):
        score += 0.2
    if "```" in t:
        score += 0.15
    if VAGUE_PHRASES.search(t):
        score -= 0.25
    if len(t) < 25 and not GOAL_VERBS.search(t):
        score -= 0.2
    if CODE_HINTS.search(t) and not re.search(r"\b(python|node|java|go|rust|sql|jwt|fastapi|django)\b", t, re.I):
        score -= 0.1
    return max(0.0, min(1.0, score))


def should_clarify(
    text: str,
    completion_mode: str,
    workflow: Dict[str, Any],
) -> bool:
    if completion_mode == "fast":
        return False
    clarification = workflow.get("clarification") or {}
    if int(clarification.get("round", 0)) >= 1:
        return False
    brief = workflow.get("task_brief") or {}
    if brief.get("goal") and workflow.get("phase") == "ready":
        return False

    confidence = intent_confidence(text)
    if completion_mode == "clarify_first":
        return confidence < 0.85 or not brief.get("goal")
    # balanced
    return confidence < 0.6


def build_clarification_questions(text: str) -> List[ClarificationQuestion]:
    """2–4 targeted questions (no LLM)."""
    questions: List[ClarificationQuestion] = []
    t = text.lower()

    questions.append(
        ClarificationQuestion(
            id="goal",
            text="What is the main outcome you want from this request?",
            choices=["Explain / teach", "Write or change code", "Review / audit", "Research / summarize"],
        )
    )

    if CODE_HINTS.search(text):
        questions.append(
            ClarificationQuestion(
                id="stack",
                text="Which stack or environment should we assume?",
                choices=["Python / FastAPI", "JavaScript / Node", "Other (describe in answer)"],
            )
        )
        questions.append(
            ClarificationQuestion(
                id="constraints",
                text="Any hard constraints? (auth, data, deployment, etc.)",
            )
        )
    else:
        questions.append(
            ClarificationQuestion(
                id="scope",
                text="How deep should the answer go?",
                choices=["Quick overview", "Step-by-step", "Production-ready detail"],
            )
        )

    questions.append(
        ClarificationQuestion(
            id="acceptance",
            text="How will you know the answer is good enough?",
        )
    )
    return questions[:4]


def extract_brief_from_message(text: str) -> Dict[str, Any]:
    """Lightweight brief from a single user message."""
    goal = text.strip()[:500]
    constraints: List[str] = []
    must_not: List[str] = []
    acceptance = ""
    stack = ""

    if CODE_HINTS.search(text):
        stack_match = re.search(
            r"\b(python|fastapi|django|node|react|typescript|java|go|rust|sql|postgres|jwt)\b",
            text,
            re.I,
        )
        if stack_match:
            stack = stack_match.group(0)

    for line in text.splitlines():
        low = line.lower().strip()
        if low.startswith("must not:") or low.startswith("don't:"):
            must_not.append(line.split(":", 1)[-1].strip())
        elif low.startswith("must:") or low.startswith("constraint:"):
            constraints.append(line.split(":", 1)[-1].strip())

    return {
        "goal": goal,
        "constraints": constraints,
        "must_not": must_not,
        "acceptance": acceptance,
        "stack": stack,
        "lessons": [],
    }


def merge_clarification_answers(
    workflow: Dict[str, Any],
    answers: Dict[str, str],
    original_prompt: str,
) -> Dict[str, Any]:
    brief = dict(workflow.get("task_brief") or {})
    if not brief.get("goal"):
        brief = extract_brief_from_message(original_prompt)

    goal_answer = answers.get("goal", "").strip()
    if goal_answer:
        brief["goal"] = f"{brief.get('goal', '').strip()} — {goal_answer}".strip(" —")

    stack = answers.get("stack", "").strip()
    if stack:
        brief["stack"] = stack

    constraints = answers.get("constraints", "").strip()
    if constraints:
        brief.setdefault("constraints", [])
        if constraints not in brief["constraints"]:
            brief["constraints"].append(constraints)

    scope = answers.get("scope", "").strip()
    if scope:
        brief.setdefault("constraints", [])
        brief["constraints"].append(f"Depth: {scope}")

    acceptance = answers.get("acceptance", "").strip()
    if acceptance:
        brief["acceptance"] = acceptance

    workflow["task_brief"] = brief
    workflow["phase"] = "ready"
    workflow["pending_user_prompt"] = None
    clar = workflow.get("clarification") or {}
    clar["answers"] = answers
    clar["round"] = int(clar.get("round", 0)) + 1
    clar["questions"] = []
    workflow["clarification"] = clar
    return workflow


def build_brief_header(workflow: Dict[str, Any]) -> str:
    brief = workflow.get("task_brief") or {}
    if not any(brief.get(k) for k in ("goal", "constraints", "must_not", "acceptance", "stack", "lessons")):
        return ""
    lines = ["[Task brief — authoritative]"]
    if brief.get("goal"):
        lines.append(f"Goal: {brief['goal']}")
    if brief.get("stack"):
        lines.append(f"Stack: {brief['stack']}")
    if brief.get("constraints"):
        lines.append("Constraints: " + "; ".join(brief["constraints"]))
    if brief.get("must_not"):
        lines.append("Must not: " + "; ".join(brief["must_not"]))
    if brief.get("acceptance"):
        lines.append(f"Acceptance: {brief['acceptance']}")
    lessons = brief.get("lessons") or []
    if lessons:
        lines.append("Lessons from prior attempts:")
        for item in lessons[-3:]:
            if isinstance(item, dict):
                lines.append(f"- {item.get('issue', '')}: {item.get('fix', '')}")
            else:
                lines.append(f"- {item}")
    lines.append("[End brief]")
    return "\n".join(lines)


def append_regen_lesson(workflow: Dict[str, Any], issue: str, fix: str, attempt: int) -> None:
    brief = dict(workflow.get("task_brief") or {})
    lessons = list(brief.get("lessons") or [])
    lessons.append({"attempt": attempt, "issue": issue, "fix": fix})
    brief["lessons"] = lessons[-3:]
    workflow["task_brief"] = brief


def format_clarification_message(questions: List[ClarificationQuestion]) -> str:
    lines = [
        "Before I write a full answer, I need a little more detail from you.",
        "",
        "Tap **Answer questions** below (or use the button at the top of the chat).",
        "",
    ]
    for i, q in enumerate(questions, 1):
        lines.append(f"{i}. **{q.text}**")
        if q.choices:
            lines.append("   Options: " + " · ".join(q.choices))
    return "\n".join(lines)
