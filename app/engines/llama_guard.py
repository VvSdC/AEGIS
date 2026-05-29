"""
Llama Guard 3 via Hugging Face Inference API (OpenAI-compatible router).

Used for Tier 2 input semantic safety (jailbreak, policy categories, multilingual).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from ..config import settings

HF_CHAT_URL = "https://router.huggingface.co/v1/chat/completions"
_CATEGORY_RE = re.compile(r"^S\d+", re.IGNORECASE)


@dataclass
class LlamaGuardResult:
    safe: bool
    categories: List[str] = field(default_factory=list)
    raw_response: str = ""
    latency_ms: float = 0.0
    error: Optional[str] = None


def is_llama_guard_available() -> bool:
    return bool(settings.huggingface_api_key and settings.tier2_enabled)


def _parse_guard_output(text: str) -> LlamaGuardResult:
    """Parse Llama Guard 3 text output (e.g. 'safe' or 'unsafe\\nS2')."""
    raw = (text or "").strip()
    if not raw:
        return LlamaGuardResult(safe=True, raw_response=raw)

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    head = lines[0].lower() if lines else "safe"

    # Model may return "safe", "unsafe", or prose containing both — prefer explicit first line.
    if head == "safe":
        is_safe = True
    elif head == "unsafe" or head.startswith("unsafe"):
        is_safe = False
    elif "unsafe" in raw.lower() and "safe" not in head:
        is_safe = False
    else:
        is_safe = True

    categories = [ln for ln in lines[1:] if _CATEGORY_RE.match(ln)]
    if not categories and not is_safe:
        for part in re.findall(r"S\d+", raw, re.IGNORECASE):
            if part.upper() not in [c.upper() for c in categories]:
                categories.append(part.upper())

    return LlamaGuardResult(
        safe=is_safe,
        categories=categories,
        raw_response=raw,
    )


async def classify_user_prompt(text: str) -> LlamaGuardResult:
    """
    Classify a user prompt (input guard) with Llama Guard 3 on Hugging Face.
    """
    import time

    if not settings.huggingface_api_key:
        return LlamaGuardResult(safe=True, error="HUGGINGFACE_API_KEY not configured")

    model = settings.llama_guard_model
    content = (text or "")[: settings.llama_guard_max_input_chars]
    messages = [{"role": "user", "content": content}]

    headers = {
        "Authorization": f"Bearer {settings.huggingface_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": settings.llama_guard_max_tokens,
        "temperature": 0.0,
    }

    start = time.perf_counter()
    try:
        timeout = settings.tier2_timeout_seconds
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(HF_CHAT_URL, headers=headers, json=payload)
        latency_ms = (time.perf_counter() - start) * 1000

        if resp.status_code != 200:
            return LlamaGuardResult(
                safe=True,
                latency_ms=latency_ms,
                error=f"HuggingFace Llama Guard error {resp.status_code}: {resp.text[:300]}",
            )

        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            return LlamaGuardResult(
                safe=True,
                latency_ms=latency_ms,
                error="Llama Guard returned no choices",
            )
        out = (choices[0].get("message", {}) or {}).get("content", "") or ""
        parsed = _parse_guard_output(out)
        parsed.latency_ms = latency_ms
        return parsed
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        return LlamaGuardResult(
            safe=True,
            latency_ms=latency_ms,
            error=str(exc),
        )


def categories_to_block_reason(categories: List[str]) -> str:
    if not categories:
        return "Content flagged unsafe by Llama Guard"
    return f"Content flagged unsafe by Llama Guard ({', '.join(categories)})"
