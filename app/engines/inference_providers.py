"""
Inference providers for AEGIS.

Each provider has its own model IDs. The UI sends `api_model` exactly as listed
for the selected provider.
"""

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import httpx

from ..config import settings


@dataclass(frozen=True)
class InferenceModel:
    id: str
    label: str
    api_model: str


# Google AI Studio free tier — see ai.google.dev/gemini-api/docs/rate-limits
# Flash / Flash-Lite: generous quotas. Pro: low daily quota on free tier (if enabled for your key).
GEMINI_STATIC_MODELS: List[InferenceModel] = [
    InferenceModel(
        id="gemini-2.5-pro",
        label="Gemini 2.5 Pro (free tier, low quota)",
        api_model="gemini-2.5-pro",
    ),
    InferenceModel(
        id="gemini-2.5-flash",
        label="Gemini 2.5 Flash (free tier)",
        api_model="gemini-2.5-flash",
    ),
    InferenceModel(
        id="gemini-2.5-flash-lite",
        label="Gemini 2.5 Flash-Lite (free tier)",
        api_model="gemini-2.5-flash-lite",
    ),
    InferenceModel(
        id="gemini-2.0-flash",
        label="Gemini 2.0 Flash (free tier)",
        api_model="gemini-2.0-flash",
    ),
    InferenceModel(
        id="gemini-2.0-flash-lite",
        label="Gemini 2.0 Flash-Lite (free tier)",
        api_model="gemini-2.0-flash-lite",
    ),
]

# Mistral La Plateforme Experiment plan — all commercial chat models, rate-limited (no card).
MISTRAL_STATIC_MODELS: List[InferenceModel] = [
    InferenceModel(
        id="mistral-large",
        label="Mistral Large (Experiment free)",
        api_model="mistral-large-latest",
    ),
    InferenceModel(
        id="mistral-medium",
        label="Mistral Medium (Experiment free)",
        api_model="mistral-medium-latest",
    ),
    InferenceModel(
        id="mistral-codestral",
        label="Codestral (Experiment free)",
        api_model="codestral-latest",
    ),
    InferenceModel(
        id="mistral-small",
        label="Mistral Small (Experiment free)",
        api_model="mistral-small-latest",
    ),
    InferenceModel(
        id="mistral-ministral-8b",
        label="Ministral 8B (Experiment free)",
        api_model="ministral-8b-latest",
    ),
    InferenceModel(
        id="mistral-nemo",
        label="Mistral Nemo 12B (Experiment free)",
        api_model="open-mistral-nemo",
    ),
    InferenceModel(
        id="mistral-ministral-3b",
        label="Ministral 3B (Experiment free)",
        api_model="ministral-3b-latest",
    ),
]

# OpenRouter — IDs ending in :free (openrouter.ai/collections/free-models)
OPENROUTER_STATIC_MODELS: List[InferenceModel] = [
    InferenceModel(
        id="openrouter-qwen3-coder",
        label="Qwen3 Coder (free)",
        api_model="qwen/qwen3-coder:free",
    ),
    InferenceModel(
        id="openrouter-deepseek-v4",
        label="DeepSeek V4 Flash (free)",
        api_model="deepseek/deepseek-v4-flash:free",
    ),
    InferenceModel(
        id="openrouter-llama-70b",
        label="Llama 3.3 70B Instruct (free)",
        api_model="meta-llama/llama-3.3-70b-instruct:free",
    ),
    InferenceModel(
        id="openrouter-gpt-oss-120b",
        label="GPT-OSS 120B (free)",
        api_model="openai/gpt-oss-120b:free",
    ),
    InferenceModel(
        id="openrouter-nemotron-super",
        label="Nemotron 3 Super 120B (free)",
        api_model="nvidia/nemotron-3-super-120b-a12b:free",
    ),
    InferenceModel(
        id="openrouter-gemma-31b",
        label="Gemma 4 31B (free)",
        api_model="google/gemma-4-31b-it:free",
    ),
    InferenceModel(
        id="openrouter-nemotron-9b",
        label="NVIDIA Nemotron Nano 9B (free)",
        api_model="nvidia/nemotron-nano-9b-v2:free",
    ),
    InferenceModel(
        id="openrouter-llama-3b",
        label="Llama 3.2 3B Instruct (free)",
        api_model="meta-llama/llama-3.2-3b-instruct:free",
    ),
    InferenceModel(
        id="openrouter-lfm",
        label="Liquid LFM 2.5 1.2B (free)",
        api_model="liquid/lfm-2.5-1.2b-instruct:free",
    ),
]

# Hugging Face Inference Providers — ~$0.10/mo free credits; larger models burn credits fast.
HF_STATIC_MODELS: List[InferenceModel] = [
    InferenceModel(
        id="hf-llama-70b",
        label="Llama 3.1 70B Instruct (HF credits)",
        api_model="meta-llama/Meta-Llama-3.1-70B-Instruct",
    ),
    InferenceModel(
        id="hf-qwen-72b",
        label="Qwen 2.5 72B Instruct (HF credits)",
        api_model="Qwen/Qwen2.5-72B-Instruct",
    ),
    InferenceModel(
        id="hf-mistral",
        label="Mistral 7B Instruct (HF credits)",
        api_model="mistralai/Mistral-7B-Instruct-v0.3",
    ),
    InferenceModel(
        id="hf-qwen-7b",
        label="Qwen 2.5 7B Instruct (HF credits)",
        api_model="Qwen/Qwen2.5-7B-Instruct",
    ),
    InferenceModel(
        id="hf-llama-3b",
        label="Llama 3.2 3B Instruct (HF credits)",
        api_model="meta-llama/Llama-3.2-3B-Instruct",
    ),
]

PROVIDER_MODEL_CATALOG: Dict[str, List[InferenceModel]] = {
    "gemini": list(GEMINI_STATIC_MODELS),
    "mistral": list(MISTRAL_STATIC_MODELS),
    "openrouter": list(OPENROUTER_STATIC_MODELS),
    "huggingface": list(HF_STATIC_MODELS),
}

_PROVIDER_HINTS: Dict[str, str] = {
    "gemini": (
        "Free tier: Flash models have generous limits. Pro may work with very low daily quotas "
        "(see ai.google.dev rate limits)."
    ),
    "mistral": (
        "Experiment plan: Large/Medium/Small and Codestral are included; phone verification only, "
        "strict rate limits."
    ),
    "openrouter": (
        "Models with :free suffix — 20 requests/min; 50/day without paid credits, "
        "1000/day after $10+ lifetime credits (openrouter.ai/docs)."
    ),
    "huggingface": (
        "Free accounts get small monthly credits (~$0.10); larger models use credits quickly. "
        "Not unlimited like OpenRouter :free."
    ),
}

_GEMINI_SKIP = re.compile(
    r"embed|imagen|tts|live|robotics|aqa|gemma|learnlm|nano-banana|thinking-exp",
    re.IGNORECASE,
)
_MISTRAL_SKIP = re.compile(
    r"embed|moderation|ocr|voxtral|realtime|tts|transcribe|pixtral|vibe-cli|labs-",
    re.IGNORECASE,
)


def _catalog_for(provider: str) -> List[InferenceModel]:
    return PROVIDER_MODEL_CATALOG.get(provider, [])


def _find_entry(provider: str, model: str) -> Optional[InferenceModel]:
    model = (model or "").strip()
    if not model:
        return None
    for entry in _catalog_for(provider):
        if model == entry.api_model or model == entry.id:
            return entry
    return None


def resolve_api_model(provider: str, model: str) -> str:
    entry = _find_entry(provider, model)
    if entry:
        return entry.api_model
    allowed = [m.api_model for m in _catalog_for(provider)]
    raise RuntimeError(
        f"Unknown model '{model}' for '{provider}'. Choose one of: {allowed}"
    )


_CATALOG_REFRESH_TS: Dict[str, float] = {
    "gemini": 0.0,
    "mistral": 0.0,
    "openrouter": 0.0,
}
_CATALOG_TTL_SECONDS = 300.0
_CATALOG_MAX_GEMINI = 12
_CATALOG_MAX_MISTRAL = 14
_CATALOG_MAX_OPENROUTER = 20


async def refresh_gemini_catalog(*, force: bool = False) -> None:
    """Merge Flash / Pro models from the Gemini API (free-tier friendly)."""
    now = time.monotonic()
    if not force and now - _CATALOG_REFRESH_TS["gemini"] < _CATALOG_TTL_SECONDS:
        return
    if not settings.gemini_api_key:
        PROVIDER_MODEL_CATALOG["gemini"] = []
        return

    entries = list(GEMINI_STATIC_MODELS)
    known = {m.api_model for m in entries}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                params={"key": settings.gemini_api_key},
            )
            if resp.status_code == 200:
                for item in resp.json().get("models", []):
                    raw_name = (item.get("name") or "").strip()
                    api_id = raw_name.replace("models/", "")
                    methods = item.get("supportedGenerationMethods") or []
                    if "generateContent" not in methods:
                        continue
                    if api_id in known or _GEMINI_SKIP.search(api_id):
                        continue
                    lower = api_id.lower()
                    is_flash = "flash" in lower
                    is_pro = re.search(r"(^|[.-])pro($|[.-])", lower)
                    if not is_flash and not is_pro:
                        continue
                    known.add(api_id)
                    suffix = (
                        " (free tier, low quota)"
                        if is_pro
                        else " (free tier)"
                    )
                    entries.append(
                        InferenceModel(
                            id=f"gemini-{api_id.replace('.', '-')}",
                            label=f"{api_id}{suffix}",
                            api_model=api_id,
                        )
                    )
    except Exception:
        pass

    PROVIDER_MODEL_CATALOG["gemini"] = entries[:_CATALOG_MAX_GEMINI]
    _CATALOG_REFRESH_TS["gemini"] = time.monotonic()


async def refresh_mistral_catalog(*, force: bool = False) -> None:
    """Merge chat-capable models from Mistral API (Experiment plan)."""
    now = time.monotonic()
    if not force and now - _CATALOG_REFRESH_TS["mistral"] < _CATALOG_TTL_SECONDS:
        return
    if not settings.mistral_api_key:
        PROVIDER_MODEL_CATALOG["mistral"] = []
        return

    entries = list(MISTRAL_STATIC_MODELS)
    known = {m.api_model for m in entries}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                "https://api.mistral.ai/v1/models",
                headers={"Authorization": f"Bearer {settings.mistral_api_key}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("data", data if isinstance(data, list) else [])
                for item in items:
                    api_id = (item.get("id") if isinstance(item, dict) else str(item)).strip()
                    if not api_id or api_id in known or _MISTRAL_SKIP.search(api_id):
                        continue
                    if not re.search(r"mistral|ministral|nemo|codestral|devstral|magistral", api_id, re.I):
                        continue
                    known.add(api_id)
                    entries.append(
                        InferenceModel(
                            id=f"mistral-{api_id.replace('/', '-')}",
                            label=f"{api_id} (Mistral)",
                            api_model=api_id,
                        )
                    )
    except Exception:
        pass

    PROVIDER_MODEL_CATALOG["mistral"] = entries[:_CATALOG_MAX_MISTRAL]
    _CATALOG_REFRESH_TS["mistral"] = time.monotonic()


async def refresh_openrouter_catalog(*, force: bool = False) -> None:
    """Merge :free models from OpenRouter (larger models first by context length)."""
    now = time.monotonic()
    if not force and now - _CATALOG_REFRESH_TS["openrouter"] < _CATALOG_TTL_SECONDS:
        return
    if not settings.openrouter_api_key:
        PROVIDER_MODEL_CATALOG["openrouter"] = list(OPENROUTER_STATIC_MODELS)
        return

    static = list(OPENROUTER_STATIC_MODELS)
    known = {m.api_model for m in static}
    dynamic: List[InferenceModel] = []

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get("https://openrouter.ai/api/v1/models")
            if resp.status_code == 200:
                items = []
                for item in resp.json().get("data", []):
                    api_id = (item.get("id") or "").strip()
                    if not api_id.endswith(":free") or api_id in known:
                        continue
                    ctx = int(item.get("context_length") or 0)
                    name = (item.get("name") or api_id).strip()
                    items.append((ctx, api_id, name))
                items.sort(key=lambda row: -row[0])
                for ctx, api_id, name in items:
                    known.add(api_id)
                    label = f"{name} (free)"
                    if ctx >= 100_000:
                        label = f"{name} (free, {ctx // 1000}K ctx)"
                    dynamic.append(
                        InferenceModel(
                            id=f"openrouter-{api_id.replace('/', '-').replace(':', '-')}",
                            label=label,
                            api_model=api_id,
                        )
                    )
    except Exception:
        pass

    PROVIDER_MODEL_CATALOG["openrouter"] = (
        static + dynamic[: max(0, _CATALOG_MAX_OPENROUTER - len(static))]
    )
    _CATALOG_REFRESH_TS["openrouter"] = time.monotonic()


class BaseInferenceProvider:
    provider_name: str = "base"

    def is_available(self) -> bool:
        raise NotImplementedError

    async def generate_content_async(self, prompt: str, model: str) -> str:
        raise NotImplementedError

    def _messages_with_system(
        self,
        messages: List[Dict[str, str]],
        compliance_header: str,
    ) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        if compliance_header.strip():
            out.append({"role": "system", "content": compliance_header.strip()})
        for msg in messages:
            role = msg.get("role", "user")
            if role not in ("user", "assistant", "system"):
                role = "user"
            out.append({"role": role, "content": msg.get("content", "") or ""})
        return out

    async def generate_messages_async(
        self,
        messages: List[Dict[str, str]],
        model: str,
        compliance_header: str = "",
    ) -> str:
        if not messages:
            return await self.generate_content_async(compliance_header, model)
        parts = []
        if compliance_header:
            parts.append(f"System: {compliance_header.strip()}")
        for msg in messages:
            role = msg.get("role", "user")
            label = "Assistant" if role == "assistant" else "User"
            parts.append(f"{label}: {msg.get('content', '')}")
        combined = "\n\n".join(parts) + "\n\nAssistant:"
        return await self.generate_content_async(combined, model)


class GeminiInferenceProvider(BaseInferenceProvider):
    provider_name = "gemini"

    def __init__(self, timeout: int = 120):
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(settings.gemini_api_key)

    async def generate_messages_async(
        self,
        messages: List[Dict[str, str]],
        model: str,
        compliance_header: str = "",
    ) -> str:
        if not settings.gemini_api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured.")
        api_model = resolve_api_model(self.provider_name, model)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{api_model}:generateContent"
        contents = []
        if compliance_header.strip():
            contents.append({"role": "user", "parts": [{"text": compliance_header.strip()}]})
            contents.append({
                "role": "model",
                "parts": [{"text": "Understood. I will apply governance silently and answer the user directly."}],
            })
        for msg in messages:
            role = "model" if msg.get("role") == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": msg.get("content", "")}]})
        payload = {"contents": contents}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url,
                params={"key": settings.gemini_api_key},
                json=payload,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Gemini API error {resp.status_code} for model '{api_model}': {resp.text[:300]}"
                )
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError(f"Gemini API returned no candidates: {str(data)[:200]}")
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
            if not text.strip():
                raise RuntimeError("Gemini API returned empty content.")
            return text.strip()

    async def generate_content_async(self, prompt: str, model: str) -> str:
        if not settings.gemini_api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured.")

        api_model = resolve_api_model(self.provider_name, model)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{api_model}:generateContent"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url,
                params={"key": settings.gemini_api_key},
                json=payload,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Gemini API error {resp.status_code} for model '{api_model}': {resp.text[:300]}"
                )
            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError(f"Gemini API returned no candidates: {str(data)[:200]}")
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
            if not text.strip():
                raise RuntimeError("Gemini API returned empty content.")
            return text.strip()


class OpenRouterInferenceProvider(BaseInferenceProvider):
    provider_name = "openrouter"

    def __init__(self, timeout: int = 120):
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(settings.openrouter_api_key)

    async def generate_messages_async(
        self,
        messages: List[Dict[str, str]],
        model: str,
        compliance_header: str = "",
    ) -> str:
        if not settings.openrouter_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not configured.")
        api_model = resolve_api_model(self.provider_name, model)
        headers = {
            "Authorization": f"Bearer {settings.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://127.0.0.1:8001",
            "X-Title": "AEGIS",
        }
        payload = {
            "model": api_model,
            "messages": self._messages_with_system(messages, compliance_header),
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"OpenRouter API error {resp.status_code} for model '{api_model}': {resp.text[:300]}"
                )
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("OpenRouter API returned no choices.")
            content = choices[0].get("message", {}).get("content", "")
            if not content:
                raise RuntimeError("OpenRouter API returned empty content.")
            return content.strip()

    async def generate_content_async(self, prompt: str, model: str) -> str:
        if not settings.openrouter_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not configured.")

        api_model = resolve_api_model(self.provider_name, model)
        headers = {
            "Authorization": f"Bearer {settings.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://127.0.0.1:8001",
            "X-Title": "AEGIS",
        }
        payload = {
            "model": api_model,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"OpenRouter API error {resp.status_code} for model '{api_model}': {resp.text[:300]}"
                )
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("OpenRouter API returned no choices.")
            content = choices[0].get("message", {}).get("content", "")
            if not content:
                raise RuntimeError("OpenRouter API returned empty content.")
            return content.strip()


class HuggingFaceInferenceProvider(BaseInferenceProvider):
    provider_name = "huggingface"

    def __init__(self, timeout: int = 120):
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(settings.huggingface_api_key)

    async def generate_messages_async(
        self,
        messages: List[Dict[str, str]],
        model: str,
        compliance_header: str = "",
    ) -> str:
        if not settings.huggingface_api_key:
            raise RuntimeError("HUGGINGFACE_API_KEY is not configured.")
        api_model = resolve_api_model(self.provider_name, model)
        headers = {
            "Authorization": f"Bearer {settings.huggingface_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": api_model,
            "messages": self._messages_with_system(messages, compliance_header),
            "max_tokens": 2048,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                "https://router.huggingface.co/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"HuggingFace API error {resp.status_code} for model '{api_model}': {resp.text[:300]}"
                )
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("HuggingFace API returned no choices.")
            content = choices[0].get("message", {}).get("content", "")
            if not content:
                raise RuntimeError("HuggingFace API returned empty content.")
            return content.strip()

    async def generate_content_async(self, prompt: str, model: str) -> str:
        if not settings.huggingface_api_key:
            raise RuntimeError("HUGGINGFACE_API_KEY is not configured.")

        api_model = resolve_api_model(self.provider_name, model)
        headers = {
            "Authorization": f"Bearer {settings.huggingface_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": api_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 512,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                "https://router.huggingface.co/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"HuggingFace API error {resp.status_code} for model '{api_model}': {resp.text[:300]}"
                )
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("HuggingFace API returned no choices.")
            content = choices[0].get("message", {}).get("content", "")
            if not content:
                raise RuntimeError("HuggingFace API returned empty content.")
            return content.strip()


class MistralInferenceProvider(BaseInferenceProvider):
    provider_name = "mistral"

    def __init__(self, timeout: int = 120):
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(settings.mistral_api_key)

    async def generate_messages_async(
        self,
        messages: List[Dict[str, str]],
        model: str,
        compliance_header: str = "",
    ) -> str:
        if not settings.mistral_api_key:
            raise RuntimeError("MISTRAL_API_KEY is not configured.")
        api_model = resolve_api_model(self.provider_name, model)
        headers = {
            "Authorization": f"Bearer {settings.mistral_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": api_model,
            "messages": self._messages_with_system(messages, compliance_header),
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                "https://api.mistral.ai/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Mistral API error {resp.status_code} for model '{api_model}': {resp.text[:300]}"
                )
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("Mistral API returned no choices.")
            content = choices[0].get("message", {}).get("content", "")
            if not content:
                raise RuntimeError("Mistral API returned empty content.")
            return content.strip()

    async def generate_content_async(self, prompt: str, model: str) -> str:
        if not settings.mistral_api_key:
            raise RuntimeError("MISTRAL_API_KEY is not configured.")

        api_model = resolve_api_model(self.provider_name, model)
        headers = {
            "Authorization": f"Bearer {settings.mistral_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": api_model,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                "https://api.mistral.ai/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Mistral API error {resp.status_code} for model '{api_model}': {resp.text[:300]}"
                )
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("Mistral API returned no choices.")
            content = choices[0].get("message", {}).get("content", "")
            if not content:
                raise RuntimeError("Mistral API returned empty content.")
            return content.strip()


class InferenceRouter:
    def __init__(self):
        self._providers: Dict[str, BaseInferenceProvider] = {
            "gemini": GeminiInferenceProvider(),
            "mistral": MistralInferenceProvider(),
            "openrouter": OpenRouterInferenceProvider(),
            "huggingface": HuggingFaceInferenceProvider(),
        }

    def get_models_for_provider(self, provider: str) -> List[str]:
        return [m.api_model for m in _catalog_for(provider)]

    def is_valid_model(self, provider: str, model: str) -> bool:
        return _find_entry(provider, model) is not None

    def get_available_provider_options(self) -> List[Dict[str, object]]:
        options = []
        for provider_name in ("gemini", "mistral", "openrouter", "huggingface"):
            provider = self._providers[provider_name]
            models = _catalog_for(provider_name)
            options.append(
                {
                    "provider": provider_name,
                    "available": provider.is_available(),
                    "models": [
                        {"id": m.id, "label": m.label, "api_model": m.api_model}
                        for m in models
                    ],
                    "hint": _PROVIDER_HINTS.get(provider_name, ""),
                }
            )
        return options

    async def generate(
        self,
        provider_name: str,
        model: str,
        prompt: str,
        *,
        refresh_catalog: bool = True,
    ) -> str:
        if refresh_catalog:
            if provider_name == "gemini":
                await refresh_gemini_catalog()
            if provider_name == "mistral":
                await refresh_mistral_catalog()
            if provider_name == "openrouter":
                await refresh_openrouter_catalog()
        provider = self._providers.get(provider_name)
        if not provider:
            raise RuntimeError(f"Unsupported inference provider: {provider_name}")
        if not self.is_valid_model(provider_name, model):
            allowed = self.get_models_for_provider(provider_name)
            raise RuntimeError(
                f"Model '{model}' is not valid for '{provider_name}'. Allowed: {allowed}"
            )
        if not provider.is_available():
            raise RuntimeError(f"Inference provider '{provider_name}' is not configured (missing API key).")
        return await provider.generate_content_async(prompt, model)

    async def generate_messages(
        self,
        provider_name: str,
        model: str,
        messages: List[Dict[str, str]],
        compliance_header: str = "",
        *,
        refresh_catalog: bool = True,
    ) -> str:
        if refresh_catalog:
            if provider_name == "gemini":
                await refresh_gemini_catalog()
            if provider_name == "mistral":
                await refresh_mistral_catalog()
            if provider_name == "openrouter":
                await refresh_openrouter_catalog()
        provider = self._providers.get(provider_name)
        if not provider:
            raise RuntimeError(f"Unsupported inference provider: {provider_name}")
        if not self.is_valid_model(provider_name, model):
            allowed = self.get_models_for_provider(provider_name)
            raise RuntimeError(
                f"Model '{model}' is not valid for '{provider_name}'. Allowed: {allowed}"
            )
        if not provider.is_available():
            raise RuntimeError(f"Inference provider '{provider_name}' is not configured (missing API key).")
        return await provider.generate_messages_async(messages, model, compliance_header)


_inference_router: Optional[InferenceRouter] = None


def get_inference_router() -> InferenceRouter:
    global _inference_router
    if _inference_router is None:
        _inference_router = InferenceRouter()
    return _inference_router
