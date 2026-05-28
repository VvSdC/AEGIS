"""
Inference providers for AEGIS.

Each provider has its own model IDs. The UI sends `api_model` exactly as listed
for the selected provider.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

import httpx

from ..config import settings


@dataclass(frozen=True)
class InferenceModel:
    id: str
    label: str
    api_model: str


# Google AI Studio free tier — Flash / Flash-Lite (see ai.google.dev pricing).
GEMINI_STATIC_MODELS: List[InferenceModel] = [
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

MISTRAL_STATIC_MODELS: List[InferenceModel] = [
    InferenceModel(
        id="mistral-ministral-8b",
        label="Ministral 8B (Experiment)",
        api_model="ministral-8b-latest",
    ),
    InferenceModel(
        id="mistral-ministral-3b",
        label="Ministral 3B (Experiment)",
        api_model="ministral-3b-latest",
    ),
    InferenceModel(
        id="mistral-small",
        label="Mistral Small (Experiment)",
        api_model="mistral-small-latest",
    ),
    InferenceModel(
        id="mistral-nemo",
        label="Mistral Nemo 12B (Experiment)",
        api_model="open-mistral-nemo",
    ),
]

PROVIDER_MODEL_CATALOG: Dict[str, List[InferenceModel]] = {
    "gemini": list(GEMINI_STATIC_MODELS),
    "mistral": list(MISTRAL_STATIC_MODELS),
    "openrouter": [
        InferenceModel(
            id="openrouter-lfm",
            label="Liquid LFM 2.5 1.2B (free)",
            api_model="liquid/lfm-2.5-1.2b-instruct:free",
        ),
        InferenceModel(
            id="openrouter-llama",
            label="Llama 3.2 3B Instruct (free)",
            api_model="meta-llama/llama-3.2-3b-instruct:free",
        ),
        InferenceModel(
            id="openrouter-nemotron",
            label="NVIDIA Nemotron Nano 9B (free)",
            api_model="nvidia/nemotron-nano-9b-v2:free",
        ),
    ],
    "huggingface": [
        InferenceModel(
            id="hf-llama-3b",
            label="Llama 3.2 3B Instruct",
            api_model="meta-llama/Llama-3.2-3B-Instruct",
        ),
        InferenceModel(
            id="hf-mistral",
            label="Mistral 7B Instruct",
            api_model="mistralai/Mistral-7B-Instruct-v0.3",
        ),
        InferenceModel(
            id="hf-qwen",
            label="Qwen 2.5 7B Instruct",
            api_model="Qwen/Qwen2.5-7B-Instruct",
        ),
    ],
}

_GEMINI_SKIP = re.compile(
    r"pro|embed|imagen|tts|live|robotics|aqa|gemma|learnlm|nano-banana",
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


async def refresh_gemini_catalog() -> None:
    """Merge Flash / Flash-Lite models from the Gemini API (free-tier friendly)."""
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
                    if "flash" not in api_id.lower():
                        continue
                    known.add(api_id)
                    entries.append(
                        InferenceModel(
                            id=f"gemini-{api_id.replace('.', '-')}",
                            label=f"{api_id} (Gemini)",
                            api_model=api_id,
                        )
                    )
    except Exception:
        pass

    PROVIDER_MODEL_CATALOG["gemini"] = entries[:8]


async def refresh_mistral_catalog() -> None:
    """Merge chat-capable models from Mistral API (Experiment plan)."""
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

    PROVIDER_MODEL_CATALOG["mistral"] = entries[:8]


class BaseInferenceProvider:
    provider_name: str = "base"

    def is_available(self) -> bool:
        raise NotImplementedError

    async def generate_content_async(self, prompt: str, model: str) -> str:
        raise NotImplementedError


class GeminiInferenceProvider(BaseInferenceProvider):
    provider_name = "gemini"

    def __init__(self, timeout: int = 120):
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(settings.gemini_api_key)

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
                    "hint": "",
                }
            )
        return options

    async def generate(self, provider_name: str, model: str, prompt: str) -> str:
        if provider_name == "gemini":
            await refresh_gemini_catalog()
        if provider_name == "mistral":
            await refresh_mistral_catalog()
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


_inference_router: Optional[InferenceRouter] = None


def get_inference_router() -> InferenceRouter:
    global _inference_router
    if _inference_router is None:
        _inference_router = InferenceRouter()
    return _inference_router
