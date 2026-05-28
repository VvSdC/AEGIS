"""
Inference provider abstraction for AEGIS.

Supports:
- Cerebras Inference API (OpenAI-compatible chat endpoint)
- Hugging Face Inference API
- OpenRouter chat completions
"""

from typing import Dict, List, Optional

import httpx

from ..config import settings


INFERENCE_MODEL_CATALOG: Dict[str, List[str]] = {
    "cerebras": [
        "llama3.1-8b",
        "Qwen/Qwen3-8B",
        "mistralai/Mathstral-7B-v0.1",
    ],
    "openrouter": [
        "mistralai/mistral-7b-instruct",
        "meta-llama/llama-3.1-8b-instruct",
        "qwen/qwen-2.5-7b-instruct",
    ],
    "huggingface": [
        "mistralai/Mistral-7B-Instruct-v0.3",
        "meta-llama/Llama-3.1-8B-Instruct",
        "Qwen/Qwen2.5-7B-Instruct",
    ],
}


class BaseInferenceProvider:
    provider_name: str = "base"

    def is_available(self) -> bool:
        raise NotImplementedError

    async def generate_content_async(self, prompt: str, model: str) -> str:
        raise NotImplementedError


class CerebrasInferenceProvider(BaseInferenceProvider):
    provider_name = "cerebras"

    def __init__(self, timeout: int = 120):
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(settings.cerebras_api_key)

    async def generate_content_async(self, prompt: str, model: str) -> str:
        if not settings.cerebras_api_key:
            raise RuntimeError("CEREBRAS_API_KEY is not configured.")

        headers = {
            "Authorization": f"Bearer {settings.cerebras_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post("https://api.cerebras.ai/v1/chat/completions", headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Cerebras API error {resp.status_code}: {resp.text[:300]}")
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("Cerebras API returned no choices.")
            message = choices[0].get("message", {})
            content = message.get("content", "")
            if not content:
                raise RuntimeError("Cerebras API returned empty content.")
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

        url = f"https://api-inference.huggingface.co/models/{model}"
        headers = {
            "Authorization": f"Bearer {settings.huggingface_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "inputs": prompt,
            "parameters": {"max_new_tokens": 512, "return_full_text": False},
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"HuggingFace API error {resp.status_code}: {resp.text[:300]}")

            data = resp.json()
            if isinstance(data, list) and data:
                first = data[0]
                if isinstance(first, dict):
                    text = first.get("generated_text", "")
                    if text:
                        return text.strip()
            if isinstance(data, dict):
                text = data.get("generated_text", "")
                if text:
                    return text.strip()
            raise RuntimeError("HuggingFace API returned an unexpected response shape.")


class OpenRouterInferenceProvider(BaseInferenceProvider):
    provider_name = "openrouter"

    def __init__(self, timeout: int = 120):
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(settings.openrouter_api_key)

    async def generate_content_async(self, prompt: str, model: str) -> str:
        if not settings.openrouter_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not configured.")

        headers = {
            "Authorization": f"Bearer {settings.openrouter_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"OpenRouter API error {resp.status_code}: {resp.text[:300]}")
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("OpenRouter API returned no choices.")
            message = choices[0].get("message", {})
            content = message.get("content", "")
            if not content:
                raise RuntimeError("OpenRouter API returned empty content.")
            return content.strip()


class InferenceRouter:
    def __init__(self):
        self._providers: Dict[str, BaseInferenceProvider] = {
            "cerebras": CerebrasInferenceProvider(),
            "openrouter": OpenRouterInferenceProvider(),
            "huggingface": HuggingFaceInferenceProvider(),
        }

    def get_models_for_provider(self, provider: str) -> List[str]:
        return INFERENCE_MODEL_CATALOG.get(provider, [])

    def get_available_provider_options(self) -> List[Dict[str, object]]:
        options = []
        for provider_name, models in INFERENCE_MODEL_CATALOG.items():
            provider = self._providers.get(provider_name)
            options.append(
                {
                    "provider": provider_name,
                    "available": bool(provider and provider.is_available()),
                    "models": models,
                }
            )
        return options

    async def generate(self, provider_name: str, model: str, prompt: str) -> str:
        provider = self._providers.get(provider_name)
        if not provider:
            raise RuntimeError(f"Unsupported inference provider: {provider_name}")
        if model not in INFERENCE_MODEL_CATALOG.get(provider_name, []):
            raise RuntimeError(f"Model '{model}' is not allowed for provider '{provider_name}'.")
        if not provider.is_available():
            raise RuntimeError(f"Inference provider '{provider_name}' is not configured.")
        return await provider.generate_content_async(prompt, model)


_inference_router: Optional[InferenceRouter] = None


def get_inference_router() -> InferenceRouter:
    global _inference_router
    if _inference_router is None:
        _inference_router = InferenceRouter()
    return _inference_router
