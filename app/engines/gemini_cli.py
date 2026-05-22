"""
Gemini Inference Engine for AEGIS

Supports authentication modes (checked in order):
1. Google GenAI SDK with Vertex AI — uses ADC + project
2. Direct HTTP to Generative Language API — uses ADC token (no API key needed)
3. Gemini CLI (local development) — uses OAuth from CLI login

Cloud Run automatically provides Application Default Credentials (ADC)
via its service account.
"""

import subprocess
import asyncio
import shutil
import sys
import os
import re
import json
from typing import Optional
import httpx


class GeminiHTTP:
    """Direct HTTP inference via generativelanguage.googleapis.com using ADC token."""

    def __init__(self, model: str = "gemini-2.0-flash", timeout: int = 120):
        self._model = model
        self._timeout = timeout
        self._available = None
        self._credentials = None

    def _get_token(self) -> str:
        from google.auth import default
        from google.auth.transport.requests import Request

        if self._credentials is None:
            self._credentials, _ = default(
                scopes=['https://www.googleapis.com/auth/cloud-platform',
                        'https://www.googleapis.com/auth/generative-language']
            )
        self._credentials.refresh(Request())
        return self._credentials.token

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            token = self._get_token()
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self._model}:generateContent"
            resp = httpx.post(
                url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": "test"}]}]},
                timeout=30,
            )
            if resp.status_code == 200:
                print(f"[AEGIS] Generative Language HTTP API initialized (model={self._model})")
                self._available = True
            else:
                print(f"[AEGIS] Generative Language HTTP API failed: {resp.status_code} {resp.text[:200]}")
                self._available = False
        except Exception as e:
            print(f"[AEGIS] Generative Language HTTP API failed: {type(e).__name__}: {e}")
            self._available = False
        return self._available

    def generate_content(self, prompt: str) -> str:
        token = self._get_token()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self._model}:generateContent"
        resp = httpx.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=self._timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Gemini API error {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            raise RuntimeError("Gemini API returned no candidates")
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts)

    async def generate_content_async(self, prompt: str) -> str:
        return await asyncio.to_thread(self.generate_content, prompt)


class GeminiGenAI:
    """Production inference via google-genai SDK with Vertex AI."""

    def __init__(self, project: str, model: str, location: str = "us-central1"):
        self._project = project
        self._model_name = model
        self._location = location
        self._client = None
        self._available = None

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            from google import genai
            from google.auth import default
            from google.auth.transport.requests import Request

            credentials, _ = default(
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
            credentials.refresh(Request())
            self._client = genai.Client(
                vertexai=True,
                project=self._project,
                location=self._location,
                credentials=credentials,
            )
            self._client.models.generate_content(
                model=self._model_name, contents='test'
            )
            print(f"[AEGIS] GenAI SDK initialized (vertexai, project={self._project}, location={self._location})")
            self._available = True
        except Exception as e:
            print(f"[AEGIS] GenAI SDK Vertex failed (location={self._location}): {type(e).__name__}: {e}")
            self._available = False
        return self._available

    def generate_content(self, prompt: str) -> str:
        response = self._client.models.generate_content(
            model=self._model_name,
            contents=prompt,
        )
        return response.text

    async def generate_content_async(self, prompt: str) -> str:
        return await asyncio.to_thread(self.generate_content, prompt)


class GeminiCLI:
    """Local development inference via gemini CLI (OAuth-based)."""

    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self._cli_available = None
        self._cli_path = None

    def _find_cli(self) -> Optional[str]:
        if self._cli_path:
            return self._cli_path
        candidates = ["gemini"]
        if sys.platform == "win32":
            candidates = ["gemini.cmd", "gemini.ps1", "gemini"]
        for name in candidates:
            path = shutil.which(name)
            if path:
                self._cli_path = path
                return path
        return None

    def is_available(self) -> bool:
        if self._cli_available is not None:
            return self._cli_available
        cli_path = self._find_cli()
        if not cli_path:
            self._cli_available = False
            return False
        try:
            result = subprocess.run(
                [cli_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                shell=(sys.platform == "win32"),
            )
            self._cli_available = result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            self._cli_available = False
        return self._cli_available

    def _clean_output(self, text: str) -> str:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        text = ansi_escape.sub('', text)
        ui_chars = re.compile(r'[▄▀▝▜▗▟▌▐░▒▓█✦ℹ]')
        text = ui_chars.sub('', text)
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text.strip()

    def generate_content(self, prompt: str) -> str:
        cli_path = self._find_cli()
        if not cli_path:
            raise RuntimeError("Gemini CLI not found.")
        try:
            result = subprocess.run(
                [cli_path, "-p", prompt],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=(sys.platform == "win32"),
            )
            if result.returncode != 0:
                raise RuntimeError(f"Gemini CLI error: {result.stderr or 'Unknown'}")
            return self._clean_output(result.stdout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Gemini CLI timed out after {self.timeout}s")

    async def generate_content_async(self, prompt: str) -> str:
        return await asyncio.to_thread(self.generate_content, prompt)


_instance = None


def get_gemini_cli():
    """
    Get the Gemini inference engine. Checks in order:
    1. Direct HTTP to Generative Language API (works with SA token, no API key)
    2. Google GenAI SDK — Vertex AI API
    3. Gemini CLI (OAuth) — for local development
    """
    global _instance
    if _instance is not None:
        return _instance

    from ..config import settings

    if settings.google_cloud_project:
        # 1. Try direct HTTP to Generative Language API (no API key needed)
        http_engine = GeminiHTTP(model=settings.gemini_model)
        if http_engine.is_available():
            _instance = http_engine
            return _instance

        # 2. Try Vertex AI SDK with configured location
        engine = GeminiGenAI(
            project=settings.google_cloud_project,
            model=settings.gemini_model,
            location=settings.google_cloud_location,
        )
        if engine.is_available():
            _instance = engine
            return _instance

        # 3. Try Vertex AI with us-central1 fallback
        if settings.google_cloud_location != "us-central1":
            engine2 = GeminiGenAI(
                project=settings.google_cloud_project,
                model=settings.gemini_model,
                location="us-central1",
            )
            if engine2.is_available():
                _instance = engine2
                return _instance

    # 4. Try Gemini CLI (local dev with OAuth)
    cli = GeminiCLI()
    if cli.is_available():
        print("[AEGIS] Using Gemini CLI (OAuth)")
        _instance = cli
        return _instance

    print("[AEGIS] WARNING: No Gemini inference backend available")
    _instance = cli
    return _instance
