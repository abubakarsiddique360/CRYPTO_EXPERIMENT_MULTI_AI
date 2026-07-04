"""Gemini client implemented via the official google-genai SDK.

This is optional and only used when runner scripts set GEMINI_USE_GENAI=1.
API keys must be provided via environment variables (e.g., GEMINI_API_KEY).
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict, List

from .base_client import BaseAIClient, AIResponse


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


class GeminiGenAISDKCryptanalyst(BaseAIClient):
    """Gemini implementation using google-genai SDK."""

    def __init__(self, api_key: str):
        from config.api_config import AIConfig

        super().__init__(api_key, model=AIConfig.GEMINI_MODEL)

        self.timeout = int(getattr(AIConfig, "GEMINI_TIMEOUT", self.timeout))
        self.max_output_tokens = int(getattr(AIConfig, "GEMINI_MAX_OUTPUT_TOKENS", 800))
        self.thinking_budget = int(getattr(AIConfig, "GEMINI_THINKING_BUDGET", 0))
        self.requests_per_minute = AIConfig.GEMINI_REQUESTS_PER_MINUTE

        # SDK options (proxy/base_url handled by the caller's gateway)
        self.base_url = (os.getenv("GEMINI_GENAI_BASE_URL", "").strip() or None)
        self.vertexai = _env_bool("GEMINI_GENAI_VERTEXAI", default=False)

        self._client = None

    async def __aenter__(self):
        # Import lazily so the repo can run without the dependency when not used.
        try:
            import google.genai as genai  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "google-genai SDK is not installed. Install it (pip install google-genai) or unset GEMINI_USE_GENAI."
            ) from e

        http_options = None
        if self.base_url:
            http_options = {"base_url": self.base_url}

        # Note: Do NOT log api_key.
        self._client = genai.Client(
            api_key=self.api_key,
            vertexai=self.vertexai,
            http_options=http_options,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # google-genai client has no async close needed
        self._client = None

    async def ping(self) -> tuple[bool, str]:
        """Lightweight network/API preflight."""
        start = time.time()
        try:
            text = await self._generate_text("Return a single word: pong.")
            t = (text or "").strip().lower()
            if "pong" in t:
                return True, f"pong ({(time.time() - start):.2f}s)"
            return True, f"ok (unexpected content: {t[:80]})"
        except Exception as e:
            return False, f"{type(e).__name__}: {e!r} (base_url={self.base_url or 'default'}, vertexai={self.vertexai})"

    async def _generate_text(self, prompt: str, *, response_mime_type: str | None = None, max_output_tokens: int | None = None) -> str:
        if self._client is None:
            raise RuntimeError("Client not initialized; use 'async with'.")

        # Call the synchronous SDK in a thread to avoid blocking the event loop.
        def _call() -> Any:
            from google.genai import types  # type: ignore

            cfg_kwargs: Dict[str, Any] = {}
            if max_output_tokens is not None:
                cfg_kwargs["max_output_tokens"] = int(max_output_tokens)
            if response_mime_type:
                cfg_kwargs["response_mime_type"] = response_mime_type

            cfg_kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=int(getattr(self, "thinking_budget", 0)))

            config = types.GenerateContentConfig(**cfg_kwargs)
            return self._client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=config,
            )

        resp = await asyncio.to_thread(_call)

        # Best-effort extract text
        if hasattr(resp, "text"):
            return getattr(resp, "text") or ""
        return str(resp)

    async def analyze_ciphertext(self, encrypted_data: Dict[str, Any], context: Dict[str, Any] | None = None) -> AIResponse:
        start_time = time.time()

        for attempt in range(self.max_retries):
            try:
                prompt_type = "hidden" if context and context.get("algorithm_hidden", False) else "informed"
                prompt = self._create_cryptanalysis_prompt(encrypted_data, context, prompt_type)
                prompt += "\n\nReturn ONLY a single valid JSON object and nothing else (no prose, no markdown/code fences).\n"
                input_tokens = self._estimate_tokens(prompt)

                await self._throttle()

                mission = None
                if context:
                    tc = context.get("test_case") or {}
                    mission = context.get("mission") or (tc.get("mission") if isinstance(tc, dict) else None)

                max_out = 800 if mission == "plaintext_recovery" else self.max_output_tokens

                response_text = await self._generate_text(
                    prompt,
                    response_mime_type="application/json",
                    max_output_tokens=max_out,
                )

                parsed_data = self._parse_response(response_text)
                # SDK does not always expose token usage consistently through proxies; keep estimates.
                return AIResponse(
                    success=True,
                    content=response_text,
                    input_tokens=input_tokens,
                    output_tokens=0,
                    parsed_data=parsed_data,
                )

            except Exception as e:
                if attempt == self.max_retries - 1:
                    return AIResponse(
                        success=False,
                        content="",
                        error=f"{type(e).__name__}: {e}",
                    )
                await asyncio.sleep(2 * (attempt + 1))

        return AIResponse(success=False, content="", error="Unknown error")

    async def batch_analyze(self, test_cases: List[Dict[str, Any]], concurrent_requests: int = 2) -> List[AIResponse]:
        semaphore = asyncio.Semaphore(concurrent_requests)

        async def bounded_analyze(test_case: Dict[str, Any]) -> AIResponse:
            async with semaphore:
                context = {"test_case": test_case}
                if "algorithm_hidden" in test_case:
                    context["algorithm_hidden"] = test_case["algorithm_hidden"]
                return await self.analyze_ciphertext(test_case["encrypted_data"], context)

        tasks = [bounded_analyze(tc) for tc in test_cases]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: List[AIResponse] = []
        for r in results:
            if isinstance(r, Exception):
                processed.append(AIResponse(success=False, content="", error=str(r)))
            else:
                processed.append(r)
        return processed


__all__ = ["GeminiGenAISDKCryptanalyst"]
