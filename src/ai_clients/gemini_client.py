"""Google Gemini client for cryptanalysis."""

import aiohttp
import asyncio
import json
import logging
import os
import time
from typing import Dict, List

from .base_client import BaseAIClient, AIResponse


class GeminiCryptanalyst(BaseAIClient):
    """Gemini implementation for cryptanalysis."""

    def __init__(self, api_key: str):
        from config.api_config import AIConfig

        super().__init__(api_key, model=AIConfig.GEMINI_MODEL)

        # Reduce terminal memory pressure: allow per-provider log level override.
        gemini_level = os.getenv("GEMINI_LOG_LEVEL", "").strip().upper()
        if gemini_level:
            self.logger.setLevel(getattr(logging, gemini_level, logging.INFO))

        self._endpoint_base = AIConfig.GEMINI_ENDPOINT
        self.endpoint = f"{AIConfig.GEMINI_ENDPOINT}?key={api_key}"

        # Gemini can be slow on long prompts; allow provider-specific timeout.
        self.timeout = int(getattr(AIConfig, "GEMINI_TIMEOUT", self.timeout))

        # Network/proxy options
        proxy = (getattr(AIConfig, "GEMINI_PROXY", "") or getattr(AIConfig, "OPENAI_PROXY", "") or "")
        proxy = str(proxy).strip()
        if proxy.lower() in ("off", "none", "0", "false", "disable", "disabled"):
            proxy = ""
        self.proxy = proxy
        trust_env_raw = getattr(AIConfig, "GEMINI_TRUST_ENV", getattr(AIConfig, "OPENAI_TRUST_ENV", "0"))
        self.trust_env = str(trust_env_raw).strip().lower() in ("1", "true", "yes", "on")

        self.requests_per_minute = AIConfig.GEMINI_REQUESTS_PER_MINUTE
        self.max_output_tokens = int(getattr(AIConfig, "GEMINI_MAX_OUTPUT_TOKENS", 800))

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(trust_env=self.trust_env)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def ping(self) -> tuple[bool, str]:
        """Lightweight network preflight.

        Returns (ok, message). Avoids cryptanalysis prompts and fails fast if proxy/network/model config is broken.
        """

        payload = {
            'contents': [{'parts': [{'text': 'Return a single word: pong.'}, {'text': 'ping'}]}],
            'generationConfig': {
                'temperature': 0,
                'maxOutputTokens': 5,
            },
        }

        session = self.session
        close_after = False
        if session is None:
            session = aiohttp.ClientSession(trust_env=self.trust_env)
            close_after = True

        try:
            async with session.post(
                self.endpoint,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=min(30, int(self.timeout) if self.timeout else 30)),
                proxy=(self.proxy or None),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    return False, f"HTTP {resp.status}: {body[:500]}"
                data = await resp.json()
                cand = ((data.get('candidates') or [{}])[0].get('content') or {})
                parts = cand.get('parts') or []
                text = (parts[0].get('text') if parts and isinstance(parts[0], dict) else '') or ''
                t = text.strip().lower()
                if 'pong' in t:
                    return True, 'pong'
                return True, f"ok (unexpected content: {t[:80]})"
        except asyncio.TimeoutError as e:
            return False, f"TimeoutError: {e!r} (endpoint={self._endpoint_base}, proxy={self.proxy or 'none'}, trust_env={self.trust_env})"
        except aiohttp.ClientError as e:
            return False, f"{type(e).__name__}: {e!r} (endpoint={self._endpoint_base}, proxy={self.proxy or 'none'}, trust_env={self.trust_env})"
        except Exception as e:
            return False, f"{type(e).__name__}: {e!r} (endpoint={self._endpoint_base}, proxy={self.proxy or 'none'}, trust_env={self.trust_env})"
        finally:
            if close_after:
                await session.close()

    async def analyze_ciphertext(self, encrypted_data: Dict, context: Dict = None) -> AIResponse:
        start_time = time.time()

        for attempt in range(self.max_retries):
            try:
                prompt_type = 'hidden' if context and context.get('algorithm_hidden', False) else 'informed'
                prompt = self._create_cryptanalysis_prompt(encrypted_data, context, prompt_type)
                prompt += "\n\nIMPORTANT: Provide your response in valid JSON format only.\n"
                input_tokens = self._estimate_tokens(prompt)

                self.logger.info('Starting API call...')
                self.logger.info('Headers prepared')

                await self._throttle()
                mission = None
                if context:
                    tc = context.get('test_case') or {}
                    mission = context.get('mission') or (tc.get('mission') if isinstance(tc, dict) else None)

                max_output_tokens = 800 if mission == 'plaintext_recovery' else self.max_output_tokens
                self.logger.info(f'Trying endpoint: {self._endpoint_base}?key=***')

                payload = {
                    'contents': [{'parts': [{'text': prompt}]}],
                    'generationConfig': {
                        'temperature': 0.3,
                        'maxOutputTokens': max_output_tokens,
                        'responseMimeType': 'application/json',
                    },
                }

                async with self.session.post(
                    self.endpoint,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    proxy=(self.proxy or None),
                ) as response:
                    if response.status == 200:
                        self.logger.info('Successful API response received')
                        result = await response.json()

                        if 'candidates' in result and result['candidates']:
                            candidate = result['candidates'][0]
                            if 'content' in candidate and 'parts' in candidate['content']:
                                parts = candidate['content']['parts']
                                if parts and 'text' in parts[0]:
                                    response_text = parts[0]['text']

                                    usage = result.get('usageMetadata', {})
                                    input_tokens = usage.get('promptTokenCount', input_tokens)
                                    output_tokens = usage.get('candidatesTokenCount', 0)

                                    parsed_data = self._parse_response(response_text)
                                    return AIResponse(
                                        success=True,
                                        content=response_text,
                                        input_tokens=input_tokens,
                                        output_tokens=output_tokens,
                                        parsed_data=parsed_data,
                                    )

                        return AIResponse(
                            success=False,
                            content=json.dumps(result),
                            error='Unexpected response structure from Gemini',
                        )

                    error_text = await response.text()
                    self.logger.warning(f'Gemini API error {response.status}: {error_text[:300]}')
                    self.logger.info('Failed to receive API response')

                    should_retry = response.status == 429 or response.status >= 500
                    if (not should_retry) or (attempt == self.max_retries - 1):
                        return AIResponse(
                            success=False,
                            content='',
                            error=f'API error {response.status}: {error_text}',
                        )

                    retry_after = response.headers.get('Retry-After')
                    if retry_after:
                        try:
                            await asyncio.sleep(float(retry_after))
                        except ValueError:
                            await asyncio.sleep(2 * (attempt + 1))
                    else:
                        await asyncio.sleep(2 * (attempt + 1))

            except asyncio.TimeoutError:
                self.logger.warning('Gemini request timeout')
                self.logger.info('Failed to receive API response')
                if attempt == self.max_retries - 1:
                    return AIResponse(
                        success=False,
                        content='',
                        error='Request timeout',
                    )
                await asyncio.sleep(2 * (attempt + 1))

            except Exception as e:
                self.logger.warning(f'Gemini request exception ({type(e).__name__}): {e}')
                self.logger.info('Failed to receive API response')
                if attempt == self.max_retries - 1:
                    return AIResponse(
                        success=False,
                        content='',
                        error=str(e),
                    )
                await asyncio.sleep(2 * (attempt + 1))

        return AIResponse(success=False, content='', error='Unknown error')

    async def batch_analyze(self, test_cases: List[Dict], concurrent_requests: int = 2) -> List[AIResponse]:
        semaphore = asyncio.Semaphore(concurrent_requests)

        async def bounded_analyze(test_case: Dict) -> AIResponse:
            async with semaphore:
                context = {'test_case': test_case}
                if 'algorithm_hidden' in test_case:
                    context['algorithm_hidden'] = test_case['algorithm_hidden']
                return await self.analyze_ciphertext(test_case['encrypted_data'], context)

        tasks = [bounded_analyze(tc) for tc in test_cases]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: List[AIResponse] = []
        for r in results:
            if isinstance(r, Exception):
                processed.append(AIResponse(success=False, content='', error=str(r)))
            else:
                processed.append(r)
        return processed

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        from config.api_config import AIConfig

        config = AIConfig()
        input_cost = (input_tokens / 1000) * config.GEMINI_COST_PER_1K_INPUT
        output_cost = (output_tokens / 1000) * config.GEMINI_COST_PER_1K_OUTPUT
        return input_cost + output_cost
