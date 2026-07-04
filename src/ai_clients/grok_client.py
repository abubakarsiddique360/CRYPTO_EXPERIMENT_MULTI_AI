"""Grok (xAI) client for cryptanalysis."""

import aiohttp
import logging
import os
import asyncio
import json
import time
from typing import Dict, List

from .base_client import BaseAIClient, AIResponse


class GrokCryptanalyst(BaseAIClient):
    """Grok implementation for cryptanalysis."""

    def __init__(self, api_key: str):
        from config.api_config import AIConfig

        super().__init__(api_key, model=AIConfig.GROK_MODEL)
        # Reduce VS Code/terminal memory pressure: allow per-provider log level override.
        grok_level = os.getenv("GROK_LOG_LEVEL", "").strip().upper()
        if grok_level:
            self.logger.setLevel(getattr(logging, grok_level, logging.INFO))
        self.endpoint = AIConfig.GROK_ENDPOINT

        # Grok can be significantly slower on long prompts; allow a provider-specific timeout.
        self.timeout = int(getattr(AIConfig, "GROK_TIMEOUT", self.timeout))

        # Network/proxy options
        self.proxy = getattr(AIConfig, "GROK_PROXY", "") or ""
        trust_env_raw = getattr(AIConfig, "GROK_TRUST_ENV", "0")
        self.trust_env = str(trust_env_raw).strip().lower() in ("1", "true", "yes", "on")

        self.requests_per_minute = AIConfig.GROK_REQUESTS_PER_MINUTE
        self.max_tokens = int(getattr(AIConfig, "GROK_MAX_TOKENS", 800))

        # Grok-specific retry cap to prevent request multiplication (e.g., retries=3 -> ~3x calls).
        self.max_retries = int(getattr(AIConfig, "GROK_MAX_RETRIES", self.max_retries))

        # Simple per-run counters for auditing actual API calls vs test cases.
        self.api_call_count = 0
        self.api_retry_count = 0
        self.api_error_count = 0

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(trust_env=self.trust_env)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    

    async def ping(self) -> tuple[bool, str]:
        """Lightweight network preflight.

        Returns (ok, message). Avoids cryptanalysis prompts (so plaintext can't be included)
        and fails fast if proxy/network/model config is broken.
        """
        payload = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': 'Return a single word: pong.'},
                {'role': 'user', 'content': 'ping'},
            ],
            'temperature': 0,
            'max_tokens': 5,
        }
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        }

        session = self.session
        close_after = False
        if session is None:
            session = aiohttp.ClientSession(trust_env=self.trust_env)
            close_after = True

        try:
            async with session.post(
                self.endpoint,
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=min(30, int(self.timeout) if self.timeout else 30)),
                proxy=(self.proxy or None),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    return False, f"HTTP {resp.status}: {body[:500]}"
                data = await resp.json()
                content = (((data.get('choices') or [{}])[0].get('message') or {}).get('content') or '').strip().lower()
                if 'pong' in content:
                    return True, 'pong'
                return True, f"ok (unexpected content: {content[:80]})"
        except Exception as e:
            self.api_error_count += 1
            return False, str(e)
        finally:
            if close_after:
                await session.close()

    async def analyze_ciphertext(self, encrypted_data: Dict, context: Dict = None) -> AIResponse:
        start_time = time.time()

        for attempt in range(self.max_retries):
            try:
                prompt_type = 'hidden' if context and context.get('algorithm_hidden', False) else 'informed'
                prompt = self._create_cryptanalysis_prompt(encrypted_data, context, prompt_type)
                prompt += "\n\nIMPORTANT: Provide your response in valid JSON format only."

                input_tokens = self._estimate_tokens(prompt)

                self.logger.info('Starting API call...')

                headers = {
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json',
                }

                self.logger.info('Headers prepared')

                await self._throttle()
                mission = None
                if context:
                    tc = context.get('test_case') or {}
                    mission = context.get('mission') or (tc.get('mission') if isinstance(tc, dict) else None)

                max_tokens = 800 if mission == 'plaintext_recovery' else self.max_tokens
                self.logger.info(f'Trying endpoint: {self.endpoint}')

                # Audit: count every outbound request.
                if attempt > 0:
                    self.api_retry_count += 1
                self.api_call_count += 1

                payload = {
                    'model': self.model,
                    'messages': [
                        {
                            'role': 'system',
                            'content': (
                                'You are an expert cryptanalyst specialized in analyzing encrypted data and '
                                'identifying cryptographic vulnerabilities. Provide your analysis in valid JSON format.'
                            ),
                        },
                        {'role': 'user', 'content': prompt},
                    ],
                    'temperature': 0.3,
                    'max_tokens': max_tokens,}

                async with self.session.post(
                    self.endpoint,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    proxy=(self.proxy or None),
                ) as response:
                    if response.status == 200:
                        self.logger.info('Successful API response received')
                        result = await response.json()

                        if 'choices' in result and result['choices']:
                            response_text = result['choices'][0]['message']['content']

                            usage = result.get('usage', {})
                            input_tokens = usage.get('prompt_tokens', input_tokens)
                            output_tokens = usage.get('completion_tokens', 0)

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
                            error='Unexpected response structure from Grok',
                        )

                    error_text = await response.text()
                    self.api_error_count += 1
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
                self.api_error_count += 1
                self.logger.info('Failed to receive API response')
                if attempt == self.max_retries - 1:
                    return AIResponse(
                        success=False,
                        content='',
                        error='Request timeout',
                    )
                await asyncio.sleep(2 * (attempt + 1))

            except Exception as e:
                self.api_error_count += 1
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
        input_cost = (input_tokens / 1000) * config.GROK_COST_PER_1K_INPUT
        output_cost = (output_tokens / 1000) * config.GROK_COST_PER_1K_OUTPUT
        return input_cost + output_cost

