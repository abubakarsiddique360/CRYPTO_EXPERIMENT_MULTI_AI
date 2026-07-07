"""DeepSeek client for cryptanalysis."""

import aiohttp
import asyncio
import json
import time
from typing import Dict, List

from .base_client import BaseAIClient, AIResponse


class DeepSeekCryptanalyst(BaseAIClient):
    """DeepSeek cryptanalysis client."""

    def __init__(self, api_key: str):
        from config.api_config import AIConfig

        super().__init__(api_key, model=AIConfig.DEEPSEEK_MODEL)
        self.endpoint = AIConfig.DEEPSEEK_ENDPOINT

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def analyze_ciphertext(self, encrypted_data: Dict, context: Dict = None) -> AIResponse:
        """Analyze encrypted data with DeepSeek."""
        start_time = time.time()

        for attempt in range(self.max_retries):
            try:
                prompt_type = 'hidden' if context and context.get('algorithm_hidden', False) else 'informed'
                prompt = self._create_cryptanalysis_prompt(encrypted_data, context, prompt_type)

                input_tokens = self._estimate_tokens(prompt)

                mission = None
                if context:
                    tc = context.get('test_case') or {}
                    mission = context.get('mission') or (tc.get('mission') if isinstance(tc, dict) else None)

                # Plaintext-recovery prompts require short JSON; keep outputs bounded
                max_tokens = 800 if mission == 'plaintext_recovery' else 4000

                self.logger.info('Starting API call...')

                headers = {
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                }

                self.logger.info('Headers prepared')
                self.logger.info(f'Trying endpoint: {self.endpoint}')

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
                    'max_tokens': max_tokens,
                    'stream': False,
                }

                async with self.session.post(
                    self.endpoint,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
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
                            error='Unexpected response structure',
                        )

                    error_text = await response.text()
                    self.logger.info('Failed to receive API response')
                    self.logger.info(f'HTTP status: {response.status}')
                    if error_text:
                        self.logger.info(f'Error: {error_text[:500]}')

                    # Retry only on rate limits (429) or transient server errors (5xx).
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
                self.logger.info('Failed to receive API response')
                self.logger.info('Error: Request timeout')
                if attempt == self.max_retries - 1:
                    return AIResponse(
                        success=False,
                        content='',
                        error='Request timeout',
                    )
                await asyncio.sleep(2 * (attempt + 1))

            except Exception as e:
                self.logger.info('Failed to receive API response')
                self.logger.info(f'Error: {type(e).__name__}: {e}')
                if attempt == self.max_retries - 1:
                    return AIResponse(
                        success=False,
                        content='',
                        error=str(e),
                    )
                await asyncio.sleep(2 * (attempt + 1))

        return AIResponse(success=False, content='', error='Unknown error')

    async def batch_analyze(self, test_cases: List[Dict], concurrent_requests: int = 2) -> List[AIResponse]:
        """Analyze multiple test cases."""
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
        """Calculate cost for DeepSeek API call."""
        from config.api_config import AIConfig

        config = AIConfig()
        input_cost = (input_tokens / 1000) * config.DEEPSEEK_COST_PER_1K_INPUT
        output_cost = (output_tokens / 1000) * config.DEEPSEEK_COST_PER_1K_OUTPUT
        return input_cost + output_cost

# REFRESH_2026
