"""ChatGPT/OpenAI client for cryptanalysis.

For GPT-5 family models (including `gpt-5-mini`), the recommended API is:
- Endpoint: https://api.openai.com/v1/responses
- SDK call: client.responses.create(...)

This client primarily uses the official OpenAI Python SDK when available, and
falls back to aiohttp-based raw HTTP if needed.

Networking knobs (env vars via config/api_config.py):
- OPENAI_API_STYLE: responses | chat_completions
- OPENAI_PROXY: explicit proxy URL (e.g. http://proxy:8080)
- OPENAI_TRUST_ENV: 1 to honor HTTPS_PROXY/HTTP_PROXY, 0 to ignore
- OPENAI_CONNECT_TIMEOUT: connect timeout seconds
"""

import aiohttp
import asyncio
import os
import socket
import time
from typing import Dict, List, Optional, Tuple

from .base_client import BaseAIClient, AIResponse

try:
    import httpx
    from openai import AsyncOpenAI  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore
    AsyncOpenAI = None  # type: ignore


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _has_proxy_env() -> bool:
    return any(os.getenv(k) for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"))


def _should_use_responses(api_style: str, model: str) -> bool:
    api_style = (api_style or "").strip().lower()
    model = (model or "").strip().lower()
    return api_style == "responses"


class ChatGPTCryptanalyst(BaseAIClient):
    """OpenAI implementation for cryptanalysis."""

    def __init__(self, api_key: str):
        from config.api_config import AIConfig

        super().__init__(api_key, model=AIConfig.CHATGPT_MODEL)

        self.api_style = (getattr(AIConfig, "OPENAI_API_STYLE", "responses") or "responses").strip().lower()

        # Endpoints
        self.responses_endpoint = getattr(
            AIConfig,
            "OPENAI_RESPONSES_ENDPOINT",
            "https://api.openai.com/v1/responses",
        )
        self.chat_completions_endpoint = getattr(
            AIConfig,
            "OPENAI_CHAT_COMPLETIONS_ENDPOINT",
            "https://api.openai.com/v1/chat/completions",
        )

        # For backward compatibility, keep OPENAI_ENDPOINT as the primary configured endpoint.
        # In this repo, OPENAI_ENDPOINT now defaults to /v1/responses.
        self.endpoint = AIConfig.OPENAI_ENDPOINT

        self.requests_per_minute = AIConfig.OPENAI_REQUESTS_PER_MINUTE

        self.proxy = (AIConfig.OPENAI_PROXY or "").strip() or None
        self.trust_env = _truthy(getattr(AIConfig, "OPENAI_TRUST_ENV", "0"))
        self.force_ipv4 = _truthy(AIConfig.OPENAI_FORCE_IPV4)
        self.connect_timeout = int(getattr(AIConfig, "OPENAI_CONNECT_TIMEOUT", 20))
        # OpenAI requests can be slower than other providers for cryptanalysis; allow a dedicated timeout.
        self.timeout = int(getattr(AIConfig, "OPENAI_TIMEOUT", self.timeout))
        self.max_retries = int(getattr(AIConfig, 'OPENAI_MAX_RETRIES', 3))
        self.max_completion_tokens = int(getattr(AIConfig, "OPENAI_MAX_COMPLETION_TOKENS", 4000))
        # For Responses API (GPT-5*), cap output tokens to avoid long generations/timeouts.
        self.max_output_tokens = int(getattr(AIConfig, "OPENAI_MAX_OUTPUT_TOKENS", 800))

        self._openai: Optional[object] = None

    async def __aenter__(self):
        # Prefer official OpenAI SDK when installed.
        if AsyncOpenAI is not None and httpx is not None:
            # Avoid hangs from broken system auto-proxy: control trust_env explicitly.
            timeout = httpx.Timeout(self.timeout, connect=self.connect_timeout)
            if self.proxy:
                http_client = httpx.AsyncClient(timeout=timeout, proxy=self.proxy, trust_env=False)
            else:
                http_client = httpx.AsyncClient(timeout=timeout, trust_env=self.trust_env)

            self._openai = AsyncOpenAI(
                api_key=self.api_key,
                timeout=self.timeout,
                max_retries=self.max_retries,
                http_client=http_client,
            )
            return self

        # Fallback to aiohttp
        connector_kwargs = {
            "ttl_dns_cache": 300,
            "limit": 20,
            "limit_per_host": 10,
        }
        if self.force_ipv4:
            connector_kwargs["family"] = socket.AF_INET
        connector = aiohttp.TCPConnector(**connector_kwargs)

        trust_env = bool(self.proxy) or self.trust_env
        self.session = aiohttp.ClientSession(trust_env=trust_env, connector=connector)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

        if self._openai is not None:
            close_fn = getattr(self._openai, "close", None)
            if callable(close_fn):
                result = close_fn()
                if asyncio.iscoroutine(result):
                    await result


    async def ping(self) -> tuple[bool, str]:
        """Lightweight network preflight.

        This makes a cheap call to the OpenAI Models API to detect:
        - broken proxy/VPN/network
        - invalid credentials
        - region restrictions like `unsupported_country_region_territory`

        Returns (ok, message).
        """

        def classify_error(msg: str) -> tuple[bool, str]:
            m = (msg or '').strip()
            ml = m.lower()
            if 'unsupported_country_region_territory' in ml:
                return False, (
                    'OpenAI rejected this network location: unsupported_country_region_territory. '
                    'Switch your VPN exit node to a supported region (or disable VPN) and retry.'
                )
            if 'status code: 403' in ml or ' 403 ' in ml or 'forbidden' in ml:
                return False, f'Forbidden (403). {m}'
            if 'status code: 401' in ml or ' 401 ' in ml or 'unauthorized' in ml:
                return False, f'Unauthorized (401). Check OPENAI_API_KEY. {m}'
            return False, m or 'Unknown error'

        # Prefer SDK when available, but never hang indefinitely.
        if self._openai is not None:
            PING_SDK_TIMEOUT_S = 20
            try:
                await asyncio.wait_for(self._openai.models.list(), timeout=PING_SDK_TIMEOUT_S)
                return True, 'ok'
            except asyncio.TimeoutError:
                # Fall back to raw HTTP ping below (can succeed even if SDK is stuck).
                pass
            except Exception as e:
                raw = f"{type(e).__name__}: {e}"
                cause = getattr(e, '__cause__', None) or getattr(e, '__context__', None)
                if cause and cause is not e:
                    raw = f"{raw} (cause: {type(cause).__name__}: {cause})"
                ok, msg = classify_error(raw)
                return ok, msg

        # aiohttp fallback
        import aiohttp

        url = 'https://api.openai.com/v1/models'
        headers = {'Authorization': f'Bearer {self.api_key}'}

        session = self.session
        close_after = False
        if session is None:
            connector_kwargs = {"ttl_dns_cache": 300, "limit": 5, "limit_per_host": 5}
            if self.force_ipv4:
                import socket as _socket
                connector_kwargs['family'] = _socket.AF_INET
            connector = aiohttp.TCPConnector(**connector_kwargs)
            trust_env = bool(self.proxy) or self.trust_env
            session = aiohttp.ClientSession(trust_env=trust_env, connector=connector)
            close_after = True

        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=min(30, int(self.timeout) if self.timeout else 30)),
                proxy=(self.proxy or None),
            ) as resp:
                body = await resp.text()
                if resp.status == 200:
                    return True, 'ok'
                ok, msg = classify_error(f'HTTP {resp.status}: {body[:500]}')
                return ok, msg
        except Exception as e:
            raw = f"{type(e).__name__}: {e}"
            cause = getattr(e, '__cause__', None) or getattr(e, '__context__', None)
            if cause and cause is not e:
                raw = f"{raw} (cause: {type(cause).__name__}: {cause})"
            ok, msg = classify_error(raw)
            return ok, msg
        finally:
            if close_after:
                await session.close()

    def _usage_tokens(self, usage_obj, fallback_input: int) -> Tuple[int, int]:
        if usage_obj is None:
            return fallback_input, 0

        def _get(name: str, default=None):
            if isinstance(usage_obj, dict):
                return usage_obj.get(name, default)
            return getattr(usage_obj, name, default)

        input_tokens = _get("input_tokens", None)
        if input_tokens is None:
            input_tokens = _get("prompt_tokens", fallback_input)

        output_tokens = _get("output_tokens", None)
        if output_tokens is None:
            output_tokens = _get("completion_tokens", 0)

        return int(input_tokens or 0), int(output_tokens or 0)

    def _extract_output_text_from_responses_json(self, data: Dict) -> str:
        # Best effort parsing for raw /v1/responses.
        if not isinstance(data, dict):
            return ""
        if isinstance(data.get("output_text"), str) and data["output_text"].strip():
            return data["output_text"].strip()

        output = data.get("output")
        if isinstance(output, list):
            chunks: List[str] = []
            for item in output:
                if not isinstance(item, dict):
                    continue
                content = item.get("content")
                if not isinstance(content, list):
                    continue
                for c in content:
                    if not isinstance(c, dict):
                        continue
                    if c.get("type") in {"output_text", "text"}:
                        t = c.get("text")
                        if isinstance(t, dict) and isinstance(t.get("value"), str):
                            t = t.get("value")
                        if isinstance(t, str):
                            chunks.append(t)
            return "\n".join([c for c in chunks if c])

        return ""
    def _extract_output_text_from_sdk_response(self, response: object) -> str:
        """Best-effort output_text extraction from OpenAI SDK Responses objects.

        The SDK returns rich objects (not plain dicts). This method supports both.
        """

        def _get(obj: object, name: str, default=None):
            if isinstance(obj, dict):
                return obj.get(name, default)
            return getattr(obj, name, default)

        output_text = _get(response, "output_text", None)
        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()

        output = _get(response, "output", None)
        if isinstance(output, list):
            chunks: list[str] = []
            for item in output:
                content = _get(item, "content", None)
                if not isinstance(content, list):
                    continue
                for c in content:
                    c_type = _get(c, "type", None)
                    text = _get(c, "text", None)
                    if not isinstance(text, str) and text is not None:
                        # SDK sometimes returns a rich text object/dict (e.g., {"value": "..."}).
                        if isinstance(text, dict) and isinstance(text.get('value'), str):
                            text = text.get('value')
                        else:
                            v = getattr(text, 'value', None)
                            if isinstance(v, str):
                                text = v
                    if c_type in {"output_text", "text"} and isinstance(text, str):
                        chunks.append(text)

            joined = "\n".join([c for c in chunks if c]).strip()
            if joined:
                return joined

        return ""


    async def analyze_ciphertext(self, encrypted_data: Dict, context: Dict = None) -> AIResponse:
        start_time = time.time()

        for attempt in range(self.max_retries):
            try:
                prompt_type = 'hidden' if context and context.get('algorithm_hidden', False) else 'informed'
                prompt = self._create_cryptanalysis_prompt(encrypted_data, context, prompt_type)
                input_tokens_est = self._estimate_tokens(prompt)

                self.logger.info('Starting API call...')
                self.logger.info('Headers prepared')

                await self._throttle()

                system_text = (
                    'You are an expert cryptanalyst specialized in analyzing encrypted data and '
                    'identifying cryptographic vulnerabilities. Provide your analysis in valid JSON format.'
                )

                use_responses = _should_use_responses(self.api_style, self.model)

                mission = None
                if context:
                    tc = context.get('test_case') or {}
                    mission = context.get('mission') or (tc.get('mission') if isinstance(tc, dict) else None)

                algorithm_hidden = bool(context and context.get('algorithm_hidden', False))

                # Keep plaintext-recovery outputs short and cheap; allow algorithm_hidden enough budget to return valid JSON.
                if mission == 'plaintext_recovery':
                    max_output_tokens = 800
                    max_completion_tokens = 800
                else:
                    max_output_tokens = max(self.max_output_tokens, 1400) if algorithm_hidden else self.max_output_tokens
                    max_completion_tokens = self.max_completion_tokens


                # OpenAI SDK path
                if self._openai is not None:
                    if use_responses:
                        self.logger.info(f'Trying endpoint: {self.responses_endpoint}')
                        input_text = f"{system_text}\n\n{prompt}\n\nReturn ONLY a single JSON object matching the RESPONSE FORMAT in the prompt. Include ALL keys. Choose identified_algorithm and identified_category from the provided lists (do not use unknown). Keep reasoning_steps <= 6 (one short sentence each). Keep suggested_attacks and vulnerabilities_found high-level and non-actionable. Follow the DECRYPTION_ATTEMPT RULE in the prompt. Return a single minified JSON object (no markdown, no code fences). Do not output 'unknown' for identified_algorithm/identified_category."

                        response = await getattr(self._openai, 'responses').create(
                            model=self.model,
                            input=input_text,
                            max_output_tokens=max_output_tokens,
                            timeout=self.timeout,
                            text={'format': {'type': 'json_object'}, 'verbosity': 'low'},
                            reasoning={'effort': 'low'},
                        )

                        response_text = self._extract_output_text_from_sdk_response(response)
                        usage = getattr(response, 'usage', None)
                        in_tok, out_tok = self._usage_tokens(usage, input_tokens_est)

                        parsed_data = self._parse_response(response_text)
                        self.logger.info('Successful API response received')
                        return AIResponse(
                            success=True,
                            content=response_text,
                            input_tokens=in_tok,
                            output_tokens=out_tok,
                            parsed_data=parsed_data,
                        )

                    # Legacy: chat.completions
                    self.logger.info(f'Trying endpoint: {self.chat_completions_endpoint}')
                    response = await getattr(self._openai, 'chat').completions.create(
                        model=self.model,
                        messages=[
                            {'role': 'system', 'content': system_text},
                            {'role': 'user', 'content': prompt},
                        ],
                        max_completion_tokens=max_completion_tokens,
                        response_format={'type': 'json_object'},
                        timeout=self.timeout,
                    )

                    response_text = response.choices[0].message.content
                    usage = getattr(response, 'usage', None)
                    in_tok, out_tok = self._usage_tokens(usage, input_tokens_est)

                    parsed_data = self._parse_response(response_text)
                    self.logger.info('Successful API response received')
                    return AIResponse(
                        success=True,
                        content=response_text,
                        input_tokens=in_tok,
                        output_tokens=out_tok,
                        parsed_data=parsed_data,
                    )

                # aiohttp fallback
                headers = {
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json',
                }

                timeout = aiohttp.ClientTimeout(
                    total=self.timeout,
                    connect=min(self.connect_timeout, self.timeout),
                    sock_connect=min(self.connect_timeout, self.timeout),
                    sock_read=self.timeout,
                )

                if use_responses:
                    self.logger.info(f'Trying endpoint: {self.responses_endpoint}')
                    input_text = f"{system_text}\n\n{prompt}\n\nReturn ONLY a single JSON object matching the RESPONSE FORMAT in the prompt. Include ALL keys. Choose identified_algorithm and identified_category from the provided lists (do not use unknown). Keep reasoning_steps <= 6 (one short sentence each). Keep suggested_attacks and vulnerabilities_found high-level and non-actionable. Follow the DECRYPTION_ATTEMPT RULE in the prompt. Return a single minified JSON object (no markdown, no code fences). Do not output 'unknown' for identified_algorithm/identified_category."
                    payload = {'model': self.model, 'input': input_text, 'max_output_tokens': max_output_tokens, 'text': {'format': {'type': 'json_object'}, 'verbosity': 'low'}, 'reasoning': {'effort': 'low'}}
                    url = self.responses_endpoint
                else:
                    self.logger.info(f'Trying endpoint: {self.chat_completions_endpoint}')
                    payload = {
                        'model': self.model,
                        'messages': [
                            {'role': 'system', 'content': system_text},
                            {'role': 'user', 'content': prompt},
                        ],
                        'max_completion_tokens': max_completion_tokens,
                        'response_format': {'type': 'json_object'},
                    }
                    url = self.chat_completions_endpoint

                request_kwargs = {'headers': headers, 'json': payload, 'timeout': timeout}
                if self.proxy:
                    request_kwargs['proxy'] = self.proxy

                async with self.session.post(url, **request_kwargs) as response:
                    if response.status == 200:
                        data = await response.json()

                        if use_responses:
                            response_text = self._extract_output_text_from_responses_json(data)
                        else:
                            response_text = data['choices'][0]['message']['content']

                        usage = data.get('usage') if isinstance(data, dict) else None
                        in_tok, out_tok = self._usage_tokens(usage, input_tokens_est)

                        parsed_data = self._parse_response(response_text)
                        self.logger.info('Successful API response received')
                        return AIResponse(
                            success=True,
                            content=response_text,
                            input_tokens=in_tok,
                            output_tokens=out_tok,
                            parsed_data=parsed_data,
                        )

                    error_text = await response.text()
                    self.logger.info('Failed to receive API response')
                    self.logger.info(f'HTTP status: {response.status}')
                    if error_text:
                        self.logger.info(f'Error: {error_text[:500]}')

                    should_retry = response.status == 429 or response.status >= 500
                    if (not should_retry) or (attempt == self.max_retries - 1):
                        return AIResponse(
                            success=False,
                            content='',
                            error=f'API error {response.status}: {error_text}',
                        )

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
                    hint = (
                        'If this is a ConnectTimeout/ClientConnectorError, your network likely blocks outbound '
                        'connections to api.openai.com:443. Set OPENAI_PROXY or HTTPS_PROXY if you need a proxy.'
                    )
                    return AIResponse(
                        success=False,
                        content='',
                        error=f'{e} | {hint}',
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
        input_cost = (input_tokens / 1000) * config.OPENAI_COST_PER_1K_INPUT
        output_cost = (output_tokens / 1000) * config.OPENAI_COST_PER_1K_OUTPUT
        return input_cost + output_cost








# REFRESH_2026
