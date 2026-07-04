"""Base abstract class for all AI cryptanalysis clients."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class AIResponse:
    """Container for AI API responses."""

    success: bool
    content: str
    input_tokens: int = 0
    output_tokens: int = 0
    error: Optional[str] = None
    parsed_data: Optional[Dict[str, Any]] = None


class BaseAIClient(ABC):
    """Abstract base class for all AI cryptanalysis clients."""

    def __init__(self, api_key: str, model: str | None = None):
        self.api_key = api_key
        self.model = model

        # Defaults; overridden by config if available
        self.timeout = 45
        self.max_retries = 3

        # Optional per-provider throttling (requests per minute)
        self.requests_per_minute: int | None = None
        self._rate_limit_lock = asyncio.Lock()
        self._next_allowed_time = 0.0

        self.session = None

        # Shared console logging (matches the user's desired format)
        # NOTE: basicConfig only applies once per process; safe to call here.
        log_level_name = os.getenv("AI_LOG_LEVEL", "INFO").upper()
        log_level = getattr(logging, log_level_name, logging.INFO)
        logging.basicConfig(
            level=log_level,
            format='%(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stderr)],
            force=True,
        )
        self.logger = logging.getLogger(self.__class__.__name__)

        # Pull shared retry/timeout defaults from config if present.
        try:
            from config.api_config import AIConfig

            self.timeout = int(getattr(AIConfig, 'TIMEOUT', self.timeout))
            self.max_retries = int(getattr(AIConfig, 'MAX_RETRIES', self.max_retries))
        except Exception:
            # Keep safe defaults if config isn't available.
            pass

    @abstractmethod
    async def __aenter__(self):
        """Async context manager entry."""
        raise NotImplementedError

    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        raise NotImplementedError

    @abstractmethod
    async def analyze_ciphertext(self, encrypted_data: Dict[str, Any], context: Dict[str, Any] | None = None) -> AIResponse:
        """Analyze encrypted data with AI."""
        raise NotImplementedError

    @abstractmethod
    async def batch_analyze(self, test_cases: List[Dict[str, Any]], concurrent_requests: int = 2) -> List[AIResponse]:
        """Analyze multiple test cases."""
        raise NotImplementedError

    async def _throttle(self) -> None:
        """Enforce a simple per-client requests-per-minute throttle.

        Many API keys (especially free-tier) are limited to very low RPM.
        Runner scripts may batch quickly; this prevents repeated 429 failures.
        """
        rpm = self.requests_per_minute
        if not rpm or rpm <= 0:
            return

        interval = 60.0 / float(rpm)
        async with self._rate_limit_lock:
            now = time.monotonic()
            if now < self._next_allowed_time:
                await asyncio.sleep(self._next_allowed_time - now)
                now = time.monotonic()
            self._next_allowed_time = max(now, self._next_allowed_time) + interval

    def validate_api_key(self) -> bool:
        """Lightweight API key format check (does not call the provider)."""
        return bool(self.api_key) and len(self.api_key) > 10
    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """Parse JSON response from AI.

        Robust against common model-output issues:
        - leading/trailing text around JSON
        - markdown code fences
        - multiple JSON objects (keeps the first decodable object)
        """
        cleaned_text = (response_text or "").strip()


        # Normalize decryption_attempt: it must be plaintext-only (or empty).
        # If the model outputs refusals/explanations here, move that text into further_analysis and blank it.
        refusal_re = re.compile(
            r"\b(unable|cannot|can't|not possible|infeasible|without (?:the )?(?:key|private key))\b",
            re.IGNORECASE,
        )

        def _sanitize_decryption_attempt(obj: Dict[str, Any]) -> Dict[str, Any]:
            attempt = obj.get('decryption_attempt', '')
            if attempt is None:
                attempt = ''
            if not isinstance(attempt, str):
                attempt = str(attempt)

            # If attempt is a JSON object string (e.g. {"guessed_plaintext": "..."}), extract guessed_plaintext.
            candidate = attempt.strip()
            # If missing/empty, normalize to a standard non-empty sentence.
            if not candidate:
                obj['decryption_attempt'] = 'Plaintext not recovered; see further_analysis.'
                fa = obj.get('further_analysis', [])
                if not isinstance(fa, list):
                    fa = [str(fa)]
                fa.append('No decryption_attempt provided (empty).')
                obj['further_analysis'] = fa
                return obj


            # Strip common prefixes like "Guess:".
            for prefix in ("guess:", "guessed:", "guessed plaintext:", "plaintext:", "decryption_attempt:"):
                if candidate.lower().startswith(prefix):
                    candidate = candidate[len(prefix):].strip()
                    break

            # Handle JSON-encoded strings ("{...}")
            if candidate.startswith('"') and candidate.endswith('"'):
                try:
                    candidate = __import__('json').loads(candidate)
                except Exception:
                    pass

            parsed_json = None

            # candidate may be a JSON object/array string
            if isinstance(candidate, str) and ((candidate.startswith('{') and candidate.endswith('}')) or (candidate.startswith('[') and candidate.endswith(']'))):
                try:
                    parsed_json = __import__('json').loads(candidate)
                except Exception:
                    parsed_json = None

            # If attempt is a JSON wrapper like {"guessed_plaintext": "..."}, extract the plaintext.
            if isinstance(parsed_json, dict) and isinstance(parsed_json.get('guessed_plaintext'), str):
                attempt = parsed_json['guessed_plaintext'].strip()
                obj['decryption_attempt'] = attempt

            # If attempt is structured JSON (dict/list) without a guessed_plaintext wrapper,
            # treat it as "not recovered" to avoid escaped-JSON noise in raw results.
            elif isinstance(parsed_json, (dict, list)):
                note = f"Model returned JSON-like decryption_attempt (ignored): {candidate}"
                obj['decryption_attempt'] = 'Plaintext not recovered; see further_analysis.'

                fa = obj.get('further_analysis', [])
                if not isinstance(fa, list):
                    fa = [str(fa)]
                if note and (not fa or fa[-1] != note):
                    fa.append(note)
                obj['further_analysis'] = fa

                attempt = obj['decryption_attempt']

            attempt_lower = attempt.lower()

            # Avoid false positives: only treat this as a refusal if it is explicitly about decryption.
            if 'decrypt' not in attempt_lower and 'decryption' not in attempt_lower:
                return obj

            if refusal_re.search(attempt):
                note = attempt.strip()
                # Keep decryption_attempt non-empty to reflect an attempt, while moving refusal/explanation text.
                obj['decryption_attempt'] = 'Plaintext not recovered; see further_analysis.'

                fa = obj.get('further_analysis', [])
                if not isinstance(fa, list):
                    fa = [str(fa)]
                if note:
                    fa.append(note)
                obj['further_analysis'] = fa

            return obj

        def _apply_defaults(obj: Any) -> Dict[str, Any]:
            if not isinstance(obj, dict):
                return {
                    'identified_algorithm': 'unknown',
                    'identified_category': 'unknown',
                    'identified_confidence': 0.5,
                    'estimated_parameters': {},
                    'suggested_attacks': [],
                    'decryption_attempt': 'Plaintext not recovered; see further_analysis.',
                    'confidence_score': 0.5,
                    'reasoning_steps': ['Response parsing failed'],
                    'vulnerabilities_found': [],
                    'further_analysis': ['Parsed JSON is not an object'],
                    'security_assessment': 'medium',
                    'parse_success': False,
                }

            # Ensure required fields (both informed + hidden evaluators tolerate extras)
            # NOTE: For schema parity with DeepSeek raw results, we do not persist the raw model text here.
            obj.setdefault('identified_algorithm', 'unknown')
            obj.setdefault('identified_category', 'unknown')
            if "identified_confidence" in obj and "confidence_score" not in obj:
                obj["confidence_score"] = obj.get("identified_confidence", 0.5)
            if "confidence_score" in obj and "identified_confidence" not in obj:
                obj["identified_confidence"] = obj.get("confidence_score", 0.5)
            obj.setdefault('estimated_parameters', {})
            obj.setdefault('suggested_attacks', [])
            obj.setdefault('decryption_attempt', '')
            obj.setdefault('confidence_score', 0.5)
            obj.setdefault('reasoning_steps', [])
            obj.setdefault('vulnerabilities_found', [])
            obj.setdefault('further_analysis', [])
            obj.setdefault('security_assessment', 'medium')
            obj['parse_success'] = True
            obj = _sanitize_decryption_attempt(obj)

            # Schema parity: keep only DeepSeek-standard fields.
            # Some models emit extra keys (e.g., key_size/mode/vulnerabilities); drop them here.
            if 'vulnerabilities' in obj and not obj.get('vulnerabilities_found'):
                v = obj.get('vulnerabilities')
                if isinstance(v, list):
                    obj['vulnerabilities_found'] = v

            allowed_keys = [
                'identified_algorithm',
                'identified_category',
                'identified_confidence',
                'estimated_parameters',
                'suggested_attacks',
                'decryption_attempt',
                'confidence_score',
                'reasoning_steps',
                'vulnerabilities_found',
                'further_analysis',
                'security_assessment',
                'parse_success',
            ]
            return {k: obj.get(k) for k in allowed_keys}

        # If the model wrapped JSON in a fenced code block, prefer the first fenced section containing '{'.
        if '```' in cleaned_text:
            parts = cleaned_text.split('```')
            fenced_candidates = [p for p in parts if '{' in p]
            if fenced_candidates:
                candidate = fenced_candidates[0].strip()
                # Strip an optional language tag line (e.g., "json\n{...}")
                if candidate.lower().startswith('json'):
                    candidate = candidate[4:].lstrip()
                cleaned_text = candidate

        # Fast path: exact JSON
        try:
            return _apply_defaults(json.loads(cleaned_text))
        except Exception:
            pass

        # Robust path: scan for the first JSON object and decode it (ignores trailing text)
        decoder = json.JSONDecoder()
        for m in re.finditer(r'\{', cleaned_text):
            try:
                obj, _end = decoder.raw_decode(cleaned_text[m.start():])
                return _apply_defaults(obj)
            except Exception:
                continue

        return {
            'identified_algorithm': 'unknown',
            'identified_category': 'unknown',
            'identified_confidence': 0.5,
            'estimated_parameters': {},
            'suggested_attacks': [],
            'decryption_attempt': 'Plaintext not recovered; see further_analysis.',
            'confidence_score': 0.5,
            'reasoning_steps': ['Response parsing failed'],
            'vulnerabilities_found': [],
            'further_analysis': [],
            'security_assessment': 'medium',
            'parse_success': False,
        }

    def _create_cryptanalysis_prompt(self, encrypted_data: Dict[str, Any], context: Dict[str, Any] | None = None, prompt_type: str = 'informed') -> str:
        """Create a prompt for cryptanalysis.

        Important: runner scripts add the repo's `src/` to `sys.path`, so imports must be top-level
        (e.g. `analysis_prompts.*`) rather than parent-relative imports.
        """
        # Mission-specific prompt family (plaintext recovery benchmark)
        mission = None
        if context:
            mission = context.get('mission')
            if not mission:
                tc = context.get('test_case') or {}
                if isinstance(tc, dict):
                    mission = tc.get('mission')
        if mission == 'plaintext_recovery':
            from analysis_prompts.plaintext_recovery_prompts import PlaintextRecoveryPrompts

            pm = PlaintextRecoveryPrompts()
            if prompt_type == 'hidden':
                return pm.create_hidden_prompt(encrypted_data, context)
            return pm.create_informed_prompt(encrypted_data, context)

        if prompt_type == 'hidden':
            from analysis_prompts.algorithm_hidden_analysis_prompts import AlgorithmHiddenAnalysisPrompts

            prompt_maker = AlgorithmHiddenAnalysisPrompts()
            return prompt_maker.create_algorithm_hidden_prompt(encrypted_data, context)

        from analysis_prompts.algorithm_informed_cryptanalysis_prompts import CryptanalysisPrompts
        prompt_maker = CryptanalysisPrompts()
        return prompt_maker.create_informed_prompt(encrypted_data, context)

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (approximate)."""
        return len(text) // 4

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for API call (override in concrete clients)."""
        return 0.0


__all__ = ["AIResponse", "BaseAIClient"]


