"""API Configuration for all AI models in Multi-AI Cryptanalysis Experiment.

Model names can be overridden via environment variables:
- DEEPSEEK_MODEL
- CHATGPT_MODEL
- GEMINI_MODEL
- GROK_MODEL

This repo is configured for the experiment versions:
- OpenAI: gpt-5-mini (override via CHATGPT_MODEL)
- xAI: Grok 4.1
- Google: Gemini 3 Flash
- DeepSeek: deepseek-chat (override via DEEPSEEK_MODEL)
"""

import os
from pathlib import Path

# Load .env early so class-level os.getenv defaults reflect local settings.
# NOTE: python-dotenv won't override env vars by default. On Windows it's common
# to have an env var defined but empty, which would otherwise mask the real value
# in .env. We therefore *fill empty* env vars from .env without overriding any
# non-empty environment variables.
try:
    from dotenv import dotenv_values, load_dotenv

    _ROOT = Path(__file__).resolve().parent.parent
    _ENV_PATH = _ROOT / ".env"
    load_dotenv(_ENV_PATH, override=False)

    for _k, _v in (dotenv_values(_ENV_PATH) or {}).items():
        if _v is None:
            continue
        if (os.getenv(_k) or "").strip() == "" and str(_v).strip() != "":
            os.environ[_k] = str(_v)
except Exception:
    pass
from dataclasses import dataclass


@dataclass
class AIConfig:
    """Configuration for all AI APIs"""

    # API Keys (set via environment variables)
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GROK_API_KEY: str = os.getenv("GROK_API_KEY", "")

    # Model Names (defaults for this experiment)
    DEEPSEEK_MODEL: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    CHATGPT_MODEL: str = os.getenv("CHATGPT_MODEL", "gpt-5-mini")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    GROK_MODEL: str = os.getenv("GROK_MODEL", "grok-4-1-fast-reasoning")

    # API Endpoints
    DEEPSEEK_ENDPOINT: str = os.getenv("DEEPSEEK_ENDPOINT", "https://api.deepseek.com/chat/completions")
    OPENAI_ENDPOINT: str = os.getenv("OPENAI_ENDPOINT", "https://api.openai.com/v1/responses")

    # OpenAI API style: "chat_completions" (default) or "responses" (official newer API)
    OPENAI_API_STYLE: str = os.getenv("OPENAI_API_STYLE", "responses")

    # OpenAI Responses endpoint (used by SDK / optional fallbacks)
    OPENAI_RESPONSES_ENDPOINT: str = os.getenv("OPENAI_RESPONSES_ENDPOINT", "https://api.openai.com/v1/responses")

    # Legacy Chat Completions endpoint (kept for older models / back-compat)
    OPENAI_CHAT_COMPLETIONS_ENDPOINT: str = os.getenv("OPENAI_CHAT_COMPLETIONS_ENDPOINT", "https://api.openai.com/v1/chat/completions")


    # Optional: explicit proxy for OpenAI calls. If empty, proxy is taken from HTTPS_PROXY/HTTP_PROXY when enabled.
    OPENAI_PROXY: str = os.getenv("OPENAI_PROXY", "")

    # Optional: explicit proxy for Gemini calls. Defaults to OPENAI_PROXY if set.
    GEMINI_PROXY: str = (os.getenv("GEMINI_PROXY", "").strip() or os.getenv("OPENAI_PROXY", "").strip())

    # Whether to honor system proxy environment variables (HTTPS_PROXY/HTTP_PROXY) for Gemini.
    GEMINI_TRUST_ENV: str = os.getenv("GEMINI_TRUST_ENV", "0")

    # Optional: explicit proxy for Grok calls. Defaults to OPENAI_PROXY if set.
    GROK_PROXY: str = os.getenv("GROK_PROXY", "")

    # Whether to honor system proxy environment variables (HTTPS_PROXY/HTTP_PROXY) for Grok.
    # Default is off for the same reason as OpenAI_TRUST_ENV.
    GROK_TRUST_ENV: str = os.getenv("GROK_TRUST_ENV", "0")
    # Whether to honor system proxy environment variables (HTTPS_PROXY/HTTP_PROXY).
    # Default is off because some Windows environments have broken auto-proxy settings that cause hangs.
    OPENAI_TRUST_ENV: str = os.getenv("OPENAI_TRUST_ENV", "0")


    # Optional: force IPv4 for OpenAI. Helps on some Windows networks where IPv6 routing is broken.
    OPENAI_FORCE_IPV4: str = os.getenv("OPENAI_FORCE_IPV4", "1" if os.name == 'nt' else "0")

    # Optional: connect timeout (seconds) for OpenAI.
    OPENAI_CONNECT_TIMEOUT: int = int(os.getenv("OPENAI_CONNECT_TIMEOUT", "20"))

    # Optional: total request timeout (seconds) for OpenAI.
    # Cryptanalysis prompts can be slow; default is higher than the global TIMEOUT.
    OPENAI_TIMEOUT: int = int(os.getenv("OPENAI_TIMEOUT", "300"))
    OPENAI_MAX_RETRIES: int = int(os.getenv("OPENAI_MAX_RETRIES", "3"))

    # Optional: cap output tokens for OpenAI Responses API to avoid long/hanging generations.
    OPENAI_MAX_OUTPUT_TOKENS: int = int(os.getenv("OPENAI_MAX_OUTPUT_TOKENS", "1600"))

    # Optional: max output tokens for OpenAI Chat Completions requests.
    OPENAI_MAX_COMPLETION_TOKENS: int = int(os.getenv("OPENAI_MAX_COMPLETION_TOKENS", "4000"))

    # Optional: cap output tokens for Gemini responses
    GEMINI_MAX_OUTPUT_TOKENS: int = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "800"))

    # Optional: total request timeout (seconds) for Gemini.
    GEMINI_TIMEOUT: int = int(os.getenv("GEMINI_TIMEOUT", os.getenv("TIMEOUT", "45")))

    # Optional: cap output tokens for Grok responses
    GROK_MAX_TOKENS: int = int(os.getenv("GROK_MAX_TOKENS", "800"))

    # Optional: cap retries for Grok to avoid runaway request amplification (e.g., 900 tests * 3 retries).
    GROK_MAX_RETRIES: int = int(os.getenv("GROK_MAX_RETRIES", "1"))

    # Gemini endpoint includes the model name in the URL.
    GEMINI_ENDPOINT: str = os.getenv(
        "GEMINI_ENDPOINT",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
    )

    GROK_ENDPOINT: str = os.getenv("GROK_ENDPOINT", "https://api.x.ai/v1/chat/completions")

    # Cost per 1000 tokens (USD). Defaults tuned for common low-cost tiers; override via env vars as needed.
    DEEPSEEK_COST_PER_1K_INPUT: float = float(os.getenv("DEEPSEEK_COST_PER_1K_INPUT", "0.00014"))
    DEEPSEEK_COST_PER_1K_OUTPUT: float = float(os.getenv("DEEPSEEK_COST_PER_1K_OUTPUT", "0.00028"))
    OPENAI_COST_PER_1K_INPUT: float = float(os.getenv("OPENAI_COST_PER_1K_INPUT", "0.01"))
    OPENAI_COST_PER_1K_OUTPUT: float = float(os.getenv("OPENAI_COST_PER_1K_OUTPUT", "0.03"))
    GEMINI_COST_PER_1K_INPUT: float = float(os.getenv("GEMINI_COST_PER_1K_INPUT", "0.000125"))
    GEMINI_COST_PER_1K_OUTPUT: float = float(os.getenv("GEMINI_COST_PER_1K_OUTPUT", "0.000375"))
    GROK_COST_PER_1K_INPUT: float = float(os.getenv("GROK_COST_PER_1K_INPUT", "0.0002"))
    GROK_COST_PER_1K_OUTPUT: float = float(os.getenv("GROK_COST_PER_1K_OUTPUT", "0.0005"))

    # Rate Limiting
    # Global defaults (legacy); per-provider overrides are preferred.
    REQUESTS_PER_MINUTE: int = int(os.getenv("REQUESTS_PER_MINUTE", "30"))

    # Per-provider request limits (RPM)
    # NOTE: many OpenAI trial keys are limited (e.g., 3 RPM).
    OPENAI_REQUESTS_PER_MINUTE: int = int(os.getenv("OPENAI_REQUESTS_PER_MINUTE", "3"))
    DEEPSEEK_REQUESTS_PER_MINUTE: int = int(os.getenv("DEEPSEEK_REQUESTS_PER_MINUTE", str(REQUESTS_PER_MINUTE)))
    GEMINI_REQUESTS_PER_MINUTE: int = int(os.getenv("GEMINI_REQUESTS_PER_MINUTE", str(REQUESTS_PER_MINUTE)))
    GROK_REQUESTS_PER_MINUTE: int = int(os.getenv("GROK_REQUESTS_PER_MINUTE", str(REQUESTS_PER_MINUTE)))

    BATCH_DELAY: float = float(os.getenv("BATCH_DELAY", "2.0"))
    MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
    TIMEOUT: int = int(os.getenv("TIMEOUT", "45"))

    # Optional: total request timeout (seconds) for Grok.
    GROK_TIMEOUT: int = int(os.getenv("GROK_TIMEOUT", str(TIMEOUT)))

    # Experiment Settings
    DEFAULT_CONCURRENT_REQUESTS: int = int(os.getenv("DEFAULT_CONCURRENT_REQUESTS", "2"))
    DEFAULT_BATCH_SIZE: int = int(os.getenv("DEFAULT_BATCH_SIZE", "20"))

    @classmethod
    def validate_all_keys(cls) -> list:
        """Validate all API keys are present, return missing keys"""
        missing = []
        config = cls()

        if not config.DEEPSEEK_API_KEY:
            missing.append("DEEPSEEK_API_KEY")
        if not config.OPENAI_API_KEY:
            missing.append("OPENAI_API_KEY")
        if not config.GEMINI_API_KEY:
            missing.append("GEMINI_API_KEY")
        if not config.GROK_API_KEY:
            missing.append("GROK_API_KEY")

        return missing

    @classmethod
    def get_model_cost(cls, model_name: str) -> dict:
        """Get cost structure for specific model"""
        costs = {
            "deepseek": {
                "input": cls.DEEPSEEK_COST_PER_1K_INPUT,
                "output": cls.DEEPSEEK_COST_PER_1K_OUTPUT,
                "model": cls.DEEPSEEK_MODEL,
            },
            "chatgpt": {
                "input": cls.OPENAI_COST_PER_1K_INPUT,
                "output": cls.OPENAI_COST_PER_1K_OUTPUT,
                "model": cls.CHATGPT_MODEL,
            },
            "gemini": {
                "input": cls.GEMINI_COST_PER_1K_INPUT,
                "output": cls.GEMINI_COST_PER_1K_OUTPUT,
                "model": cls.GEMINI_MODEL,
            },
            "grok": {
                "input": cls.GROK_COST_PER_1K_INPUT,
                "output": cls.GROK_COST_PER_1K_OUTPUT,
                "model": cls.GROK_MODEL,
            },
        }

        return costs.get((model_name or "").lower(), {})

    @classmethod
    def get_endpoint(cls, model_name: str) -> str:
        """Get API endpoint for specific model"""
        endpoints = {
            "deepseek": cls.DEEPSEEK_ENDPOINT,
            "chatgpt": cls.OPENAI_ENDPOINT,
            "gemini": cls.GEMINI_ENDPOINT,
            "grok": cls.GROK_ENDPOINT,
        }

        return endpoints.get((model_name or "").lower(), "")








# REFRESH_2026
