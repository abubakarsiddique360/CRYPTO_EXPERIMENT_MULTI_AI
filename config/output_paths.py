"""Utilities for consistent results output paths.

All experiment runner scripts should save artifacts under:
  data/results/{platform}/{condition}/{topic}/

Where:
- platform: deepseek | chatgpt | gemini | grok
- condition: algorithm_hidden | algorithm_informed
- topic: experiment_summary | raw_results | charts | tables | logs | comparisons | etc.

You can override the root with CRYPTO_RESULTS_ROOT.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional


def project_root() -> Path:
    """Resolve the repository root reliably from this file location."""
    return Path(__file__).resolve().parent.parent


def results_root() -> Path:
    override = os.getenv("CRYPTO_RESULTS_ROOT")
    if override:
        return Path(override)
    return project_root() / "data" / "results"


def _slug(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "unknown"


def normalize_platform(platform: str) -> str:
    platform = (platform or "").strip().lower()
    platform = platform.replace("openai", "chatgpt")
    return _slug(platform)


def normalize_condition(condition: str) -> str:
    condition = (condition or "").strip().lower()

    aliases = {
        "hidden": "algorithm_hidden",
        "algorithm_hidden": "algorithm_hidden",
        "algorithm-hidden": "algorithm_hidden",
        "algorithm_hidden_experiment": "algorithm_hidden",
        "informed": "algorithm_informed",
        "informed_algorithm": "algorithm_informed",
        "algorithm_informed": "algorithm_informed",
        "algorithm-informed": "algorithm_informed",
    }

    return aliases.get(condition, _slug(condition))


def results_dir(platform: str, condition: str, topic: Optional[str] = None) -> Path:
    """Return a directory for results, creating it if needed."""
    platform = normalize_platform(platform)
    condition = normalize_condition(condition)

    base = results_root() / platform / condition
    if topic:
        base = base / _slug(topic)

    base.mkdir(parents=True, exist_ok=True)
    return base



def platform_results_dir(platform: str, topic: Optional[str] = None) -> Path:
    """Return a platform-level results directory, creating it if needed.

    This supports flat artifact paths like:
      data/results/{platform}/algorithm_hidden_performance_by_algorithm_{timestamp}.html

    Use this for user-facing artifacts (charts/tables/CSV) when you don't want
    nested condition/topic folders.
    """
    platform = normalize_platform(platform)

    base = results_root() / platform
    if topic:
        base = base / _slug(topic)

    base.mkdir(parents=True, exist_ok=True)
    return base


def platform_artifact_path(*, platform: str, filename: str, topic: Optional[str] = None) -> Path:
    """Create a full artifact path under the platform-level results directory."""
    return platform_results_dir(platform, topic) / filename


def artifact_path(
    *,
    platform: str,
    condition: str,
    topic: str,
    filename: str,
) -> Path:
    """Create a full artifact path under the standardized results tree."""
    out_dir = results_dir(platform, condition, topic)
    return out_dir / filename

# REFRESH_2026
