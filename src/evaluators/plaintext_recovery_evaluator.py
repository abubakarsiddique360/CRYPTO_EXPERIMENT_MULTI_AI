"""Evaluator for plaintext-recovery mission.

This mission is intentionally scored primarily by plaintext recovery.
We still emit the same evaluation keys used by existing visualization/table code.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict


_STOP_WORDS = set(
    "the a an and or but if then else to of in on for with as at by from into is are was were be been being "
    "it this that these those i you he she we they them my your our their not no yes can could should would "
    "will just very also only such"
    .split()
)


def _meaningful_tokens(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", (text or "").lower())
    return [t for t in tokens if len(t) >= 4 and t not in _STOP_WORDS]


def plaintext_recovery_score(attempt: str, plaintext: str) -> float:
    """Return fraction of meaningful plaintext tokens recovered by attempt."""
    if not attempt or not plaintext:
        return 0.0

    if attempt.strip() == plaintext.strip():
        return 1.0

    actual_tokens = _meaningful_tokens(plaintext)
    attempt_tokens = _meaningful_tokens(attempt)
    if not actual_tokens or not attempt_tokens:
        return 0.0

    actual_counts = Counter(actual_tokens)
    attempt_counts = Counter(attempt_tokens)
    common = sum(min(actual_counts[w], attempt_counts.get(w, 0)) for w in actual_counts)
    total = sum(actual_counts.values())
    return (common / total) if total else 0.0


def _len_based_score(n: int) -> float:
    """Map a non-negative count to a stable 0..1 score.

    Used to avoid constant zeros for vulnerability/reasoning fields while keeping
    plaintext recovery as the primary signal.

    0 -> 0.0
    1 -> 0.3
    2 -> 0.6
    3 -> 0.8
    >=4 -> 1.0
    """
    n = int(n or 0)
    if n <= 0:
        return 0.0
    if n >= 4:
        return 1.0
    if n >= 3:
        return 0.8
    if n >= 2:
        return 0.6
    return 0.3


class PlaintextRecoveryEvaluator:
    def evaluate(self, ai_response: Any, test_case: Dict[str, Any]) -> Dict[str, Any]:
        evaluation: Dict[str, Any] = {
            "test_id": test_case.get("test_id", ""),
            "algorithm": test_case.get("algorithm", "unknown"),
            "difficulty": test_case.get("difficulty", "unknown"),
            "category": test_case.get("category", "unknown"),
            "response_success": bool(getattr(ai_response, "success", False)),
            "error": getattr(ai_response, "error", None),
        }

        if not evaluation["response_success"]:
            evaluation.update(
                {
                    "overall_score": 0.0,
                    "vulnerability_detection_score": 0.0,
                    "decryption_success_score": 0.0,
                    "reasoning_quality_score": 0.0,
                    "confidence_calibration_score": 0.0,
                    "confidence_score": 0.0,
                    "evaluation_notes": ["API call failed"],
                }
            )
            return evaluation

        parsed = getattr(ai_response, "parsed_data", None) or {}
        attempt = parsed.get("decryption_attempt", "") or ""
        plaintext = test_case.get("plaintext", "") or ""

        dec = float(plaintext_recovery_score(attempt, plaintext))

        vulnerabilities = parsed.get("vulnerabilities_found", []) or []
        reasoning_steps = parsed.get("reasoning_steps", []) or []

        conf = parsed.get("confidence_score", 0.0)
        try:
            conf = float(conf)
        except Exception:
            conf = 0.0

        evaluation.update(
            {
                # Primary signal
                "overall_score": dec,
                "decryption_success_score": dec,

                # Secondary signals (non-zero when content exists)
                "vulnerability_detection_score": _len_based_score(len(vulnerabilities)),
                "reasoning_quality_score": _len_based_score(len(reasoning_steps)),

                # Kept for schema compatibility
                "confidence_calibration_score": 0.0,
                "confidence_score": conf,
                "suggested_attacks": parsed.get("suggested_attacks", []) or [],
                "vulnerabilities_found": vulnerabilities,
                "evaluation_notes": [],
            }
        )
        return evaluation
# REFRESH_2026
