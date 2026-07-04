"""Plaintext recovery prompts.

This prompt family is optimized for the "ciphertext-only plaintext recovery" mission:
- Do NOT request keys / private keys / extra secrets.
- Do NOT output long explanations.
- Always output a single JSON object.

The repository parsers expect at least:
  identified_algorithm, decryption_attempt, confidence_score, reasoning_steps,
  vulnerabilities_found, suggested_attacks, estimated_parameters

We keep those keys for compatibility with existing evaluators/visualizations.
"""

from __future__ import annotations

import json
from typing import Any, Dict


class PlaintextRecoveryPrompts:
    def _common_instructions(self) -> str:
        return (
            "You are taking part in a ciphertext-only plaintext recovery benchmark.\n"
            "Goal: output your BEST plaintext guess from the given encrypted data.\n\n"
            "Rules:\n"
            "- Do NOT ask for keys, private keys, public keys, IVs, nonces, or any additional data.\n"
            "- Do NOT say 'cannot decrypt without a key'. Just attempt cryptanalysis.\n"
            "- If you truly cannot recover plaintext, set decryption_attempt to an empty string and set confidence_score low.\n"
            "- Output ONLY a single valid JSON object. No markdown, no code fences.\n\n"
            "Return JSON with EXACT keys:\n"
            "{\n"
            "  \"identified_algorithm\": string,\n"
            "  \"estimated_parameters\": object,\n"
            "  \"decryption_attempt\": string,\n"
            "  \"confidence_score\": number,\n"
            "  \"reasoning_steps\": array of strings (max 5),\n"
            "  \"vulnerabilities_found\": array of strings,\n"
            "  \"suggested_attacks\": array of strings,\n"
            "  \"further_analysis\": array of strings\n"
            "}\n"
        )

    def create_informed_prompt(self, encrypted_data: Dict[str, Any], context: Dict[str, Any] | None = None) -> str:
        test_case = (context or {}).get("test_case") or {}
        algorithm = test_case.get("algorithm", "unknown")
        payload = {
            "test_id": test_case.get("test_id", ""),
            "algorithm": algorithm,
            "encrypted_data": encrypted_data,
        }

        return (
            self._common_instructions()
            + "\nKnown algorithm (informed condition): "
            + str(algorithm)
            + "\n\nEncrypted data (JSON):\n"
            + json.dumps(payload, ensure_ascii=False, indent=2)
        )

    def create_hidden_prompt(self, encrypted_data: Dict[str, Any], context: Dict[str, Any] | None = None) -> str:
        test_case = (context or {}).get("test_case") or {}
        payload = {
            "test_id": test_case.get("test_id", ""),
            "encrypted_data": encrypted_data,
        }
        return (
            self._common_instructions()
            + "\nAlgorithm is hidden. Infer it if you can and recover plaintext.\n\n"
            + "POSSIBLE ALGORITHMS (use EXACT names):\n"
            + "Classical: Caesar cipher, Vigenère cipher, Substitution cipher\n"
            + "Symmetric: AES-GCM, AES-CBC, AES-CTR, ChaCha20-Poly1305, AES-ECB\n"
            + "Asymmetric: RSA-2048, RSA-4096, ECDSA (P-256), Ed25519\n"
            + "Hash: SHA-256, SHA-3-256, BLAKE3\n\n"
            + "MANDATORY: identified_algorithm MUST be exactly one of the names above.\n\n"
            + "Encrypted data (JSON):\n"
            + json.dumps(payload, ensure_ascii=False, indent=2)
        )
