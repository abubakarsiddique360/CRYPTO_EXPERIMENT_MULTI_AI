"""Test-case generator for plaintext recovery mission.

Important design choice for this mission:
- Only include algorithms where ciphertext-only recovery is at least *plausible*.
- Default suite: classical ciphers (Caesar/Vigenere/Substitution).

Modern crypto (AES/RSA) is intentionally excluded by default because it is
computationally infeasible without secrets; keeping it would mostly measure
model honesty rather than plaintext recovery.
"""

from __future__ import annotations

import random
from typing import Dict, List

from crypto_systems.classical_ciphers import ClassicalCiphers


def generate_plaintext_recovery_cases(
    per_algorithm: int = 60,
    seed: int = 42,
    include_substitution: bool = True,
) -> List[Dict]:
    rng = random.Random(seed)

    c = ClassicalCiphers()

    test_cases: List[Dict] = []

    # Caesar
    for i in range(per_algorithm):
        plaintext = rng.choice(c.plaintext_samples)
        shift = rng.randint(1, 25)
        ciphertext = c.caesar_cipher(plaintext, shift)
        test_cases.append(
            {
                "test_id": f"caesar_{i:03d}",
                "algorithm": "Caesar cipher",
                "plaintext": plaintext,
                "ciphertext": ciphertext,
                "encrypted_data": {"ciphertext": ciphertext, "algorithm": "Caesar cipher"},
                "difficulty": "easy",
                "category": "classical",
            }
        )

    # Vigenere (random short keys; not disclosed)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for i in range(per_algorithm):
        plaintext = rng.choice(c.plaintext_samples)
        key_len = rng.randint(3, 7)
        key = "".join(rng.choice(alphabet) for _ in range(key_len))
        ciphertext = c.vigenere_cipher(plaintext, key)
        test_cases.append(
            {
                "test_id": f"vigenere_{i:03d}",
                "algorithm": "Vigenère cipher",
                "plaintext": plaintext,
                "ciphertext": ciphertext,
                "encrypted_data": {"ciphertext": ciphertext, "algorithm": "Vigenère cipher"},
                "difficulty": "medium",
                "category": "classical",
            }
        )

    # Substitution (very hard ciphertext-only; optional)
    if include_substitution:
        for i in range(per_algorithm):
            plaintext = rng.choice(c.plaintext_samples)
            key = c._generate_substitution_key()
            ciphertext = c.substitution_cipher(plaintext, key)
            test_cases.append(
                {
                    "test_id": f"substitution_{i:03d}",
                    "algorithm": "Substitution cipher",
                    "plaintext": plaintext,
                    "ciphertext": ciphertext,
                    "encrypted_data": {"ciphertext": ciphertext, "algorithm": "Substitution cipher"},
                    "difficulty": "hard",
                    "category": "classical",
                }
            )

    return test_cases
