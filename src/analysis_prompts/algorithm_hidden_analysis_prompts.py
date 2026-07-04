"""Algorithm Hidden Analysis Prompts - prompts where algorithm info is hidden."""

from typing import Dict
import re
import random


class AlgorithmHiddenAnalysisPrompts:
    def __init__(self):
        self.prompt_templates = self._setup_templates()

    def _setup_templates(self) -> Dict[str, str]:
        return {
            'algorithm_hidden_comprehensive_analysis': """
You are an expert cryptanalyst. Analyze the following encrypted data.

ENCRYPTED DATA:
{ciphertext_data}
{additional_context}

CATEGORIES (use EXACT names):
{category_list}

ALGORITHMS (use EXACT names):
{algorithm_list}

ANALYSIS REQUIREMENTS:
- When writing "identified_algorithm" and "identified_category", you MUST copy the values EXACTLY from the lists above (including hyphens/case/accents).
- Note: the "Mode" field values like "Mode_A" may be anonymized placeholders; do not assume they map to real modes. Use evidence like presence/absence of iv/nonce/tag/digest/signature to decide.
- Hybrid rule: If 'Encryption Type' indicates 'hybrid' and an 'Encrypted Session Key' is present, the overall algorithm refers to the OUTER key-encapsulation (RSA-2048/RSA-4096), not the inner payload cipher.

1. Identify ONE algorithm from the list above
2. Identify its category (MUST be EXACTLY one of: Classical, Modern Symmetric, Asymmetric, Hash)
3. Provide confidence score (0.0 to 1.0)
4. Analyze vulnerabilities
5. Suggest attack vectors
6. Attempt decryption if possible
7. Explain reasoning step by step

DECRYPTION_ATTEMPT RULE (MANDATORY):
- For ALL categories (Classical, Modern Symmetric, Asymmetric, Hash): set 'decryption_attempt' to your best-effort plaintext guess.
- If true recovery is not possible, STILL provide a plausible plaintext sentence guess (do NOT leave it empty).
- Plaintext only: no prefixes/labels, no markdown, no JSON fragments.
- Do NOT include prefixes like "Speculative plaintext guess:" and do NOT wrap the plaintext in extra quotes.


RESPONSE FORMAT (JSON):
{{
    "identified_algorithm": "algorithm_name",
    "identified_category": "Classical|Modern Symmetric|Asymmetric|Hash",
    "identified_confidence": 0.85,
    "estimated_parameters": {{}},
    "suggested_attacks": [],
    "decryption_attempt": "<plaintext-only best guess sentence (non-empty)>",
    "confidence_score": 0.85,
    "reasoning_steps": [],
    "vulnerabilities_found": [],
    "further_analysis": [],
    "security_assessment": "high|medium|low"
}}
"""
        }

    def create_algorithm_hidden_prompt(self, encrypted_data: Dict, context: Dict | None = None) -> str:
        template = self.prompt_templates['algorithm_hidden_comprehensive_analysis']
        sanitized_data = self.sanitize_encrypted_data_for_prompt(encrypted_data)
        ciphertext_data = self._format_ciphertext_data(sanitized_data)
        additional_context = self._format_additional_context(context)
        category_list = self._build_category_list(context)
        algorithm_list = self._build_algorithm_list(context)
        return template.format(ciphertext_data=ciphertext_data, additional_context=additional_context, category_list=category_list, algorithm_list=algorithm_list)

    def sanitize_encrypted_data_for_prompt(self, encrypted_data: Dict) -> Dict:
        """Return a sanitized copy of encrypted_data safe to show to the model.

        This removes/obscures fields that would break the experiment's intent (e.g., plaintext messages)
        and strips common ground-truth leakage fields (e.g., key_size / nested algorithm markers).
        """

        if not isinstance(encrypted_data, dict):
            return {}

        sanitized = dict(encrypted_data)

        # Remove explicit key-size hints (kept only in generator/original_info)
        sanitized.pop('key_size', None)
        sanitized.pop('hash_algorithm', None)

        # Never reveal plaintext message content in algorithm_hidden prompts.
        if 'message' in sanitized:
            msg = sanitized.get('message')
            if isinstance(msg, str):
                sanitized['message'] = f"(redacted, {len(msg)} chars)"
            else:
                sanitized['message'] = "(redacted)"

        # RSA hybrid payload may be nested; drop common ground-truth markers there too.
        nested = sanitized.get('encrypted_data')
        if isinstance(nested, dict):
            nested_s = dict(nested)
            nested_s.pop('algorithm', None)
            nested_s.pop('key_size', None)
            nested_s.pop('mode', None)
            sanitized['encrypted_data'] = nested_s

        return sanitized

    def _build_category_list(self, context: Dict | None) -> str:
        categories = ["Classical", "Modern Symmetric", "Asymmetric", "Hash"]

        seed = 42
        if context and isinstance(context.get("test_case"), dict):
            test_id = context["test_case"].get("test_id")
            if isinstance(test_id, str) and test_id:
                seed = sum(ord(ch) for ch in test_id) + 17

        rnd = random.Random(seed)
        rnd.shuffle(categories)
        return "\n".join(categories)

    def _build_algorithm_list(self, context: Dict | None) -> str:
        algorithms = [
            "Caesar cipher",
            "Vigenère cipher",
            "Substitution cipher",
            "AES-GCM",
            "AES-CBC",
            "AES-CTR",
            "ChaCha20-Poly1305",
            "AES-ECB",
            "RSA-2048",
            "RSA-4096",
            "ECDSA (P-256)",
            "Ed25519",
            "SHA-256",
            "SHA-3-256",
            "BLAKE3",
        ]

        seed = 42
        if context and isinstance(context.get("test_case"), dict):
            test_id = context["test_case"].get("test_id")
            if isinstance(test_id, str) and test_id:
                seed = sum(ord(ch) for ch in test_id) + 101

        rnd = random.Random(seed)
        rnd.shuffle(algorithms)
        return "\n".join(algorithms)

    def _build_algorithm_catalog(self, context: Dict | None) -> str:
        catalog = {
            "Classical": ["Caesar cipher", "Vigenère cipher", "Substitution cipher"],
            "Modern Symmetric": ["AES-GCM", "AES-CBC", "AES-CTR", "ChaCha20-Poly1305", "AES-ECB"],
            "Asymmetric": ["RSA-2048", "RSA-4096", "ECDSA (P-256)", "Ed25519"],
            "Hash": ["SHA-256", "SHA-3-256", "BLAKE3"],
        }

        seed = 42
        if context and isinstance(context.get("test_case"), dict):
            test_id = context["test_case"].get("test_id")
            if isinstance(test_id, str) and test_id:
                seed = sum(ord(ch) for ch in test_id)

        rnd = random.Random(seed)
        categories = list(catalog.items())
        rnd.shuffle(categories)

        lines = []
        for category, algorithms in categories:
            algos = list(algorithms)
            rnd.shuffle(algos)
            lines.append(f"{category}: " + ", ".join(algos))

        return "\n".join(lines)


    def _format_ciphertext_data(self, encrypted_data: Dict) -> str:
        """Format ciphertext and related public metadata without leaking ground-truth fields.

        Notes:
        - Many values in generated test cases are Base64 (ciphertext/iv/nonce/tag/signature/encrypted_session_key).
        - Hashes are hex.
        - Some cases (RSA hybrid) nest a dict in 'encrypted_data'; we must not stringify it because it
          contains ground-truth fields like 'algorithm' and 'key_size'.
        """

        def _safe_truncate(s: str, limit: int) -> str:
            s = '' if s is None else str(s)
            return (s[:limit] + '...') if len(s) > limit else s

        def _b64_len(value: object) -> int | None:
            if not isinstance(value, str) or not value:
                return None
            import base64
            try:
                pad = (-len(value)) % 4
                raw = base64.b64decode(value + ('=' * pad), validate=False)
                return len(raw)
            except Exception:
                return None


        def _b64_decode(value: object) -> bytes | None:
            if not isinstance(value, str) or not value:
                return None
            import base64
            try:
                pad = (-len(value)) % 4
                return base64.b64decode(value + ('=' * pad), validate=False)
            except Exception:
                return None

        def _block16_stats_b64(value: object) -> dict | None:
            raw = _b64_decode(value)
            if raw is None:
                return None
            multiple = (len(raw) % 16 == 0)
            full_len = (len(raw) // 16) * 16
            blocks = [raw[i:i+16] for i in range(0, full_len, 16)]
            if not blocks:
                return {'multiple': multiple, 'block_count': 0, 'unique_blocks': 0, 'max_repeat': 0}
            from collections import Counter
            c = Counter(blocks)
            return {
                'multiple': multiple,
                'block_count': len(blocks),
                'unique_blocks': len(c),
                'max_repeat': max(c.values()) if c else 0,
            }

        def _hex_len(value: object) -> int | None:
            if not isinstance(value, str) or not value:
                return None
            s = value.strip().lower()
            if not re.fullmatch(r"[0-9a-f]+", s):
                return None
            if len(s) % 2 != 0:
                return None
            return len(s) // 2

        data_lines: list[str] = []

        # Primary ciphertext (typical symmetric/hash items)
        if 'ciphertext' in encrypted_data:
            ct = encrypted_data.get('ciphertext')
            n = _b64_len(ct)
            if n is not None:
                data_lines.append(f"Ciphertext (base64, {n} bytes): {_safe_truncate(ct, 500)}")
                st = _block16_stats_b64(ct)
                if st is not None:
                    data_lines.append(
                        f"Ciphertext 16-byte blocks: {st['block_count']} (unique {st['unique_blocks']}, max repeat {st['max_repeat']}), multiple-of-16: {st['multiple']}"
                    )
            else:
                data_lines.append(f"Ciphertext: {_safe_truncate(ct, 500)}")

        # Classical cipher parameters
        if 'parameters' in encrypted_data:
            data_lines.append(f"Parameters: {encrypted_data['parameters']}")

        # IV/nonce/tag (public in AEAD/modes)
        if 'iv' in encrypted_data:
            iv = encrypted_data.get('iv')
            n = _b64_len(iv)
            if n is not None:
                data_lines.append(f"IV/Nonce (base64, {n} bytes): {iv}")
            else:
                data_lines.append(f"IV/Nonce: {iv}")

        if 'nonce' in encrypted_data:
            nonce = encrypted_data.get('nonce')
            n = _b64_len(nonce)
            if n is not None:
                data_lines.append(f"Nonce (base64, {n} bytes): {nonce}")
            else:
                data_lines.append(f"Nonce: {nonce}")

        if 'tag' in encrypted_data:
            tag = encrypted_data.get('tag')
            n = _b64_len(tag)
            if n is not None:
                data_lines.append(f"Authentication Tag (base64, {n} bytes): {tag}")
            else:
                data_lines.append(f"Authentication Tag: {tag}")

        # Hash outputs (hex)
        if 'digest_size' in encrypted_data:
            data_lines.append(f"Digest Size: {encrypted_data['digest_size']}")

        if 'hash' in encrypted_data:
            hv = encrypted_data.get('hash')
            n = _hex_len(hv)
            if n is not None:
                data_lines.append(f"Digest (hex, {n} bytes): {hv}")
                # Hash-context header: realistic, network-visible, and non-identifying
                present_fields = sorted([k for k, v in encrypted_data.items() if v is not None and k not in ('algorithm', 'key_size')])
                ds = encrypted_data.get('digest_size')
                if isinstance(ds, int):
                    data_lines.append(f"Digest Context: encoding=hex; digest_length={n} bytes; digest_size_hint={ds} bits; fields={present_fields}")
                else:
                    data_lines.append(f"Digest Context: encoding=hex; digest_length={n} bytes; fields={present_fields}")
                data_lines.append("Digest Note: multiple candidate algorithms may share identical digest lengths; choose ONE from the provided list.")
            else:
                data_lines.append(f"Digest: {hv}")

        # Signature cases

        if 'message' in encrypted_data:
            msg = encrypted_data.get('message')
            if isinstance(msg, str) and msg.startswith('(redacted'):
                data_lines.append(f"Message: {msg}")
            elif isinstance(msg, str):
                data_lines.append(f"Message: (redacted, {len(msg)} chars)")
            else:
                data_lines.append("Message: (redacted)")

        if 'signature' in encrypted_data:
            sig = encrypted_data.get('signature')
            n = _b64_len(sig)
            if n is not None:
                data_lines.append(f"Signature (base64, {n} bytes): {_safe_truncate(sig, 300)}")
            else:
                data_lines.append(f"Signature: {_safe_truncate(sig, 300)}")

            raw_sig = _b64_decode(sig)
            if raw_sig is not None and len(raw_sig) >= 2:
                # Minimal ASN.1 DER check: SEQUENCE of 2 INTEGERs (common signature container)
                def _looks_like_der_seq_two_ints(b: bytes) -> bool:
                    try:
                        if len(b) < 8 or b[0] != 0x30:
                            return False
                        ln = b[1]
                        if ln & 0x80:
                            return False  # long-form not handled
                        if 2 + ln != len(b):
                            return False
                        i = 2
                        if b[i] != 0x02:
                            return False
                        lr = b[i + 1]
                        i += 2 + lr
                        if i + 2 > len(b) or b[i] != 0x02:
                            return False
                        ls = b[i + 1]
                        i += 2 + ls
                        return i == len(b)
                    except Exception:
                        return False

                der_like = _looks_like_der_seq_two_ints(raw_sig)
                data_lines.append(f"Signature Structure Hint: {'ASN.1 DER (SEQUENCE of 2 INTEGERs)' if der_like else 'Not ASN.1 DER (raw bytes)'}")

        # RSA hybrid cases
        if 'encrypted_session_key' in encrypted_data:
            esk = encrypted_data.get('encrypted_session_key')
            n = _b64_len(esk)
            if n is not None:
                data_lines.append(f"Encrypted Session Key (base64, {n} bytes): {_safe_truncate(esk, 200)}")
                data_lines.append(f"Encrypted Session Key Bit Length Hint: {n * 8} bits")
            else:
                data_lines.append(f"Encrypted Session Key: {_safe_truncate(esk, 200)}")

        if 'encryption_type' in encrypted_data:
            data_lines.append(f"Encryption Type: {encrypted_data['encryption_type']}")

        # IMPORTANT: Some RSA cases store a dict under 'encrypted_data' (nested symmetric payload).
        # Do NOT stringify it; extract safe, public fields.
        if 'encrypted_data' in encrypted_data:
            nested = encrypted_data.get('encrypted_data')
            if isinstance(nested, dict):
                # Surface only public fields, without algorithm/key_size/mode leaks.
                payload_ct = nested.get('ciphertext')
                payload_nonce = nested.get('nonce')
                payload_tag = nested.get('tag')
                payload_iv = nested.get('iv')

                if payload_ct is not None:
                    n = _b64_len(payload_ct)
                    if n is not None:
                        data_lines.append(f"Payload Ciphertext (base64, {n} bytes): {_safe_truncate(payload_ct, 500)}")
                        st = _block16_stats_b64(payload_ct)
                        if st is not None:
                            data_lines.append(
                                f"Payload Ciphertext 16-byte blocks: {st['block_count']} (unique {st['unique_blocks']}, max repeat {st['max_repeat']}), multiple-of-16: {st['multiple']}"
                            )
                    else:
                        data_lines.append(f"Payload Ciphertext: {_safe_truncate(payload_ct, 500)}")

                if payload_iv is not None:
                    n = _b64_len(payload_iv)
                    if n is not None:
                        data_lines.append(f"Payload IV/Nonce (base64, {n} bytes): {payload_iv}")
                    else:
                        data_lines.append(f"Payload IV/Nonce: {payload_iv}")

                if payload_nonce is not None:
                    n = _b64_len(payload_nonce)
                    if n is not None:
                        data_lines.append(f"Payload Nonce (base64, {n} bytes): {payload_nonce}")
                    else:
                        data_lines.append(f"Payload Nonce: {payload_nonce}")

                if payload_tag is not None:
                    n = _b64_len(payload_tag)
                    if n is not None:
                        data_lines.append(f"Payload Authentication Tag (base64, {n} bytes): {payload_tag}")
                    else:
                        data_lines.append(f"Payload Authentication Tag: {payload_tag}")
            else:
                ed = str(nested)
                data_lines.append(f"Encrypted Data: {_safe_truncate(ed, 200)}")

        # Mode placeholder when present (do not assume mapping)
        if 'mode' in encrypted_data:
            data_lines.append(f"Mode: {encrypted_data['mode']}")

        return '\n'.join(data_lines)

    def _format_additional_context(self, context: Dict | None) -> str:
        if not context:
            return "No additional context"

        if 'test_case' in context:
            test_case = context['test_case']
            return f"Test ID: {test_case.get('test_id', 'Unknown')}"

        return ""
