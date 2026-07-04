# src/deepseek_analyst/response_parser.py

import json

import re

from typing import Dict, List, Any, Tuple



class ResponseEvaluator:

    def __init__(self):

        # Updated to include all 15 algorithms with their common variations

        self.crypto_keywords = {

            'caesar cipher': ['shift', 'rotation', 'substitution', 'caesar', 'rot'],

            'vigenère cipher': ['polyalphabetic', 'key', 'repeating key', 'vigenere', 'vigenère'],

            'substitution cipher': ['monoalphabetic', 'character mapping', 'substitution'],

            'aes-gcm': ['authenticated', 'galois counter mode', 'gcm', 'authentication tag'],

            'aes-cbc': ['cipher block chaining', 'iv', 'initialization vector', 'padding oracle'],

            'aes-ctr': ['counter mode', 'stream cipher', 'nonce'],

            'chacha20-poly1305': ['chacha20', 'poly1305', 'stream cipher', 'authenticated'],

            'aes-ecb': ['electronic codebook', 'pattern', 'deterministic'],

            'rsa-2048': ['rivest shamir adleman', 'public key', 'factorization', '2048'],

            'rsa-4096': ['rivest shamir adleman', 'public key', 'factorization', '4096'],

            'ecdsa (p-256)': ['elliptic curve', 'digital signature', 'p-256', 'nist curve'],

            'ed25519': ['edwards curve', 'eddsa', 'modern signature'],

            'sha-256': ['secure hash algorithm', '256 bit', 'hashing'],

            'sha-3-256': ['sha3', 'keccak', 'hashing'],

            'blake3': ['blake', 'modern hash', 'high performance']

        }

    

    def evaluate_cryptanalysis(self, deepseek_response, test_case: Dict) -> Dict[str, Any]:

        """Comprehensive evaluation of DeepSeek cryptanalysis"""

        evaluation = {

            'test_id': test_case['test_id'],

            'algorithm': test_case['algorithm'],

            'difficulty': test_case['difficulty'],

            'category': test_case['category'],

            'response_success': deepseek_response.success,


            'error': deepseek_response.error

        }

        

        if not deepseek_response.success:

            evaluation['overall_score'] = 0

            evaluation['evaluation_notes'] = 'API call failed'

            return evaluation

        

        parsed_data = deepseek_response.parsed_data or {}

        

        # Vulnerability detection

        vulnerability_score = self._evaluate_vulnerability_detection(

            parsed_data, test_case

        )

        

        # Decryption success (only for encryption algorithms)

        decryption_score = self._evaluate_decryption_success(

            parsed_data, test_case

        )

        

        # Reasoning quality

        reasoning_score = self._evaluate_reasoning_quality(parsed_data)

        

        # Confidence calibration

        confidence_score = self._evaluate_confidence_calibration(parsed_data)

        

        # Overall score (weighted average) - adjusted for hash functions

        if test_case['category'] == 'hash':

            # For hash functions, decryption doesn't apply

            overall_score = (

                vulnerability_score * 0.4 +

                reasoning_score * 0.4 +

                confidence_score * 0.2

            )

        else:

            # For encryption algorithms

            overall_score = (

                vulnerability_score * 0.4 +

                decryption_score * 0.4 +

                reasoning_score * 0.15 +

                confidence_score * 0.05

            )

        

        evaluation.update({

            'overall_score': overall_score,

            'vulnerability_detection_score': vulnerability_score,

            'decryption_success_score': decryption_score,

            'reasoning_quality_score': reasoning_score,

            'confidence_calibration_score': confidence_score,

            'suggested_attacks': parsed_data.get('suggested_attacks', []),

            'vulnerabilities_found': parsed_data.get('vulnerabilities_found', []),

            'confidence_score': parsed_data.get('confidence_score', 0.0),

            'evaluation_notes': self._generate_evaluation_notes(parsed_data, test_case)

        })

        

        return evaluation

    

    def _evaluate_vulnerability_detection(self, parsed_data: Dict, test_case: Dict) -> float:

        """Evaluate vulnerability detection accuracy"""

        # For hash functions, check if they identified hash-specific vulnerabilities

        if test_case['category'] == 'hash':

            vulnerabilities_found = parsed_data.get('vulnerabilities_found', [])

            hash_vulnerabilities = ['collision', 'preimage', 'length_extension', 'birthday_attack']

            if any(vuln in ' '.join(vulnerabilities_found).lower() for vuln in hash_vulnerabilities):

                return 0.8  # Partial credit for recognizing hash vulnerabilities

            return 0.3  # Base score for hash analysis

        

        if 'weakness' not in test_case:

            return 0.5  # Neutral score for cases without known weaknesses

        

        vulnerabilities_found = parsed_data.get('vulnerabilities_found', [])

        known_weakness = test_case['weakness']

        

        # Check if known weakness was detected

        weakness_detected = any(

            known_weakness in vuln.lower() or vuln.lower() in known_weakness

            for vuln in vulnerabilities_found

        )

        

        return 1.0 if weakness_detected else 0.0



    def _evaluate_decryption_success(self, parsed_data: Dict, test_case: Dict) -> float:

        """Evaluate decryption success.



        Notes:

        - Hash tasks are not decryptable; if no plaintext is provided, we return 0.5 as a neutral marker.
          If plaintext is present, we score the attempt against it (usually 0.0).

        - Signature tasks (ECDSA/Ed25519) are not decryptable, but when the test case includes the signed

          message in `plaintext`, we score the model's `decryption_attempt` against that message.

        """

        decryption_attempt = parsed_data.get('decryption_attempt', '')

        actual_plaintext = test_case.get('plaintext', '')

        # Hash functions are not decryptable, but some test cases include the original message in plaintext.

        # If plaintext is missing, keep a neutral marker; otherwise, score the attempt like other tasks.

        if test_case['category'] == 'hash' and not actual_plaintext:

            return 0.5

        # Digital signature tasks: if plaintext is missing, treat as non-decryption.

        if test_case['category'] == 'asymmetric' and 'signature' in test_case.get('encrypted_data', {}):

            if not actual_plaintext:

                return 0.5



        if not decryption_attempt or not actual_plaintext:

            return 0.0



        # Exact match

        if decryption_attempt.strip() == actual_plaintext.strip():

            return 1.0

        # Partial match (percentage of plaintext recovered)
        #
        # Previous logic used pure *recall* ("how many plaintext tokens appear anywhere"), which can
        # incorrectly give 1.0 when the model outputs a long explanation that merely includes all
        # plaintext words.
        #
        # New logic uses a precision/recall balance (F1) + a small ordering similarity signal.
        # If *all* meaningful plaintext tokens are present (recall == 1) but the string is not
        # identical, we cap the score below 1.0 and ensure it lands in [0.5, 1).

        stop_words = set(
            "the a an and or but if then else to of in on for with as at by from into is are was were be been being "
            "it this that these those i you he she we they them my your our their not no yes can could should would "
            "will just very also only such"
            .split()
        )

        def _meaningful_tokens(text: str) -> list:
            tokens = re.findall(r"[a-z0-9]+", (text or "").lower())
            return [t for t in tokens if len(t) >= 4 and t not in stop_words]

        actual_tokens = _meaningful_tokens(actual_plaintext)
        attempt_tokens = _meaningful_tokens(decryption_attempt)
        if not actual_tokens or not attempt_tokens:
            return 0.0

        from collections import Counter
        from difflib import SequenceMatcher

        actual_counts = Counter(actual_tokens)
        attempt_counts = Counter(attempt_tokens)
        common = sum(min(actual_counts[w], attempt_counts.get(w, 0)) for w in actual_counts)
        total_actual = sum(actual_counts.values())
        total_attempt = sum(attempt_counts.values())
        if total_actual == 0 or total_attempt == 0:
            return 0.0

        recall = common / total_actual
        precision = common / total_attempt
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        norm_actual = ' '.join(actual_tokens)
        norm_attempt = ' '.join(attempt_tokens)
        order_sim = SequenceMatcher(None, norm_actual, norm_attempt).ratio()

        score = min(1.0, max(0.0, f1))

        # If the attempt contains *all* meaningful plaintext tokens but isn't identical,
        # penalize extra filler / reordering; keep it in [0.5, 1).
        if recall >= 0.999 and decryption_attempt.strip() != actual_plaintext.strip():
            score = 0.5 + 0.5 * max(precision, order_sim)
            score = min(0.99, max(0.5, score))

        return float(score)

    def _evaluate_reasoning_quality(self, parsed_data: Dict) -> float:

        """Evaluate quality of reasoning steps"""

        reasoning_steps = parsed_data.get('reasoning_steps', [])

        

        if not reasoning_steps:

            return 0.0

        

        # Score based on number and quality of reasoning steps

        step_count = len(reasoning_steps)

        

        # Check for technical depth

        technical_terms = 0

        crypto_terms = ['frequency', 'analysis', 'pattern', 'key', 'algorithm', 'vulnerability', 

                       'hash', 'collision', 'encryption', 'decryption', 'signature', 'authentication']

        

        for step in reasoning_steps:

            if any(term in step.lower() for term in crypto_terms):

                technical_terms += 1

        

        quality_score = min(1.0, technical_terms / max(1, step_count))

        quantity_score = min(1.0, step_count / 5)  # 5 steps is ideal

        

        return (quality_score + quantity_score) / 2

    

    def _evaluate_confidence_calibration(self, parsed_data: Dict) -> float:

        """Evaluate if confidence score is well-calibrated"""

        confidence = parsed_data.get('confidence_score', 0.5)

        

        # For now, return neutral score - this would need actual accuracy data

        # to properly evaluate calibration

        return 0.5

    

    def _generate_evaluation_notes(self, parsed_data: Dict, test_case: Dict) -> List[str]:

        """Generate detailed evaluation notes"""

        notes = []

        

        # Vulnerability detection note

        if 'weakness' in test_case:

            vulnerabilities_found = parsed_data.get('vulnerabilities_found', [])

            if vulnerabilities_found:

                notes.append(f"Detected vulnerabilities: {', '.join(vulnerabilities_found)}")

            else:

                notes.append("No vulnerabilities detected")

        elif test_case['category'] == 'hash':

            vulnerabilities_found = parsed_data.get('vulnerabilities_found', [])

            if vulnerabilities_found:

                notes.append(f"Identified hash analysis: {', '.join(vulnerabilities_found)}")

            else:

                notes.append("Limited hash function analysis")

        

        # Reasoning quality note

        reasoning_steps = parsed_data.get('reasoning_steps', [])

        if len(reasoning_steps) >= 3:

            notes.append(f"Good reasoning depth: {len(reasoning_steps)} steps")

        else:

            notes.append("Limited reasoning provided")

        

        # Category-specific notes

        if test_case['category'] == 'hash':

            notes.append("Hash function analysis task")

        elif test_case['category'] == 'asymmetric' and 'signature' in test_case.get('encrypted_data', {}):

            notes.append("Digital signature analysis task")

        

        return notes