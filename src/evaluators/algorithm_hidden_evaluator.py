"""
Algorithm Hidden Evaluator - Corrected scoring system for algorithm hidden cryptanalysis.
Created for: Experiment where algorithms are hidden from AI
"""

import json
import re
import unicodedata
from typing import Dict, List, Any

import numpy as np


class AlgorithmHiddenEvaluator:
    """Evaluator with scoring for algorithm-hidden cryptanalysis."""

    def _normalize_algo_name(self, name: str) -> str:
        s = (name or "").strip().lower()
        # Preserve parenthetical content (e.g., "ECDSA (P-256)") while normalizing punctuation.
        s = s.replace("(", " ").replace(")", " ")
        # Remove accents: VigenÃ¨re -> vigenere
        s = unicodedata.normalize("NFKD", s)
        s = "".join(ch for ch in s if not unicodedata.combining(ch))
        # Normalize punctuation/whitespace
        s = re.sub(r"[^a-z0-9]+", " ", s).strip()
        return s

    def _normalize_category(self, cat: str) -> str:
        s = (cat or "").strip().lower()
        s = s.replace("_", " ")
        s = re.sub(r"\s+", " ", s).strip()
        # Keep the generator's canonical keys when present
        if s in {"classical", "modern", "symmetric", "asymmetric", "hash"}:
            return s
        # Map common synonyms
        if s in {"classical cipher", "classical ciphers"}:
            return "classical"
        if s in {"sym", "symmetric crypto", "symmetric encryption"}:
            return "symmetric"
        if s in {"asym", "asymmetric crypto", "public key", "public key crypto"}:
            return "asymmetric"
        if s in {"hashing", "hash function", "hash functions"}:
            return "hash"
        return s or "unknown"

    def _infer_category_from_algorithm(self, algo_name: str) -> str:
        a = self._normalize_algo_name(algo_name)
        if any(k in a for k in ["caesar", "vigenere", "substitution"]):
            return "classical"
        if any(k in a for k in ["aes", "chacha"]):
            return "symmetric"
        if any(k in a for k in ["rsa", "ecdsa", "ed25519"]):
            return "asymmetric"
        if any(k in a for k in ["sha", "blake"]):
            return "hash"
        return "unknown"

    def __init__(
        self,
        allow_partial_identification: bool = False,
        identification_weight: float = 0.5,
        category_weight: float = 0.0,
        decryption_weight: float = 0.3,
        vulnerability_weight: float = 0.1,
        reasoning_weight: float = 0.1,
    ):
        self.algorithm_list = [
            'Caesar cipher', 'Vigenère cipher', 'Substitution cipher',
            'AES-GCM', 'AES-CBC', 'AES-CTR', 'ChaCha20-Poly1305', 'AES-ECB',
            'RSA-2048', 'RSA-4096', 'ECDSA (P-256)', 'Ed25519',
            'SHA-256', 'SHA-3-256', 'BLAKE3'
        ]

        self.allow_partial_identification = bool(allow_partial_identification)
        # Map normalized canonical names -> canonical display names
        self._canonical_name_by_norm = {self._normalize_algo_name(a): a for a in self.algorithm_list}

        total = float(identification_weight + category_weight + decryption_weight + vulnerability_weight + reasoning_weight)
        if total <= 0:
            total = 1.0

        self.identification_weight = float(identification_weight) / total
        self.category_weight = float(category_weight) / total
        self.decryption_weight = float(decryption_weight) / total
        self.vulnerability_weight = float(vulnerability_weight) / total
        self.reasoning_weight = float(reasoning_weight) / total

    def _canonicalize_algorithm(self, name: str) -> str | None:
        norm = self._normalize_algo_name(name)
        if not norm:
            return None
        return self._canonical_name_by_norm.get(norm)


    def evaluate_cryptanalysis(self, deepseek_response, test_case: Dict) -> Dict[str, Any]:
        """Evaluate a model response for the algorithm-hidden condition."""
        evaluation = {
            'test_id': test_case['test_id'],
            'algorithm': test_case.get('algorithm', 'unknown'),
            'category': test_case.get('category', 'unknown'),
            'response_success': deepseek_response.success,
            'error': deepseek_response.error,
        }

        if not deepseek_response.success:
            return self._create_failed_evaluation(evaluation)

        parsed_data = deepseek_response.parsed_data or {}
        actual_algo = evaluation['algorithm']
        actual_category = evaluation['category']
        plaintext = test_case.get('original_test_case', {}).get('plaintext', '')

        # Decryption diagnostics (do not store plaintext; store only derived signals)
        decryption_attempt = ''
        if isinstance(parsed_data, dict):
            decryption_attempt = str(parsed_data.get('decryption_attempt') or '').strip()

        decryption_applicable = self._is_decryption_applicable(actual_algo, actual_category)
        decryption_ack_infeasible = bool(decryption_attempt) and self._acknowledges_infeasible_decryption(
            decryption_attempt, actual_algo, actual_category
        )

        decryption_plaintext_similarity = 0.0
        decryption_plaintext_exact_match = False
        if decryption_applicable and decryption_attempt and plaintext and not decryption_ack_infeasible:
            gold = str(plaintext).strip()
            decryption_plaintext_exact_match = (decryption_attempt == gold)
            decryption_plaintext_similarity = 1.0 if decryption_plaintext_exact_match else self._calculate_word_overlap(decryption_attempt, gold)

        if not decryption_applicable:
            decryption_kind = 'not_applicable'
        elif decryption_ack_infeasible:
            decryption_kind = 'ack_infeasible'
        elif decryption_plaintext_similarity > 0:
            decryption_kind = 'plaintext_similarity'
        else:
            decryption_kind = 'none'

        # 1) Algorithm identification score
        identification_result = self._evaluate_algorithm_identification(
            parsed_data, actual_algo, actual_category
        )

        # 2) Decryption score - depends on exact identification
        decryption_score = self._evaluate_decryption(
            parsed_data, plaintext, identification_result['exact_match'], actual_algo, actual_category
        )

        # 3) Vulnerability detection
        vulnerability_score = self._evaluate_vulnerability_detection(
            parsed_data, actual_algo, identification_result['exact_match']
        )

        # 4) Reasoning quality
        reasoning_score = self._evaluate_reasoning_quality(parsed_data)

        # Overall score (weighted)
        overall_score = (
            identification_result['score'] * self.identification_weight
            + identification_result['category_score'] * self.category_weight
            + decryption_score * self.decryption_weight
            + vulnerability_score * self.vulnerability_weight
            + reasoning_score * self.reasoning_weight
        )

        identified_algo = parsed_data.get('identified_algorithm', 'unknown')
        confidence = parsed_data.get('confidence_score', 0)

        evaluation.update({
            'overall_score': round(overall_score, 3),
            'identified_algorithm': identified_algo,
            'identified_algorithm_score': round(identification_result['score'], 3),
            'identified_category': identification_result['identified_category'],
            'identified_category_score': round(identification_result['category_score'], 3),
            'vulnerability_score': round(vulnerability_score, 3),
            'decryption_score': round(decryption_score, 3),
            'reasoning_score': round(reasoning_score, 3),
            'confidence': round(confidence, 3),
            'suggested_attacks_count': len(parsed_data.get('suggested_attacks', [])),
            'vulnerabilities_count': len(parsed_data.get('vulnerabilities_found', [])),
            'exact_match': identification_result['exact_match'],
            'category_match': identification_result['category_match'],

            # Decryption breakdown (helps interpret "decryption_score")
            'decryption_applicable': bool(decryption_applicable),
            'decryption_kind': decryption_kind,
            'decryption_acknowledged_infeasible': bool(decryption_ack_infeasible),
            'decryption_plaintext_similarity': round(float(decryption_plaintext_similarity), 3),
            'decryption_plaintext_exact_match': bool(decryption_plaintext_exact_match),
        })

        return evaluation

    def _create_failed_evaluation(self, evaluation: Dict) -> Dict:
        evaluation.update({
            'overall_score': 0.0,
            'identified_algorithm': 'failed',
            'identified_algorithm_score': 0.0,
            'identified_category': 'unknown',
            'identified_category_score': 0.0,
            'vulnerability_score': 0.0,
            'decryption_score': 0.0,
            'reasoning_score': 0.0,
            'confidence': 0.0,
            'suggested_attacks_count': 0,
            'vulnerabilities_count': 0,
            'exact_match': False,
            'category_match': False,
        })
        return evaluation

    def _evaluate_algorithm_identification(self, parsed_data: Dict, actual_algo: str, actual_category: str) -> Dict:
        identified_algo = (parsed_data.get('identified_algorithm', '') or '').strip()

        result = {
            'score': 0.0,
            'exact_match': False,
            'category_match': False,
            'identified_category': 'unknown',
            'category_score': 0.0,
        }

        actual_cat_norm = self._normalize_category(actual_category)

        if not identified_algo or identified_algo.lower() == 'unknown':
            # Unknown algorithm => unknown category
            result['identified_category'] = 'unknown'
            return result

        identified_norm = self._normalize_algo_name(identified_algo)
        actual_norm = self._normalize_algo_name(actual_algo)

        # Determine model's category: use explicit field if present, otherwise infer from identified algorithm
        predicted_cat = parsed_data.get('identified_category') or parsed_data.get('category') or ''
        predicted_cat_norm = self._normalize_category(predicted_cat) if predicted_cat else self._infer_category_from_algorithm(identified_algo)

        result['identified_category'] = predicted_cat_norm
        result['category_match'] = (predicted_cat_norm != 'unknown' and predicted_cat_norm == actual_cat_norm)
        result['category_score'] = 1.0 if result['category_match'] else 0.0

        # Canonicalize algorithm names to enforce the 15-name list in strict mode
        identified_canonical = self._canonicalize_algorithm(identified_algo)
        actual_canonical = self._canonicalize_algorithm(actual_algo)

        # 1) EXACT MATCH
        if (
            identified_canonical is not None
            and actual_canonical is not None
            and identified_canonical == actual_canonical
        ):
            result['exact_match'] = True
            result['score'] = 1.0
            # If we can infer category, treat it as match on exact algorithm.
            if actual_cat_norm != 'unknown' and predicted_cat_norm == 'unknown':
                inferred = self._infer_category_from_algorithm(actual_algo)
                result['identified_category'] = inferred
                result['category_match'] = (inferred != 'unknown' and inferred == actual_cat_norm)
                result['category_score'] = 1.0 if result['category_match'] else 0.0
            return result

        if not self.allow_partial_identification:
            # Strict mode: no partial credit for algorithm identification.
            return result

        # 2) SAME FAMILY MATCH (partial algorithm credit)
        family_score = self._get_family_match_score(actual_norm, identified_norm)
        if family_score > 0:
            result['score'] = family_score
            return result

        # 3) SAME BROAD CATEGORY (very partial algorithm credit)
        if self._is_same_broad_category(actual_norm, identified_norm):
            result['score'] = 0.3
            return result

        # 4) COMPLETELY WRONG
        return result

    def _get_family_match_score(self, actual: str, predicted: str) -> float:
        if 'aes' in actual and 'aes' in predicted:
            return 0.7
        if 'rsa' in actual and 'rsa' in predicted:
            return 0.9
        if any(word in actual for word in ['sha', 'blake']) and any(word in predicted for word in ['sha', 'blake']):
            if 'sha 256' in actual and 'sha' in predicted:
                return 0.9
            return 0.7
        if any(word in actual for word in ['ecdsa', 'ed25519']) and any(word in predicted for word in ['ecdsa', 'ed25519']):
            return 0.8
        if any(word in actual for word in ['caesar', 'vigenere', 'substitution']) and any(word in predicted for word in ['caesar', 'vigenere', 'substitution']):
            return 0.6
        return 0.0

    def _is_same_broad_category(self, actual: str, predicted: str) -> bool:
        categories = {
            'Classical': ['caesar', 'vigenere', 'substitution'],
            'Symmetric': ['aes', 'chacha'],
            'Asymmetric': ['rsa', 'ecdsa', 'ed25519'],
            'Hash': ['sha', 'blake'],
        }

        for _, keywords in categories.items():
            actual_in_category = any(keyword in actual for keyword in keywords)
            predicted_in_category = any(keyword in predicted for keyword in keywords)
            if actual_in_category and predicted_in_category:
                return True

        return False

    def _evaluate_decryption(self, parsed_data: Dict, plaintext: str, exact_match: bool, actual_algo: str, actual_category: str) -> float:
        # Decryption score should reflect how much of the true plaintext was recovered.
        # We score by word overlap with the gold plaintext (recall-like), not by admitting infeasibility.
        decryption_attempt = parsed_data.get('decryption_attempt', '')
        if not decryption_attempt or str(decryption_attempt).strip() == '':
            return 0.0

        # Hashes and signatures are not decryptable (decryption not applicable).
        if not self._is_decryption_applicable(actual_algo, actual_category):
            return 0.0

        attempt = str(decryption_attempt).strip()

        # Saying "can't decrypt" is correct behavior, but it is not a decryption success.
        if self._acknowledges_infeasible_decryption(attempt, actual_algo, actual_category):
            return 0.0

        if not plaintext or plaintext.strip() == '':
            return 0.0

        gold = plaintext.strip()

        if attempt == gold:
            return 1.0

        return float(self._calculate_word_overlap(attempt, gold))

    def _acknowledges_infeasible_decryption(self, attempt: str, actual_algo: str, actual_category: str) -> bool:
        a = (attempt or '').lower()
        algo_norm = self._normalize_algo_name(actual_algo)
        cat_norm = self._normalize_category(actual_category)

        # Hashes are one-way; "decryption" isn't applicable.
        if cat_norm == 'hash' or any(k in algo_norm for k in ['sha', 'blake']):
            return any(k in a for k in [
                'hash',
                'one-way',
                'not reversible',
                'cannot reverse',
                "can't reverse",
                'not encrypted',
                'cannot be decrypted',
                "can't be decrypted",
            ])

        # Signatures authenticate; they are not encryption.
        if any(k in algo_norm for k in ['ecdsa', 'ed25519']):
            return any(k in a for k in [
                'signature',
                'signed',
                'not encrypted',
                'no encryption',
                'cannot recover',
                "can't recover",
                'without the original message',
                'message is redacted',
                'redacted',
            ])

        # Modern encryption (and hybrid RSA) requires key material.
        if any(k in algo_norm for k in ['aes', 'chacha', 'rsa']):
            return any(k in a for k in [
                'cannot decrypt',
                "can't decrypt",
                'without the key',
                'without key',
                'requires the key',
                'need the key',
                'private key',
                'session key',
                'not possible to decrypt',
                'plaintext not recovered',
                'cannot recover plaintext',
                "can't recover plaintext",
                'unable to decrypt',
                'unable to recover',
                'no key provided',
                'key not provided',
            ])

        return False

    def _is_decryption_applicable(self, actual_algo: str, actual_category: str) -> bool:
        algo_norm = self._normalize_algo_name(actual_algo)
        cat_norm = self._normalize_category(actual_category)

        if cat_norm == 'hash' or any(k in algo_norm for k in ['sha', 'blake']):
            return False

        # Signatures are not encryption; "decryption" is not applicable.
        if any(k in algo_norm for k in ['ecdsa', 'ed25519']):
            return False

        # Classical + encryption (symmetric/hybrid RSA) are considered applicable in principle.
        return True


    def _calculate_word_overlap(self, attempt: str, plaintext: str) -> float:
        # Score by how many plaintext words appear in the attempt.
        # Returns common_word_count / plaintext_word_count in [0, 1].
        if not attempt or not plaintext:
            return 0.0

        stop_words = set(
            "the a an and or but if then else to of in on for with as at by from into is are was were be been being "
            "it this that these those i you he she we they them my your our their not no yes can could should would "
            "will just very also only such".split()
        )

        def _tokens(s: str) -> list[str]:
            return [
                w
                for w in re.findall(r"[a-z0-9]+", (s or "").lower())
                if len(w) >= 3 and w not in stop_words
            ]

        gold_tokens = _tokens(plaintext)
        attempt_tokens = _tokens(attempt)
        if not gold_tokens or not attempt_tokens:
            return 0.0

        from collections import Counter

        gold_counts = Counter(gold_tokens)
        attempt_counts = Counter(attempt_tokens)
        common = sum(min(gold_counts[w], attempt_counts.get(w, 0)) for w in gold_counts)
        total = sum(gold_counts.values())
        return (common / total) if total else 0.0

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        if not text1 or not text2:
            return 0.0
        stop_words = set(
            "the a an and or but if then else to of in on for with as at by from into is are was were be been being "
            "it this that these those i you he she we they them my your our their not no yes can could should would "
            "will just very also only such".split()
        )

        def _tokens(s: str) -> list:
            return [w for w in re.findall(r"[a-z0-9]+", (s or "").lower()) if len(w) >= 4 and w not in stop_words]

        attempt_tokens = _tokens(text1)
        plain_tokens = _tokens(text2)
        if not attempt_tokens or not plain_tokens:
            return 0.0

        from collections import Counter

        plain_counts = Counter(plain_tokens)
        attempt_counts = Counter(attempt_tokens)
        common = sum(min(plain_counts[w], attempt_counts.get(w, 0)) for w in plain_counts)
        total = sum(plain_counts.values())
        return (common / total) if total else 0.0

    def _evaluate_vulnerability_detection(self, parsed_data: Dict, actual_algo: str, exact_match: bool) -> float:
        vulnerabilities_found = parsed_data.get('vulnerabilities_found', [])

        if not exact_match:
            if vulnerabilities_found:
                return 0.1
            return 0.0

        expected_vulns = self._get_expected_vulnerabilities(actual_algo)
        if not expected_vulns:
            return 0.3

        if not vulnerabilities_found:
            return 0.2

        correct = 0
        for found in vulnerabilities_found:
            found_lower = found.lower()
            for expected in expected_vulns:
                if expected in found_lower:
                    correct += 1
                    break

        score = correct / len(expected_vulns) if expected_vulns else 0.0
        irrelevant = len(vulnerabilities_found) - correct
        penalty = min(0.3, irrelevant * 0.1)

        return max(0, score - penalty)

    def _get_expected_vulnerabilities(self, algorithm: str) -> List[str]:
        vuln_map = {
            'AES-ECB': ['pattern', 'deterministic', 'ecb'],
            'RSA-2048': ['factorization', 'small', 'weak prime'],
            'RSA-4096': ['factorization', 'weak prime'],
            'Caesar cipher': ['frequency', 'brute force', 'shift'],
            'Vigenere cipher': ['kasiski', 'frequency', 'repeating key'],
            'Substitution cipher': ['frequency', 'monoalphabetic'],
            'SHA-256': ['collision', 'length extension'],
            'SHA-3-256': ['collision'],
            'BLAKE3': ['collision'],
            'AES-CBC': ['padding oracle', 'iv reuse'],
            'AES-GCM': ['nonce reuse'],
            'AES-CTR': ['nonce reuse'],
            'ChaCha20-Poly1305': ['nonce reuse'],
            'ECDSA (P-256)': ['nonce reuse', 'side channel'],
            'Ed25519': ['implementation', 'side channel'],
        }
        return [v.lower() for v in vuln_map.get(algorithm, [])]

    def _evaluate_reasoning_quality(self, parsed_data: Dict) -> float:
        reasoning_steps = parsed_data.get('reasoning_steps', [])

        if not reasoning_steps:
            return 0.0

        step_score = min(len(reasoning_steps) / 5, 1.0) * 0.5

        technical_terms = 0
        crypto_terms = [
            'frequency', 'analysis', 'algorithm', 'key', 'encryption',
            'decryption', 'vulnerability', 'attack', 'cipher', 'hash',
            'signature', 'mode', 'iv', 'nonce', 'padding',
        ]

        for step in reasoning_steps:
            if any(term in step.lower() for term in crypto_terms):
                technical_terms += 1

        technical_score = (technical_terms / len(reasoning_steps)) * 0.5

        return step_score + technical_score

    def calculate_aggregate_metrics(self, evaluations: List[Dict]) -> Dict:
        if not evaluations:
            return {}

        successful = [e for e in evaluations if e['response_success']]

        if not successful:
            return {
                'total_tests': len(evaluations),
                'successful_analyses': 0,
                'success_rate': 0,
                'avg_overall_score': 0,
                'avg_identification_score': 0,
                'avg_category_score': 0,
                'avg_vulnerability_score': 0,
                'avg_decryption_score': 0,
                'avg_reasoning_score': 0,
                'exact_match_rate': 0,
                'category_match_rate': 0,
            }

        metrics = {
            'total_tests': len(evaluations),
            'successful_analyses': len(successful),
            'success_rate': len(successful) / len(evaluations),
            'avg_overall_score': np.mean([e['overall_score'] for e in successful]),
            'avg_identification_score': np.mean([e['identified_algorithm_score'] for e in successful]),
            'avg_category_score': np.mean([e.get('identified_category_score', 0.0) for e in successful]),
            'avg_vulnerability_score': np.mean([e['vulnerability_score'] for e in successful]),
            'avg_decryption_score': np.mean([e['decryption_score'] for e in successful]),
            'avg_decryption_score_applicable': np.mean([e['decryption_score'] for e in successful if e.get('decryption_applicable')]) if any(e.get('decryption_applicable') for e in successful) else 0.0,
            'decryption_applicable_count': int(sum(1 for e in successful if e.get('decryption_applicable'))),
            'decryption_ack_infeasible_rate': np.mean([bool(e.get('decryption_acknowledged_infeasible')) for e in successful]),
            'avg_decryption_plaintext_similarity_applicable': np.mean([float(e.get('decryption_plaintext_similarity', 0.0) or 0.0) for e in successful if e.get('decryption_applicable')]) if any(e.get('decryption_applicable') for e in successful) else 0.0,
            'decryption_plaintext_recovery_rate_0_9': np.mean([float(e.get('decryption_plaintext_similarity', 0.0) or 0.0) >= 0.9 for e in successful if e.get('decryption_applicable')]) if any(e.get('decryption_applicable') for e in successful) else 0.0,
            'avg_reasoning_score': np.mean([e['reasoning_score'] for e in successful]),
            'exact_match_rate': np.mean([e['exact_match'] for e in successful]),
            'category_match_rate': np.mean([e['category_match'] for e in successful]),
        }

        for key, value in metrics.items():
            if isinstance(value, float):
                metrics[key] = round(value, 3)

        # Backward-compatible aliases (some runners expect these keys)
        metrics['avg_identified_algorithm_score'] = metrics.get('avg_identification_score', 0)
        metrics['avg_identified_category_score'] = metrics.get('avg_category_score', 0)

        return metrics

