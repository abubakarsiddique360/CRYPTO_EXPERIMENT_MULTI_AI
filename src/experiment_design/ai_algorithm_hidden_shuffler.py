"""
AI AlgorithmHidden Shuffler - Randomizes and anonymizes test cases to prevent AI from 
detecting algorithms through patterns or sequence.
Created for: Experiment where algorithms are hidden from AI
"""

import random
import json
import copy
from typing import Dict, List


_SECRET_TOP_LEVEL_KEYS = {
    'private_key',
    'secret_key',
    'shared_secret',
    'raw_key',
    'key_bytes',
}


def _redact_secret_top_level_keys(obj):
    '''Remove clearly-secret top-level fields.

    Important: this is intentionally NOT recursive, so we preserve
    researcher-facing algorithm parameters like encrypted_data.parameters.key
    (DeepSeek keeps these in original_case).
    '''
    if not isinstance(obj, dict):
        return
    for k in _SECRET_TOP_LEVEL_KEYS:
        obj.pop(k, None)


class AIAlgorithmHiddenShuffler:
    """Shuffle and anonymize test cases to prevent AI pattern detection"""
    
    def __init__(self, test_cases: List[Dict]):
        self.test_cases = test_cases
        self.shuffled_cases = []
        self.mapping = {}
        
    def shuffle_with_stratification(self, seed: int = 42):
        """Shuffle test cases with stratification to prevent algorithm inference"""
        random.seed(seed)
        
        # Group by algorithm
        algorithm_groups = {}
        for test_case in self.test_cases:
            algo = test_case['algorithm']
            if algo not in algorithm_groups:
                algorithm_groups[algo] = []
            algorithm_groups[algo].append(test_case)
        
        # Get max cases per algorithm
        max_cases = max(len(cases) for cases in algorithm_groups.values())
        
        # Interleave cases from different algorithms
        interleaved = []
        for i in range(max_cases):
            for algo, cases in algorithm_groups.items():
                if i < len(cases):
                    interleaved.append(cases[i])
        
        # Final shuffle
        random.shuffle(interleaved)
        
        # Create anonymized versions
        self.shuffled_cases = []
        for i, original_case in enumerate(interleaved, 1):
            anonymized_case = self._anonymize_test_case(original_case, i)
            oc = copy.deepcopy(original_case)
            _redact_secret_top_level_keys(oc)

            self.mapping[anonymized_case['test_id']] = {
                'original_id': original_case['test_id'],
                'algorithm': original_case['algorithm'],
                'category': original_case['category'],
                'difficulty': original_case['difficulty'],
                'original_case': oc,
            }
            self.shuffled_cases.append(anonymized_case)
        
        print(f"Shuffled {len(self.shuffled_cases)} test cases")
        return self.shuffled_cases
    
    def _anonymize_test_case(self, test_case: Dict, counter: int) -> Dict:
        """Remove all algorithm-specific information from test case"""
        anonymized_id = f"test_{counter:03d}"
        
        anonymized = {
            'test_id': anonymized_id,
            'encrypted_data': copy.deepcopy(test_case['encrypted_data'])
        }
        
        # Remove algorithm hints
        encrypted_data = anonymized['encrypted_data']
        fields_to_remove = ['algorithm', 'security_level', 'security_warning', 
                           'vulnerabilities', 'authentication', 'stream_cipher']
        
        for field in fields_to_remove:
            encrypted_data.pop(field, None)
        
        # Anonymize mode
        if 'mode' in encrypted_data:
            mode_mapping = {
                'ECB': 'Mode_A', 'CBC': 'Mode_B', 
                'GCM': 'Mode_C', 'CTR': 'Mode_D'
            }
            if encrypted_data['mode'] in mode_mapping:
                encrypted_data['mode'] = mode_mapping[encrypted_data['mode']]
        
        return anonymized
    
    def get_original_info(self, anonymized_id: str) -> Dict:
        """Get original test case information"""
        return self.mapping.get(anonymized_id, {})
    
    def save_mapping(self, filename: str):
        """Save mapping file.

        The mapping is for researcher reference only; redact plaintext/key material to avoid
        accidental leakage into artifacts.
        """

        safe_mapping: Dict[str, Dict] = {}
        for test_id, info in self.mapping.items():
            entry = dict(info)
            oc = entry.get('original_case')
            if isinstance(oc, dict):
                oc2 = dict(oc)
                oc2.pop('plaintext', None)
                for k in ('key', 'private_key', 'secret_key', 'shared_secret', 'raw_key', 'key_bytes'):
                    oc2.pop(k, None)
                entry['original_case'] = oc2
            safe_mapping[test_id] = entry

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(safe_mapping, f, indent=2, ensure_ascii=False)
        print(f"Mapping saved to {filename}")

    def save_audit_mapping(self, filename: str):
        """Save an audit mapping file.

        This file is *not* meant for normal result artifacts. It keeps plaintext
        for manual spot-checking, but still removes key material.
        """

        audit_mapping: Dict[str, Dict] = {}
        for test_id, info in self.mapping.items():
            entry = dict(info)
            oc = entry.get('original_case')
            if isinstance(oc, dict):
                oc2 = dict(oc)
                for k in ('key', 'private_key', 'secret_key', 'shared_secret', 'raw_key', 'key_bytes'):
                    oc2.pop(k, None)
                entry['original_case'] = oc2
            audit_mapping[test_id] = entry

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(audit_mapping, f, indent=2, ensure_ascii=False)
        print(f"Audit mapping saved to {filename}")

