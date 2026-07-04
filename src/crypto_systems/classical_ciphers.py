# src/crypto_systems/classical_ciphers.py
import string
import random
from typing import Dict, List, Tuple
import math

class ClassicalCiphers:
    def __init__(self):
        self.alphabet = string.ascii_lowercase
        self.alphabet_upper = string.ascii_uppercase
        from .NIST_STANDARD_TEXTS import NIST_STANDARD_TEXTS
        from .text_processor import chunk_text
        
        self.plaintext_samples = []
        for text in NIST_STANDARD_TEXTS:
            self.plaintext_samples.extend(chunk_text(text, 100))
    
    def caesar_cipher(self, text: str, shift: int, preserve_case: bool = True) -> str:
        result = []
        
        for char in text:
            if char.islower() and char in self.alphabet:
                new_pos = (self.alphabet.index(char) + shift) % 26
                result.append(self.alphabet[new_pos])
            elif char.isupper() and char in self.alphabet_upper:
                new_pos = (self.alphabet_upper.index(char) + shift) % 26
                result.append(self.alphabet_upper[new_pos])
            else:
                result.append(char)
        
        return ''.join(result)
    
    def vigenere_cipher(self, text: str, key: str, preserve_case: bool = True) -> str:
        result = []
        key = key.lower()
        key_index = 0
        
        for char in text:
            if char.islower() and char in self.alphabet:
                shift = self.alphabet.index(key[key_index % len(key)])
                new_pos = (self.alphabet.index(char) + shift) % 26
                result.append(self.alphabet[new_pos])
                key_index += 1
            elif char.isupper() and char in self.alphabet_upper:
                shift = self.alphabet.index(key[key_index % len(key)])
                new_pos = (self.alphabet_upper.index(char) + shift) % 26
                result.append(self.alphabet_upper[new_pos])
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def substitution_cipher(self, text: str, key: Dict[str, str] = None) -> str:
        if key is None:
            key = self._generate_substitution_key()
        
        result = []
        for char in text:
            if char.lower() in key:
                if char.isupper():
                    result.append(key[char.lower()].upper())
                else:
                    result.append(key[char])
            else:
                result.append(char)
        
        return ''.join(result)
    
    def _generate_substitution_key(self) -> Dict[str, str]:
        shuffled = list(self.alphabet)
        random.shuffle(shuffled)
        return dict(zip(self.alphabet, shuffled))
    
    def generate_test_cases(self, max_per_algorithm: int | None = None) -> List[Dict]:
        from config.experiment_config import ExperimentConfig
        config = ExperimentConfig()
        test_cases = []

        def _limit(n: int) -> int:
            return n if max_per_algorithm is None else min(n, int(max_per_algorithm))
        
        # Caesar cipher cases - 60 tests
        for i in range(_limit(config.caesar_count)):
            plaintext = random.choice(self.plaintext_samples)
            shift = random.randint(1, 25)
            ciphertext = self.caesar_cipher(plaintext, shift)
            
            test_cases.append({
                'test_id': f'caesar_{i:03d}',
                'algorithm': 'Caesar cipher',
                'plaintext': plaintext,
                'ciphertext': ciphertext,
                'encrypted_data': {
                    'ciphertext': ciphertext,
                    'algorithm': 'Caesar cipher',},
                'difficulty': 'easy',
                'category': 'classical'
            })
        
        # Vigenere cipher cases - 60 tests
        vigenere_keys = ['CRYPTO', 'SECRET', 'PASSWORD', 'ALGORITHM', 'SECURITY', 
                        'COMPLEX', 'ADVANCED', 'ANALYSIS', 'QUANTUM', 'NETWORK',
                        'ENCRYPT', 'DECRYPT', 'CIPHER', 'MESSAGE', 'PROTECT']
        for i in range(_limit(config.vigenere_count)):
            plaintext = random.choice(self.plaintext_samples)
            key = random.choice(vigenere_keys)
            ciphertext = self.vigenere_cipher(plaintext, key)
            
            test_cases.append({
                'test_id': f'vigenere_{i:03d}',
                'algorithm': 'Vigenère cipher',
                'plaintext': plaintext,
                'ciphertext': ciphertext,
                'encrypted_data': {
                    'ciphertext': ciphertext,
                    'algorithm': 'Vigenère cipher',},
                'difficulty': 'medium',
                'category': 'classical'
            })
        
        # Substitution cipher cases - 60 tests
        for i in range(_limit(config.substitution_count)):
            plaintext = random.choice(self.plaintext_samples)
            key = self._generate_substitution_key()
            ciphertext = self.substitution_cipher(plaintext, key)
            
            test_cases.append({
                'test_id': f'substitution_{i:03d}',
                'algorithm': 'Substitution cipher',
                'plaintext': plaintext,
                'ciphertext': ciphertext,
                'encrypted_data': {
                    'ciphertext': ciphertext,
                    'algorithm': 'Substitution cipher',
                    'parameters': {'key': 'random'}
                },
                'difficulty': 'hard',
                'category': 'classical'
            })
        
        print(f"Generated {len(test_cases)} classical cipher test cases")
        return test_cases