# src/crypto_systems/symmetric_modern.py
from Crypto.Cipher import AES, DES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import random
from typing import Dict, List
import hashlib

class ModernSymmetricCrypto:
    def __init__(self):
        self.supported_modes = ['ECB', 'CBC', 'CTR', 'GCM']
        from .NIST_STANDARD_TEXTS import NIST_STANDARD_TEXTS
        from .text_processor import chunk_text
        
        self.plaintext_samples = []
        for text in NIST_STANDARD_TEXTS:
            self.plaintext_samples.extend(chunk_text(text, 100))
    
    def aes_encrypt(self, plaintext: str, key: bytes, mode: str = 'CBC', **kwargs) -> Dict:
        if mode.upper() == 'ECB':
            return self._aes_ecb(plaintext, key)
        elif mode.upper() == 'CBC':
            return self._aes_cbc(plaintext, key)
        elif mode.upper() == 'CTR':
            return self._aes_ctr(plaintext, key)
        elif mode.upper() == 'GCM':
            return self._aes_gcm(plaintext, key)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
    
    def _aes_ecb(self, plaintext: str, key: bytes) -> Dict:
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'ciphertext_len_bytes': len(ciphertext),
            'iv_len_bytes': 0,
            'nonce_len_bytes': 0,
            'tag_len_bytes': 0,
            'algorithm': 'AES-ECB',
            'key_size': len(key) * 8,
            'mode': 'ECB',
            'security_warning': 'ECB mode is insecure and reveals patterns',
            'vulnerabilities': ['pattern_revelation', 'deterministic_encryption']
        }
    
    def _aes_cbc(self, plaintext: str, key: bytes) -> Dict:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'ciphertext_len_bytes': len(ciphertext),
            'iv': base64.b64encode(iv).decode(),
            'iv_len_bytes': len(iv),
            'nonce_len_bytes': 0,
            'tag_len_bytes': 0,
            'algorithm': 'AES-CBC',
            'key_size': len(key) * 8,
            'mode': 'CBC',
            'security_level': 'medium'
        }
    
    def _aes_gcm(self, plaintext: str, key: bytes) -> Dict:
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'ciphertext_len_bytes': len(ciphertext),
            'nonce': base64.b64encode(nonce).decode(),
            'nonce_len_bytes': len(nonce),
            'tag': base64.b64encode(tag).decode(),
            'tag_len_bytes': len(tag),
            'iv_len_bytes': 0,
            'algorithm': 'AES-GCM',
            'key_size': len(key) * 8,
            'mode': 'GCM',
            'security_level': 'high',
            'authentication': True
        }
    
    def _aes_ctr(self, plaintext: str, key: bytes) -> Dict:
        nonce = get_random_bytes(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext.encode())
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'ciphertext_len_bytes': len(ciphertext),
            'nonce': base64.b64encode(nonce).decode(),
            'nonce_len_bytes': len(nonce),
            'iv_len_bytes': 0,
            'tag_len_bytes': 0,
            'algorithm': 'AES-CTR',
            'key_size': len(key) * 8,
            'mode': 'CTR',
            'security_level': 'medium'
        }
    
    def chacha20_encrypt(self, plaintext: str, key: bytes) -> Dict:
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'ciphertext_len_bytes': len(ciphertext),
            'nonce': base64.b64encode(nonce).decode(),
            'nonce_len_bytes': len(nonce),
            'tag': base64.b64encode(tag).decode(),
            'tag_len_bytes': len(tag),
            'iv_len_bytes': 0,
            'algorithm': 'ChaCha20-Poly1305',
            'key_size': len(key) * 8,
            'security_level': 'high',
            'authentication': True
        }
    
    def generate_hash_test_cases(self, max_per_algorithm: int | None = None) -> List[Dict]:
        from config.experiment_config import ExperimentConfig
        config = ExperimentConfig()
        test_cases = []

        def _limit(n: int) -> int:
            return n if max_per_algorithm is None else min(n, int(max_per_algorithm))

        def _limit(n: int) -> int:
            return n if max_per_algorithm is None else min(n, int(max_per_algorithm))
        
        # SHA-256 cases - 60 tests
        for i in range(_limit(config.sha256_count)):
            plaintext = random.choice(self.plaintext_samples)
            hash_value = hashlib.sha256(plaintext.encode()).hexdigest()
            
            test_cases.append({
                'test_id': f"sha256_{i:03d}",
                'algorithm': 'SHA-256',
                'plaintext': plaintext,
                'encrypted_data': {
                    'hash': hash_value,
                    'digest_len_bytes': 32,
                    'algorithm': 'SHA-256',
                    'digest_size': 256
                },
                'difficulty': 'medium',
                'category': 'hash'
            })
        
        # SHA-3-256 cases - 60 tests
        for i in range(_limit(config.sha3_256_count)):
            plaintext = random.choice(self.plaintext_samples)
            hash_value = hashlib.sha3_256(plaintext.encode()).hexdigest()
            
            test_cases.append({
                'test_id': f"sha3_256_{i:03d}",
                'algorithm': 'SHA-3-256',
                'plaintext': plaintext,
                'encrypted_data': {
                    'hash': hash_value,
                    'digest_len_bytes': 32,
                    'algorithm': 'SHA-3-256',
                    'digest_size': 256
                },
                'difficulty': 'medium',
                'category': 'hash'
            })
        
        # BLAKE3 cases - 60 tests
        try:
            import blake3
            for i in range(_limit(config.blake3_count)):
                plaintext = random.choice(self.plaintext_samples)
                hash_value = blake3.blake3(plaintext.encode()).hexdigest()
                
                test_cases.append({
                    'test_id': f"blake3_{i:03d}",
                    'algorithm': 'BLAKE3',
                    'plaintext': plaintext,
                    'encrypted_data': {
                        'hash': hash_value,
                        'digest_len_bytes': 32,
                        'algorithm': 'BLAKE3'
                    },
                    'difficulty': 'medium',
                    'category': 'hash'
                })
        except ImportError:
            # Fallback to hashlib if blake3 not available
            for i in range(_limit(config.blake3_count)):
                plaintext = random.choice(self.plaintext_samples)
                hash_value = hashlib.sha256(plaintext.encode()).hexdigest()
                
                test_cases.append({
                    'test_id': f"blake3_{i:03d}",
                    'algorithm': 'BLAKE3',
                    'plaintext': plaintext,
                    'encrypted_data': {
                        'hash': hash_value,
                        'digest_len_bytes': 32,
                        'algorithm': 'BLAKE3'
                    },
                    'difficulty': 'medium',
                    'category': 'hash'
                })
        
        return test_cases
    
    def generate_symmetric_test_cases(self, max_per_algorithm: int | None = None) -> List[Dict]:
        from config.experiment_config import ExperimentConfig
        config = ExperimentConfig()
        test_cases = []

        def _limit(n: int) -> int:
            return n if max_per_algorithm is None else min(n, int(max_per_algorithm))

        def _limit(n: int) -> int:
            return n if max_per_algorithm is None else min(n, int(max_per_algorithm))
        
        # AES-GCM cases - 60 tests
        for i in range(_limit(config.aes_gcm_count)):
            plaintext = random.choice(self.plaintext_samples)
            key = get_random_bytes(32)
            encrypted = self._aes_gcm(plaintext, key)
            
            test_cases.append({
                'test_id': f"aes_gcm_{i:03d}",
                'algorithm': 'AES-GCM',
                'plaintext': plaintext,
                'encrypted_data': encrypted,
                'security_level': 'high',
                'difficulty': 'very_hard',
                'category': 'modern_symmetric'
            })
        
        # AES-CBC cases - 60 tests
        for i in range(_limit(config.aes_cbc_count)):
            plaintext = random.choice(self.plaintext_samples)
            key = get_random_bytes(32)
            encrypted = self._aes_cbc(plaintext, key)
            
            test_cases.append({
                'test_id': f"aes_cbc_{i:03d}",
                'algorithm': 'AES-CBC',
                'plaintext': plaintext,
                'encrypted_data': encrypted,
                'security_level': 'medium',
                'difficulty': 'hard',
                'category': 'modern_symmetric'
            })
        
        # AES-CTR cases - 60 tests
        for i in range(_limit(config.aes_ctr_count)):
            plaintext = random.choice(self.plaintext_samples)
            key = get_random_bytes(32)
            encrypted = self._aes_ctr(plaintext, key)
            
            test_cases.append({
                'test_id': f"aes_ctr_{i:03d}",
                'algorithm': 'AES-CTR',
                'plaintext': plaintext,
                'encrypted_data': encrypted,
                'security_level': 'medium',
                'difficulty': 'hard',
                'category': 'modern_symmetric'
            })
        
        # ChaCha20-Poly1305 cases - 60 tests
        for i in range(_limit(config.chacha20_count)):
            plaintext = random.choice(self.plaintext_samples)
            key = get_random_bytes(32)
            encrypted = self.chacha20_encrypt(plaintext, key)
            
            test_cases.append({
                'test_id': f"chacha20_{i:03d}",
                'algorithm': 'ChaCha20-Poly1305',
                'plaintext': plaintext,
                'encrypted_data': encrypted,
                'security_level': 'high',
                'difficulty': 'very_hard',
                'category': 'modern_symmetric'
            })
        
        # AES-ECB cases - 60 tests
        for i in range(_limit(config.aes_ecb_count)):
            plaintext = random.choice(self.plaintext_samples)
            key = get_random_bytes(16)
            encrypted = self._aes_ecb(plaintext, key)
            
            test_cases.append({
                'test_id': f"aes_ecb_{i:03d}",
                'algorithm': 'AES-ECB',
                'plaintext': plaintext,
                'encrypted_data': encrypted,
                'weakness': 'ECB_mode_patterns',
                'difficulty': 'medium',
                'category': 'modern_symmetric'
            })
        
        return test_cases
        
    def generate_test_cases(self, max_per_algorithm: int | None = None) -> List[Dict]:
        symmetric_cases = self.generate_symmetric_test_cases(max_per_algorithm=max_per_algorithm)
        hash_cases = self.generate_hash_test_cases(max_per_algorithm=max_per_algorithm)
        return symmetric_cases + hash_cases