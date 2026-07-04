# src/crypto_systems/asymmetric_crypto.py
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15, eddsa, DSS
from Crypto.Hash import SHA256, SHA512, SHA3_256
from Crypto.Random import get_random_bytes
import base64
import random
from typing import Dict, List

class AsymmetricCrypto:
    def __init__(self):
        from .NIST_STANDARD_TEXTS import NIST_STANDARD_TEXTS
        from .text_processor import chunk_text
        
        self.plaintext_samples = []
        for text in NIST_STANDARD_TEXTS:
            self.plaintext_samples.extend(chunk_text(text, 100))
    
    def generate_rsa_keypair(self, key_size: int = 2048) -> Dict:
        key = RSA.generate(key_size)
        
        return {
            'private_key': key.export_key().decode(),
            'public_key': key.publickey().export_key().decode(),
            'key_size': key_size,
            'algorithm': f'RSA-{key_size}',
            'security_level': 'strong' if key_size >= 2048 else 'weak'
        }
    
    def generate_ecdsa_keypair(self) -> Dict:
        key = ECC.generate(curve='P-256')
        
        return {
            'private_key': key.export_key(format='PEM'),
            'public_key': key.public_key().export_key(format='PEM'),
            'algorithm': 'ECDSA (P-256)',
            'curve': 'P-256',
            'security_level': 'high'
        }
    
    def generate_ed25519_keypair(self) -> Dict:
        key = ECC.generate(curve='ed25519')
        
        return {
            'private_key': key.export_key(format='PEM'),
            'public_key': key.public_key().export_key(format='PEM'),
            'algorithm': 'Ed25519',
            'curve': 'ed25519',
            'security_level': 'high'
        }
    
    def rsa_encrypt(self, plaintext: str, public_key_pem: str) -> Dict:
        public_key = RSA.import_key(public_key_pem)
        return self._rsa_hybrid_encrypt(plaintext, public_key)
    
    def _rsa_hybrid_encrypt(self, plaintext: str, public_key: RSA.RsaKey) -> Dict:
        from .symmetric_modern import ModernSymmetricCrypto
        
        session_key = get_random_bytes(32)
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        encrypted_key = cipher_rsa.encrypt(session_key)
        
        sym_crypto = ModernSymmetricCrypto()
        encrypted_data = sym_crypto.aes_encrypt(plaintext, session_key, 'GCM')
        
        return {
            'encrypted_session_key': base64.b64encode(encrypted_key).decode(),
            'encrypted_session_key_len_bytes': len(encrypted_key),
            'encrypted_data': encrypted_data,
            'algorithm': f'RSA-{public_key.size_in_bits()}-AES-GCM',
            'key_size': public_key.size_in_bits(),
            'encryption_type': 'hybrid'
        }
    
    def ecdsa_sign(self, message: str, private_key_pem: str) -> Dict:
        key = ECC.import_key(private_key_pem)
        h = SHA256.new(message.encode())
        signer = DSS.new(key, 'fips-186-3', encoding='der')
        signature = signer.sign(h)
        
        return {
            'message': message,
            'signature': base64.b64encode(signature).decode(),
            'signature_len_bytes': len(signature),
            'algorithm': 'ECDSA (P-256)',
            'hash_algorithm': 'SHA-256'
        }
    
    def ed25519_sign(self, message: str, private_key_pem: str) -> Dict:
        key = ECC.import_key(private_key_pem)
        
        # Ed25519 requires the raw message, not a hash
        signer = eddsa.new(key, 'rfc8032')
        signature = signer.sign(message.encode())
        
        return {
            'message': message,
            'signature': base64.b64encode(signature).decode(),
            'signature_len_bytes': len(signature),
            'algorithm': 'Ed25519',
            'hash_algorithm': 'SHA-512'  # Ed25519 internally uses SHA-512
        }
    
    def generate_test_cases(self, max_per_algorithm: int | None = None) -> List[Dict]:
        from config.experiment_config import ExperimentConfig
        config = ExperimentConfig()
        test_cases = []

        def _limit(n: int) -> int:
            return n if max_per_algorithm is None else min(n, int(max_per_algorithm))
        
        # RSA-2048 cases - 60 tests
        for i in range(_limit(config.rsa_2048_count)):
            keypair = self.generate_rsa_keypair(2048)
            plaintext = random.choice(self.plaintext_samples)
            encrypted = self.rsa_encrypt(plaintext, keypair['public_key'])
            
            test_cases.append({
                'test_id': f"rsa_2048_{i:03d}",
                'algorithm': 'RSA-2048',
                'plaintext': plaintext,
                'encrypted_data': encrypted,
                'keypair_info': {
                    'key_size': 2048,
                    'description': 'standard'
                },
                'difficulty': 'hard',
                'category': 'asymmetric'
            })
        
        # RSA-4096 cases - 60 tests
        for i in range(_limit(config.rsa_4096_count)):
            keypair = self.generate_rsa_keypair(4096)
            plaintext = random.choice(self.plaintext_samples)
            encrypted = self.rsa_encrypt(plaintext, keypair['public_key'])
            
            test_cases.append({
                'test_id': f"rsa_4096_{i:03d}",
                'algorithm': 'RSA-4096',
                'plaintext': plaintext,
                'encrypted_data': encrypted,
                'keypair_info': {
                    'key_size': 4096,
                    'description': 'strong'
                },
                'difficulty': 'very_hard',
                'category': 'asymmetric'
            })
        
        # ECDSA cases - 60 tests
        for i in range(_limit(config.ecdsa_count)):
            keypair = self.generate_ecdsa_keypair()
            plaintext = random.choice(self.plaintext_samples)
            signed = self.ecdsa_sign(plaintext, keypair['private_key'])
            
            test_cases.append({
                'test_id': f"ecdsa_{i:03d}",
                'algorithm': 'ECDSA (P-256)',
                'plaintext': plaintext,
                'encrypted_data': signed,
                'keypair_info': {
                    'curve': 'P-256',
                    'description': 'elliptic_curve'
                },
                'difficulty': 'very_hard',
                'category': 'asymmetric'
            })
        
        # Ed25519 cases - 60 tests
        for i in range(_limit(config.ed25519_count)):
            keypair = self.generate_ed25519_keypair()
            plaintext = random.choice(self.plaintext_samples)
            signed = self.ed25519_sign(plaintext, keypair['private_key'])
            
            test_cases.append({
                'test_id': f"ed25519_{i:03d}",
                'algorithm': 'Ed25519',
                'plaintext': plaintext,
                'encrypted_data': signed,
                'keypair_info': {
                    'curve': 'ed25519',
                    'description': 'edwards_curve'
                },
                'difficulty': 'very_hard',
                'category': 'asymmetric'
            })
        
        print(f"Generated {len(test_cases)} asymmetric crypto test cases")
        return test_cases