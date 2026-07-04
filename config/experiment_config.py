# config/experiment_config.py
class ExperimentConfig:
    def __init__(self):
        # API Configuration
        self.batch_size = 5
        self.batch_delay = 5
        self.concurrent_requests = 1
        self.max_retries = 3
        self.request_timeout = 120
        
        # Test case configuration - 60 tests for each of 15 algorithms = 900 total
        self.caesar_count = 60
        self.vigenere_count = 60  
        self.substitution_count = 60
        self.aes_gcm_count = 60
        self.aes_cbc_count = 60
        self.aes_ctr_count = 60
        self.chacha20_count = 60
        self.aes_ecb_count = 60
        self.rsa_2048_count = 60
        self.rsa_4096_count = 60
        self.ecdsa_count = 60
        self.ed25519_count = 60
        self.sha256_count = 60
        self.sha3_256_count = 60
        self.blake3_count = 60
        
        # Derived totals
        self.classical_cipher_count = self.caesar_count + self.vigenere_count + self.substitution_count
        self.modern_symmetric_count = (self.aes_gcm_count + self.aes_cbc_count + self.aes_ctr_count + 
                                     self.chacha20_count + self.aes_ecb_count)
        self.asymmetric_count = self.rsa_2048_count + self.rsa_4096_count + self.ecdsa_count + self.ed25519_count
        self.hash_count = self.sha256_count + self.sha3_256_count + self.blake3_count
        self.total_tests = (self.classical_cipher_count + self.modern_symmetric_count + 
                          self.asymmetric_count + self.hash_count)