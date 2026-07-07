# src/deepseek_analyst/cryptanalysis_prompts.py
from typing import Dict, List

class CryptanalysisPrompts:

    def create_informed_prompt(self, encrypted_data: Dict, context: Dict = None) -> str:
        """Backwards-compatible alias for older clients/runners."""
        return self.create_deepseek_prompt(encrypted_data, context)
    def __init__(self):
        self.prompt_templates = self._setup_templates()
    
    def _setup_templates(self) -> Dict[str, str]:
        return {
            'comprehensive_analysis': """
You are an expert cryptanalyst. Analyze the following encrypted data and attempt cryptanalysis.

ENCRYPTED DATA:
{ciphertext_data}
{additional_context}

POSSIBLE ALGORITHMS (use these exact names if identified):
Classical Ciphers:
- Caesar cipher
- Vigenère cipher  
- Substitution cipher

Modern Symmetric Encryption:
- AES-GCM
- AES-CBC
- AES-CTR
- ChaCha20-Poly1305
- AES-ECB

Asymmetric Encryption:
- RSA-2048
- RSA-4096
- ECDSA (P-256)
- Ed25519

Hash Functions:
- SHA-256
- SHA-3-256
- BLAKE3

CRYPTOGRAPHIC KNOWLEDGE BASE:
- Classical Ciphers: Caesar, Vigenère, Substitution, Playfair, Transposition
- Modern Symmetric: AES (ECB, CBC, CTR, GCM), DES, 3DES, ChaCha20
- Modern Asymmetric: RSA, ECC, Diffie-Hellman
- Hash Functions: SHA-256, MD5, SHA-1, SHA-3, BLAKE3
- Cryptanalytic Techniques: Frequency analysis, Pattern recognition, Mathematical attacks, Side-channel analysis, Differential cryptanalysis

ANALYSIS REQUIREMENTS:
1. The encryption algorithm is provided in the data; confirm it and use it in your analysis
2. Analyze for known vulnerabilities or weaknesses
3. Suggest specific cryptanalytic attack vectors
4. If possible, provide decrypted plaintext or partial information
5. Explain your reasoning step by step with technical details
6. Rate your confidence in the analysis (0.0 to 1.0)
7. Suggest further analysis or verification steps
8. 'decryption_attempt' MUST be a short plain-English sentence
   - If you cannot decrypt or you are guessing, set it to: "Plaintext not recovered; see further_analysis."
   - Do NOT fabricate plausible plaintext.
   - Do NOT output structured JSON inside 'decryption_attempt'.

RESPONSE FORMAT (JSON):
{{
    "identified_algorithm": "algorithm_name_from_list",
    "estimated_parameters": {{"key_size": 128, "mode": "CBC", "vulnerabilities": []}},
    "suggested_attacks": ["attack1", "attack2", "attack3"],
    "decryption_attempt": "<plaintext if recovered; otherwise: Plaintext not recovered; see further_analysis.>",
    "confidence_score": 0.85,
    "reasoning_steps": [
        "Step 1: Analysis of ciphertext patterns",
        "Step 2: Identification of potential algorithm",
        "Step 3: Vulnerability assessment", 
        "Step 4: Attack vector selection",
        "Step 5: Decryption attempt"
    ],
    "vulnerabilities_found": ["vulnerability1", "vulnerability2"],
    "further_analysis": ["next_step1", "next_step2"],
    "security_assessment": "high|medium|low"
}}
""",
            'classical_cipher_focus': """
Focus on classical cipher analysis:

CIPHERTEXT: {ciphertext}
CONTEXT: {context}

POSSIBLE CLASSICAL ALGORITHMS:
- Caesar cipher
- Vigenère cipher
- Substitution cipher

SPECIFIC CLASSICAL TECHNIQUES TO APPLY:
1. Frequency analysis of characters
2. Pattern recognition for substitution ciphers  
3. Index of coincidence calculation
4. Kasiski examination for Vigenère
5. Playfair matrix reconstruction
6. Caesar shift detection

Provide detailed cryptanalysis with mathematical reasoning.
""",
            'modern_crypto_focus': """
Focus on modern cryptography analysis:

ENCRYPTION DATA: {encryption_data}
CONTEXT: {context}

POSSIBLE MODERN ALGORITHMS:
- AES-GCM
- AES-CBC
- AES-CTR
- ChaCha20-Poly1305
- AES-ECB
- RSA-2048
- RSA-4096
- ECDSA (P-256)
- Ed25519
- SHA-256
- SHA-3-256
- BLAKE3

MODERN CRYPTOANALYSIS APPROACHES:
1. Analyze encryption mode weaknesses (ECB patterns, CBC padding oracle)
2. Check for weak key usage or key derivation
3. Identify mathematical vulnerabilities (small RSA modulus, weak primes)
4. Assess implementation flaws
5. Evaluate side-channel attack possibilities

Provide technical analysis with cryptographic principles.
"""
        }
    
    def create_deepseek_prompt(self, encrypted_data: Dict, context: Dict = None) -> str:
        """Create specialized prompt for DeepSeek analysis"""
        template = self.prompt_templates['comprehensive_analysis']
        
        # Format ciphertext data (algorithm is included for algorithm_informed)
        ciphertext_data = self._format_ciphertext_data(encrypted_data)
        
        # Additional context
        additional_context = self._format_additional_context(context, encrypted_data)
        
        return template.format(
            ciphertext_data=ciphertext_data,
            additional_context=additional_context
        )
    
    def _format_ciphertext_data(self, encrypted_data: Dict) -> str:
        """Format ciphertext data for prompt (includes algorithm hints for algorithm_informed)."""
        data_lines = []
        
        if 'ciphertext' in encrypted_data:
            ciphertext = encrypted_data['ciphertext']
            # Truncate very long ciphertexts for readability
            if len(ciphertext) > 500:
                ciphertext = ciphertext[:500] + "... [truncated]"
            data_lines.append(f"Ciphertext: {ciphertext}")

        # Algorithm-informed setting: include explicit algorithm and any provided security hints
        if 'algorithm' in encrypted_data:
            data_lines.append(f"Known Algorithm: {encrypted_data['algorithm']}")

        if 'weakness' in encrypted_data:
            data_lines.append(f"Known Weakness: {encrypted_data['weakness']}")

        if 'security_warning' in encrypted_data:
            data_lines.append(f"Security Warning: {encrypted_data['security_warning']}")

        if 'vulnerabilities' in encrypted_data:
            data_lines.append(f"Known Vulnerabilities: {encrypted_data['vulnerabilities']}")

        
        # Include technical parameters but NOT the algorithm name
        if 'iv' in encrypted_data:
            data_lines.append(f"IV/Nonce: {encrypted_data['iv']}")
        
        if 'tag' in encrypted_data:
            data_lines.append(f"Authentication Tag: {encrypted_data['tag']}")
        
        if 'hash' in encrypted_data:
            data_lines.append(f"Hash: {encrypted_data['hash']}")
        
        if 'signature' in encrypted_data:
            data_lines.append(f"Signature: {encrypted_data['signature']}")
        
        if 'encrypted_session_key' in encrypted_data:
            data_lines.append(f"Encrypted Session Key: {encrypted_data['encrypted_session_key'][:100]}...")
        
        # Include technical parameters that might help identification but don't reveal algorithm
        if 'key_size' in encrypted_data:
            data_lines.append(f"Key Size: {encrypted_data['key_size']} bits")
        
        if 'mode' in encrypted_data:
            data_lines.append(f"Mode: {encrypted_data['mode']}")
        
        return '\n'.join(data_lines) if data_lines else "Encrypted data provided"
    
    def _format_additional_context(self, context: Dict, encrypted_data: Dict) -> str:
        """Format additional context for prompt"""
        if not context:
            return "No additional context provided"
        
        context_lines = []
        
        if 'test_case' in context:
            test_case = context['test_case']
            context_lines.append(f"Test ID: {test_case.get('test_id', 'Unknown')}")
            context_lines.append(f"Difficulty: {test_case.get('difficulty', 'Unknown')}")
            context_lines.append(f"Category: {test_case.get('category', 'Unknown')}")
        
        if 'hints' in context:
            context_lines.append(f"Hints: {context['hints']}")
        
        # Algorithm-informed setting: include any explicit weakness/warnings if present
        if 'weakness' in encrypted_data:
            context_lines.append(f"Known Weakness: {encrypted_data['weakness']}")

        if 'security_warning' in encrypted_data:
            context_lines.append(f"Security Warning: {encrypted_data['security_warning']}")
        
        return '\n'.join(context_lines)
# REFRESH_2026
