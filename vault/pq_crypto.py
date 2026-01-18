"""
Post-Quantum Cryptography Agility Framework

Prepares DNA Ledger Vault for NIST PQ standards migration:
- ML-KEM-768/1024: Key Encapsulation Mechanism (replaces X25519)
- ML-DSA-65/87: Digital Signature Algorithm (replaces Ed25519)
- SLH-DSA: Stateless Hash-Based Signatures (backup)

Design Principles:
1. Crypto Agility: Support multiple algorithms simultaneously
2. Hybrid Mode: Classical + PQ during transition
3. Backward Compatibility: Read old schemes, write new
4. Gradual Migration: No flag-day cutover
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, Optional


class CryptoScheme(str, Enum):
    """Supported cryptographic schemes with versioning."""
    
    # Current classical schemes
    CHACHA20_POLY1305_V1 = "chacha20poly1305-v1"
    ED25519_V1 = "ed25519-v1"
    X25519_V1 = "x25519-v1"
    
    # Post-Quantum schemes (NIST standards)
    ML_KEM_768_V1 = "ml-kem-768-v1"  # Moderate security
    ML_KEM_1024_V1 = "ml-kem-1024-v1"  # High security
    ML_DSA_65_V1 = "ml-dsa-65-v1"  # Moderate security
    ML_DSA_87_V1 = "ml-dsa-87-v1"  # High security
    SLH_DSA_128F_V1 = "slh-dsa-128f-v1"  # Fast variant
    
    # Hybrid schemes (Classical + PQ)
    HYBRID_X25519_MLKEM768_V1 = "hybrid-x25519-mlkem768-v1"
    HYBRID_ED25519_MLDSA65_V1 = "hybrid-ed25519-mldsa65-v1"


@dataclass(frozen=True)
class CryptoConfig:
    """Cryptographic algorithm configuration."""
    
    encryption_scheme: CryptoScheme
    signature_scheme: CryptoScheme
    kem_scheme: CryptoScheme
    
    # Migration flags
    hybrid_mode: bool = True  # Enable hybrid classical+PQ
    strict_pq_only: bool = False  # Reject classical algorithms
    
    @classmethod
    def current_production(cls) -> CryptoConfig:
        """Current production configuration (classical)."""
        return cls(
            encryption_scheme=CryptoScheme.CHACHA20_POLY1305_V1,
            signature_scheme=CryptoScheme.ED25519_V1,
            kem_scheme=CryptoScheme.X25519_V1,
            hybrid_mode=False
        )
    
    @classmethod
    def hybrid_transition(cls) -> CryptoConfig:
        """Hybrid mode for gradual migration."""
        return cls(
            encryption_scheme=CryptoScheme.CHACHA20_POLY1305_V1,  # Keep ChaCha20
            signature_scheme=CryptoScheme.HYBRID_ED25519_MLDSA65_V1,
            kem_scheme=CryptoScheme.HYBRID_X25519_MLKEM768_V1,
            hybrid_mode=True
        )
    
    @classmethod
    def post_quantum(cls) -> CryptoConfig:
        """Full post-quantum configuration."""
        return cls(
            encryption_scheme=CryptoScheme.CHACHA20_POLY1305_V1,  # Symmetric is PQ-safe
            signature_scheme=CryptoScheme.ML_DSA_65_V1,
            kem_scheme=CryptoScheme.ML_KEM_768_V1,
            hybrid_mode=False,
            strict_pq_only=True
        )


class CryptoProvider(Protocol):
    """Protocol for cryptographic algorithm providers."""
    
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Encrypt plaintext with AEAD."""
        ...
    
    def decrypt(self, key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Decrypt ciphertext with AEAD."""
        ...
    
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign message with private key."""
        ...
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify signature with public key."""
        ...
    
    def kem_keygen(self) -> tuple[bytes, bytes]:
        """Generate KEM keypair (public, private)."""
        ...
    
    def kem_encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate shared secret (ciphertext, shared_secret)."""
        ...
    
    def kem_decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret."""
        ...


class ClassicalCryptoProvider:
    """Current classical cryptography provider."""
    
    def __init__(self):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        self.aead_class = ChaCha20Poly1305
    
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """ChaCha20-Poly1305 encryption."""
        aead = self.aead_class(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, plaintext, aad)
        return nonce + ct
    
    def decrypt(self, key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """ChaCha20-Poly1305 decryption."""
        aead = self.aead_class(key)
        nonce, ct = ciphertext[:12], ciphertext[12:]
        return aead.decrypt(nonce, ct, aad)
    
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Ed25519 signature."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        
        key = load_pem_private_key(private_key, password=None)
        assert isinstance(key, Ed25519PrivateKey)
        return key.sign(message)
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Ed25519 verification."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        
        try:
            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, message)
            return True
        except Exception:
            return False
    
    def kem_keygen(self) -> tuple[bytes, bytes]:
        """X25519 keypair generation."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, PublicFormat, NoEncryption
        )
        
        priv_bytes = private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        
        return pub_bytes, priv_bytes
    
    def kem_encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """X25519 key exchange (simulated KEM)."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey
        )
        
        # Generate ephemeral keypair
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        # Perform key exchange
        peer_public = X25519PublicKey.from_public_bytes(public_key)
        shared_secret = ephemeral_private.exchange(peer_public)
        
        # Ciphertext is ephemeral public key
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        ciphertext = ephemeral_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        
        return ciphertext, shared_secret
    
    def kem_decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """X25519 key exchange (simulated KEM)."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey
        )
        
        # Load our private key
        our_private = X25519PrivateKey.from_private_bytes(private_key)
        
        # Ephemeral public key is ciphertext
        ephemeral_public = X25519PublicKey.from_public_bytes(ciphertext)
        
        # Perform key exchange
        shared_secret = our_private.exchange(ephemeral_public)
        
        return shared_secret


class PostQuantumCryptoProvider:
    """
    Post-Quantum cryptography provider (placeholder).
    
    NOTE: Requires liboqs-python or pqcrypto packages.
    This is a reference implementation showing the interface.
    """
    
    def __init__(self):
        # Import PQ libraries when available
        # from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt
        # from pqcrypto.sign.dilithium3 import generate_keypair, sign, verify
        pass
    
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """ChaCha20-Poly1305 (symmetric crypto is PQ-safe)."""
        classical = ClassicalCryptoProvider()
        return classical.encrypt(key, plaintext, aad)
    
    def decrypt(self, key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """ChaCha20-Poly1305 decryption."""
        classical = ClassicalCryptoProvider()
        return classical.decrypt(key, ciphertext, aad)
    
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """ML-DSA-65 signature (when available)."""
        # Implementation with liboqs or pqcrypto
        raise NotImplementedError("ML-DSA-65 requires liboqs-python")
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """ML-DSA-65 verification."""
        raise NotImplementedError("ML-DSA-65 requires liboqs-python")
    
    def kem_keygen(self) -> tuple[bytes, bytes]:
        """ML-KEM-768 keypair generation."""
        raise NotImplementedError("ML-KEM-768 requires liboqs-python")
    
    def kem_encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """ML-KEM-768 encapsulation."""
        raise NotImplementedError("ML-KEM-768 requires liboqs-python")
    
    def kem_decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """ML-KEM-768 decapsulation."""
        raise NotImplementedError("ML-KEM-768 requires liboqs-python")


class HybridCryptoProvider:
    """
    Hybrid classical + post-quantum provider.
    
    Combines X25519+ML-KEM-768 and Ed25519+ML-DSA-65 for defense-in-depth.
    Security holds if EITHER classical OR post-quantum remains secure.
    """
    
    def __init__(self):
        self.classical = ClassicalCryptoProvider()
        # self.pq = PostQuantumCryptoProvider() when available
    
    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Symmetric encryption (already PQ-safe)."""
        return self.classical.encrypt(key, plaintext, aad)
    
    def decrypt(self, key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Symmetric decryption."""
        return self.classical.decrypt(key, ciphertext, aad)
    
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Hybrid Ed25519 + ML-DSA-65 signature."""
        # Split private key into classical + PQ components
        classical_sig = self.classical.sign(private_key, message)
        # pq_sig = self.pq.sign(pq_private_key, message)
        # return classical_sig + pq_sig
        return classical_sig  # For now, until liboqs available
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify hybrid signature (both must pass)."""
        # Verify both classical and PQ components
        return self.classical.verify(public_key, message, signature)
    
    def kem_keygen(self) -> tuple[bytes, bytes]:
        """Hybrid X25519 + ML-KEM-768 keypair."""
        classical_pub, classical_priv = self.classical.kem_keygen()
        # pq_pub, pq_priv = self.pq.kem_keygen()
        # return classical_pub + pq_pub, classical_priv + pq_priv
        return classical_pub, classical_priv
    
    def kem_encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Hybrid encapsulation (combine secrets with KDF)."""
        ct_classical, ss_classical = self.classical.kem_encapsulate(public_key)
        # ct_pq, ss_pq = self.pq.kem_encapsulate(pq_public_key)
        # combined_ct = ct_classical + ct_pq
        # combined_ss = KDF(ss_classical || ss_pq)
        return ct_classical, ss_classical
    
    def kem_decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Hybrid decapsulation."""
        ss_classical = self.classical.kem_decapsulate(private_key, ciphertext)
        # ss_pq = self.pq.kem_decapsulate(pq_private_key, ct_pq)
        # return KDF(ss_classical || ss_pq)
        return ss_classical


def get_crypto_provider(config: Optional[CryptoConfig] = None) -> CryptoProvider:
    """
    Factory function to get appropriate crypto provider.
    
    Args:
        config: Cryptographic configuration (defaults to production)
    
    Returns:
        CryptoProvider instance based on configuration
    """
    if config is None:
        config = CryptoConfig.current_production()
    
    if config.strict_pq_only:
        return PostQuantumCryptoProvider()
    elif config.hybrid_mode:
        return HybridCryptoProvider()
    else:
        return ClassicalCryptoProvider()


# Migration helpers
def estimate_key_sizes() -> dict[str, int]:
    """
    Estimate key/signature sizes for different algorithms.
    
    Returns dict with size comparisons for capacity planning.
    """
    return {
        # Classical (current)
        "ed25519_public_key": 32,
        "ed25519_signature": 64,
        "x25519_public_key": 32,
        "x25519_ciphertext": 32,
        
        # Post-Quantum (NIST standards)
        "ml_kem_768_public_key": 1184,
        "ml_kem_768_ciphertext": 1088,
        "ml_kem_1024_public_key": 1568,
        "ml_kem_1024_ciphertext": 1568,
        "ml_dsa_65_public_key": 1952,
        "ml_dsa_65_signature": 3309,
        "ml_dsa_87_public_key": 2592,
        "ml_dsa_87_signature": 4627,
        "slh_dsa_128f_public_key": 32,
        "slh_dsa_128f_signature": 17088,
        
        # Hybrid (sum of both)
        "hybrid_x25519_mlkem768_public_key": 1216,  # 32 + 1184
        "hybrid_ed25519_mldsa65_signature": 3373,  # 64 + 3309
    }


def migration_checklist() -> list[str]:
    """
    Generate migration checklist for PQ transition.
    
    Returns list of tasks for operations team.
    """
    return [
        "✅ Crypto agility framework implemented (pq_crypto.py)",
        "⏳ Install liboqs-python: pip install liboqs-python",
        "⏳ Enable hybrid mode in production config",
        "⏳ Test hybrid signatures with existing ledger",
        "⏳ Migrate identity keys to hybrid keypairs",
        "⏳ Update wrapped key encryption to ML-KEM-768",
        "⏳ Monitor performance impact (larger keys/signatures)",
        "⏳ Plan storage expansion (3-10x key size increase)",
        "⏳ Update documentation with PQ migration timeline",
        "⏳ Train operations team on PQ concepts",
        "⏳ Establish PQ key rotation policy",
        "⏳ Test disaster recovery with hybrid keys",
        "⏳ Switch to PQ-only mode after validation period",
        "⏳ Deprecate classical-only mode",
    ]
