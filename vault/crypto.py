from __future__ import annotations

import binascii
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def new_key() -> bytes:
    return os.urandom(32)

def key_to_hex(k: bytes) -> str:
    return binascii.hexlify(k).decode()

def key_from_hex(s: str) -> bytes:
    return binascii.unhexlify(s.strip())

def seal_bytes(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """
    Encrypt with ChaCha20-Poly1305 AEAD.
    
    Scheme: chacha20poly1305-v1
    - 96-bit nonces (cryptographically sufficient with proper key rotation)
    - Critical: DEK rotated per dataset, never reused across datasets
    - AAD binding prevents ciphertext reinterpretation
    """
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce + ct

def open_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Decrypt with ChaCha20-Poly1305 AEAD."""
    aead = ChaCha20Poly1305(key)
    nonce, ct = blob[:12], blob[12:]  # 96-bit nonce
    return aead.decrypt(nonce, ct, aad)
