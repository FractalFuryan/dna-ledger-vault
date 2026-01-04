from __future__ import annotations
import os, base64, binascii
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def new_key() -> bytes:
    return os.urandom(32)

def key_to_hex(k: bytes) -> str:
    return binascii.hexlify(k).decode()

def key_from_hex(s: str) -> bytes:
    return binascii.unhexlify(s.strip())

def seal_bytes(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce + ct

def open_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    nonce, ct = blob[:12], blob[12:]
    return aead.decrypt(nonce, ct, aad)
