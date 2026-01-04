from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def gen_x25519() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem

def _derive_wrap_key(shared: bytes, context: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dna-ledger-vault/wrap|" + context
    )
    return hkdf.derive(shared)

def wrap_dek(
    owner_x25519_priv_pem: bytes,
    grantee_x25519_pub_pem: bytes,
    dek: bytes,
    context: bytes,
) -> str:
    owner_priv = load_pem_private_key(owner_x25519_priv_pem, password=None)
    grantee_pub = load_pem_public_key(grantee_x25519_pub_pem)
    if not isinstance(owner_priv, X25519PrivateKey) or not isinstance(grantee_pub, X25519PublicKey):
        raise TypeError("wrap_dek requires X25519 keys")
    shared = owner_priv.exchange(grantee_pub)
    wk = _derive_wrap_key(shared, context)
    aead = ChaCha20Poly1305(wk)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, dek, context)
    return b64e(nonce + ct)

def unwrap_dek(
    grantee_x25519_priv_pem: bytes,
    owner_x25519_pub_pem: bytes,
    wrapped_b64: str,
    context: bytes,
) -> bytes:
    grantee_priv = load_pem_private_key(grantee_x25519_priv_pem, password=None)
    owner_pub = load_pem_public_key(owner_x25519_pub_pem)
    if not isinstance(grantee_priv, X25519PrivateKey) or not isinstance(owner_pub, X25519PublicKey):
        raise TypeError("unwrap_dek requires X25519 keys")
    shared = grantee_priv.exchange(owner_pub)
    wk = _derive_wrap_key(shared, context)
    blob = b64d(wrapped_b64)
    nonce, ct = blob[:12], blob[12:]
    aead = ChaCha20Poly1305(wk)
    return aead.decrypt(nonce, ct, context)
