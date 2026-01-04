from __future__ import annotations

import base64
import json
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def gen_ed25519() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem

def sign_payload(priv_pem: bytes, payload: Dict[str, Any]) -> str:
    priv = load_pem_private_key(priv_pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise TypeError("Not an Ed25519 private key")
    sig = priv.sign(canonical(payload))
    return b64e(sig)

def verify_payload(pub_pem: bytes, payload: Dict[str, Any], sig_b64: str) -> bool:
    pub = load_pem_public_key(pub_pem)
    if not isinstance(pub, Ed25519PublicKey):
        raise TypeError("Not an Ed25519 public key")
    pub.verify(b64d(sig_b64), canonical(payload))
    return True
