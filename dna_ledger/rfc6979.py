"""
RFC6979 Deterministic ECDSA for secp256k1

This module provides audit-grade deterministic ECDSA signing using RFC6979
with low-S normalization for canonical signatures.

Key Properties:
- Deterministic k generation (no random nonce risk)
- Low-S normalization (canonical signatures for Bitcoin/Ethereum)
- Domain separation via optional 'extra' parameter
- secp256k1 specialized (256-bit curve used by Bitcoin/Ethereum)

IMPORTANT: The 'extra' parameter is for DOMAIN SEPARATION only, not entropy.
It allows you to bind signatures to application context (e.g., commitment metadata)
while maintaining RFC6979 determinism.

Security Model:
- Nonce security: RFC6979 HMAC-DRBG (HMAC-SHA256)
- Signature malleability: Prevented via low-S normalization
- Domain separation: SHA-256(extra) mixed into HMAC state
- No custom entropy: All randomness from RFC6979 HMAC chain

References:
- RFC6979: https://datatracker.ietf.org/doc/html/rfc6979
- BIP 146: Low-S signatures
- SEC1: Elliptic Curve Cryptography
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Tuple

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigdecode_der, sigencode_der

# secp256k1 curve order (number of points on the curve)
CURVE_ORDER = SECP256k1.order


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 as specified in RFC6979."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _int2octets(x: int, rolen: int) -> bytes:
    """Convert integer to octet string of specified length (big-endian)."""
    return x.to_bytes(rolen, "big")


def _bits2int(b: bytes, qlen: int) -> int:
    """Convert bit string to integer as per SEC1 2.3.8."""
    i = int.from_bytes(b, "big")
    blen = len(b) * 8
    if blen > qlen:
        i >>= (blen - qlen)
    return i


def _bits2octets(b: bytes, q: int, qlen: int, rolen: int) -> bytes:
    """Convert bit string to octet string, reducing modulo q."""
    z1 = _bits2int(b, qlen)
    z2 = z1 % q
    return _int2octets(z2, rolen)


def rfc6979_generate_k(
    priv_int: int,
    hash_bytes: bytes,
    extra: bytes = b"",
) -> int:
    """
    Generate deterministic ECDSA nonce using RFC6979 for secp256k1.

    Args:
        priv_int: Private key as integer (must be in [1, CURVE_ORDER-1])
        hash_bytes: Message hash (typically SHA-256 digest, 32 bytes)
        extra: Optional domain separation data (default: empty)
               This is hashed to 32 bytes and mixed into HMAC state.
               Use for binding signatures to application context.

    Returns:
        Deterministic nonce k in range [1, CURVE_ORDER-1]

    Raises:
        ValueError: If priv_int is out of valid range

    Note:
        The 'extra' parameter enables domain separation without breaking
        RFC6979 determinism. Changing 'extra' produces different signatures
        for the same message, but remains deterministic.

    Example:
        >>> priv_int = 0x1234...
        >>> msg_hash = hashlib.sha256(b"message").digest()
        >>> extra = b"SNAKE_TETRIS_V1|commitment_hash"
        >>> k = rfc6979_generate_k(priv_int, msg_hash, extra)
    """
    if not (1 <= priv_int < CURVE_ORDER):
        raise ValueError(f"Private key must be in [1, {CURVE_ORDER-1}]")

    q = CURVE_ORDER
    qlen = q.bit_length()  # 256 bits for secp256k1
    rolen = (qlen + 7) // 8  # 32 bytes
    holen = hashlib.sha256().digest_size  # 32 bytes

    # Step a: Convert private key to octet string
    bx = _int2octets(priv_int, rolen)

    # Step b: Process message hash
    bh = _bits2octets(hash_bytes, q, qlen, rolen)

    # Step c: Initialize HMAC state
    V = b"\x01" * holen
    K = b"\x00" * holen

    # Hash extra data for domain separation (if provided)
    extra_h = hashlib.sha256(extra).digest() if extra else b""

    # Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || extra)
    K = _hmac_sha256(K, V + b"\x00" + bx + bh + extra_h)

    # Step e: V = HMAC_K(V)
    V = _hmac_sha256(K, V)

    # Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1) || extra)
    K = _hmac_sha256(K, V + b"\x01" + bx + bh + extra_h)

    # Step g: V = HMAC_K(V)
    V = _hmac_sha256(K, V)

    # Step h: Generate k
    while True:
        T = b""
        while len(T) < rolen:
            V = _hmac_sha256(K, V)
            T += V

        k = _bits2int(T, qlen)

        # CRITICAL: Reject and retry if k is out of range
        # This prevents modulo bias (don't use k % q)
        if 1 <= k < q:
            return k

        # If k was invalid, update K and V and retry
        K = _hmac_sha256(K, V + b"\x00")
        V = _hmac_sha256(K, V)


def _low_s_normalize(r: int, s: int, n: int) -> Tuple[int, int]:
    """
    Normalize ECDSA signature to low-S form (BIP 146).

    Bitcoin and Ethereum require signatures with s <= n/2 to prevent
    signature malleability attacks.

    Args:
        r: ECDSA signature component r
        s: ECDSA signature component s
        n: Curve order

    Returns:
        (r, s_normalized) where s_normalized <= n/2
    """
    if s > n // 2:
        s = n - s
    return r, s


def sign_with_rfc6979(
    priv_int: int,
    msg: bytes,
    extra: bytes = b"",
) -> bytes:
    """
    Sign message with RFC6979 deterministic ECDSA + low-S normalization.

    Args:
        priv_int: Private key as integer (secp256k1)
        msg: Message to sign (will be SHA-256 hashed)
        extra: Optional domain separation data (e.g., commitment metadata)

    Returns:
        DER-encoded ECDSA signature (canonical low-S form)

    Example:
        >>> from ecdsa import SigningKey, SECP256k1
        >>> sk = SigningKey.generate(curve=SECP256k1)
        >>> priv_int = sk.privkey.secret_multiplier
        >>> sig = sign_with_rfc6979(priv_int, b"message", b"DOMAIN_V1")
    """
    # Hash message
    z = hashlib.sha256(msg).digest()

    # Generate deterministic nonce
    k = rfc6979_generate_k(priv_int, z, extra=extra)

    # Sign using ecdsa library with our deterministic k
    sk = SigningKey.from_secret_exponent(priv_int, curve=SECP256k1)
    der_sig = sk.sign_digest(z, sigencode=sigencode_der, k=k)

    # Decode signature components
    r, s = sigdecode_der(der_sig, CURVE_ORDER)

    # Normalize to low-S form
    r, s = _low_s_normalize(r, s, CURVE_ORDER)

    # Re-encode as DER
    return _encode_der_signature(r, s)


def _encode_der_signature(r: int, s: int) -> bytes:
    """
    Encode ECDSA (r, s) as DER format.

    DER encoding:
    0x30 [total_length] 0x02 [r_length] [r_bytes] 0x02 [s_length] [s_bytes]

    Integers are big-endian with 0x00 prefix if high bit is set.
    """

    def _der_int(x: int) -> bytes:
        """Encode integer as DER INTEGER."""
        # Convert to bytes (minimal length)
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        # Add 0x00 prefix if high bit is set (prevent negative interpretation)
        if b[0] & 0x80:
            b = b"\x00" + b
        return b

    r_bytes = _der_int(r)
    s_bytes = _der_int(s)

    # Build DER SEQUENCE
    # 0x02 = INTEGER tag
    sequence = (
        b"\x02"
        + bytes([len(r_bytes)])
        + r_bytes
        + b"\x02"
        + bytes([len(s_bytes)])
        + s_bytes
    )

    # 0x30 = SEQUENCE tag
    return b"\x30" + bytes([len(sequence)]) + sequence


def verify_signature(pub_point: tuple[int, int], msg: bytes, sig: bytes) -> bool:
    """
    Verify RFC6979 signature (for testing/validation).

    Args:
        pub_point: Public key as (x, y) point on secp256k1
        msg: Original message (will be SHA-256 hashed)
        sig: DER-encoded signature

    Returns:
        True if signature is valid

    Note:
        For production verification, use ecdsa.VerifyingKey or web3.eth.account
    """
    from ecdsa import VerifyingKey

    z = hashlib.sha256(msg).digest()

    # Construct verifying key from point
    vk = VerifyingKey.from_public_point(
        point=pub_point,  # type: ignore
        curve=SECP256k1,
    )

    try:
        vk.verify_digest(sig, z, sigdecode=sigdecode_der)
        return True
    except Exception:
        return False
