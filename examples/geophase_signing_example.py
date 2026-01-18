"""
GeoPhase Commitment Signing Example

Demonstrates how to use RFC6979 deterministic ECDSA signing with
domain separation for GeoPhase commitment attestations.
"""

import hashlib

from ecdsa import SECP256k1, SigningKey

from dna_ledger.rfc6979 import sign_with_rfc6979


def create_grail_commitment(
    food_hash: bytes,
    tetris_pattern: str,
    mersenne_prime: int,
) -> bytes:
    """
    Create GeoPhase GRAIL commitment (example pattern).

    Args:
        food_hash: SHA-256 hash of food/input data
        tetris_pattern: Tetris block arrangement pattern
        mersenne_prime: Mersenne prime used in mixing

    Returns:
        Commitment hash (32 bytes)
    """
    blob = (
        b"GRAIL|"
        + food_hash
        + b"|t2|"
        + tetris_pattern.encode()
        + b"|M|"
        + str(mersenne_prime).encode()
    )
    return hashlib.sha256(blob).digest()


def sign_geophase_attestation(
    priv_int: int,
    commitment_hash: bytes,
    protocol_version: str = "V1",
) -> bytes:
    """
    Sign GeoPhase attestation with domain-separated RFC6979 signature.

    Args:
        priv_int: Private key (secp256k1 integer)
        commitment_hash: GeoPhase commitment hash
        protocol_version: Protocol version tag (for domain separation)

    Returns:
        DER-encoded ECDSA signature
    """
    # Build domain separation tag
    extra = f"ZETA_SNAKE_TETRIS_{protocol_version}|".encode() + commitment_hash

    # Message to sign (could be full attestation structure)
    message = b"GEOPHASE_ATTESTATION|" + commitment_hash

    # Sign with RFC6979 (deterministic, low-S normalized)
    signature = sign_with_rfc6979(priv_int, message, extra=extra)

    return signature


def main():
    """Example usage."""
    print("━━━ GeoPhase RFC6979 Signing Example ━━━\n")

    # 1. Generate key pair (for demo purposes)
    sk = SigningKey.generate(curve=SECP256k1)
    priv_int = sk.privkey.secret_multiplier
    vk = sk.get_verifying_key()

    print(f"Private key (first 16 hex): {hex(priv_int)[:18]}...")
    print(f"Public key X: {hex(vk.pubkey.point.x())[:18]}...")
    print()

    # 2. Create GeoPhase commitment
    food_hash = hashlib.sha256(b"sample_food_data_xyz").digest()
    tetris_pattern = "TLJZ-rotate-90"
    mersenne_prime = 2**127 - 1

    commitment = create_grail_commitment(food_hash, tetris_pattern, mersenne_prime)

    print(f"Food hash: {food_hash.hex()[:32]}...")
    print(f"Tetris pattern: {tetris_pattern}")
    print(f"Mersenne prime: M{127}")
    print(f"Commitment: {commitment.hex()}")
    print()

    # 3. Sign attestation (V1 protocol)
    sig_v1 = sign_geophase_attestation(priv_int, commitment, "V1")

    print(f"Signature (V1): {sig_v1.hex()}")
    print(f"Signature length: {len(sig_v1)} bytes")
    print()

    # 4. Demonstrate determinism
    sig_v1_again = sign_geophase_attestation(priv_int, commitment, "V1")

    print(f"Determinism check: {sig_v1 == sig_v1_again} ✅")
    print()

    # 5. Demonstrate domain separation
    sig_v2 = sign_geophase_attestation(priv_int, commitment, "V2")

    print(f"V1 signature: {sig_v1.hex()[:32]}...")
    print(f"V2 signature: {sig_v2.hex()[:32]}...")
    print(f"Domain separation: {sig_v1 != sig_v2} ✅")
    print()

    # 6. Verify signature
    from ecdsa.util import sigdecode_der

    msg = b"GEOPHASE_ATTESTATION|" + commitment
    msg_hash = hashlib.sha256(msg).digest()

    try:
        vk.verify_digest(sig_v1, msg_hash, sigdecode=sigdecode_der)
        print("Signature verification: ✅ VALID")
    except Exception as e:
        print(f"Signature verification: ❌ FAILED - {e}")

    print("\n━━━ Example Complete ━━━")


if __name__ == "__main__":
    main()
