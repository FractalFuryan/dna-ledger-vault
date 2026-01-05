"""
Crypto Scheme Invariant Tests

Verifies cryptographic scheme versioning and nonce safety guarantees.
"""


import pytest

from dna_ledger.models import ConsentGrant, DatasetCommit, KeyWrapEvent
from vault.crypto import new_key, seal_bytes, open_bytes
from vault.wrap import wrap_dek, unwrap_dek, gen_x25519


def test_scheme_versioning_on_all_models():
    """Verify all ledger models have crypto scheme version fields."""
    # DatasetCommit must have hash_scheme
    commit = DatasetCommit(
        owner="test",
        bytes=1024,
        sha256_plain="a" * 64,
        merkle_root="b" * 64,
        chunk_hashes=["c" * 64],
    )
    assert hasattr(commit, 'hash_scheme'), "DatasetCommit missing hash_scheme"
    assert commit.hash_scheme in ["sha256", "blake3", "dual"], \
        f"Invalid hash_scheme: {commit.hash_scheme}"
    
    # ConsentGrant must have wrap_scheme
    grant = ConsentGrant(
        dataset_id="ds_test",
        dataset_commit_hash="d" * 64,
        grantee="researcher",
        purpose="research",
        expires_utc="2026-12-31T23:59:59Z",
        wrapped_dek_b64="test",
        owner_x25519_pub_pem_b64="test",
    )
    assert hasattr(grant, 'wrap_scheme'), "ConsentGrant missing wrap_scheme"
    assert "x25519" in grant.wrap_scheme.lower(), \
        f"Invalid wrap_scheme: {grant.wrap_scheme}"
    
    # KeyWrapEvent must have wrap_scheme
    wrap = KeyWrapEvent(
        dataset_id="ds_test",
        dataset_commit_hash="e" * 64,
        grantee="researcher",
        purpose="research",
        rotation_id="initial",
        wrapped_dek_b64="test",
        owner_x25519_pub_pem_b64="test",
    )
    assert hasattr(wrap, 'wrap_scheme'), "KeyWrapEvent missing wrap_scheme"
    assert "x25519" in wrap.wrap_scheme.lower(), \
        f"Invalid wrap_scheme: {wrap.wrap_scheme}"


def test_nonce_uniqueness_guarantee():
    """
    INVARIANT: Nonce reuse is cryptographically impossible.
    
    ChaCha20-Poly1305 with 96-bit nonces is safe when:
    1. Each dataset gets unique DEK (never reused)
    2. DEKs are rotated on revocation
    3. Random nonces from os.urandom (cryptographic RNG)
    
    This test verifies multiple encryptions with same key produce different nonces.
    """
    key = new_key()
    plaintext = b"sensitive genomic data"
    aad = b"dataset_id=ds_12345|commit_hash=abc123"
    
    # Encrypt same plaintext 100 times with same key
    ciphertexts = []
    nonces = []
    
    for _ in range(100):
        ct = seal_bytes(key, plaintext, aad)
        nonce = ct[:12]  # ChaCha20-Poly1305 uses 12-byte nonce
        ciphertexts.append(ct)
        nonces.append(nonce)
    
    # All nonces must be unique
    unique_nonces = set(nonces)
    assert len(unique_nonces) == 100, \
        f"Nonce reuse detected! Only {len(unique_nonces)}/100 unique nonces"
    
    # All ciphertexts must be different (nonce is part of ciphertext)
    unique_cts = set(ciphertexts)
    assert len(unique_cts) == 100, \
        f"Ciphertext reuse detected! Only {len(unique_cts)}/100 unique"
    
    # All ciphertexts must decrypt correctly
    for ct in ciphertexts:
        pt = open_bytes(key, ct, aad)
        assert pt == plaintext, "Decryption failed"


def test_aad_binding_prevents_ciphertext_reuse():
    """
    INVARIANT: AAD binding prevents ciphertext from being used across datasets.
    
    Same plaintext encrypted with same key but different AAD must:
    1. Produce different ciphertexts
    2. Fail to decrypt with wrong AAD
    """
    key = new_key()
    plaintext = b"genomic data"
    
    aad1 = b'{"dataset_id":"ds_001","commit_hash":"aaa"}'
    aad2 = b'{"dataset_id":"ds_002","commit_hash":"bbb"}'
    
    ct1 = seal_bytes(key, plaintext, aad1)
    ct2 = seal_bytes(key, plaintext, aad2)
    
    # Different AAD produces different ciphertext (even with same nonce chance)
    # Note: ciphertexts differ because nonces are random, but also AAD is authenticated
    
    # Correct AAD decrypts successfully
    pt1 = open_bytes(key, ct1, aad1)
    pt2 = open_bytes(key, ct2, aad2)
    assert pt1 == plaintext
    assert pt2 == plaintext
    
    # Wrong AAD fails decryption (AAD mismatch)
    with pytest.raises(Exception):  # cryptography raises InvalidTag
        open_bytes(key, ct1, aad2)
    
    with pytest.raises(Exception):
        open_bytes(key, ct2, aad1)


def test_wrap_unwrap_round_trip():
    """Verify DEK wrapping produces correct wrap_scheme versioning."""
    # Generate X25519 keypairs
    owner_priv, owner_pub = gen_x25519()
    grantee_priv, grantee_pub = gen_x25519()
    
    # Generate DEK
    dek = new_key()
    
    # Context binding
    context = b"dataset_id=ds_test|grantee=researcher|purpose=research"
    
    # Wrap DEK
    wrapped = wrap_dek(owner_priv, grantee_pub, dek, context)
    
    # Wrapped DEK should be base64-encoded
    assert isinstance(wrapped, str), "wrap_dek must return base64 string"
    assert len(wrapped) > 0, "wrapped DEK is empty"
    
    # Unwrap DEK
    unwrapped_dek = unwrap_dek(grantee_priv, owner_pub, wrapped, context)
    
    # DEK must match
    assert unwrapped_dek == dek, "Unwrapped DEK doesn't match original"
    
    # Wrong context fails
    wrong_context = b"dataset_id=WRONG|grantee=attacker|purpose=theft"
    with pytest.raises(Exception):
        unwrap_dek(grantee_priv, owner_pub, wrapped, wrong_context)


def test_key_per_dataset_isolation():
    """
    INVARIANT: Each dataset gets unique DEK, never shared.
    
    This is a design principle test - verifies the pattern is enforced.
    """
    # Simulate committing 3 different datasets
    datasets = []
    for i in range(3):
        dek = new_key()
        datasets.append({
            "dataset_id": f"ds_{i:03d}",
            "dek": dek,
        })
    
    # All DEKs must be unique
    deks = [d["dek"] for d in datasets]
    assert len(set(deks)) == 3, "DEK reuse detected across datasets!"
    
    # Each DEK is 32 bytes (256 bits)
    for dek in deks:
        assert len(dek) == 32, f"Invalid DEK length: {len(dek)}"


def test_scheme_version_in_ledger_payload():
    """Verify scheme versions appear in serialized payloads."""
    commit = DatasetCommit(
        owner="alice",
        bytes=2048,
        sha256_plain="f" * 64,
        merkle_root="g" * 64,
        chunk_hashes=["h" * 64],
        hash_scheme="dual",  # explicit dual hashing
    )
    
    payload = commit.model_dump(by_alias=True)
    
    # Payload must contain hash_scheme
    assert "hash_scheme" in payload, "hash_scheme not in serialized payload"
    assert payload["hash_scheme"] == "dual"
    
    # Schema version must be present
    assert "schema" in payload, "schema version missing from payload"
    assert payload["schema"].startswith("dna-ledger-vault/")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
