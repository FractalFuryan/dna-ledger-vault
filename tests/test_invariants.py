"""
Simplified Security Invariant Tests

Tests core invariants without complex fixtures.
Run with: pytest tests/test_invariants_simple.py -v
"""

import tempfile

import pytest

from dna_ledger.hashing import h_block, h_commit, h_leaf, h_node, h_payload, merkle_root
from dna_ledger.ledger import HashChainedLedger
from dna_ledger.merkle_proof import merkle_proof, verify_merkle_proof


def test_domain_separation():
    """INVARIANT 3: Domain-separated hashing prevents structural collisions."""
    data = b"test_data"
    
    # Different prefixes must produce different hashes
    leaf_hash = h_leaf(data)
    node_hash = h_node(leaf_hash, leaf_hash)  # h_node expects hex strings
    
    assert leaf_hash != node_hash, "h_leaf == h_node (domain separation failed!)"
    
    # Hash functions on same object must differ
    test_obj = {"test": "data"}
    payload_hash = h_payload(test_obj)
    block_hash = h_block(test_obj)
    commit_hash = h_commit(test_obj)
    
    assert len({payload_hash, block_hash, commit_hash}) == 3, \
        "Different hash functions produced same output!"


def test_merkle_proof_valid():
    """INVARIANT 8: Valid Merkle inclusion proofs must verify."""
    chunks = [b"chunk0", b"chunk1", b"chunk2", b"chunk3"]
    leaves = [h_leaf(c) for c in chunks]  # Pre-hash chunks to leaves
    root = merkle_root(leaves)  # merkle_root expects hex string leaves
    
    # Generate and verify proof for chunk 2
    index = 2
    proof = merkle_proof(index, leaves)
    is_valid = verify_merkle_proof(leaves[index], index, proof, root)
    
    assert is_valid is True, "Valid Merkle proof rejected!"


def test_merkle_proof_invalid():
    """INVARIANT 8: Invalid Merkle proofs must be rejected."""
    chunks = [b"chunk0", b"chunk1", b"chunk2", b"chunk3"]
    leaves = [h_leaf(c) for c in chunks]
    root = merkle_root(leaves)
    
    # Generate proof for chunk 1
    index = 1
    proof = merkle_proof(index, leaves)
    
    # Tamper with leaf
    tampered_leaf = h_leaf(b"tampered_data")
    
    # Should fail verification
    is_valid = verify_merkle_proof(tampered_leaf, index, proof, root)
    
    assert is_valid is False, "Tampered Merkle proof accepted!"


def test_ledger_chain_integrity():
    """INVARIANT 2: Ledger verification must pass (chain + signatures)."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
        ledger_path = f.name
    
    try:
        import base64

        from dna_ledger.signing import gen_ed25519, sign_payload
        
        ledger = HashChainedLedger(ledger_path)
        
        # Create identity
        ed_priv, ed_pub = gen_ed25519()
        signer = {
            "id": "test_owner",
            "ed25519_pub_pem_b64": base64.b64encode(ed_pub).decode()
        }
        
        # Create test payload
        payload = {
            "kind": "DatasetCommit",
            "schema": "dna-ledger-vault/vNext.2",
            "dataset_id": "ds_test",
            "owner": "test_owner",
            "bytes": 100,
            "sha256_plain": "test_hash",
            "merkle_root": "test_root",
            "chunk_hashes": ["hash1"],
            "commit_hash": "commit_test",
            "created_utc": "2026-01-01T00:00:00Z"
        }
        
        # Sign and append
        sig = sign_payload(ed_priv, payload)
        ledger.append(payload, signer, sig)
        
        # Verify chain integrity
        assert ledger.verify() is True, "Ledger verification failed!"
        
    finally:
        import os
        os.unlink(ledger_path)


def test_schema_versioning():
    """INVARIANT (Versioning): All payloads must include schema field."""
    from dna_ledger import __schema__
    from dna_ledger.models import DatasetCommit
    
    commit = DatasetCommit(
        owner="test",
        bytes=100,
        sha256_plain="x",
        merkle_root="y",
        chunk_hashes=["z"]
    )
    
    payload = commit.model_dump(by_alias=True)
    
    assert "schema" in payload, "Payload missing schema field!"
    assert payload["schema"] == __schema__, "Wrong schema version!"


def test_no_duplicate_ids_in_ledger():
    """INVARIANT 1: Append-only ledger has unique IDs."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
        ledger_path = f.name
    
    try:
        import base64

        from dna_ledger.signing import gen_ed25519, sign_payload
        
        ledger = HashChainedLedger(ledger_path)
        
        ed_priv, ed_pub = gen_ed25519()
        signer = {
            "id": "test",
            "ed25519_pub_pem_b64": base64.b64encode(ed_pub).decode()
        }
        
        # Append two different payloads
        payloads = [
            {
                "kind": "ConsentGrant",
                "schema": "dna-ledger-vault/vNext.2",
                "grant_id": "cg_test1",
                "dataset_id": "ds_test",
                "dataset_commit_hash": "commit_abc",
                "grantee": "user1",
                "purpose": "research",
                "expires_utc": "2026-12-31T23:59:59Z",
                "wrapped_dek_b64": "dek1",
                "owner_x25519_pub_pem_b64": "pub1",
                "created_utc": "2026-01-01T00:00:00Z"
            },
            {
                "kind": "ConsentGrant",
                "schema": "dna-ledger-vault/vNext.2",
                "grant_id": "cg_test2",
                "dataset_id": "ds_test",
                "dataset_commit_hash": "commit_abc",
                "grantee": "user2",
                "purpose": "clinical",
                "expires_utc": "2026-12-31T23:59:59Z",
                "wrapped_dek_b64": "dek2",
                "owner_x25519_pub_pem_b64": "pub2",
                "created_utc": "2026-01-01T00:00:01Z"
            }
        ]
        
        for p in payloads:
            sig = sign_payload(ed_priv, p)
            ledger.append(p, signer, sig)
        
        # Check uniqueness
        blocks = ledger._read_blocks()
        grant_ids = [b["payload"]["grant_id"] for b in blocks]
        
        assert len(grant_ids) == 2
        assert len(set(grant_ids)) == 2, "Duplicate grant IDs detected!"
        
    finally:
        import os
        os.unlink(ledger_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
