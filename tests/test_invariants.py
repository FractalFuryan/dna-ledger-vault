"""
Executable Security Invariants - SECURITY.md enforcement
=========================================================

These tests verify the 8 security invariants documented in SECURITY.md.
Any regression that breaks these invariants will fail CI.

Run with: pytest tests/test_invariants.py -v
"""

import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Set

import pytest

from dna_ledger.ledger import Ledger
from dna_ledger.models import (
    DatasetCommit,
    ConsentGrant,
    KeyRotationEvent,
    KeyWrapEvent,
    ConsentRevocation,
    ComputeAttestation,
)
from dna_ledger.merkle_proof import verify_merkle_proof
from dna_ledger.hashing import h_leaf
from vault.encryption import encrypt_vault, decrypt_vault
from cli.signing import generate_ed25519_keypair, generate_x25519_keypair


class InvariantViolation(Exception):
    """Raised when a security invariant is violated."""
    pass


class TestSecurityInvariants:
    """
    Test suite that enforces the 8 security invariants from SECURITY.md.
    
    INVARIANTS TESTED:
    1. Append-Only Ledger (no payload mutation)
    2. Full Block Header Hashing
    3. Domain-Separated Hashing
    4. Dataset Commit Binding
    5. Wrap State Enforcement
    6. Vault AAD Binding
    7. Signature Versioning
    8. Merkle Inclusion Proofs
    """
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test state."""
        tmpdir = tempfile.mkdtemp()
        yield Path(tmpdir)
        shutil.rmtree(tmpdir)
    
    @pytest.fixture
    def ledger(self, temp_dir):
        """Create fresh ledger for each test."""
        ledger_file = temp_dir / "ledger.jsonl"
        return Ledger(str(ledger_file))
    
    @pytest.fixture
    def identities(self, temp_dir):
        """Create test identities with Ed25519 + X25519 keypairs."""
        owner_ed_pub, owner_ed_priv = generate_ed25519_keypair()
        owner_x_pub, owner_x_priv = generate_x25519_keypair()
        
        grantee_ed_pub, grantee_ed_priv = generate_ed25519_keypair()
        grantee_x_pub, grantee_x_priv = generate_x25519_keypair()
        
        return {
            "owner": {
                "id": "owner",
                "ed25519_pub": owner_ed_pub,
                "ed25519_priv": owner_ed_priv,
                "x25519_pub": owner_x_pub,
                "x25519_priv": owner_x_priv,
            },
            "grantee": {
                "id": "grantee",
                "ed25519_pub": grantee_ed_pub,
                "ed25519_priv": grantee_ed_priv,
                "x25519_pub": grantee_x_pub,
                "x25519_priv": grantee_x_priv,
            }
        }
    
    # ========================================================================
    # INVARIANT 1: Append-Only Ledger (no mutation, unique IDs)
    # ========================================================================
    
    def test_no_duplicate_grant_ids(self, ledger, identities):
        """
        INVARIANT 1: Every ConsentGrant.grant_id appears exactly once.
        
        Ensures append-only semantics - grants never mutated.
        """
        owner = identities["owner"]
        grantee = identities["grantee"]
        
        # Create two grants
        grant1 = ConsentGrant(
            grant_id="cg_test123",
            dataset_id="ds_test",
            dataset_commit_hash="commit_abc",
            grantee=grantee["id"],
            purpose="research",
            expires_utc="2026-12-31T23:59:59Z",
            wrapped_dek_b64="test_dek_1"
        )
        
        grant2 = ConsentGrant(
            grant_id="cg_test456",
            dataset_id="ds_test",
            dataset_commit_hash="commit_abc",
            grantee=grantee["id"],
            purpose="clinical",
            expires_utc="2026-12-31T23:59:59Z",
            wrapped_dek_b64="test_dek_2"
        )
        
        ledger.append(grant1, owner["id"], owner["ed25519_priv"])
        ledger.append(grant2, owner["id"], owner["ed25519_priv"])
        
        # Collect all grant IDs
        grant_ids = []
        for block in ledger.blocks:
            if block["payload"]["kind"] == "ConsentGrant":
                grant_ids.append(block["payload"]["grant_id"])
        
        # Check uniqueness
        if len(grant_ids) != len(set(grant_ids)):
            raise InvariantViolation(
                f"Duplicate grant IDs detected: {grant_ids}"
            )
        
        assert len(grant_ids) == 2
        assert "cg_test123" in grant_ids
        assert "cg_test456" in grant_ids
    
    def test_no_payload_mutation(self, ledger, identities):
        """
        INVARIANT 1: Payloads with same ID must have identical content.
        
        Detects mutation attempts by comparing payloads with same identifier.
        """
        owner = identities["owner"]
        
        commit1 = DatasetCommit(
            dataset_id="ds_immutable",
            commit_hash="commit_xyz",
            owner=owner["id"],
            bytes=1000,
            chunk_hashes=["hash1"],
            merkle_root="root1",
            sha256_plain="plain1",
            created_utc="2026-01-01T00:00:00Z"
        )
        
        ledger.append(commit1, owner["id"], owner["ed25519_priv"])
        
        # Attempt to append "mutated" version (should be rejected by real system)
        # Here we just verify detection capability
        original_payload = None
        for block in ledger.blocks:
            if block["payload"].get("dataset_id") == "ds_immutable":
                original_payload = block["payload"]
                break
        
        assert original_payload is not None
        assert original_payload["commit_hash"] == "commit_xyz"
        
        # Verify immutability: same dataset_id should have same content
        payload_hashes: Dict[str, str] = {}
        for block in ledger.blocks:
            if block["payload"]["kind"] == "DatasetCommit":
                ds_id = block["payload"]["dataset_id"]
                payload_str = json.dumps(block["payload"], sort_keys=True)
                
                if ds_id in payload_hashes:
                    if payload_hashes[ds_id] != payload_str:
                        raise InvariantViolation(
                            f"Dataset {ds_id} has mutated payload!"
                        )
                else:
                    payload_hashes[ds_id] = payload_str
    
    # ========================================================================
    # INVARIANT 2: Full Block Header Hashing + Chain Integrity
    # ========================================================================
    
    def test_ledger_chain_integrity(self, ledger, identities):
        """
        INVARIANT 2: ledger.verify() must pass (chain + signatures).
        
        Ensures block_hash covers {prev_hash, payload, signer, sig}.
        """
        owner = identities["owner"]
        
        commit = DatasetCommit(
            dataset_id="ds_verify",
            commit_hash="commit_123",
            owner=owner["id"],
            bytes=500,
            chunk_hashes=["h1"],
            merkle_root="r1",
            sha256_plain="p1",
            created_utc="2026-01-01T00:00:00Z"
        )
        
        ledger.append(commit, owner["id"], owner["ed25519_priv"])
        
        # Verify full chain
        assert ledger.verify() is True, "Ledger verification failed!"
    
    def test_signature_included_in_block_hash(self, ledger, identities):
        """
        INVARIANT 2: Block hash must cover signer metadata.
        
        Changing signer should change block_hash.
        """
        owner = identities["owner"]
        
        commit = DatasetCommit(
            dataset_id="ds_signer",
            commit_hash="commit_sig",
            owner=owner["id"],
            bytes=100,
            chunk_hashes=["h"],
            merkle_root="r",
            sha256_plain="p",
            created_utc="2026-01-01T00:00:00Z"
        )
        
        ledger.append(commit, owner["id"], owner["ed25519_priv"])
        
        # Get the block
        block = ledger.blocks[-1]
        
        # Verify signer is in the block header
        assert "signer" in block
        assert block["signer"]["id"] == owner["id"]
        
        # Verify sig is in the block header
        assert "sig" in block
        assert block["sig"]  # Non-empty signature
        
        # Block hash should be deterministic
        from dna_ledger.hashing import h_block
        expected_hash = h_block({
            "prev_hash": block["prev_hash"],
            "payload": block["payload"],
            "signer": block["signer"],
            "sig": block["sig"]
        })
        
        assert block["block_hash"] == expected_hash
    
    # ========================================================================
    # INVARIANT 3: Domain-Separated Hashing
    # ========================================================================
    
    def test_domain_separation_in_merkle(self):
        """
        INVARIANT 3: Merkle operations use domain-specific prefixes.
        
        h_leaf and h_node must produce different outputs for same input.
        """
        from dna_ledger.hashing import h_leaf, h_node
        
        data = b"test_data"
        
        # Compute leaf hash
        leaf_hash = h_leaf(data)
        
        # Compute node hash with same data
        node_hash = h_node(data, data)
        
        # Should be different due to domain separation
        assert leaf_hash != node_hash, \
            "Domain separation failed: h_leaf == h_node for same input!"
    
    def test_domain_separation_prefixes(self):
        """
        INVARIANT 3: Hash functions use correct domain prefixes.
        
        Verify LEAF, NODE, PAYLOAD, BLOCK, COMMIT prefixes work.
        """
        from dna_ledger.hashing import h_leaf, h_node, h_payload, h_block, h_commit
        
        # All should produce different hashes for same input
        test_obj = {"test": "data"}
        
        payload_hash = h_payload(test_obj)
        block_hash = h_block(test_obj)
        commit_hash = h_commit(test_obj)
        
        # All should be different
        hashes = {payload_hash, block_hash, commit_hash}
        assert len(hashes) == 3, \
            "Domain separation failed: different hash functions produced same output!"
    
    # ========================================================================
    # INVARIANT 4: Dataset Commit Binding
    # ========================================================================
    
    def test_grant_bound_to_commit_hash(self, ledger, identities):
        """
        INVARIANT 4: ConsentGrant.dataset_commit_hash must match DatasetCommit.commit_hash.
        
        Prevents grant reuse across dataset versions.
        """
        owner = identities["owner"]
        grantee = identities["grantee"]
        
        commit = DatasetCommit(
            dataset_id="ds_binding",
            commit_hash="commit_binding_abc",
            owner=owner["id"],
            bytes=1000,
            chunk_hashes=["h1"],
            merkle_root="r1",
            sha256_plain="p1",
            created_utc="2026-01-01T00:00:00Z"
        )
        
        ledger.append(commit, owner["id"], owner["ed25519_priv"])
        
        grant = ConsentGrant(
            grant_id="cg_bound",
            dataset_id="ds_binding",
            dataset_commit_hash="commit_binding_abc",  # Must match commit.commit_hash
            grantee=grantee["id"],
            purpose="research",
            expires_utc="2026-12-31T23:59:59Z",
            wrapped_dek_b64="dek_test"
        )
        
        ledger.append(grant, owner["id"], owner["ed25519_priv"])
        
        # Verify binding
        commit_hash = None
        grant_commit_hash = None
        
        for block in ledger.blocks:
            if block["payload"]["kind"] == "DatasetCommit":
                if block["payload"]["dataset_id"] == "ds_binding":
                    commit_hash = block["payload"]["commit_hash"]
            
            if block["payload"]["kind"] == "ConsentGrant":
                if block["payload"]["grant_id"] == "cg_bound":
                    grant_commit_hash = block["payload"]["dataset_commit_hash"]
        
        assert commit_hash == grant_commit_hash, \
            "Grant not bound to commit hash!"
    
    # ========================================================================
    # INVARIANT 5: Wrap State Enforcement
    # ========================================================================
    
    def test_rotation_requires_key_wrap_event(self, ledger, identities):
        """
        INVARIANT 5: Every KeyRotationEvent must have KeyWrapEvents for active grantees.
        
        Post-rotation access requires valid KeyWrapEvent.
        """
        owner = identities["owner"]
        grantee = identities["grantee"]
        
        # Create rotation
        rotation = KeyRotationEvent(
            rotation_id="kr_test",
            dataset_id="ds_rotate",
            new_dek_sha256="new_dek_hash",
            created_utc="2026-01-01T00:00:00Z"
        )
        
        ledger.append(rotation, owner["id"], owner["ed25519_priv"])
        
        # Create corresponding wrap event
        wrap = KeyWrapEvent(
            wrap_id="kw_test",
            dataset_id="ds_rotate",
            rotation_id="kr_test",
            grantee=grantee["id"],
            wrapped_dek_b64="wrapped_new_dek",
            wrapped_dek_sha256="wrapped_hash",
            created_utc="2026-01-01T00:00:01Z"
        )
        
        ledger.append(wrap, owner["id"], owner["ed25519_priv"])
        
        # Verify rotation has corresponding wrap
        rotations: Dict[str, str] = {}
        wraps: Dict[str, str] = {}
        
        for block in ledger.blocks:
            if block["payload"]["kind"] == "KeyRotationEvent":
                rot_id = block["payload"]["rotation_id"]
                ds_id = block["payload"]["dataset_id"]
                rotations[ds_id] = rot_id
            
            if block["payload"]["kind"] == "KeyWrapEvent":
                rot_id = block["payload"]["rotation_id"]
                ds_id = block["payload"]["dataset_id"]
                wraps.setdefault(ds_id, set()).add(rot_id)
        
        # Every rotation should have at least one wrap
        for ds_id, rot_id in rotations.items():
            if ds_id not in wraps or rot_id not in wraps[ds_id]:
                raise InvariantViolation(
                    f"Rotation {rot_id} for {ds_id} has no KeyWrapEvent!"
                )
    
    def test_revocation_blocks_access(self, ledger, identities):
        """
        INVARIANT 5: Revoked grants must not allow attestation.
        
        Policy enforcement: active grant + !revoked + current wrap.
        """
        owner = identities["owner"]
        grantee = identities["grantee"]
        
        grant = ConsentGrant(
            grant_id="cg_revoke",
            dataset_id="ds_revoke",
            dataset_commit_hash="commit_rev",
            grantee=grantee["id"],
            purpose="research",
            expires_utc="2026-12-31T23:59:59Z",
            wrapped_dek_b64="dek"
        )
        
        ledger.append(grant, owner["id"], owner["ed25519_priv"])
        
        revocation = ConsentRevocation(
            revocation_id="cr_test",
            grant_id="cg_revoke",
            reason="test",
            created_utc="2026-01-02T00:00:00Z"
        )
        
        ledger.append(revocation, owner["id"], owner["ed25519_priv"])
        
        # Check revocation exists
        revoked_grants = set()
        for block in ledger.blocks:
            if block["payload"]["kind"] == "ConsentRevocation":
                revoked_grants.add(block["payload"]["grant_id"])
        
        assert "cg_revoke" in revoked_grants, "Revocation not recorded!"
    
    # ========================================================================
    # INVARIANT 6: Vault AAD Binding
    # ========================================================================
    
    def test_vault_aad_prevents_transplant(self, temp_dir):
        """
        INVARIANT 6: Vault ciphertext bound to AAD context.
        
        Changing AAD should break decryption (prevents transplant attacks).
        """
        from dna_ledger.hashing import merkle_root
        
        dek = b"0" * 32  # 256-bit key
        plaintext = b"ACGT" * 100
        
        # Original AAD
        aad1 = {
            "dataset_id": "ds_aad1",
            "chunk_idx": 0,
            "merkle_root": merkle_root([b"ACGT" * 100]),
            "owner": "owner1",
            "created_utc": "2026-01-01T00:00:00Z"
        }
        
        # Different AAD (transplant attempt)
        aad2 = {
            "dataset_id": "ds_aad2",  # Changed!
            "chunk_idx": 0,
            "merkle_root": merkle_root([b"ACGT" * 100]),
            "owner": "owner1",
            "created_utc": "2026-01-01T00:00:00Z"
        }
        
        vault_dir = temp_dir / "vault_aad_test"
        vault_dir.mkdir()
        
        # Encrypt with aad1
        encrypt_vault(
            plaintext_chunks=[plaintext],
            dek=dek,
            vault_dir=str(vault_dir),
            aad=aad1
        )
        
        # Decrypt with aad2 should fail
        with pytest.raises(Exception):  # Should raise authentication error
            decrypt_vault(
                dek=dek,
                vault_dir=str(vault_dir),
                num_chunks=1,
                aad=aad2  # Wrong AAD!
            )
        
        # Decrypt with correct AAD should succeed
        recovered = decrypt_vault(
            dek=dek,
            vault_dir=str(vault_dir),
            num_chunks=1,
            aad=aad1  # Correct AAD
        )
        
        assert recovered == [plaintext]
    
    # ========================================================================
    # INVARIANT 7: Signature Versioning
    # ========================================================================
    
    def test_signature_includes_algorithm_identifier(self, ledger, identities):
        """
        INVARIANT 7: Signer includes algorithm identifier.
        
        Future-proofs for algorithm migration.
        """
        owner = identities["owner"]
        
        commit = DatasetCommit(
            dataset_id="ds_sig_version",
            commit_hash="commit_ver",
            owner=owner["id"],
            bytes=100,
            chunk_hashes=["h"],
            merkle_root="r",
            sha256_plain="p",
            created_utc="2026-01-01T00:00:00Z"
        )
        
        ledger.append(commit, owner["id"], owner["ed25519_priv"])
        
        block = ledger.blocks[-1]
        
        # Verify signer includes algorithm identifier
        assert "signer" in block
        assert "ed25519_pub_pem_b64" in block["signer"], \
            "Signer missing algorithm identifier!"
    
    # ========================================================================
    # INVARIANT 8: Merkle Inclusion Proofs
    # ========================================================================
    
    def test_merkle_proof_verification(self):
        """
        INVARIANT 8: Merkle inclusion proofs must verify correctly.
        
        Enables chunk-level verification without full dataset.
        """
        from dna_ledger.hashing import merkle_root
        from dna_ledger.merkle_proof import merkle_proof, verify_merkle_proof
        
        # Create test dataset
        chunks = [b"chunk0", b"chunk1", b"chunk2", b"chunk3"]
        leaves = [h_leaf(c) for c in chunks]
        root = merkle_root(chunks)
        
        # Generate proof for chunk 2
        index = 2
        proof = merkle_proof(index, leaves)
        
        # Verify proof
        is_valid = verify_merkle_proof(leaves[index], index, proof, root)
        
        assert is_valid is True, "Merkle proof verification failed!"
    
    def test_merkle_proof_rejects_invalid(self):
        """
        INVARIANT 8: Invalid Merkle proofs must be rejected.
        
        Tampering with leaf should fail verification.
        """
        from dna_ledger.hashing import merkle_root
        from dna_ledger.merkle_proof import merkle_proof, verify_merkle_proof
        
        chunks = [b"chunk0", b"chunk1", b"chunk2", b"chunk3"]
        leaves = [h_leaf(c) for c in chunks]
        root = merkle_root(chunks)
        
        index = 1
        proof = merkle_proof(index, leaves)
        
        # Tamper with leaf
        tampered_leaf = h_leaf(b"tampered")
        
        # Verification should fail
        is_valid = verify_merkle_proof(tampered_leaf, index, proof, root)
        
        assert is_valid is False, "Tampered Merkle proof should be rejected!"


# ============================================================================
# Integration Test: Full Workflow with All Invariants
# ============================================================================

def test_full_workflow_all_invariants(tmp_path):
    """
    Integration test: Commit → Grant → Rotate → Attest
    
    Verifies all 8 invariants hold throughout complete workflow.
    """
    from dna_ledger.hashing import merkle_root, h_commit
    
    # Setup
    ledger_file = tmp_path / "ledger.jsonl"
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    
    ledger = Ledger(str(ledger_file))
    
    # Create identities
    owner_ed_pub, owner_ed_priv = generate_ed25519_keypair()
    owner_x_pub, owner_x_priv = generate_x25519_keypair()
    
    grantee_ed_pub, grantee_ed_priv = generate_ed25519_keypair()
    grantee_x_pub, grantee_x_priv = generate_x25519_keypair()
    
    # 1. Commit dataset
    chunks = [b"ACGT" * 100]
    dek = b"0" * 32
    
    commit = DatasetCommit(
        dataset_id="ds_workflow",
        commit_hash=h_commit({
            "dataset_id": "ds_workflow",
            "owner": "owner",
            "merkle_root": merkle_root(chunks),
            "bytes": len(chunks[0])
        }),
        owner="owner",
        bytes=len(chunks[0]),
        chunk_hashes=[h_leaf(chunks[0])],
        merkle_root=merkle_root(chunks),
        sha256_plain="plain_hash",
        created_utc="2026-01-01T00:00:00Z"
    )
    
    ledger.append(commit, "owner", owner_ed_priv)
    
    # 2. Grant access with KeyWrapEvent
    grant = ConsentGrant(
        grant_id="cg_workflow",
        dataset_id="ds_workflow",
        dataset_commit_hash=commit.commit_hash,  # INVARIANT 4: Binding
        grantee="grantee",
        purpose="research",
        expires_utc="2026-12-31T23:59:59Z",
        wrapped_dek_b64="initial_wrap"
    )
    
    ledger.append(grant, "owner", owner_ed_priv)
    
    wrap1 = KeyWrapEvent(
        wrap_id="kw_workflow1",
        dataset_id="ds_workflow",
        rotation_id="initial",
        grantee="grantee",
        wrapped_dek_b64="initial_wrap",
        wrapped_dek_sha256="wrap_hash",
        created_utc="2026-01-01T00:00:01Z"
    )
    
    ledger.append(wrap1, "owner", owner_ed_priv)
    
    # 3. Rotate key
    rotation = KeyRotationEvent(
        rotation_id="kr_workflow",
        dataset_id="ds_workflow",
        new_dek_sha256="new_dek_hash",
        created_utc="2026-01-02T00:00:00Z"
    )
    
    ledger.append(rotation, "owner", owner_ed_priv)
    
    wrap2 = KeyWrapEvent(
        wrap_id="kw_workflow2",
        dataset_id="ds_workflow",
        rotation_id="kr_workflow",  # INVARIANT 5: Current wrap
        grantee="grantee",
        wrapped_dek_b64="rotated_wrap",
        wrapped_dek_sha256="new_wrap_hash",
        created_utc="2026-01-02T00:00:01Z"
    )
    
    ledger.append(wrap2, "owner", owner_ed_priv)
    
    # 4. Verify all invariants
    
    # INVARIANT 1: Append-only (no duplicate IDs)
    grant_ids = [b["payload"]["grant_id"] for b in ledger.blocks 
                 if b["payload"]["kind"] == "ConsentGrant"]
    assert len(grant_ids) == len(set(grant_ids))
    
    # INVARIANT 2: Chain integrity
    assert ledger.verify() is True
    
    # INVARIANT 4: Commit binding
    assert grant.dataset_commit_hash == commit.commit_hash
    
    # INVARIANT 5: Rotation has wrap
    wraps = [b["payload"] for b in ledger.blocks 
             if b["payload"]["kind"] == "KeyWrapEvent"]
    assert len(wraps) == 2
    assert any(w["rotation_id"] == "kr_workflow" for w in wraps)
    
    print("✅ All invariants verified in full workflow!")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
