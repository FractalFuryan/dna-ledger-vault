"""
Test GDPR/CPRA Right to Erasure implementation.

Test Coverage:
- Cryptographic shredding of DEKs
- Vault data deletion
- Full purge operations
- Erasure event creation
- Compliance report generation
- Multi-pass overwrite verification
"""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from dna_ledger.erasure_models import (
    ComplianceReport,
    ErasureMethod,
    SecureErasureEvent,
)
from vault.erasure_manager import ErasureManager, ErasureProof


class TestCryptoShredding:
    """Test cryptographic shredding of encryption keys."""
    
    def test_crypto_shred_dek(self):
        """Test DEK destruction with proof generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ErasureManager(vault_root=tmpdir)
            
            # Create a fake DEK
            dataset_id = "test_dataset_123"
            dek_path = Path(tmpdir) / f"{dataset_id}.dek"
            original_key = os.urandom(32)  # 256-bit key
            dek_path.write_bytes(original_key)
            
            # Execute shred
            proof = manager.crypto_shred_dataset(dataset_id)
            
            # Verify proof structure
            assert isinstance(proof, ErasureProof)
            assert proof.method == ErasureMethod.CRYPTO_SHRED
            assert len(proof.proof_hash) == 64  # SHA256 hex
            assert "original_dek_hash" in proof.evidence_data
            assert proof.evidence_data["shredding_standard"] == "DoD_5220.22-M_3_pass"
            
            # Verify file is deleted
            assert not dek_path.exists()
    
    def test_crypto_shred_nonexistent_dek(self):
        """Test error handling for missing DEK."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ErasureManager(vault_root=tmpdir)
            
            with pytest.raises(FileNotFoundError):
                manager.crypto_shred_dataset("nonexistent_dataset")
    
    def test_wrapped_keys_removal(self):
        """Test that wrapped keys are removed during shredding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ErasureManager(vault_root=tmpdir)
            
            # Create DEK and wrapped keys
            dataset_id = "test_ds_456"
            dek_path = Path(tmpdir) / f"{dataset_id}.dek"
            dek_path.write_bytes(os.urandom(32))
            
            # Create wrapped_keys directory
            wrapped_dir = Path(tmpdir) / "wrapped_keys"
            wrapped_dir.mkdir()
            
            # Create some wrapped keys
            for i in range(3):
                wrapped_key = wrapped_dir / f"{dataset_id}_grantee{i}.key"
                wrapped_key.write_bytes(os.urandom(64))
            
            # Execute shred
            proof = manager.crypto_shred_dataset(dataset_id)
            
            # Verify wrapped keys are removed
            assert proof.evidence_data["wrapped_keys_removed"] == "3"
            assert not any(wrapped_dir.glob(f"{dataset_id}_*.key"))


class TestVaultDeletion:
    """Test physical deletion of encrypted vault data."""
    
    def test_delete_vault_data(self):
        """Test secure deletion of encrypted files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ErasureManager(vault_root=tmpdir)
            
            # Create fake encrypted data
            dataset_id = "test_data_789"
            data_path = Path(tmpdir) / f"{dataset_id}.enc"
            original_data = os.urandom(1024)  # 1KB encrypted data
            data_path.write_bytes(original_data)
            
            # Execute deletion
            proof = manager.delete_vault_data(dataset_id)
            
            # Verify proof
            assert proof.method == ErasureMethod.VAULT_DELETION
            assert len(proof.proof_hash) == 64
            assert "deleted_file_hash" in proof.evidence_data
            assert proof.evidence_data["deletion_method"] == "secure_overwrite_3_pass"
            
            # Verify file is deleted
            assert not data_path.exists()
    
    def test_delete_nonexistent_data(self):
        """Test graceful handling of missing encrypted data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ErasureManager(vault_root=tmpdir)
            
            # Should not raise, but return proof with NO_DATA_FOUND
            proof = manager.delete_vault_data("nonexistent")
            
            assert proof.method == ErasureMethod.VAULT_DELETION
            assert proof.evidence_data["deleted_file_hash"] == "NO_DATA_FOUND"
    
    def test_full_purge(self):
        """Test complete destruction (shred + delete)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ErasureManager(vault_root=tmpdir)
            
            # Create both DEK and encrypted data
            dataset_id = "test_purge_abc"
            dek_path = Path(tmpdir) / f"{dataset_id}.dek"
            data_path = Path(tmpdir) / f"{dataset_id}.enc"
            
            dek_path.write_bytes(os.urandom(32))
            data_path.write_bytes(os.urandom(2048))
            
            # Execute full purge
            shred_proof, delete_proof = manager.full_purge(dataset_id)
            
            # Verify both proofs
            assert shred_proof.method == ErasureMethod.CRYPTO_SHRED
            assert delete_proof.method == ErasureMethod.VAULT_DELETION
            
            # Verify both files deleted
            assert not dek_path.exists()
            assert not data_path.exists()


class TestErasureEvents:
    """Test SecureErasureEvent model creation."""
    
    def test_erasure_event_creation(self):
        """Test GDPR-compliant erasure event generation."""
        event = SecureErasureEvent.from_destruction(
            dataset_id="ds_test_123",
            identity="data_owner",
            method=ErasureMethod.CRYPTO_SHRED,
            destroyed_key_hash="a" * 64,
            pre_erasure_root="b" * 64,
            regulator_id="GDPR-2024-001",
            reason="User requested deletion",
            prior_accesses=5,
            affected_users=["researcher1", "researcher2"]
        )
        
        # Verify structure
        assert event.kind == "SecureErasureEvent"
        assert event.erasure_method == ErasureMethod.CRYPTO_SHRED
        assert event.legal_basis == "GDPR_Article_17_Right_to_Erasure"
        assert event.regulator_case_id == "GDPR-2024-001"
        assert event.erasure_reason == "User requested deletion"
        assert len(event.affected_grantees) == 2
        assert event.prior_access_count == 5
        assert event.erasure_scheme == "gdpr-secure-erasure-v1"
    
    def test_erasure_event_defaults(self):
        """Test default values for optional fields."""
        event = SecureErasureEvent.from_destruction(
            dataset_id="ds_min",
            identity="owner",
            method=ErasureMethod.VAULT_DELETION,
            destroyed_key_hash="c" * 64,
            pre_erasure_root="d" * 64
        )
        
        assert event.regulator_case_id is None
        assert event.erasure_reason is None
        assert event.prior_access_count == 0
        assert event.affected_grantees == []
        assert event.post_erasure_state == "ERASED_PERMANENTLY"


class TestComplianceReports:
    """Test compliance report generation."""
    
    def test_compliance_report_generation(self):
        """Test report creation from erasure event."""
        # Create erasure event
        event = SecureErasureEvent.from_destruction(
            dataset_id="ds_report_test",
            identity="data_owner",
            method=ErasureMethod.FULL_PURGE,
            destroyed_key_hash="e" * 64,
            pre_erasure_root="f" * 64,
            regulator_id="GDPR-2024-002",
            prior_accesses=10,
            affected_users=["user1", "user2", "user3"]
        )
        
        # Create compliance report
        report = ComplianceReport(
            dataset_id="ds_report_test",
            erasure_event=event,
            ledger_chain_integrity=True,
            data_unrecoverable=True,
            cryptographic_proof_valid=True
        )
        
        # Verify report structure
        assert report.dataset_id == "ds_report_test"
        assert report.erasure_event == event
        assert report.ledger_chain_integrity is True
        assert report.data_unrecoverable is True
        assert "GDPR Article 17" in report.legal_statement
    
    def test_compliance_report_human_readable(self):
        """Test human-readable report format."""
        event = SecureErasureEvent.from_destruction(
            dataset_id="ds_human",
            identity="owner",
            method=ErasureMethod.CRYPTO_SHRED,
            destroyed_key_hash="g" * 64,
            pre_erasure_root="h" * 64
        )
        
        report = ComplianceReport(
            dataset_id="ds_human",
            erasure_event=event
        )
        
        human_report = report.to_human_readable()
        
        # Verify key sections present
        assert "GENOMIC DATA ERASURE COMPLIANCE REPORT" in human_report
        assert event.erasure_id in human_report
        assert "crypto_shred" in human_report
        assert "GDPR Article 17" in human_report
        assert "permanently destroyed" in human_report
        assert "VERIFIED" in human_report
    
    def test_compliance_report_json_export(self):
        """Test JSON export format."""
        event = SecureErasureEvent.from_destruction(
            dataset_id="ds_json",
            identity="owner",
            method=ErasureMethod.VAULT_DELETION,
            destroyed_key_hash="i" * 64,
            pre_erasure_root="j" * 64
        )
        
        report = ComplianceReport(
            dataset_id="ds_json",
            erasure_event=event
        )
        
        json_dict = report.to_json_dict()
        
        # Verify JSON structure
        assert isinstance(json_dict, dict)
        assert "report_id" in json_dict
        assert "erasure_event" in json_dict
        assert "verification" in json_dict
        assert "compliance" in json_dict
        
        # Verify nested structure
        assert json_dict["verification"]["ledger_integrity"] is True
        assert json_dict["verification"]["data_unrecoverable"] is True
    
    def test_manager_compliance_report_generation(self):
        """Test compliance report generation via manager."""
        manager = ErasureManager()
        
        event = SecureErasureEvent.from_destruction(
            dataset_id="ds_manager",
            identity="owner",
            method=ErasureMethod.CRYPTO_SHRED,
            destroyed_key_hash="k" * 64,
            pre_erasure_root="l" * 64
        )
        
        report = manager.generate_compliance_report(
            dataset_id="ds_manager",
            erasure_event=event,
            ledger_integrity=True
        )
        
        # Verify report dictionary structure
        assert "json" in report
        assert "human" in report
        assert "pdf_ready" in report
        
        # Verify content
        assert report["json"]["dataset_id"] == "ds_manager"
        assert "COMPLIANCE REPORT" in report["human"]


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
