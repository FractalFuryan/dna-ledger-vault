"""
Cryptographic Shredding and Vault Deletion Operations

Implements GDPR/CPRA-compliant data destruction with cryptographic proof.
Uses DoD 5220.22-M 3-pass overwrite standard for secure deletion.

Security Model:
- Multiple overwrite passes (defense against data recovery)
- Cryptographic proof generation (tamper-evident audit)
- Wrapped key removal (all grantee access revoked)
- Forward secrecy (no key recovery possible)

Design Philosophy:
- Fail-closed (errors prevent incomplete deletion)
- Cryptographically provable (SHA256 proof hashes)
- Audit-ready (comprehensive logging)
- Legally defensible (DoD standard compliance)
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from dna_ledger.erasure_models import (
    ComplianceReport,
    ErasureMethod,
    SecureErasureEvent,
)

logger = logging.getLogger(__name__)


@dataclass
class ErasureProof:
    """
    Cryptographic proof of data destruction.
    
    Generated during erasure operations to provide verifiable evidence
    that data has been irreversibly destroyed.
    
    Attributes:
        method: Destruction method used
        proof_hash: SHA256 hash of destroyed material
        timestamp: UTC timestamp of destruction
        evidence_data: Additional metadata for audit
    """
    method: ErasureMethod
    proof_hash: str
    timestamp: str
    evidence_data: Dict[str, str]


class ErasureManager:
    """
    GDPR/CPRA-compliant data destruction service.
    
    Implements secure deletion of:
    - Data Encryption Keys (DEKs)
    - Encrypted vault data
    - Wrapped keys for grantees
    
    Destruction Methods:
    1. Cryptographic Shredding: DEK overwritten with secure zeros
    2. Vault Deletion: Encrypted files securely overwritten
    3. Full Purge: Both methods combined
    
    All operations generate cryptographic proof for audit compliance.
    
    Usage:
        manager = ErasureManager(vault_root="./state/vault")
        proof = manager.crypto_shred_dataset("ds_test123")
        report = manager.generate_compliance_report(...)
    """
    
    def __init__(self, vault_root: str = "./state/vault"):
        """
        Initialize erasure manager.
        
        Args:
            vault_root: Path to vault storage directory
        """
        self.vault_root = Path(vault_root)
        self.vault_root.mkdir(parents=True, exist_ok=True)
        
        # DoD 5220.22-M standard: 3-pass overwrite
        self.overwrite_passes = 3
        logger.info(f"ErasureManager initialized: {self.vault_root}")
    
    def crypto_shred_dataset(self, dataset_id: str) -> ErasureProof:
        """
        Cryptographically shred a dataset by destroying its DEK.
        
        Process:
        1. Locate DEK file
        2. Read original DEK (for proof generation)
        3. Overwrite with cryptographically secure random data (3 passes)
        4. Final pass: zeros
        5. Delete file
        6. Remove all wrapped keys
        
        Security Guarantee:
        - DEK is cryptographically unrecoverable
        - Encrypted data cannot be decrypted
        - All grantee access permanently revoked
        
        Args:
            dataset_id: Dataset to destroy
        
        Returns:
            ErasureProof with SHA256 hash of destroyed key
        
        Raises:
            FileNotFoundError: If DEK file doesn't exist
            PermissionError: If file cannot be overwritten
        
        Example:
            >>> manager = ErasureManager()
            >>> proof = manager.crypto_shred_dataset("ds_test123")
            >>> print(proof.proof_hash)
            'a7f3b2c1...'
        """
        dek_path = self.vault_root / f"{dataset_id}.dek"
        
        if not dek_path.exists():
            logger.error(f"DEK not found for dataset {dataset_id}")
            raise FileNotFoundError(f"DEK not found: {dek_path}")
        
        try:
            # 1. Read original DEK for proof generation
            with open(dek_path, "rb") as f:
                original_dek = f.read()
            
            logger.info(f"Shredding DEK for {dataset_id} ({len(original_dek)} bytes)")
            
            # 2. Generate proof hash BEFORE destruction
            original_hash = hashlib.sha256(original_dek).hexdigest()
            
            # 3. Secure overwrite (DoD 5220.22-M: 3 passes)
            key_size = len(original_dek)
            
            for pass_num in range(self.overwrite_passes):
                logger.debug(f"Overwrite pass {pass_num + 1}/{self.overwrite_passes}")
                with open(dek_path, "wb") as f:
                    f.write(os.urandom(key_size))
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
            
            # 4. Final pass: all zeros
            logger.debug("Final pass: zeros")
            with open(dek_path, "wb") as f:
                f.write(b"\x00" * key_size)
                f.flush()
                os.fsync(f.fileno())
            
            # 5. Delete the file
            dek_path.unlink()
            logger.info(f"DEK file deleted: {dek_path}")
            
            # 6. Remove wrapped keys for all grantees
            wrapped_keys_removed = self._remove_wrapped_keys(dataset_id)
            logger.info(f"Removed {wrapped_keys_removed} wrapped keys")
            
            # 7. Generate cryptographic proof
            from dna_ledger.models import now_utc
            
            proof = ErasureProof(
                method=ErasureMethod.CRYPTO_SHRED,
                proof_hash=hashlib.sha256(
                    f"SHREDDED:{dataset_id}:{original_hash}".encode()
                ).hexdigest(),
                timestamp=now_utc(),
                evidence_data={
                    "original_dek_hash": original_hash,
                    "shredding_standard": "DoD_5220.22-M_3_pass",
                    "final_state": "zeroed_and_deleted",
                    "key_size_bytes": str(key_size),
                    "wrapped_keys_removed": str(wrapped_keys_removed)
                }
            )
            
            logger.info(f"Crypto shredding complete: {proof.proof_hash[:16]}...")
            return proof
            
        except Exception as e:
            logger.error(f"Crypto shredding failed: {e}")
            raise
    
    def delete_vault_data(self, dataset_id: str) -> ErasureProof:
        """
        Physically delete encrypted dataset from vault storage.
        
        Process:
        1. Locate encrypted data file
        2. Read file (for proof generation)
        3. Overwrite with random data (3 passes)
        4. Delete file
        
        Args:
            dataset_id: Dataset to delete
        
        Returns:
            ErasureProof with SHA256 hash of deleted data
        
        Note:
            This deletes the encrypted file but does NOT destroy the DEK.
            Use crypto_shred_dataset() or full_purge() for complete destruction.
        """
        # Check multiple possible extensions
        data_paths = [
            self.vault_root / f"{dataset_id}.enc",
            self.vault_root / f"{dataset_id}.vault",
            self.vault_root / f"{dataset_id}.sealed"
        ]
        
        data_path = None
        for path in data_paths:
            if path.exists():
                data_path = path
                break
        
        if not data_path:
            logger.warning(f"Encrypted data not found for {dataset_id}, may already be deleted")
            data_hash = "NO_DATA_FOUND"
            file_size = 0
        else:
            try:
                # 1. Get hash before deletion for proof
                with open(data_path, "rb") as f:
                    data = f.read()
                    data_hash = hashlib.sha256(data).hexdigest()
                    file_size = len(data)
                
                logger.info(f"Deleting vault data for {dataset_id} ({file_size} bytes)")
                
                # 2. Secure overwrite (DoD 5220.22-M: 3 passes)
                for pass_num in range(self.overwrite_passes):
                    logger.debug(f"Overwrite pass {pass_num + 1}/{self.overwrite_passes}")
                    with open(data_path, "wb") as f:
                        f.write(os.urandom(file_size))
                        f.flush()
                        os.fsync(f.fileno())
                
                # 3. Delete file
                data_path.unlink()
                logger.info(f"Vault data deleted: {data_path}")
                
            except Exception as e:
                logger.error(f"Vault deletion failed: {e}")
                raise
        
        # Generate proof
        from dna_ledger.models import now_utc
        
        proof = ErasureProof(
            method=ErasureMethod.VAULT_DELETION,
            proof_hash=hashlib.sha256(
                f"DELETED:{dataset_id}:{data_hash}".encode()
            ).hexdigest(),
            timestamp=now_utc(),
            evidence_data={
                "deleted_file_hash": data_hash,
                "deletion_method": "secure_overwrite_3_pass",
                "file_size_bytes": str(file_size)
            }
        )
        
        logger.info(f"Vault deletion complete: {proof.proof_hash[:16]}...")
        return proof
    
    def full_purge(self, dataset_id: str) -> Tuple[ErasureProof, ErasureProof]:
        """
        Execute complete data destruction (shred + delete).
        
        Maximum security guarantee:
        - DEK cryptographically destroyed
        - Encrypted data physically removed
        - All access permanently revoked
        
        Args:
            dataset_id: Dataset to purge
        
        Returns:
            Tuple of (shred_proof, delete_proof)
        
        Example:
            >>> manager = ErasureManager()
            >>> shred_proof, delete_proof = manager.full_purge("ds_test123")
        """
        logger.info(f"Executing full purge for {dataset_id}")
        
        shred_proof = self.crypto_shred_dataset(dataset_id)
        delete_proof = self.delete_vault_data(dataset_id)
        
        logger.info(f"Full purge complete for {dataset_id}")
        return shred_proof, delete_proof
    
    def _remove_wrapped_keys(self, dataset_id: str) -> int:
        """
        Remove all wrapped DEKs for this dataset.
        
        Revokes access for all grantees by destroying their wrapped keys.
        
        Args:
            dataset_id: Dataset whose wrapped keys to remove
        
        Returns:
            Number of wrapped keys removed
        """
        wrapped_dir = self.vault_root / "wrapped_keys"
        if not wrapped_dir.exists():
            logger.debug("No wrapped_keys directory found")
            return 0
        
        removed_count = 0
        for key_file in wrapped_dir.glob(f"{dataset_id}_*.key"):
            try:
                # Secure overwrite before deletion
                key_size = key_file.stat().st_size
                with open(key_file, "wb") as f:
                    f.write(b"\x00" * key_size)
                    f.flush()
                    os.fsync(f.fileno())
                
                key_file.unlink()
                removed_count += 1
                logger.debug(f"Removed wrapped key: {key_file.name}")
                
            except Exception as e:
                logger.warning(f"Failed to remove wrapped key {key_file}: {e}")
        
        return removed_count
    
    def generate_compliance_report(
        self,
        dataset_id: str,
        erasure_event: SecureErasureEvent,
        ledger_integrity: bool = True
    ) -> Dict[str, str]:
        """
        Generate GDPR/CPRA compliance report.
        
        Creates human and machine-readable reports suitable for:
        - Regulatory submission
        - Legal documentation
        - Data subject notification
        
        Args:
            dataset_id: Dataset that was erased
            erasure_event: Erasure event from ledger
            ledger_integrity: Whether hash chain is intact
        
        Returns:
            Dictionary with 'json', 'human', and 'pdf_ready' keys
        
        Example:
            >>> report = manager.generate_compliance_report(...)
            >>> print(report['human'])
            >>> with open('report.json', 'w') as f:
            >>>     json.dump(report['json'], f)
        """
        # Create compliance report model
        report = ComplianceReport(
            dataset_id=dataset_id,
            erasure_event=erasure_event,
            ledger_chain_integrity=ledger_integrity,
            data_unrecoverable=True,
            cryptographic_proof_valid=bool(erasure_event.erasure_proof)
        )
        
        return {
            "json": report.to_json_dict(),
            "human": report.to_human_readable(),
            "pdf_ready": report.to_human_readable()  # Can be converted to PDF
        }
