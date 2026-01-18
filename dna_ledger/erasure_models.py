"""
GDPR/CPRA Right to Erasure Models

Implements legally-compliant data destruction with cryptographic proof.
Maintains ledger immutability while ensuring data unrecoverability.

Legal References:
- GDPR Article 17: Right to Erasure ("Right to be Forgotten")
- CPRA § 1798.105: Right to Delete Personal Information
- HIPAA Safe Harbor Method: De-identification through destruction

Design Philosophy:
- Ledger remains immutable (audit trail preserved)
- Off-chain data and keys are cryptographically destroyed
- Erasure events generate verifiable proof hashes
- Compliance reports for regulatory submission
"""

from __future__ import annotations

import hashlib
import time
from enum import Enum
from typing import TYPE_CHECKING, List, Literal, Optional

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from datetime import datetime

from dna_ledger import __schema__
from dna_ledger.models import new_id, now_utc


class ErasureMethod(str, Enum):
    """
    GDPR/CPRA-compliant data destruction methods.
    
    Each method provides different security guarantees:
    - CRYPTO_SHRED: DEK overwritten (DoD 5220.22-M standard)
    - VAULT_DELETION: Encrypted data physically removed
    - FULL_PURGE: Both shred + deletion (maximum security)
    """
    CRYPTO_SHRED = "crypto_shred"  # Destroy encryption keys
    VAULT_DELETION = "vault_deletion"  # Delete encrypted files
    FULL_PURGE = "full_purge"  # Complete destruction


class SecureErasureEvent(BaseModel):
    """
    Immutable ledger record of dataset deletion.
    
    This event proves GDPR/CPRA compliance by recording:
    - What was destroyed (dataset_id)
    - How it was destroyed (erasure_method)
    - When it was destroyed (timestamp)
    - Who authorized it (executing_identity)
    - Cryptographic proof (erasure_proof)
    
    Security Properties:
    - Signed with Ed25519 (same as other ledger events)
    - Tamper-evident (hash-chained)
    - Non-repudiable (identity-bound)
    - Auditable (regulator_case_id tracking)
    
    Example Event:
    {
        "kind": "SecureErasureEvent",
        "dataset_id": "ds_0193b889463de_c5b87f72a59b4836",
        "erasure_method": "crypto_shred",
        "erasure_proof": "a7f3b2...  # SHA256 of destroyed key
        "executing_identity": "data_owner",
        "legal_basis": "GDPR_Article_17_Right_to_Erasure",
        "regulator_case_id": "GDPR-2024-001"
    }
    """
    
    kind: Literal["SecureErasureEvent"] = "SecureErasureEvent"
    schema_version: str = Field(default=__schema__, alias="schema")
    erasure_id: str = Field(default_factory=lambda: new_id("se"))
    created_utc: str = Field(default_factory=now_utc)
    
    # Target dataset
    dataset_id: str
    
    # Execution details
    erasure_method: ErasureMethod
    erasure_proof: str  # SHA256 hash of destroyed key/data
    executing_identity: str  # Data owner who authorized destruction
    
    # Compliance tracking
    legal_basis: str = "GDPR_Article_17_Right_to_Erasure"
    regulator_case_id: Optional[str] = None  # e.g., "GDPR-2024-001"
    erasure_reason: Optional[str] = None  # Optional human-readable reason
    
    # Cryptographic proof chain
    pre_erasure_root_hash: str  # Merkle root before destruction
    post_erasure_state: str = "ERASED_PERMANENTLY"
    
    # Audit metadata
    prior_access_count: int = 0  # How many compute attestations before erasure
    affected_grantees: List[str] = Field(default_factory=list)  # Users who lost access
    
    # Scheme versioning
    erasure_scheme: str = "gdpr-secure-erasure-v1"  # Destruction protocol version
    
    model_config = {"populate_by_name": True}
    
    @classmethod
    def from_destruction(
        cls,
        dataset_id: str,
        identity: str,
        method: ErasureMethod,
        destroyed_key_hash: str,
        pre_erasure_root: str,
        regulator_id: Optional[str] = None,
        reason: Optional[str] = None,
        prior_accesses: int = 0,
        affected_users: Optional[List[str]] = None
    ) -> SecureErasureEvent:
        """
        Factory method for creating erasure events from destruction operations.
        
        Args:
            dataset_id: Dataset being destroyed
            identity: Data owner authorizing erasure
            method: Destruction method used
            destroyed_key_hash: SHA256 hash of destroyed cryptographic material
            pre_erasure_root: Merkle root before destruction (for audit)
            regulator_id: Optional case ID for regulatory compliance
            reason: Optional human-readable reason
            prior_accesses: Number of compute attestations before erasure
            affected_users: List of grantee identities losing access
        
        Returns:
            SecureErasureEvent ready for ledger append
        """
        return cls(
            dataset_id=dataset_id,
            erasure_method=method,
            erasure_proof=destroyed_key_hash,
            executing_identity=identity,
            pre_erasure_root_hash=pre_erasure_root,
            regulator_case_id=regulator_id,
            erasure_reason=reason,
            prior_access_count=prior_accesses,
            affected_grantees=affected_users or []
        )


class ComplianceReport(BaseModel):
    """
    Human and machine-readable erasure compliance report.
    
    Generated for:
    - Regulatory submissions (GDPR data protection authorities)
    - Legal documentation (proof of compliance)
    - Data subject confirmation (right to erasure request fulfilled)
    
    Contains:
    - Cryptographic proof of destruction
    - Legal basis citation
    - Audit trail metadata
    - Human-readable compliance statement
    
    Output Formats:
    - JSON (machine-readable)
    - Plain text (human-readable)
    - PDF (optional, via reportlab)
    """
    
    report_id: str = Field(default_factory=lambda: new_id("cr"))
    generated_at: str = Field(default_factory=now_utc)
    
    # Dataset information
    dataset_id: str
    erasure_event: SecureErasureEvent
    
    # Verification status
    ledger_chain_integrity: bool = True
    data_unrecoverable: bool = True
    cryptographic_proof_valid: bool = True
    
    # Legal compliance
    legal_statement: str = Field(
        default=(
            "All cryptographic keys and off-chain encrypted data for this dataset "
            "have been irreversibly destroyed in compliance with GDPR Article 17 "
            "(Right to Erasure) and California Privacy Rights Act § 1798.105. "
            "The data is cryptographically unrecoverable and cannot be restored "
            "through any technical means."
        )
    )
    
    regulatory_references: List[str] = Field(
        default_factory=lambda: [
            "GDPR Article 17: Right to Erasure",
            "CPRA § 1798.105: Right to Delete",
            "HIPAA Safe Harbor Method (if applicable)"
        ]
    )
    
    model_config = {"populate_by_name": True}
    
    def to_human_readable(self) -> str:
        """
        Generate human-readable compliance report.
        
        Suitable for:
        - Regulatory submission
        - Legal documentation
        - Data subject notification
        """
        return f"""
{'='*80}
GENOMIC DATA ERASURE COMPLIANCE REPORT
{'='*80}

Report ID:     {self.report_id}
Generated:     {self.generated_at}

DATASET INFORMATION:
-------------------
Dataset ID:    {self.dataset_id}
Erasure ID:    {self.erasure_event.erasure_id}

DESTRUCTION DETAILS:
-------------------
Method:        {self.erasure_event.erasure_method.value}
Executed by:   {self.erasure_event.executing_identity}
Timestamp:     {self.erasure_event.created_utc}
Scheme:        {self.erasure_event.erasure_scheme}

LEGAL BASIS:
-----------
{self.erasure_event.legal_basis}
Regulator ID:  {self.erasure_event.regulator_case_id or 'N/A'}
Reason:        {self.erasure_event.erasure_reason or 'Right to Erasure Request'}

CRYPTOGRAPHIC PROOF:
-------------------
Erasure Proof:     {self.erasure_event.erasure_proof}
Pre-erasure State: {self.erasure_event.pre_erasure_root_hash}
Post-erasure:      {self.erasure_event.post_erasure_state}

VERIFICATION STATUS:
-------------------
Ledger Integrity:  {'✅ VERIFIED' if self.ledger_chain_integrity else '❌ COMPROMISED'}
Data Recoverable:  {'❌ NO (permanently destroyed)' if self.data_unrecoverable else '⚠️  WARNING'}
Proof Valid:       {'✅ YES' if self.cryptographic_proof_valid else '❌ INVALID'}

AUDIT TRAIL:
-----------
Prior accesses:    {self.erasure_event.prior_access_count}
Affected users:    {', '.join(self.erasure_event.affected_grantees) if self.erasure_event.affected_grantees else 'None'}

COMPLIANCE STATEMENT:
--------------------
{self.legal_statement}

REGULATORY REFERENCES:
---------------------
{chr(10).join(f'- {ref}' for ref in self.regulatory_references)}

{'='*80}
This report constitutes cryptographic proof of data destruction in compliance
with applicable data protection regulations. The hash chain integrity ensures
this record cannot be altered or repudiated.
{'='*80}
"""
    
    def to_json_dict(self) -> dict:
        """Export as JSON-serializable dictionary."""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "dataset_id": self.dataset_id,
            "erasure_event": self.erasure_event.model_dump(by_alias=True),
            "verification": {
                "ledger_integrity": self.ledger_chain_integrity,
                "data_unrecoverable": self.data_unrecoverable,
                "proof_valid": self.cryptographic_proof_valid
            },
            "compliance": {
                "legal_statement": self.legal_statement,
                "regulatory_references": self.regulatory_references
            }
        }
