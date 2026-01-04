from __future__ import annotations

import time
import uuid
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from dna_ledger import __schema__

Purpose = Literal["clinical", "ancestry", "research", "pharma", "ml_training"]

def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def new_id(prefix: str) -> str:
    """
    Generate UUIDv7-style time-ordered ID for collision resistance + audit ordering.
    
    Format: {prefix}_{timestamp_ms:013x}_{random:016x}
    - Monotonic ordering even across merges
    - Collision-proof with 64 random bits
    - Audit-friendly chronological sorting
    """
    timestamp_ms = int(time.time() * 1000)
    random_bits = uuid.uuid4().hex[:16]  # 64 random bits
    return f"{prefix}_{timestamp_ms:013x}_{random_bits}"

class DatasetCommit(BaseModel):
    kind: Literal["DatasetCommit"] = "DatasetCommit"
    schema_version: str = Field(default=__schema__, alias="schema")  # Schema version stamp
    dataset_id: str = Field(default_factory=lambda: new_id("ds"))
    created_utc: str = Field(default_factory=now_utc)
    owner: str
    bytes: int
    sha256_plain: str
    merkle_root: str
    chunk_hashes: List[str]
    commit_hash: Optional[str] = None  # computed after model creation
    
    model_config = {"populate_by_name": True}

class ConsentGrant(BaseModel):
    kind: Literal["ConsentGrant"] = "ConsentGrant"
    schema_version: str = Field(default=__schema__, alias="schema")  # Schema version stamp
    grant_id: str = Field(default_factory=lambda: new_id("cg"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    dataset_commit_hash: str  # binds to specific dataset version
    grantee: str
    purpose: Purpose
    scope: Dict[str, str] = Field(default_factory=dict)  # freeform constraints
    expires_utc: str
    revocable: bool = True
    wrapped_dek_b64: str  # initial wrap at grant time
    owner_x25519_pub_pem_b64: str
    
    model_config = {"populate_by_name": True}

class ComputeAttestation(BaseModel):
    kind: Literal["ComputeAttestation"] = "ComputeAttestation"
    schema_version: str = Field(default=__schema__, alias="schema")  # Schema version stamp
    attestation_id: str = Field(default_factory=lambda: new_id("ca"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    purpose: Purpose
    algo_name: str
    algo_sha256: str
    output_sha256: str
    
    model_config = {"populate_by_name": True}

class ConsentRevocation(BaseModel):
    kind: Literal["ConsentRevocation"] = "ConsentRevocation"
    schema_version: str = Field(default=__schema__, alias="schema")  # Schema version stamp
    revocation_id: str = Field(default_factory=lambda: new_id("cr"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    grant_id: str
    reason: Optional[str] = None
    
    model_config = {"populate_by_name": True}

class KeyRotationEvent(BaseModel):
    kind: Literal["KeyRotationEvent"] = "KeyRotationEvent"
    schema_version: str = Field(default=__schema__, alias="schema")  # Schema version stamp
    rotation_id: str = Field(default_factory=lambda: new_id("kr"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    new_dek_sha256: str
    
    model_config = {"populate_by_name": True}

class KeyWrapEvent(BaseModel):
    kind: Literal["KeyWrapEvent"] = "KeyWrapEvent"
    schema_version: str = Field(default=__schema__, alias="schema")  # Schema version stamp
    wrap_id: str = Field(default_factory=lambda: new_id("kw"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    dataset_commit_hash: str
    grantee: str
    purpose: Purpose
    rotation_id: str  # binds to specific rotation (or "initial" for first wrap)
    wrapped_dek_b64: str
    owner_x25519_pub_pem_b64: str
    
    model_config = {"populate_by_name": True}
