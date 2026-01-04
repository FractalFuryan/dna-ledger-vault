from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Dict, Literal, Optional, List
import time
import uuid

Purpose = Literal["clinical", "ancestry", "research", "pharma", "ml_training"]

def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"

class DatasetCommit(BaseModel):
    kind: Literal["DatasetCommit"] = "DatasetCommit"
    dataset_id: str = Field(default_factory=lambda: new_id("ds"))
    created_utc: str = Field(default_factory=now_utc)
    owner: str
    bytes: int
    sha256_plain: str
    merkle_root: str
    chunk_hashes: List[str]
    commit_hash: Optional[str] = None  # computed after model creation

class ConsentGrant(BaseModel):
    kind: Literal["ConsentGrant"] = "ConsentGrant"
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

class ComputeAttestation(BaseModel):
    kind: Literal["ComputeAttestation"] = "ComputeAttestation"
    attestation_id: str = Field(default_factory=lambda: new_id("ca"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    purpose: Purpose
    algo_name: str
    algo_sha256: str
    output_sha256: str

class ConsentRevocation(BaseModel):
    kind: Literal["ConsentRevocation"] = "ConsentRevocation"
    revocation_id: str = Field(default_factory=lambda: new_id("cr"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    grant_id: str
    reason: Optional[str] = None

class KeyRotationEvent(BaseModel):
    kind: Literal["KeyRotationEvent"] = "KeyRotationEvent"
    rotation_id: str = Field(default_factory=lambda: new_id("kr"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    new_dek_sha256: str

class KeyWrapEvent(BaseModel):
    kind: Literal["KeyWrapEvent"] = "KeyWrapEvent"
    wrap_id: str = Field(default_factory=lambda: new_id("kw"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    dataset_commit_hash: str
    grantee: str
    purpose: Purpose
    rotation_id: str  # binds to specific rotation (or "initial" for first wrap)
    wrapped_dek_b64: str
    owner_x25519_pub_pem_b64: str
