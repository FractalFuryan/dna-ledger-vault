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

class ConsentGrant(BaseModel):
    kind: Literal["ConsentGrant"] = "ConsentGrant"
    grant_id: str = Field(default_factory=lambda: new_id("cg"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    grantee: str
    purpose: Purpose
    scope: Dict[str, str] = Field(default_factory=dict)  # freeform constraints
    expires_utc: str
    revocable: bool = True

class ComputeAttestation(BaseModel):
    kind: Literal["ComputeAttestation"] = "ComputeAttestation"
    attestation_id: str = Field(default_factory=lambda: new_id("ca"))
    created_utc: str = Field(default_factory=now_utc)
    dataset_id: str
    purpose: Purpose
    algo_name: str
    algo_sha256: str
    output_sha256: str
