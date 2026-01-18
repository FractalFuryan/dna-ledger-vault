"""
GA4GH Passport and Visa Models (v1.1 Specification)

Implements standard GA4GH Passport Visas for genomic data access control.
Translates internal ConsentGrant model into globally-recognized credentials.

Reference: https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md

Design Philosophy:
- ConsentGrant remains source of truth (internal)
- GA4GH Visa is translation layer (external interop)
- No modification to existing crypto schemes
- Maintains audit trail (asserted timestamp preserved)
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from dna_ledger.models import ConsentGrant

# GA4GH Visa Types (standard values)
VisaType = Literal[
    "AffiliationAndRole",
    "AcceptedTermsAndPolicies",
    "ResearcherStatus",
    "ControlledAccessGrants",
    "LinkedIdentities"
]

# GA4GH Assertion Sources
AssertionBy = Literal["self", "peer", "system", "so", "dac"]


class GA4GHVisaCondition(BaseModel):
    """
    GA4GH Visa Condition - restricts visa validity to specific contexts.
    
    Example: DataAccess condition binds visa to specific dataset.
    """
    type: str  # "AffiliationAndRole" | "DataAccess" | custom
    value: str  # The specific constraint value
    source: Optional[str] = None  # Where this condition was asserted
    by: Optional[AssertionBy] = None  # Who asserted this condition
    
    model_config = {"extra": "allow"}  # Allow extension fields


class GA4GHVisa(BaseModel):
    """
    GA4GH Visa (v1.1) - A single access credential claim.
    
    For DNA Ledger Vault, we primarily use ControlledAccessGrants visas
    to represent consent grants. The visa binds a researcher identity to
    a specific genomic dataset access permission.
    
    Security Properties:
    - Immutable once issued (signed in JWT)
    - Time-bounded (asserted timestamp + expiry in Passport)
    - Revocable (check ledger for revocations)
    - Dataset-specific (via conditions)
    
    Example Visa for Research Access:
    {
        "type": "ControlledAccessGrants",
        "value": "https://dnaledger.example/purpose#research",
        "source": "https://github.com/FractalFuryan/dna-ledger-vault",
        "asserted": 1737244800,
        "by": "system",
        "conditions": [{
            "type": "DataAccess",
            "value": "ds_0193b889463de_c5b87f72a59b4836"
        }]
    }
    """
    
    # Core GA4GH claims (required)
    type: VisaType
    value: str  # Purpose URI, role, status, etc.
    source: str  # Issuing organization/system
    asserted: int  # Unix timestamp when claim was asserted
    by: AssertionBy = "system"  # Default: system-generated (not self-asserted)
    
    # Optional GA4GH claims
    conditions: Optional[List[GA4GHVisaCondition]] = None
    
    model_config = {"extra": "allow"}  # GA4GH allows extension fields
    
    @classmethod
    def from_consent_grant(
        cls,
        grant: ConsentGrant,
        issuer_uri: str = "https://github.com/FractalFuryan/dna-ledger-vault"
    ) -> GA4GHVisa:
        """
        Translate internal ConsentGrant into standard GA4GH ControlledAccessGrants visa.
        
        Mapping Strategy:
        - grant.purpose → visa.value (as URI)
        - grant.created_utc → visa.asserted (preserved timestamp)
        - grant.dataset_id → visa.conditions (DataAccess binding)
        - grant.grantee → Passport.sub (not in visa itself)
        
        Args:
            grant: Internal consent grant from ledger
            issuer_uri: Organization identifier (defaults to repo URL)
        
        Returns:
            GA4GH-compliant ControlledAccessGrants visa
        
        Example:
            >>> grant = ConsentGrant(...)
            >>> visa = GA4GHVisa.from_consent_grant(grant)
            >>> assert visa.type == "ControlledAccessGrants"
        """
        # Convert grant.created_utc (ISO 8601) to Unix timestamp
        try:
            dt = datetime.fromisoformat(grant.created_utc.replace("Z", "+00:00"))
            asserted_ts = int(dt.timestamp())
        except (ValueError, AttributeError):
            # Fallback: current time if parsing fails
            asserted_ts = int(time.time())
        
        # Map internal purpose to GA4GH-compatible URI
        # Standard format: https://{issuer}/purpose#{purpose_value}
        purpose_uri = f"{issuer_uri}/purpose#{grant.purpose}"
        
        # Create DataAccess condition binding visa to specific dataset
        conditions = [
            GA4GHVisaCondition(
                type="DataAccess",
                value=grant.dataset_id,
                source=issuer_uri,
                by="system"
            )
        ]
        
        # Add scope constraints as additional conditions (if present)
        for scope_key, scope_value in grant.scope.items():
            conditions.append(
                GA4GHVisaCondition(
                    type=f"Scope_{scope_key}",  # Custom condition type
                    value=scope_value,
                    source=issuer_uri,
                    by="system"
                )
            )
        
        return cls(
            type="ControlledAccessGrants",
            value=purpose_uri,
            source=issuer_uri,
            asserted=asserted_ts,
            by="system",  # System-generated (not researcher self-asserted)
            conditions=conditions
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Export visa as GA4GH-compliant dictionary (for JWT payload)."""
        return self.model_dump(exclude_none=True, by_alias=True)


class GA4GHPassportClaims(BaseModel):
    """
    GA4GH Passport JWT Claims (v1.1)
    
    A Passport is a signed JWT containing one or more Visas.
    The JWT payload follows standard claims (iss, sub, exp, etc.)
    with the addition of the ga4gh_passport_v1 array.
    
    JWT Structure:
    {
        "iss": "dna-ledger-vault",           # Issuer identifier
        "sub": "researcher1",                 # Subject (researcher identity)
        "iat": 1737244800,                    # Issued at (Unix timestamp)
        "exp": 1737331200,                    # Expires at (Unix timestamp)
        "jti": "pp_0193b889463de_...",       # Unique passport ID
        "ga4gh_passport_v1": [                # Array of GA4GH Visas
            {
                "type": "ControlledAccessGrants",
                "value": "https://dnaledger.example/purpose#research",
                "source": "https://github.com/FractalFuryan/dna-ledger-vault",
                "asserted": 1737244800,
                "by": "system",
                "conditions": [...]
            }
        ]
    }
    
    This is the payload that gets signed into the JWT.
    """
    
    # Standard JWT claims
    iss: str  # Issuer (your DNA Ledger Vault instance)
    sub: str  # Subject (researcher identity)
    iat: int  # Issued at (Unix timestamp)
    exp: int  # Expires at (Unix timestamp)
    jti: Optional[str] = None  # JWT ID (unique passport identifier)
    
    # GA4GH-specific claim
    ga4gh_passport_v1: List[Dict[str, Any]]  # Array of visa dictionaries
    
    @classmethod
    def from_visas(
        cls,
        issuer: str,
        subject: str,
        visas: List[GA4GHVisa],
        lifetime_hours: int = 24,
        passport_id: Optional[str] = None
    ) -> GA4GHPassportClaims:
        """
        Create Passport claims from a list of visas.
        
        Args:
            issuer: Issuer identifier (e.g., "dna-ledger-vault")
            subject: Researcher identity (grantee)
            visas: List of GA4GH visas to bundle
            lifetime_hours: Passport validity period (default: 24 hours)
            passport_id: Optional unique ID for this passport
        
        Returns:
            GA4GH Passport claims ready for JWT signing
        """
        now = int(time.time())
        exp = now + (lifetime_hours * 3600)
        
        return cls(
            iss=issuer,
            sub=subject,
            iat=now,
            exp=exp,
            jti=passport_id,
            ga4gh_passport_v1=[visa.to_dict() for visa in visas]
        )
    
    def to_jwt_payload(self) -> Dict[str, Any]:
        """Export as JWT payload dictionary."""
        return self.model_dump(exclude_none=True, by_alias=True)
