"""
GA4GH Passport Issuer - JWT Signing Service

Issues signed GA4GH Passport JWTs from ConsentGrant ledger entries.
Uses existing Ed25519 identity keys with EdDSA algorithm (RFC 8037).

Security Model:
- Same Ed25519 keys used for ledger signing
- EdDSA (RFC 8037) for JWT signatures
- No new keypairs needed (cryptographic consistency)
- Passports cryptographically bound to issuer identity

Scheme Versioning:
- passport_scheme: "ga4gh-passport-v1.1-eddsa"
- Maintains audit trail of signing method
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from dna_ledger.ga4gh_models import GA4GHPassportClaims, GA4GHVisa
from dna_ledger.models import ConsentGrant, new_id


class PassportIssuer:
    """
    Issues GA4GH Passport JWTs using Ed25519 signing keys.
    
    Uses EdDSA algorithm (RFC 8037) for JWT signatures, maintaining
    cryptographic consistency with existing Ed25519 ledger signatures.
    
    Key Format:
    - Private key: Raw 32-byte Ed25519 seed (hex-encoded in identities.json)
    - Public key: PEM format for JWKS export
    - Algorithm: EdDSA (Ed25519 curve)
    
    Usage:
        issuer = PassportIssuer.from_identity("state/identities.json", "dave")
        visa = GA4GHVisa.from_consent_grant(grant)
        passport_jwt = issuer.issue_passport("researcher1", [visa])
    """
    
    def __init__(
        self,
        issuer_id: str,
        private_key: ed25519.Ed25519PrivateKey,
        public_key: ed25519.Ed25519PublicKey,
        key_id: str
    ):
        """
        Initialize passport issuer with Ed25519 keys.
        
        Args:
            issuer_id: Issuer identifier (e.g., "dna-ledger-vault")
            private_key: Ed25519 private key for signing
            public_key: Ed25519 public key for verification/JWKS
            key_id: Key identifier for JWT header (kid)
        """
        self.issuer_id = issuer_id
        self.private_key = private_key
        self.public_key = public_key
        self.key_id = key_id
        self.scheme = "ga4gh-passport-v1.1-eddsa"  # Scheme versioning
    
    def issue_passport(
        self,
        subject: str,
        visas: List[GA4GHVisa],
        lifetime_hours: int = 24,
        passport_id: Optional[str] = None
    ) -> str:
        """
        Issue a signed GA4GH Passport JWT.
        
        Args:
            subject: Researcher identity (grantee)
            visas: List of GA4GH visas to include
            lifetime_hours: Passport validity period (default: 24h)
            passport_id: Optional unique passport ID
        
        Returns:
            Signed JWT string (base64url-encoded)
        
        Security Properties:
        - EdDSA signatures (deterministic, no nonce reuse risk)
        - Time-bounded (exp claim enforced)
        - Revocable (check ledger for revocations)
        - Tamper-evident (JWT signature verification)
        
        Example:
            >>> visa = GA4GHVisa.from_consent_grant(grant)
            >>> passport_jwt = issuer.issue_passport("researcher1", [visa])
            >>> # JWT can be presented to GA4GH-compatible services
        """
        # Generate unique passport ID if not provided
        if passport_id is None:
            passport_id = new_id("pp")
        
        # Create passport claims
        claims = GA4GHPassportClaims.from_visas(
            issuer=self.issuer_id,
            subject=subject,
            visas=visas,
            lifetime_hours=lifetime_hours,
            passport_id=passport_id
        )
        
        # Convert Ed25519 private key to PEM for PyJWT
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # JWT header (EdDSA algorithm per RFC 8037)
        headers = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": self.key_id
        }
        
        # Sign and encode JWT
        passport_jwt = jwt.encode(
            payload=claims.to_jwt_payload(),
            key=private_pem,
            algorithm="EdDSA",
            headers=headers
        )
        
        return passport_jwt
    
    def verify_passport(self, passport_jwt: str) -> GA4GHPassportClaims:
        """
        Verify and decode a GA4GH Passport JWT.
        
        Args:
            passport_jwt: Signed JWT string
        
        Returns:
            Decoded passport claims
        
        Raises:
            jwt.InvalidTokenError: If signature invalid or expired
        
        Usage:
            >>> claims = issuer.verify_passport(passport_jwt)
            >>> visas = claims.ga4gh_passport_v1
        """
        # Convert Ed25519 public key to PEM for PyJWT
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Verify and decode JWT
        payload = jwt.decode(
            jwt=passport_jwt,
            key=public_pem,
            algorithms=["EdDSA"],
            issuer=self.issuer_id,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True
            }
        )
        
        return GA4GHPassportClaims(**payload)
    
    def get_jwks(self) -> dict:
        """
        Export public key in JWKS format for verification endpoints.
        
        Returns:
            JWKS dictionary with Ed25519 public key
        
        Usage:
            Place at /.well-known/jwks.json for GA4GH verification
        
        Example:
            >>> jwks = issuer.get_jwks()
            >>> # Serve via FastAPI endpoint
        """
        # Convert public key to raw bytes
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Base64url encode (no padding)
        import base64
        x_b64 = base64.urlsafe_b64encode(public_bytes).decode("utf-8").rstrip("=")
        
        return {
            "keys": [
                {
                    "kty": "OKP",  # Octet Key Pair (RFC 8037)
                    "crv": "Ed25519",  # Curve name
                    "kid": self.key_id,  # Key ID
                    "x": x_b64,  # Public key (base64url)
                    "use": "sig",  # Key usage: signature
                    "alg": "EdDSA"  # Algorithm
                }
            ]
        }
    
    @classmethod
    def from_identity(
        cls,
        identities_path: str,
        actor: str,
        issuer_id: str = "dna-ledger-vault"
    ) -> PassportIssuer:
        """
        Load passport issuer from existing identity file.
        
        Args:
            identities_path: Path to identities.json
            actor: Identity name (e.g., "dave")
            issuer_id: Issuer identifier (default: "dna-ledger-vault")
        
        Returns:
            Initialized PassportIssuer
        
        Raises:
            FileNotFoundError: If identities.json not found
            KeyError: If actor not in identities
        
        Example:
            >>> issuer = PassportIssuer.from_identity("state/identities.json", "dave")
        """
        # Load identities
        with open(identities_path, "r") as f:
            identities = json.load(f)
        
        if actor not in identities:
            raise KeyError(f"Identity '{actor}' not found in {identities_path}")
        
        identity = identities[actor]
        
        # Load Ed25519 private key (hex-encoded 32-byte seed)
        ed_priv_hex = identity["ed25519_priv"]
        seed_bytes = bytes.fromhex(ed_priv_hex)
        
        # Reconstruct Ed25519 keypair
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes)
        public_key = private_key.public_key()
        
        # Use actor name as key ID
        key_id = f"{actor}_ed25519"
        
        return cls(
            issuer_id=issuer_id,
            private_key=private_key,
            public_key=public_key,
            key_id=key_id
        )
    
    @classmethod
    def from_identity_folder(
        cls,
        state_folder: str,
        actor: str,
        issuer_id: str = "dna-ledger-vault"
    ) -> PassportIssuer:
        """
        Convenience method: load from state folder.
        
        Args:
            state_folder: Path to state directory (e.g., "./state")
            actor: Identity name
            issuer_id: Issuer identifier
        
        Returns:
            Initialized PassportIssuer
        
        Example:
            >>> issuer = PassportIssuer.from_identity_folder("state", "dave")
        """
        identities_path = Path(state_folder) / "identities.json"
        return cls.from_identity(str(identities_path), actor, issuer_id)
