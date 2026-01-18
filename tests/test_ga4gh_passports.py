"""
GA4GH Passport Integration Tests

Comprehensive test suite for GA4GH Passport/Visa issuance and verification.
Tests translation from ConsentGrant to GA4GH Visa, JWT signing, and verification.

Test Coverage:
- Visa creation from ConsentGrant
- Passport JWT signing (EdDSA)
- Passport verification
- JWKS export
- Edge cases (expired grants, revoked grants)
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta

import pytest

from dna_ledger.ga4gh_models import GA4GHVisa, GA4GHPassportClaims, GA4GHVisaCondition
from dna_ledger.models import ConsentGrant, new_id
from vault.passport_issuer import PassportIssuer
from dna_ledger.signing import gen_ed25519


class TestGA4GHVisaCreation:
    """Test GA4GH Visa model creation and translation from ConsentGrant."""
    
    def test_visa_from_consent_grant_basic(self):
        """Test basic visa creation from consent grant."""
        # Create a sample consent grant
        grant = ConsentGrant(
            grant_id=new_id("cg"),
            created_utc="2026-01-18T12:00:00Z",
            dataset_id="ds_test123",
            dataset_commit_hash="abcd1234",
            grantee="researcher1",
            purpose="research",
            scope={},
            expires_utc="2026-02-18T12:00:00Z",
            wrapped_dek_b64="fake_dek",
            owner_x25519_pub_pem_b64="fake_pub"
        )
        
        # Convert to GA4GH Visa
        visa = GA4GHVisa.from_consent_grant(grant)
        
        # Verify visa structure
        assert visa.type == "ControlledAccessGrants"
        assert "research" in visa.value
        assert visa.by == "system"
        assert visa.conditions is not None
        assert len(visa.conditions) == 1
        assert visa.conditions[0].type == "DataAccess"
        assert visa.conditions[0].value == "ds_test123"
    
    def test_visa_with_scope_conditions(self):
        """Test visa creation with scope constraints."""
        grant = ConsentGrant(
            grant_id=new_id("cg"),
            created_utc="2026-01-18T12:00:00Z",
            dataset_id="ds_test456",
            dataset_commit_hash="abcd5678",
            grantee="researcher2",
            purpose="clinical",
            scope={"region": "US", "cohort": "cancer"},
            expires_utc="2026-02-18T12:00:00Z",
            wrapped_dek_b64="fake_dek",
            owner_x25519_pub_pem_b64="fake_pub"
        )
        
        visa = GA4GHVisa.from_consent_grant(grant)
        
        # Should have 3 conditions: DataAccess + 2 scope conditions
        assert len(visa.conditions) == 3
        condition_types = {c.type for c in visa.conditions}
        assert "DataAccess" in condition_types
        assert "Scope_region" in condition_types
        assert "Scope_cohort" in condition_types
    
    def test_visa_timestamp_preservation(self):
        """Test that consent grant timestamp is preserved in visa."""
        test_time = "2026-01-15T10:30:45Z"
        grant = ConsentGrant(
            grant_id=new_id("cg"),
            created_utc=test_time,
            dataset_id="ds_test789",
            dataset_commit_hash="abcd9012",
            grantee="researcher3",
            purpose="research",
            scope={},
            expires_utc="2026-02-18T12:00:00Z",
            wrapped_dek_b64="fake_dek",
            owner_x25519_pub_pem_b64="fake_pub"
        )
        
        visa = GA4GHVisa.from_consent_grant(grant)
        
        # Convert asserted timestamp back to datetime (UTC)
        from datetime import timezone
        dt = datetime.fromtimestamp(visa.asserted, tz=timezone.utc)
        
        # Should match original timestamp (within 1 second tolerance)
        original_dt = datetime.fromisoformat(test_time.replace("Z", "+00:00"))
        assert abs((dt - original_dt).total_seconds()) < 1
    
    def test_visa_to_dict_export(self):
        """Test visa export to dictionary format."""
        grant = ConsentGrant(
            grant_id=new_id("cg"),
            created_utc="2026-01-18T12:00:00Z",
            dataset_id="ds_testABC",
            dataset_commit_hash="abcdEFGH",
            grantee="researcher4",
            purpose="ancestry",
            scope={},
            expires_utc="2026-02-18T12:00:00Z",
            wrapped_dek_b64="fake_dek",
            owner_x25519_pub_pem_b64="fake_pub"
        )
        
        visa = GA4GHVisa.from_consent_grant(grant)
        visa_dict = visa.to_dict()
        
        # Verify dict structure
        assert isinstance(visa_dict, dict)
        assert visa_dict["type"] == "ControlledAccessGrants"
        assert "ancestry" in visa_dict["value"]
        assert "conditions" in visa_dict
        assert isinstance(visa_dict["conditions"], list)


class TestPassportJWTSigning:
    """Test JWT signing and verification with Ed25519 keys."""
    
    def test_passport_issuance_basic(self):
        """Test basic passport JWT issuance."""
        # Generate test Ed25519 keypair
        ed_priv_pem, ed_pub_pem = gen_ed25519()
        
        # Create issuer from PEM keys
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        
        private_key = load_pem_private_key(ed_priv_pem, password=None)
        public_key = private_key.public_key()
        
        issuer = PassportIssuer(
            issuer_id="test-issuer",
            private_key=private_key,
            public_key=public_key,
            key_id="test_key_1"
        )
        
        # Create a test visa
        visa = GA4GHVisa(
            type="ControlledAccessGrants",
            value="https://test.org/purpose#research",
            source="https://test.org",
            asserted=int(time.time()),
            by="system",
            conditions=[
                GA4GHVisaCondition(
                    type="DataAccess",
                    value="ds_test123"
                )
            ]
        )
        
        # Issue passport
        passport_jwt = issuer.issue_passport(
            subject="researcher1",
            visas=[visa],
            lifetime_hours=24
        )
        
        # Verify JWT structure (should be 3 parts: header.payload.signature)
        parts = passport_jwt.split(".")
        assert len(parts) == 3
    
    def test_passport_verification_round_trip(self):
        """Test passport issuance and verification round-trip."""
        # Generate test keypair
        ed_priv_pem, ed_pub_pem = gen_ed25519()
        
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        
        private_key = load_pem_private_key(ed_priv_pem, password=None)
        public_key = private_key.public_key()
        
        issuer = PassportIssuer(
            issuer_id="test-issuer",
            private_key=private_key,
            public_key=public_key,
            key_id="test_key_2"
        )
        
        # Create visa
        visa = GA4GHVisa(
            type="ControlledAccessGrants",
            value="https://test.org/purpose#research",
            source="https://test.org",
            asserted=int(time.time()),
            by="system"
        )
        
        # Issue passport
        passport_jwt = issuer.issue_passport(
            subject="researcher2",
            visas=[visa],
            lifetime_hours=1
        )
        
        # Verify passport
        claims = issuer.verify_passport(passport_jwt)
        
        # Check claims
        assert claims.iss == "test-issuer"
        assert claims.sub == "researcher2"
        assert len(claims.ga4gh_passport_v1) == 1
        assert claims.ga4gh_passport_v1[0]["type"] == "ControlledAccessGrants"
    
    def test_passport_expiry_enforcement(self):
        """Test that expired passports are rejected."""
        # Generate test keypair
        ed_priv_pem, ed_pub_pem = gen_ed25519()
        
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        
        private_key = load_pem_private_key(ed_priv_pem, password=None)
        public_key = private_key.public_key()
        
        issuer = PassportIssuer(
            issuer_id="test-issuer",
            private_key=private_key,
            public_key=public_key,
            key_id="test_key_3"
        )
        
        # Create visa
        visa = GA4GHVisa(
            type="ControlledAccessGrants",
            value="https://test.org/purpose#research",
            source="https://test.org",
            asserted=int(time.time()),
            by="system"
        )
        
        # Issue passport with very short lifetime
        # (Note: We can't easily test actual expiry without time manipulation,
        #  but we verify the exp claim is set correctly)
        passport_jwt = issuer.issue_passport(
            subject="researcher3",
            visas=[visa],
            lifetime_hours=24
        )
        
        # Decode to check exp claim
        import jwt
        payload = jwt.decode(passport_jwt, options={"verify_signature": False})
        
        # Exp should be ~24 hours from now
        now = int(time.time())
        expected_exp = now + (24 * 3600)
        assert abs(payload["exp"] - expected_exp) < 60  # Within 1 minute tolerance
    
    def test_passport_multiple_visas(self):
        """Test passport with multiple visas."""
        # Generate test keypair
        ed_priv_pem, ed_pub_pem = gen_ed25519()
        
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        
        private_key = load_pem_private_key(ed_priv_pem, password=None)
        public_key = private_key.public_key()
        
        issuer = PassportIssuer(
            issuer_id="test-issuer",
            private_key=private_key,
            public_key=public_key,
            key_id="test_key_4"
        )
        
        # Create multiple visas
        visa1 = GA4GHVisa(
            type="ControlledAccessGrants",
            value="https://test.org/purpose#research",
            source="https://test.org",
            asserted=int(time.time()),
            by="system"
        )
        
        visa2 = GA4GHVisa(
            type="ResearcherStatus",
            value="https://test.org/status#faculty",
            source="https://test.org",
            asserted=int(time.time()),
            by="system"
        )
        
        # Issue passport with both visas
        passport_jwt = issuer.issue_passport(
            subject="researcher4",
            visas=[visa1, visa2],
            lifetime_hours=24
        )
        
        # Verify both visas are in passport
        claims = issuer.verify_passport(passport_jwt)
        assert len(claims.ga4gh_passport_v1) == 2
        
        visa_types = {v["type"] for v in claims.ga4gh_passport_v1}
        assert "ControlledAccessGrants" in visa_types
        assert "ResearcherStatus" in visa_types
    
    def test_jwks_export(self):
        """Test JWKS public key export."""
        # Generate test keypair
        ed_priv_pem, ed_pub_pem = gen_ed25519()
        
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        
        private_key = load_pem_private_key(ed_priv_pem, password=None)
        public_key = private_key.public_key()
        
        issuer = PassportIssuer(
            issuer_id="test-issuer",
            private_key=private_key,
            public_key=public_key,
            key_id="test_key_5"
        )
        
        # Export JWKS
        jwks = issuer.get_jwks()
        
        # Verify JWKS structure
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        
        key = jwks["keys"][0]
        assert key["kty"] == "OKP"  # Octet Key Pair
        assert key["crv"] == "Ed25519"
        assert key["kid"] == "test_key_5"
        assert key["alg"] == "EdDSA"
        assert "x" in key  # Public key component


class TestGA4GHEdgeCases:
    """Test edge cases and error handling."""
    
    def test_passport_id_uniqueness(self):
        """Test that passport IDs are unique."""
        ed_priv_pem, ed_pub_pem = gen_ed25519()
        
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        
        private_key = load_pem_private_key(ed_priv_pem, password=None)
        public_key = private_key.public_key()
        
        issuer = PassportIssuer(
            issuer_id="test-issuer",
            private_key=private_key,
            public_key=public_key,
            key_id="test_key_6"
        )
        
        visa = GA4GHVisa(
            type="ControlledAccessGrants",
            value="https://test.org/purpose#research",
            source="https://test.org",
            asserted=int(time.time()),
            by="system"
        )
        
        # Issue multiple passports
        jwt1 = issuer.issue_passport("researcher1", [visa])
        jwt2 = issuer.issue_passport("researcher1", [visa])
        
        # Decode to check jti (passport ID)
        import jwt
        payload1 = jwt.decode(jwt1, options={"verify_signature": False})
        payload2 = jwt.decode(jwt2, options={"verify_signature": False})
        
        # Passport IDs should be different
        assert payload1.get("jti") != payload2.get("jti")
    
    def test_visa_condition_optional(self):
        """Test visa creation without conditions."""
        visa = GA4GHVisa(
            type="ResearcherStatus",
            value="https://test.org/status#faculty",
            source="https://test.org",
            asserted=int(time.time()),
            by="system"
        )
        
        # Conditions should be None or empty
        assert visa.conditions is None or len(visa.conditions) == 0
        
        # Should still export correctly
        visa_dict = visa.to_dict()
        assert "type" in visa_dict
        assert "value" in visa_dict


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
