# GA4GH Passport Integration

**Status:** Production-ready (v1.2.0-ga4gh)  
**Standard:** GA4GH Passport v1.1  
**Algorithm:** EdDSA (Ed25519) for cryptographic consistency

---

## Overview

The DNA Ledger Vault now supports **GA4GH Passports** - standard bearer tokens recognized by the global genomics research ecosystem. This enables seamless data sharing with platforms like Terra, AnVIL, EGA, and thousands of GA4GH-compatible servers.

**Key Innovation:** Your internal `ConsentGrant` ledger entries automatically translate to internationally-recognized GA4GH Visas, maintaining cryptographic consistency with existing Ed25519 signing keys.

---

## Architecture

```
ConsentGrant (Internal)
    ↓ translation
GA4GH Visa (Standard)
    ↓ bundled into
GA4GH Passport JWT (Bearer Token)
    ↓ signed with
EdDSA (Ed25519) - Same keys as ledger signatures
```

**Design Principles:**
- ConsentGrant remains source of truth (no schema changes)
- GA4GH Visa is translation layer (interoperability)
- EdDSA signing uses existing identity keys (crypto consistency)
- Passports are time-bounded and cryptographically verifiable

---

## Quick Start

### 1. Issue a Passport

```bash
# After granting consent to a researcher
python -m cli.main issue-passport \
  --out state \
  --actor dave \
  --grantee researcher1 \
  --dataset-id ds_0193b889463de_c5b87f72a59b4836 \
  --lifetime 24 \
  --save
```

**Output:**
```
================================================================================
✅ GA4GH Passport JWT Issued
================================================================================

Issuer:    dave
Subject:   researcher1
Dataset:   ds_0193b889463de_c5b87f72a59b4836
Purpose:   research
Lifetime:  24 hours
Visas:     1 (ControlledAccessGrants)

JWT:
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImRhdmVfZWQyNTUxOSJ9.eyJpc3M...
================================================================================

💾 Passport saved to: state/passports/researcher1_ds_0193b889463de_1737244800.jwt
```

### 2. Verify a Passport

```python
from vault.passport_issuer import PassportIssuer

# Load issuer (for verification)
issuer = PassportIssuer.from_identity_folder("state", "dave")

# Verify JWT
passport_jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImRhdmVfZWQyNTUxOSJ9..."
claims = issuer.verify_passport(passport_jwt)

print(f"Subject: {claims.sub}")
print(f"Visas: {len(claims.ga4gh_passport_v1)}")
for visa in claims.ga4gh_passport_v1:
    print(f"  - {visa['type']}: {visa['value']}")
```

### 3. Export JWKS (Public Keys)

```python
# For verification endpoints (e.g., /.well-known/jwks.json)
issuer = PassportIssuer.from_identity_folder("state", "dave")
jwks = issuer.get_jwks()

import json
print(json.dumps(jwks, indent=2))
```

**Output:**
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "dave_ed25519",
      "x": "W6G8z9XmR...",
      "use": "sig",
      "alg": "EdDSA"
    }
  ]
}
```

---

## GA4GH Visa Structure

### Example Visa

```json
{
  "type": "ControlledAccessGrants",
  "value": "https://github.com/FractalFuryan/dna-ledger-vault/purpose#research",
  "source": "https://github.com/FractalFuryan/dna-ledger-vault",
  "asserted": 1737244800,
  "by": "system",
  "conditions": [
    {
      "type": "DataAccess",
      "value": "ds_0193b889463de_c5b87f72a59b4836",
      "source": "https://github.com/FractalFuryan/dna-ledger-vault",
      "by": "system"
    }
  ]
}
```

### Visa Mapping

| ConsentGrant Field | GA4GH Visa Field | Notes |
|--------------------|------------------|-------|
| `purpose` | `value` (as URI) | Mapped to standard URI format |
| `created_utc` | `asserted` (timestamp) | Preserved exactly |
| `dataset_id` | `conditions[0].value` | DataAccess condition |
| `scope` | Additional `conditions` | Custom scope constraints |
| `grantee` | Passport `sub` claim | Subject of JWT |

---

## Passport JWT Structure

### Header
```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "dave_ed25519"
}
```

### Payload
```json
{
  "iss": "dna-ledger-vault",
  "sub": "researcher1",
  "iat": 1737244800,
  "exp": 1737331200,
  "jti": "pp_0193b889463de_a1b2c3d4e5f67890",
  "ga4gh_passport_v1": [
    {
      "type": "ControlledAccessGrants",
      "value": "https://github.com/FractalFuryan/dna-ledger-vault/purpose#research",
      "source": "https://github.com/FractalFuryan/dna-ledger-vault",
      "asserted": 1737244800,
      "by": "system",
      "conditions": [...]
    }
  ]
}
```

### Signature
```
Ed25519 signature (64 bytes, base64url-encoded)
```

---

## Security Properties

### ✅ Deterministic Signing
- EdDSA (Ed25519) produces deterministic signatures
- No nonce reuse risk (unlike ECDSA without RFC6979)
- Same cryptographic foundation as ledger signatures

### ✅ Cryptographic Consistency
- Uses existing Ed25519 identity keys
- No new keypairs needed
- Maintains audit trail continuity

### ✅ Time-Bounded Validity
- `iat` (issued at) timestamp
- `exp` (expires at) timestamp
- Default: 24-hour lifetime (configurable)

### ✅ Revocation Checking
- Passport issuance checks ledger for revocations
- No passports issued for revoked grants
- Recipients must re-check ledger for active revocations

### ✅ Tamper-Evident
- JWT signature verification detects any modification
- Standard RS256/ES256/EdDSA verification libraries

---

## Integration Patterns

### Pattern 1: Data Access Gateway
```python
from vault.passport_issuer import PassportIssuer

def authorize_data_access(passport_jwt: str, dataset_id: str) -> bool:
    """Verify passport and check dataset access."""
    try:
        issuer = PassportIssuer.from_identity_folder("state", "dave")
        claims = issuer.verify_passport(passport_jwt)
        
        # Check for ControlledAccessGrants visa
        for visa in claims.ga4gh_passport_v1:
            if visa["type"] != "ControlledAccessGrants":
                continue
            
            # Check conditions for dataset access
            for condition in visa.get("conditions", []):
                if condition["type"] == "DataAccess" and condition["value"] == dataset_id:
                    return True
        
        return False
    except Exception:
        return False  # Fail closed
```

### Pattern 2: Federated Research Platform
```python
# Terra/AnVIL integration example
def submit_to_terra(passport_jwt: str, workspace: str):
    """Submit job to Terra workspace with GA4GH Passport."""
    import requests
    
    response = requests.post(
        f"https://api.firecloud.org/api/workspaces/{workspace}/submissions",
        headers={
            "Authorization": f"Bearer {passport_jwt}",
            "Content-Type": "application/json"
        },
        json={
            "methodConfiguration": "...",
            "entityType": "participant",
            "entityName": "...",
            "useCallCache": True
        }
    )
    
    return response.json()
```

### Pattern 3: JWKS Verification Endpoint
```python
from fastapi import FastAPI
from vault.passport_issuer import PassportIssuer

app = FastAPI()

@app.get("/.well-known/jwks.json")
async def get_jwks():
    """Public keys for passport verification."""
    issuer = PassportIssuer.from_identity_folder("state", "dave")
    return issuer.get_jwks()

@app.post("/verify-passport")
async def verify_passport(passport_jwt: str):
    """Verify a GA4GH Passport."""
    try:
        issuer = PassportIssuer.from_identity_folder("state", "dave")
        claims = issuer.verify_passport(passport_jwt)
        
        return {
            "valid": True,
            "subject": claims.sub,
            "visas": len(claims.ga4gh_passport_v1),
            "expires": claims.exp
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}
```

---

## Compatibility

### ✅ GA4GH Specification v1.1
- Standard visa types supported
- RFC 8037 (EdDSA) JWT signatures
- JWKS export format compliant

### ✅ Compatible Platforms
- **Terra** (Broad Institute)
- **AnVIL** (NHGRI)
- **EGA** (European Genome-phenome Archive)
- **Gen3** (University of Chicago)
- Any GA4GH Passport v1.x compliant service

### ✅ Backward Compatibility
- Existing ConsentGrant model unchanged
- No ledger schema migration required
- Passport issuance is opt-in (legacy workflows unaffected)

---

## Testing

### Run GA4GH Tests
```bash
pytest tests/test_ga4gh_passports.py -v
```

**Test Coverage (11 tests):**
- ✅ Visa creation from ConsentGrant
- ✅ Passport JWT signing (EdDSA)
- ✅ Passport verification (round-trip)
- ✅ Timestamp preservation
- ✅ Multiple visas per passport
- ✅ Scope conditions mapping
- ✅ JWKS export
- ✅ Passport ID uniqueness
- ✅ Expiry enforcement

---

## Scheme Versioning

**passport_scheme:** `ga4gh-passport-v1.1-eddsa`

This scheme identifier tracks:
- GA4GH Passport specification version (v1.1)
- Signing algorithm (EdDSA/Ed25519)

Future upgrades (e.g., PQ-hybrid signatures) will use new scheme identifiers while maintaining backward compatibility.

---

## References

- [GA4GH Passport Specification v1.1](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md)
- [RFC 8037 (EdDSA with JWK/JWT)](https://www.rfc-editor.org/rfc/rfc8037)
- [RFC 7519 (JSON Web Token)](https://www.rfc-editor.org/rfc/rfc7519)

---

**Status:** ✅ Production-ready  
**Philosophy:** Internal source of truth. External interoperability. Cryptographic consistency.
