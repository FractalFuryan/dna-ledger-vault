"""
GDPR/CPRA compliance document templates.
Generates DPA, DPIA, and compliance checklists for data stewards.

These templates provide a starting point for legal compliance.
Consult with legal counsel before using in production.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict


class ComplianceTemplates:
    """Static methods for generating compliance documents."""
    
    @staticmethod
    def generate_dpa_template(org_info: Dict[str, Any]) -> str:
        """Generate Data Processing Agreement template (GDPR Article 28)."""
        org_name = org_info.get('org_name', '[ORGANIZATION NAME]')
        jurisdiction = org_info.get('jurisdiction', 'EU')
        generated_date = datetime.now().strftime("%Y-%m-%d")
        
        return f"""# DATA PROCESSING AGREEMENT (DPA)
**Between Data Controller and Data Processor**

Generated: {generated_date}
Organization: {org_name}
Jurisdiction: {jurisdiction}

---

## 1. DEFINITIONS

**"Personal Data"** means genomic data, clinical information, or any data that can identify a natural person.

**"Processing"** means any operation performed on Personal Data, including collection, storage, retrieval, and erasure.

**"Data Controller"** means {org_name}, which determines the purposes and means of processing Personal Data.

**"Data Processor"** means any third party processing Personal Data on behalf of the Data Controller.

---

## 2. SCOPE AND PURPOSE

This agreement governs the processing of Personal Data stored in the DNA Ledger Vault system. The Data Processor shall process Personal Data only:

- For the specific research purposes authorized by Data Subjects
- Within the scope of consent grants documented in the ledger
- In compliance with GDPR (Regulation (EU) 2016/679) or CPRA (California Civil Code § 1798.100 et seq.)

---

## 3. DATA PROCESSOR OBLIGATIONS

The Data Processor shall:

### 3.1 Confidentiality
- Process Personal Data only on documented instructions from the Data Controller
- Ensure personnel authorized to process Personal Data have committed to confidentiality
- Implement role-based access control (RBAC) enforced by the ledger's consent system

### 3.2 Security Measures
- Use ChaCha20-Poly1305 AEAD encryption for data at rest
- Implement Ed25519 digital signatures for authenticity (with post-quantum migration plan)
- Maintain cryptographic audit trail for all data access events
- Follow DoD 5220.22-M standard for secure data erasure

### 3.3 Sub-Processing
- Not engage sub-processors without prior written authorization from the Data Controller
- Maintain list of authorized sub-processors in `identities.json`
- Ensure sub-processors are bound by equivalent data protection obligations

### 3.4 Data Subject Rights
- Assist the Data Controller in responding to requests for exercising Data Subject rights:
  * Right of Access (GDPR Article 15)
  * Right to Rectification (GDPR Article 16)
  * Right to Erasure (GDPR Article 17) — implemented via `secure-erase` command
  * Right to Restriction of Processing (GDPR Article 18)
  * Right to Data Portability (GDPR Article 20)

### 3.5 Data Breach Notification
- Notify the Data Controller without undue delay (within 72 hours) of any Personal Data breach
- Include in notification:
  * Nature of breach
  * Affected data subjects (consult `ledger.jsonl` for dataset linkage)
  * Likely consequences
  * Measures taken or proposed to address the breach

---

## 4. DATA CONTROLLER OBLIGATIONS

The Data Controller shall:

- Provide clear instructions for processing operations
- Maintain consent records for all data subjects
- Conduct Data Protection Impact Assessments (DPIAs) for high-risk processing
- Appoint a Data Protection Officer (DPO) if required by GDPR Article 37
  * DPO Contact: {org_info.get('dpo_email', '[DPO EMAIL]')}

---

## 5. TECHNICAL AND ORGANIZATIONAL MEASURES

The DNA Ledger Vault system implements the following safeguards:

### 5.1 Encryption
- AES-256 or ChaCha20-Poly1305 for symmetric encryption
- Ed25519 for digital signatures (2048-bit RSA equivalent)
- Post-quantum migration path to ML-KEM-768 and ML-DSA-65

### 5.2 Access Control
- Cryptographic identity management (Ed25519 key pairs)
- Consent-based access grants with time-limited permissions
- Immutable audit trail recording all dataset accesses

### 5.3 Data Minimization
- Only necessary metadata stored on-ledger
- Encrypted vault storage for bulk genomic data
- Automatic consent expiration after grant period

### 5.4 Erasure Capabilities
- Three erasure methods: CRYPTO_SHRED, VAULT_DELETE, FULL_PURGE
- DoD 5220.22-M 3-pass overwrite for physical deletion
- Cryptographic proof of erasure recorded on ledger

---

## 6. INTERNATIONAL TRANSFERS

If Personal Data is transferred outside the {jurisdiction}:

- Use Standard Contractual Clauses (SCCs) approved by the European Commission
- Conduct Transfer Impact Assessment (TIA) per Schrems II ruling
- Document transfer mechanisms in `compliance_package/transfer_log.csv`

---

## 7. AUDITS AND INSPECTIONS

The Data Processor shall:

- Allow the Data Controller to conduct audits of processing activities
- Provide access to `ledger.jsonl` and `state/` directory for audit verification
- Respond to audit findings within 30 days

---

## 8. TERM AND TERMINATION

### 8.1 Duration
This DPA remains in effect as long as the Data Processor processes Personal Data on behalf of the Data Controller.

### 8.2 Post-Termination
Upon termination, the Data Processor shall:
- Return or delete all Personal Data (use `secure-erase` command)
- Provide certification of deletion (see `ComplianceReport` in erasure_models.py)
- Retain audit logs for statutory retention periods

---

## 9. LIABILITY AND INDEMNIFICATION

The Data Processor shall indemnify the Data Controller against:
- Fines imposed by supervisory authorities due to Processor's GDPR violations
- Damages arising from unauthorized or unlawful processing by Processor

Maximum liability: [TO BE NEGOTIATED]

---

## 10. GOVERNING LAW

This DPA is governed by the laws of {jurisdiction}.

Disputes shall be resolved by:
- Supervisory authority mediation (GDPR Article 77)
- Arbitration in [ARBITRATION VENUE]

---

## SIGNATURES

**Data Controller ({org_name})**

Signature: ____________________________
Name: _________________________________
Title: ________________________________
Date: _________________________________

**Data Processor**

Signature: ____________________________
Name: _________________________________
Title: ________________________________
Date: _________________________________

---

## APPENDIX A: DATA CATEGORIES

The following Personal Data categories are processed:

- [ ] Genomic variants (VCF files)
- [ ] Gene expression data
- [ ] Clinical metadata (age, diagnosis, treatment)
- [ ] Contact information (for consent management)
- [ ] Biometric identifiers

---

## APPENDIX B: TECHNICAL SPECIFICATIONS

- **Encryption Algorithm**: ChaCha20-Poly1305
- **Signature Scheme**: Ed25519 (post-quantum migration planned)
- **Erasure Standard**: DoD 5220.22-M
- **Audit Trail Format**: JSONL with SHA256 hash chains
- **Access Control**: GA4GH Passport/Visa JWT tokens

For technical documentation, see:
- `docs/SECURITY.md`
- `docs/RIGHT_TO_ERASURE.md`
- `docs/PQ_ROADMAP.md`

---

**DISCLAIMER**: This is a template only. Consult qualified legal counsel before executing any Data Processing Agreement. This template does not constitute legal advice.
"""
    
    @staticmethod
    def generate_dpia_outline(dataset_info: Dict[str, Any]) -> str:
        """Generate Data Protection Impact Assessment (DPIA) outline (GDPR Article 35)."""
        dataset_name = dataset_info.get('metadata', {}).get('dataset_name', '[DATASET NAME]')
        dataset_id = dataset_info.get('id', '[DATASET ID]')
        data_type = dataset_info.get('metadata', {}).get('data_type', 'Genomic Data')
        generated_date = datetime.now().strftime("%Y-%m-%d")
        
        return f"""# DATA PROTECTION IMPACT ASSESSMENT (DPIA)

**Dataset**: {dataset_name}
**Dataset ID**: {dataset_id}
**Data Type**: {data_type}
**Assessment Date**: {generated_date}

---

## 1. NECESSITY AND PROPORTIONALITY

### 1.1 Processing Purpose
**Research Objective**: 
[Describe the scientific or medical research purpose]

**Legal Basis**:
- [ ] Consent (GDPR Article 6(1)(a))
- [ ] Legitimate interests (GDPR Article 6(1)(f))
- [ ] Public interest / scientific research (GDPR Article 9(2)(j))

**Necessity**:
[Explain why processing this specific genomic data is necessary to achieve the research objective]

### 1.2 Proportionality
- **Data Minimization**: Are only essential data points collected?
  * ✅ Only {data_type} required for stated purpose
  * ⚠️ Review: Is clinical metadata limited to relevant fields?

- **Storage Limitation**: How long will data be retained?
  * Default: Duration of active consent grants
  * Long-term: [Specify retention period, e.g., "10 years per IRB protocol"]

---

## 2. RISKS TO DATA SUBJECTS

### 2.1 Identification Risk
**Genomic data is inherently identifiable** (genetic fingerprint).

Mitigation measures:
- ✅ Encrypted vault storage (ChaCha20-Poly1305)
- ✅ Access control via consent grants
- ⚠️ Consider: Differential privacy for aggregate queries (future feature)

### 2.2 Discrimination Risk
Unauthorized disclosure could lead to:
- Genetic discrimination in employment or insurance
- Stigmatization based on disease predisposition

Mitigation measures:
- ✅ Immutable audit trail (who accessed what, when)
- ✅ Time-limited access grants (default: 90 days)
- ⚠️ Training: Educate researchers on ethical use obligations

### 2.3 Re-identification Risk
Even anonymized genomic data can be re-identified via:
- Cross-referencing with public databases
- Familial matching

Mitigation measures:
- ✅ Controlled access (no public data release without review)
- ⚠️ Consider: Encryption of SNP positions in VCF exports

### 2.4 Data Breach Risk
**Impact if breach occurs**:
- High: Genomic data cannot be "changed" like a password
- Permanent: Genetic information is immutable

Mitigation measures:
- ✅ Encryption at rest and in transit
- ✅ Ed25519 digital signatures prevent tampering
- ✅ Breach detection: Monitor `ledger.jsonl` for anomalous access patterns
- ✅ Incident response: `secure-erase` command for emergency data destruction

---

## 3. MEASURES TO ADDRESS RISKS

### 3.1 Technical Safeguards

| Safeguard | Implementation | Status |
|-----------|----------------|--------|
| **Encryption** | ChaCha20-Poly1305 AEAD | ✅ Deployed |
| **Authentication** | Ed25519 digital signatures | ✅ Deployed |
| **Access Control** | Consent grants + GA4GH Passports | ✅ Deployed |
| **Audit Trail** | Immutable JSONL ledger | ✅ Deployed |
| **Secure Erasure** | DoD 5220.22-M 3-pass overwrite | ✅ Deployed |
| **Post-Quantum Crypto** | ML-KEM / ML-DSA migration | ⏳ Roadmap (18 months) |

### 3.2 Organizational Safeguards

- [ ] Data steward training on GDPR/CPRA compliance
- [ ] Researcher ethics certification required before access
- [ ] Annual security audits by external assessor
- [ ] Incident response plan documented and tested
- [ ] DPO appointed (if processing >5,000 data subjects)

### 3.3 Data Subject Rights

| Right | Implementation |
|-------|----------------|
| **Access** | `ledger.jsonl` query by dataset ID |
| **Rectification** | Re-commit corrected dataset with provenance link |
| **Erasure** | `cli.main secure-erase` command (3 methods) |
| **Portability** | Export decrypted VCF with consent grant proof |
| **Restriction** | Revoke consent grant (blocks future access) |

---

## 4. CONSULTATION AND SIGN-OFF

### 4.1 Stakeholder Consultation
- [ ] Data subjects informed via consent process
- [ ] Researchers briefed on access limitations
- [ ] Institutional Review Board (IRB) approval obtained
  * IRB Number: [FROM organization_profile.json]

### 4.2 DPO Review
**Data Protection Officer Sign-Off**:

Name: _____________________________
Date: _____________________________
Comments:
[DPO to confirm adequacy of safeguards]

### 4.3 Supervisory Authority Consultation
Required if residual high risk remains after mitigation.

- [ ] Consultation with supervisory authority initiated
- [ ] Authority feedback incorporated into processing design

---

## 5. MONITORING AND REVIEW

### 5.1 Continuous Monitoring
- **Audit Trail Review**: Weekly review of `ledger.jsonl` for anomalies
- **Access Pattern Analysis**: Monthly report on consent grant usage
- **Breach Simulation**: Quarterly tabletop exercises

### 5.2 DPIA Review Schedule
This DPIA shall be reviewed:
- Annually on anniversary of first processing
- Upon significant changes to processing activities
- After any data breach or security incident

Next Review Date: [ONE YEAR FROM {generated_date}]

---

## 6. APPROVAL

**Data Controller Approval**:

I confirm that this DPIA adequately identifies and mitigates risks to data subjects.

Signature: ____________________________
Name: _________________________________
Title: ________________________________
Date: _________________________________

---

## APPENDIX: RISK MATRIX

| Risk | Likelihood | Impact | Residual Risk (Post-Mitigation) |
|------|-----------|--------|----------------------------------|
| Unauthorized access | Low | High | **Low** (encryption + access control) |
| Data breach | Low | High | **Medium** (encryption mitigates, but genomic data is permanent) |
| Re-identification | Medium | High | **Medium** (controlled access, but familial matching possible) |
| Discrimination | Low | High | **Low** (audit trail deters misuse) |

---

**REFERENCES**:
- GDPR Article 35: Data Protection Impact Assessments
- ICO DPIA Guidance (UK): https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/accountability-and-governance/data-protection-impact-assessments/
- EDPB Guidelines on DPIA: https://edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-32018-data-protection-impact-assessment-dpia_en

**DISCLAIMER**: This is a template DPIA outline. A complete DPIA requires domain-specific risk assessment by qualified professionals. Consult legal and data protection experts.
"""
    
    @staticmethod
    def generate_compliance_checklist() -> str:
        """Generate CSV compliance checklist for GDPR/CPRA requirements."""
        return """Requirement,Standard,Implemented,Evidence,Notes
Data encryption at rest,GDPR Art. 32(1),Yes,ChaCha20-Poly1305 in vault/crypto.py,256-bit keys
Data encryption in transit,GDPR Art. 32(1),Partial,HTTPS for API endpoints,Enable TLS for production
Pseudonymization,GDPR Art. 32(1)(a),Yes,Dataset IDs replace direct identifiers,VCF filenames not exposed on ledger
Access control,GDPR Art. 32(1)(b),Yes,Consent grants + GA4GH Passports,Time-limited permissions enforced
Audit trail,GDPR Art. 30,Yes,Immutable ledger.jsonl,SHA256 hash chain prevents tampering
Right to erasure,GDPR Art. 17,Yes,secure-erase command with 3 methods,DoD 5220.22-M certified
Data portability,GDPR Art. 20,Partial,VCF export via decrypt,Add automated export endpoint
Consent management,GDPR Art. 7,Yes,ConsentGrant model with expiry,Withdrawal supported (revoke grant)
Breach notification,GDPR Art. 33,No,Manual process,TODO: Automated breach detection
DPIA conducted,GDPR Art. 35,Partial,Template generated by wizard,Requires domain-specific risk assessment
DPO appointed,GDPR Art. 37,If Applicable,Check organization_profile.json,Required if >5k data subjects
International transfers,GDPR Art. 44-50,No,No cross-border transfers yet,Use SCCs if needed
Data minimization,GDPR Art. 5(1)(c),Yes,Only authorized data in vault,Regularly review consent scopes
Storage limitation,GDPR Art. 5(1)(e),Yes,Consent expiry triggers access revocation,Consider automated archival
Accuracy,GDPR Art. 5(1)(d),Partial,Provenance links for corrections,Add rectification workflow
Purpose limitation,GDPR Art. 5(1)(b),Yes,Consent purpose field required,Enforce purpose checks in API
Lawfulness,GDPR Art. 6,Yes,Consent-based processing,Document legal basis in consent records
Accountability,GDPR Art. 5(2),Partial,Audit logs + compliance reports,Conduct annual compliance review
Security testing,GDPR Art. 32(1)(d),No,No penetration testing yet,Schedule annual security audit
Incident response plan,GDPR Art. 33-34,No,No formal IRP,Draft and test incident procedures
Staff training,GDPR Art. 32(4),No,No training program,Implement annual GDPR training
Privacy by design,GDPR Art. 25,Yes,Encryption + access control by default,Continue in future features
Privacy by default,GDPR Art. 25(2),Yes,Minimal data collection,No data collected without consent
Records of processing,GDPR Art. 30,Partial,Ledger tracks operations,Create ROPA (Record of Processing Activities)
Supervisory authority cooperation,GDPR Art. 31,N/A,No investigations yet,Establish contact with local DPA
Data subject rights response,GDPR Art. 12-22,Partial,Erasure + access implemented,Add rectification + restriction workflows
CPRA: Right to know,CPRA §1798.100,Yes,Audit trail queryable by dataset,Expose via API endpoint
CPRA: Right to delete,CPRA §1798.105,Yes,secure-erase command,Certified implementation
CPRA: Right to opt-out,CPRA §1798.120,Yes,Consent withdrawal supported,Add opt-out UI element
CPRA: Right to correct,CPRA §1798.106,Partial,Provenance links,Automate correction workflow
CPRA: Data minimization,CPRA §1798.100(c),Yes,Consent-scoped access,Regular consent audits
CPRA: Sensitive PI limitations,CPRA §1798.121,Yes,No genomic data sharing without consent,Genomic = sensitive per CPRA
CPRA: Automated decision-making,CPRA §1798.185,N/A,No automated decisions made,Future: Disclose if ML models used
CPRA: Risk assessment,CPRA §1798.185(a)(15),Partial,DPIA template generated,Complete domain-specific assessment
"""


if __name__ == "__main__":
    # Generate sample templates for preview
    sample_org = {
        "org_name": "University Medical Center",
        "org_type": "Hospital",
        "jurisdiction": "EU",
        "dpo_email": "dpo@example.org"
    }
    
    sample_dataset = {
        "id": "ds_sample_001",
        "metadata": {
            "dataset_name": "Cancer Genomics Cohort",
            "data_type": "Genomic Variants (VCF)"
        }
    }
    
    print("=== DATA PROCESSING AGREEMENT ===\n")
    print(ComplianceTemplates.generate_dpa_template(sample_org))
    
    print("\n\n=== DPIA OUTLINE ===\n")
    print(ComplianceTemplates.generate_dpia_outline(sample_dataset))
    
    print("\n\n=== COMPLIANCE CHECKLIST (first 10 rows) ===\n")
    checklist_lines = ComplianceTemplates.generate_compliance_checklist().split('\n')
    print('\n'.join(checklist_lines[:10]))
