"""
FastAPI v2 Observability Endpoints for DNA Ledger Vault.

Provides enhanced operational intelligence beyond basic REST API:
- Compliance health scoring
- Regulator-ready audit reports
- Dataset lifecycle timelines
- Anomaly detection (access pattern outliers)

Usage:
    uvicorn api.v2.observability:app --host 0.0.0.0 --port 8081
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from dna_ledger.ledger import HashChainedLedger
from dna_ledger.models import (
    ConsentGrant,
    ConsentRevocation,
    DatasetCommit,
    KeyRotationEvent,
)
from dna_ledger.erasure_models import SecureErasureEvent

# Initialize FastAPI app
app = FastAPI(
    title="DNA Ledger Vault Observability API",
    description="Enhanced operational intelligence and compliance reporting",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models for API Responses ---

class ComplianceHealthResponse(BaseModel):
    """Compliance health score with risk indicators."""
    overall_score: float
    risk_level: str  # "low", "medium", "high"
    metrics: Dict[str, Any]
    recommendations: List[str]


class RegulatorReportResponse(BaseModel):
    """GDPR/CPRA audit report for regulatory submission."""
    report_id: str
    generated_at: str
    organization: str
    compliance_period: str
    total_datasets: int
    total_consents: int
    total_revocations: int
    total_erasures: int
    data_subject_requests: Dict[str, int]
    breach_incidents: int
    audit_trail_integrity: bool
    certifications: List[str]


class TimelineEvent(BaseModel):
    """Single event in dataset lifecycle timeline."""
    timestamp: str
    event_type: str
    actor: str
    description: str
    metadata: Dict[str, Any]


class TimelineResponse(BaseModel):
    """Complete lifecycle timeline for a dataset."""
    dataset_id: str
    events: List[TimelineEvent]


class AnomalyDetectionResponse(BaseModel):
    """Anomalous access patterns detected in audit trail."""
    anomalies_detected: int
    anomalies: List[Dict[str, Any]]
    scoring_method: str


# --- Helper Functions ---

def load_ledger(state_dir: str = "state") -> HashChainedLedger:
    """Load ledger from state directory."""
    ledger_path = Path(state_dir) / "ledger.jsonl"
    
    if not ledger_path.exists():
        raise HTTPException(status_code=404, detail=f"Ledger not found at {ledger_path}")
    
    try:
        return HashChainedLedger.load_from_jsonl(str(ledger_path))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load ledger: {e}")


def calculate_compliance_score(ledger: HashChainedLedger) -> Dict[str, Any]:
    """Calculate compliance health score based on ledger events."""
    metrics = {
        "total_datasets": 0,
        "datasets_with_consent": 0,
        "active_consents": 0,
        "revocations": 0,
        "erasures": 0,
        "key_rotations": 0,
        "consent_coverage": 0.0,
        "erasure_response_time_avg": 0.0,
    }
    
    dataset_ids = set()
    datasets_with_consent = set()
    active_consent_count = 0
    revoked_grants = set()
    
    for event in ledger.events:
        if isinstance(event, DatasetCommit):
            dataset_ids.add(event.dataset_id)
            metrics["total_datasets"] += 1
        
        elif isinstance(event, ConsentGrant):
            datasets_with_consent.add(event.dataset_id)
            grant_id = f"{event.dataset_id}_{event.grantee}"
            if grant_id not in revoked_grants:
                active_consent_count += 1
            metrics["active_consents"] = active_consent_count
        
        elif isinstance(event, ConsentRevocation):
            grant_id = f"{event.dataset_id}_{event.grantee}"
            revoked_grants.add(grant_id)
            active_consent_count = max(0, active_consent_count - 1)
            metrics["revocations"] += 1
        
        elif isinstance(event, SecureErasureEvent):
            metrics["erasures"] += 1
        
        elif isinstance(event, KeyRotationEvent):
            metrics["key_rotations"] += 1
    
    metrics["datasets_with_consent"] = len(datasets_with_consent)
    metrics["consent_coverage"] = (
        len(datasets_with_consent) / max(1, len(dataset_ids)) * 100
    )
    
    # Calculate overall score (0-100)
    score = 0.0
    
    # 40 points: Consent coverage
    score += metrics["consent_coverage"] * 0.4
    
    # 30 points: Erasure responsiveness (presence of erasures = good)
    if metrics["total_datasets"] > 0:
        erasure_ratio = min(1.0, metrics["erasures"] / metrics["total_datasets"])
        score += erasure_ratio * 30
    
    # 20 points: Key rotation (security hygiene)
    if metrics["total_datasets"] > 0:
        rotation_ratio = min(1.0, metrics["key_rotations"] / metrics["total_datasets"])
        score += rotation_ratio * 20
    
    # 10 points: Active consent management (revocations show active governance)
    if metrics["active_consents"] > 0:
        revocation_ratio = min(1.0, metrics["revocations"] / metrics["active_consents"])
        score += revocation_ratio * 10
    
    return {
        "score": round(score, 2),
        "metrics": metrics
    }


def generate_recommendations(score: float, metrics: Dict[str, Any]) -> List[str]:
    """Generate actionable compliance recommendations."""
    recommendations = []
    
    if metrics["consent_coverage"] < 80:
        recommendations.append(
            "⚠️  Consent coverage is low. Ensure all datasets have documented consent grants."
        )
    
    if metrics["erasures"] == 0:
        recommendations.append(
            "ℹ️  No erasure events recorded. Test Right to Erasure workflow with non-production data."
        )
    
    if metrics["key_rotations"] == 0:
        recommendations.append(
            "⚠️  No key rotations detected. Schedule regular key rotation (e.g., annually)."
        )
    
    if metrics["revocations"] == 0 and metrics["active_consents"] > 5:
        recommendations.append(
            "ℹ️  No consent revocations. Ensure data subjects know how to withdraw consent."
        )
    
    if score >= 80:
        recommendations.append("✅ Excellent compliance posture. Continue current practices.")
    
    elif score >= 60:
        recommendations.append("✔️  Good compliance. Address warnings to reach excellent.")
    
    else:
        recommendations.append("⚠️  Compliance needs improvement. Prioritize warnings above.")
    
    return recommendations


# --- API Endpoints ---

@app.get("/", tags=["Meta"])
def root():
    """API root with version info."""
    return {
        "name": "DNA Ledger Vault Observability API",
        "version": "2.0.0",
        "endpoints": [
            "/compliance-health",
            "/regulator-report",
            "/timeline/{dataset_id}",
            "/anomaly-detection"
        ]
    }


@app.get("/compliance-health", response_model=ComplianceHealthResponse, tags=["Compliance"])
def compliance_health(state_dir: str = "state"):
    """
    Calculate compliance health score (0-100) with risk level.
    
    Scoring factors:
    - Consent coverage (40 points)
    - Erasure responsiveness (30 points)
    - Key rotation hygiene (20 points)
    - Revocation management (10 points)
    
    Returns:
        ComplianceHealthResponse with overall score, risk level, metrics, and recommendations
    """
    ledger = load_ledger(state_dir)
    
    result = calculate_compliance_score(ledger)
    score = result["score"]
    metrics = result["metrics"]
    
    # Determine risk level
    if score >= 80:
        risk_level = "low"
    elif score >= 60:
        risk_level = "medium"
    else:
        risk_level = "high"
    
    recommendations = generate_recommendations(score, metrics)
    
    return ComplianceHealthResponse(
        overall_score=score,
        risk_level=risk_level,
        metrics=metrics,
        recommendations=recommendations
    )


@app.get("/regulator-report", response_model=RegulatorReportResponse, tags=["Compliance"])
def regulator_report(
    state_dir: str = "state",
    organization: str = "DNA Ledger Vault Organization",
    period_days: int = 365
):
    """
    Generate GDPR/CPRA compliance report for regulatory submission.
    
    Includes:
    - Total datasets, consents, revocations, erasures
    - Data subject request statistics
    - Breach incident count
    - Audit trail integrity verification
    
    Args:
        state_dir: Path to state directory
        organization: Organization name for report
        period_days: Compliance period in days (default: 365 for annual report)
    
    Returns:
        RegulatorReportResponse suitable for submission to supervisory authorities
    """
    ledger = load_ledger(state_dir)
    
    # Verify ledger integrity
    integrity_ok = ledger.verify()
    
    # Count event types
    total_datasets = sum(1 for e in ledger.events if isinstance(e, DatasetCommit))
    total_consents = sum(1 for e in ledger.events if isinstance(e, ConsentGrant))
    total_revocations = sum(1 for e in ledger.events if isinstance(e, ConsentRevocation))
    total_erasures = sum(1 for e in ledger.events if isinstance(e, SecureErasureEvent))
    
    # Data subject rights exercised
    data_subject_requests = {
        "right_of_access": 0,  # Not yet tracked
        "right_to_rectification": 0,  # Not yet tracked
        "right_to_erasure": total_erasures,
        "right_to_restriction": 0,  # Not yet tracked
        "right_to_portability": 0,  # Not yet tracked
        "right_to_object": total_revocations  # Revocation = objection
    }
    
    # Generate report ID
    report_id = f"DLVR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    # Compliance period
    end_date = datetime.now()
    start_date = end_date - timedelta(days=period_days)
    compliance_period = f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
    
    # Certifications (based on implemented features)
    certifications = [
        "GDPR Article 17 (Right to Erasure) - DoD 5220.22-M",
        "GDPR Article 32 (Security) - ChaCha20-Poly1305 + Ed25519",
        "GDPR Article 30 (Records of Processing) - Immutable Audit Trail",
        "GA4GH Passport v1.1 (Interoperability)"
    ]
    
    return RegulatorReportResponse(
        report_id=report_id,
        generated_at=datetime.now().isoformat(),
        organization=organization,
        compliance_period=compliance_period,
        total_datasets=total_datasets,
        total_consents=total_consents,
        total_revocations=total_revocations,
        total_erasures=total_erasures,
        data_subject_requests=data_subject_requests,
        breach_incidents=0,  # Breach tracking not yet implemented
        audit_trail_integrity=integrity_ok,
        certifications=certifications
    )


@app.get("/timeline/{dataset_id}", response_model=TimelineResponse, tags=["Audit"])
def dataset_timeline(dataset_id: str, state_dir: str = "state"):
    """
    Get complete lifecycle timeline for a dataset.
    
    Returns all events related to a specific dataset in chronological order:
    - Dataset commit
    - Consent grants
    - Consent revocations
    - Key rotations
    - Erasure events
    
    Args:
        dataset_id: Dataset identifier
        state_dir: Path to state directory
    
    Returns:
        TimelineResponse with chronological event list
    """
    ledger = load_ledger(state_dir)
    
    events = []
    
    for event in ledger.events:
        # Check if event is related to this dataset
        is_relevant = False
        event_type = ""
        description = ""
        metadata = {}
        
        if isinstance(event, DatasetCommit) and event.dataset_id == dataset_id:
            is_relevant = True
            event_type = "dataset_commit"
            description = f"Dataset committed by {event.actor}"
            metadata = {
                "data_hash": event.data_hash,
                "merkle_root": event.merkle_root
            }
        
        elif isinstance(event, ConsentGrant) and event.dataset_id == dataset_id:
            is_relevant = True
            event_type = "consent_grant"
            description = f"Consent granted to {event.grantee} for {event.purpose}"
            metadata = {
                "grantee": event.grantee,
                "purpose": event.purpose,
                "expires_at": event.expires_at
            }
        
        elif isinstance(event, ConsentRevocation) and event.dataset_id == dataset_id:
            is_relevant = True
            event_type = "consent_revocation"
            description = f"Consent revoked for {event.grantee}"
            metadata = {
                "grantee": event.grantee,
                "reason": event.reason if hasattr(event, "reason") else ""
            }
        
        elif isinstance(event, SecureErasureEvent) and event.dataset_id == dataset_id:
            is_relevant = True
            event_type = "secure_erasure"
            description = f"Dataset erased using {event.method.value} method"
            metadata = {
                "method": event.method.value,
                "regulator_case_id": event.regulator_case_id,
                "erasure_proof_sha256": event.erasure_proof_sha256[:16] + "..." if event.erasure_proof_sha256 else ""
            }
        
        elif isinstance(event, KeyRotationEvent) and event.dataset_id == dataset_id:
            is_relevant = True
            event_type = "key_rotation"
            description = f"Encryption key rotated by {event.actor}"
            metadata = {
                "old_dek_fingerprint": event.old_dek_fingerprint[:16] + "...",
                "new_dek_fingerprint": event.new_dek_fingerprint[:16] + "..."
            }
        
        if is_relevant:
            events.append(TimelineEvent(
                timestamp=event.timestamp,
                event_type=event_type,
                actor=event.actor,
                description=description,
                metadata=metadata
            ))
    
    if not events:
        raise HTTPException(status_code=404, detail=f"No events found for dataset {dataset_id}")
    
    return TimelineResponse(
        dataset_id=dataset_id,
        events=events
    )


@app.get("/anomaly-detection", response_model=AnomalyDetectionResponse, tags=["Security"])
def anomaly_detection(state_dir: str = "state", threshold: float = 2.0):
    """
    Detect anomalous access patterns in audit trail.
    
    Flags:
    - Actors accessing unusually high number of datasets (>2 std devs from mean)
    - Rapid-fire consent grants (>5 in 1 hour)
    - Datasets with no consent grants (orphaned data)
    
    Args:
        state_dir: Path to state directory
        threshold: Standard deviation threshold for outlier detection (default: 2.0)
    
    Returns:
        AnomalyDetectionResponse with detected anomalies and scoring method
    """
    ledger = load_ledger(state_dir)
    
    anomalies = []
    
    # Track actor access patterns
    actor_dataset_access = defaultdict(set)
    consent_timestamps = []
    datasets_with_consent = set()
    all_datasets = set()
    
    for event in ledger.events:
        if isinstance(event, DatasetCommit):
            all_datasets.add(event.dataset_id)
        
        elif isinstance(event, ConsentGrant):
            actor_dataset_access[event.grantee].add(event.dataset_id)
            datasets_with_consent.add(event.dataset_id)
            
            # Parse timestamp for rapid-fire detection
            try:
                ts = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
                consent_timestamps.append(ts)
            except:
                pass
    
    # Anomaly 1: Actors with unusually high dataset access
    if len(actor_dataset_access) > 1:
        access_counts = [len(datasets) for datasets in actor_dataset_access.values()]
        mean_access = sum(access_counts) / len(access_counts)
        
        if len(access_counts) > 1:
            variance = sum((x - mean_access) ** 2 for x in access_counts) / len(access_counts)
            std_dev = variance ** 0.5
            
            for actor, datasets in actor_dataset_access.items():
                if len(datasets) > mean_access + (threshold * std_dev):
                    anomalies.append({
                        "type": "excessive_access",
                        "severity": "medium",
                        "actor": actor,
                        "datasets_accessed": len(datasets),
                        "mean_access": round(mean_access, 2),
                        "threshold": round(mean_access + (threshold * std_dev), 2),
                        "description": f"Actor {actor} has accessed {len(datasets)} datasets (>{threshold}σ above mean)"
                    })
    
    # Anomaly 2: Rapid-fire consent grants
    if len(consent_timestamps) > 1:
        consent_timestamps.sort()
        for i in range(len(consent_timestamps) - 5):
            # Check if 5+ consents granted within 1 hour
            window = consent_timestamps[i:i+5]
            if (window[-1] - window[0]).total_seconds() < 3600:
                anomalies.append({
                    "type": "rapid_fire_consents",
                    "severity": "high",
                    "count": 5,
                    "timeframe_minutes": round((window[-1] - window[0]).total_seconds() / 60, 2),
                    "start_time": window[0].isoformat(),
                    "description": "5+ consent grants issued within 1 hour (potential bulk operation or compromise)"
                })
                break  # Only report once
    
    # Anomaly 3: Orphaned datasets (no consent grants)
    orphaned = all_datasets - datasets_with_consent
    if orphaned:
        anomalies.append({
            "type": "orphaned_datasets",
            "severity": "low",
            "datasets": list(orphaned),
            "count": len(orphaned),
            "description": f"{len(orphaned)} dataset(s) have no consent grants (data minimization concern)"
        })
    
    return AnomalyDetectionResponse(
        anomalies_detected=len(anomalies),
        anomalies=anomalies,
        scoring_method=f"Statistical outlier detection (threshold: {threshold}σ)"
    )


# Run with: uvicorn api.v2.observability:app --reload --port 8081
