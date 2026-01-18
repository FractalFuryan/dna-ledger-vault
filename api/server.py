"""
DNA Ledger Vault Web Dashboard API Server

Flask REST API for:
- Ledger visualization
- Dataset management
- Consent grant workflow
- Audit trail export
- GA4GH Passport issuance

Run:
    flask --app api.server run --port 8080
    
Or with gunicorn (production):
    gunicorn -w 4 -b 0.0.0.0:8080 api.server:app
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from dna_ledger.ledger import HashChainedLedger
from dna_ledger.models import (
    ComputeAttestation,
    ConsentGrant,
    ConsentRevocation,
    DatasetCommit,
    KeyRotationEvent,
)
from dna_ledger.erasure_models import SecureErasureEvent
from vault.passport_issuer import PassportIssuer

app = Flask(__name__, static_folder="../dashboard/build", static_url_path="")
CORS(app)  # Enable CORS for React development

# Configuration
STATE_DIR = os.getenv("DNA_LEDGER_STATE", "./state")
LEDGER_PATH = os.path.join(STATE_DIR, "ledger.jsonl")


@app.route("/")
def serve_frontend():
    """Serve React frontend."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/health")
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "version": "1.3.0-pq-preview",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


@app.route("/api/ledger/stats")
def ledger_stats():
    """Get ledger statistics."""
    try:
        ledger = HashChainedLedger.load_from_jsonl(LEDGER_PATH)
        
        # Count event types
        event_counts = {}
        for event in ledger.events:
            kind = event.kind
            event_counts[kind] = event_counts.get(kind, 0) + 1
        
        # Calculate chain metrics
        chain_root = ledger.chain_root()
        
        return jsonify({
            "total_events": len(ledger.events),
            "chain_root": chain_root,
            "event_types": event_counts,
            "integrity": "verified",
            "last_updated": datetime.utcnow().isoformat() + "Z"
        })
    
    except FileNotFoundError:
        return jsonify({"error": "Ledger not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ledger/events")
def get_ledger_events():
    """
    Get all ledger events with optional filtering.
    
    Query params:
        - kind: Filter by event type (DatasetCommit, ConsentGrant, etc.)
        - dataset_id: Filter by dataset ID
        - identity: Filter by identity
        - limit: Max events to return
        - offset: Pagination offset
    """
    try:
        ledger = HashChainedLedger.load_from_jsonl(LEDGER_PATH)
        
        # Apply filters
        events = ledger.events
        
        kind_filter = request.args.get("kind")
        if kind_filter:
            events = [e for e in events if e.kind == kind_filter]
        
        dataset_filter = request.args.get("dataset_id")
        if dataset_filter:
            events = [
                e for e in events 
                if hasattr(e, "dataset_id") and e.dataset_id == dataset_filter
            ]
        
        identity_filter = request.args.get("identity")
        if identity_filter:
            events = [
                e for e in events 
                if hasattr(e, "identity") and e.identity == identity_filter
            ]
        
        # Pagination
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        
        total = len(events)
        events = events[offset:offset + limit]
        
        # Serialize events
        serialized = []
        for event in events:
            event_dict = event.model_dump() if hasattr(event, "model_dump") else event.dict()
            serialized.append(event_dict)
        
        return jsonify({
            "events": serialized,
            "total": total,
            "limit": limit,
            "offset": offset
        })
    
    except FileNotFoundError:
        return jsonify({"error": "Ledger not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/datasets")
def get_datasets():
    """Get all datasets with their current status."""
    try:
        ledger = HashChainedLedger.load_from_jsonl(LEDGER_PATH)
        
        datasets = {}
        
        for event in ledger.events:
            if isinstance(event, DatasetCommit):
                dataset_id = event.dataset_id
                
                if dataset_id not in datasets:
                    datasets[dataset_id] = {
                        "dataset_id": dataset_id,
                        "owner": event.identity,
                        "merkle_root": event.merkle_root,
                        "commit_timestamp": event.timestamp_utc,
                        "active_grants": 0,
                        "total_grants": 0,
                        "compute_count": 0,
                        "erased": False
                    }
            
            elif isinstance(event, ConsentGrant):
                dataset_id = event.dataset_id
                if dataset_id in datasets:
                    datasets[dataset_id]["total_grants"] += 1
                    
                    # Check if not revoked
                    is_revoked = any(
                        isinstance(e, ConsentRevocation) and e.grant_id == event.grant_id
                        for e in ledger.events
                    )
                    if not is_revoked:
                        datasets[dataset_id]["active_grants"] += 1
            
            elif isinstance(event, ComputeAttestation):
                dataset_id = event.dataset_id
                if dataset_id in datasets:
                    datasets[dataset_id]["compute_count"] += 1
            
            elif isinstance(event, SecureErasureEvent):
                dataset_id = event.dataset_id
                if dataset_id in datasets:
                    datasets[dataset_id]["erased"] = True
                    datasets[dataset_id]["erasure_timestamp"] = event.erasure_timestamp_utc
        
        return jsonify({"datasets": list(datasets.values())})
    
    except FileNotFoundError:
        return jsonify({"error": "Ledger not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/datasets/<dataset_id>")
def get_dataset_details(dataset_id: str):
    """Get detailed information about a specific dataset."""
    try:
        ledger = HashChainedLedger.load_from_jsonl(LEDGER_PATH)
        
        # Find dataset commit
        commit = None
        for event in ledger.events:
            if isinstance(event, DatasetCommit) and event.dataset_id == dataset_id:
                commit = event
                break
        
        if not commit:
            return jsonify({"error": "Dataset not found"}), 404
        
        # Collect all related events
        grants = []
        attestations = []
        erasures = []
        
        for event in ledger.events:
            if not hasattr(event, "dataset_id") or event.dataset_id != dataset_id:
                continue
            
            if isinstance(event, ConsentGrant):
                grant_dict = event.model_dump() if hasattr(event, "model_dump") else event.dict()
                
                # Check revocation status
                is_revoked = any(
                    isinstance(e, ConsentRevocation) and e.grant_id == event.grant_id
                    for e in ledger.events
                )
                grant_dict["revoked"] = is_revoked
                grants.append(grant_dict)
            
            elif isinstance(event, ComputeAttestation):
                attestations.append(event.model_dump() if hasattr(event, "model_dump") else event.dict())
            
            elif isinstance(event, SecureErasureEvent):
                erasures.append(event.model_dump() if hasattr(event, "model_dump") else event.dict())
        
        return jsonify({
            "dataset_id": dataset_id,
            "owner": commit.identity,
            "merkle_root": commit.merkle_root,
            "commit_timestamp": commit.timestamp_utc,
            "grants": grants,
            "attestations": attestations,
            "erasures": erasures,
            "status": "erased" if erasures else "active"
        })
    
    except FileNotFoundError:
        return jsonify({"error": "Ledger not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/grants")
def get_grants():
    """Get all consent grants with revocation status."""
    try:
        ledger = HashChainedLedger.load_from_jsonl(LEDGER_PATH)
        
        grants = []
        
        for event in ledger.events:
            if isinstance(event, ConsentGrant):
                grant_dict = event.model_dump() if hasattr(event, "model_dump") else event.dict()
                
                # Check revocation
                is_revoked = any(
                    isinstance(e, ConsentRevocation) and e.grant_id == event.grant_id
                    for e in ledger.events
                )
                grant_dict["revoked"] = is_revoked
                
                # Check expiration
                try:
                    exp_dt = datetime.fromisoformat(event.expires_utc.replace("Z", "+00:00"))
                    now_dt = datetime.now(exp_dt.tzinfo)
                    grant_dict["expired"] = now_dt > exp_dt
                except Exception:
                    grant_dict["expired"] = False
                
                grants.append(grant_dict)
        
        return jsonify({"grants": grants})
    
    except FileNotFoundError:
        return jsonify({"error": "Ledger not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit-trail")
def get_audit_trail():
    """Get complete audit trail for compliance."""
    try:
        ledger = HashChainedLedger.load_from_jsonl(LEDGER_PATH)
        
        audit_events = []
        
        for i, event in enumerate(ledger.events):
            event_dict = event.model_dump() if hasattr(event, "model_dump") else event.dict()
            
            audit_events.append({
                "index": i,
                "kind": event.kind,
                "timestamp": event.timestamp_utc if hasattr(event, "timestamp_utc") else None,
                "identity": event.identity if hasattr(event, "identity") else None,
                "dataset_id": event.dataset_id if hasattr(event, "dataset_id") else None,
                "details": event_dict
            })
        
        return jsonify({
            "audit_trail": audit_events,
            "chain_root": ledger.chain_root(),
            "total_events": len(audit_events)
        })
    
    except FileNotFoundError:
        return jsonify({"error": "Ledger not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/passports/issue", methods=["POST"])
def issue_passport():
    """
    Issue a GA4GH Passport JWT.
    
    Request body:
    {
        "actor": "dataset_owner",
        "grantee": "researcher_id",
        "dataset_id": "ds_example",
        "lifetime_hours": 24
    }
    """
    try:
        data = request.get_json()
        
        actor = data.get("actor")
        grantee = data.get("grantee")
        dataset_id = data.get("dataset_id")
        lifetime_hours = int(data.get("lifetime_hours", 24))
        
        if not all([actor, grantee, dataset_id]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Load ledger
        ledger = HashChainedLedger.load_from_jsonl(LEDGER_PATH)
        
        # Find active grant
        from dna_ledger.ga4gh_models import GA4GHVisa
        
        active_grant = None
        for event in ledger.events:
            if not isinstance(event, ConsentGrant):
                continue
            if event.dataset_id != dataset_id or event.grantee != grantee:
                continue
            
            # Check not revoked
            is_revoked = any(
                isinstance(e, ConsentRevocation) and e.grant_id == event.grant_id
                for e in ledger.events
            )
            if is_revoked:
                continue
            
            active_grant = event
            break
        
        if not active_grant:
            return jsonify({"error": "No active grant found"}), 404
        
        # Create visa
        visa = GA4GHVisa.from_consent_grant(active_grant)
        
        # Issue passport
        issuer = PassportIssuer.from_identity_folder(STATE_DIR, actor)
        passport_jwt = issuer.issue_passport(
            subject=grantee,
            visas=[visa],
            lifetime_hours=lifetime_hours
        )
        
        return jsonify({
            "passport": passport_jwt,
            "expires_in_hours": lifetime_hours,
            "grantee": grantee,
            "dataset_id": dataset_id
        })
    
    except FileNotFoundError:
        return jsonify({"error": "Ledger or keys not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/verify")
def verify_ledger():
    """Verify ledger integrity."""
    try:
        ledger = HashChainedLedger(LEDGER_PATH)
        is_valid = ledger.verify()
        
        return jsonify({
            "valid": is_valid,
            "chain_root": ledger.chain_root() if is_valid else None,
            "total_events": len(ledger.events)
        })
    
    except FileNotFoundError:
        return jsonify({"error": "Ledger not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Development server
    app.run(host="0.0.0.0", port=8080, debug=True)
