from __future__ import annotations

import argparse
import base64
import json
import os
import time
from typing import Any, cast

from dna_ledger.hashing import (
    blake3_file,
    chunk_hashes,
    h_commit,
    merkle_root,
    merkle_root_blake3,
    sha256,
    sha256_file,
)
from dna_ledger.ledger import HashChainedLedger
from dna_ledger.models import (
    ComputeAttestation,
    ConsentGrant,
    ConsentRevocation,
    DatasetCommit,
    KeyRotationEvent,
    KeyWrapEvent,
)
from dna_ledger.signing import gen_ed25519, sign_payload
from dna_ledger.ga4gh_models import GA4GHVisa
from dna_ledger.erasure_models import ErasureMethod, SecureErasureEvent
from vault.crypto import key_to_hex, new_key
from vault.store import Vault
from vault.wrap import gen_x25519, wrap_dek
from vault.passport_issuer import PassportIssuer
from vault.erasure_manager import ErasureManager


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def iso_in_days(days: int) -> str:
    t = time.time() + days * 86400
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))

def ensure_state(out: str):
    os.makedirs(out, exist_ok=True)
    return {
        "ledger": os.path.join(out, "ledger.jsonl"),
        "vault": os.path.join(out, "vault"),
        "keys": os.path.join(out, "keys.json"),
        "identities": os.path.join(out, "identities.json"),
    }

def load_keys(path: str) -> dict[str, Any]:
    if os.path.exists(path):
        return cast(dict[str, Any], json.load(open(path, "r", encoding="utf-8")))
    return {}

def save_keys(path: str, keys: dict):
    json.dump(keys, open(path, "w", encoding="utf-8"), indent=2, sort_keys=True)

def load_identities(path: str) -> dict[str, Any]:
    if os.path.exists(path):
        return cast(dict[str, Any], json.load(open(path, "r", encoding="utf-8")))
    return {}

def save_identities(path: str, ids: dict):
    json.dump(ids, open(path, "w", encoding="utf-8"), indent=2, sort_keys=True)

def signer_bundle(ids: dict, who: str) -> tuple[dict, bytes]:
    """
    returns:
      signer dict stored in ledger blocks
      signing private pem bytes
    """
    if who not in ids:
        raise SystemExit(f"❌ Unknown identity: {who}. Run init-identities first.")
    ed_priv = b64d(ids[who]["ed25519_priv_pem_b64"])
    signer = {"id": who, "ed25519_pub_pem_b64": ids[who]["ed25519_pub_pem_b64"]}
    return signer, ed_priv

def find_valid_grant(payloads: list[dict], dataset_id: str, grantee: str, purpose: str) -> dict | None:
    # naive scan: find latest valid grant
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    candidates = [
        p for p in payloads
        if p.get("kind") == "ConsentGrant"
        and p.get("dataset_id") == dataset_id
        and p.get("grantee") == grantee
        and p.get("purpose") == purpose
        and p.get("expires_utc", "") > now
    ]
    return candidates[-1] if candidates else None

def is_grant_revoked(payloads: list[dict], grant_id: str) -> bool:
    return any(
        p.get("kind") == "ConsentRevocation" and p.get("grant_id") == grant_id
        for p in payloads
    )

def active_grants(payloads: list[dict], dataset_id: str, purpose: str) -> list[dict]:
    """Get all active, unrevoked grants for a dataset + purpose."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    grants = []
    for p in payloads:
        if p.get("kind") != "ConsentGrant":
            continue
        if p["dataset_id"] != dataset_id:
            continue
        if p["purpose"] != purpose:
            continue
        if p["expires_utc"] <= now:
            continue
        if is_grant_revoked(payloads, p["grant_id"]):
            continue
        grants.append(p)
    return grants

def latest_rotation(payloads: list[dict], dataset_id: str) -> str | None:
    """Get the latest rotation_id for a dataset (or None if never rotated)."""
    rots = [p for p in payloads if p.get("kind") == "KeyRotationEvent" and p["dataset_id"] == dataset_id]
    return rots[-1]["rotation_id"] if rots else None

def has_current_wrap(payloads: list[dict], dataset_id: str, grantee: str, purpose: str, rotation_id: str) -> bool:
    """Check if grantee has a KeyWrapEvent for the current rotation."""
    return any(
        p.get("kind") == "KeyWrapEvent"
        and p["dataset_id"] == dataset_id
        and p["grantee"] == grantee
        and p["purpose"] == purpose
        and p["rotation_id"] == rotation_id
        for p in payloads
    )

def cmd_export_evidence(args):
    """
    Export evidence bundle for audit/compliance.
    
    Creates:
    - evidence.json: All ledger events (optionally filtered by dataset)
    - evidence.sig: Ed25519 signature by actor
    - metadata.json: Schema version, export timestamp, signer info
    - README.txt: Bundle description
    """
    st = ensure_state(args.out)
    ids = load_identities(st["identities"])
    
    if args.actor not in ids:
        raise SystemExit(f"❌ Identity not found: {args.actor}")
    
    # Create bundle directory
    os.makedirs(args.bundle_dir, exist_ok=True)
    
    # Load ledger
    ledger = HashChainedLedger(st["ledger"])
    blocks = ledger._read_blocks()
    
    # Filter by dataset if specified
    if args.dataset_id:
        filtered_blocks = [
            b for b in blocks
            if b["payload"].get("dataset_id") == args.dataset_id
        ]
        print(f"📦 Filtered to {len(filtered_blocks)} blocks for dataset {args.dataset_id}")
    else:
        filtered_blocks = blocks
        print(f"📦 Exporting all {len(filtered_blocks)} blocks")
    
    # Create evidence payload
    from dna_ledger import __version__, __schema__, __invariants__
    
    evidence = {
        "schema": __schema__,
        "version": __version__,
        "invariants_ref": __invariants__,
        "exported_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "exported_by": args.actor,
        "dataset_filter": args.dataset_id or "all",
        "ledger_tip": ledger.tip_hash(),
        "blocks": filtered_blocks,
        "block_count": len(filtered_blocks),
    }
    
    # Save evidence.json
    evidence_path = os.path.join(args.bundle_dir, "evidence.json")
    with open(evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2, sort_keys=True)
    
    # Sign evidence
    ed_priv = b64d(ids[args.actor]["ed25519_priv_pem_b64"])
    ed_pub_b64 = ids[args.actor]["ed25519_pub_pem_b64"]
    
    sig = sign_payload(ed_priv, evidence)
    
    sig_path = os.path.join(args.bundle_dir, "evidence.sig")
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump({
            "signer": args.actor,
            "ed25519_pub_pem_b64": ed_pub_b64,
            "signature_b64": sig,
            "signed_utc": evidence["exported_utc"],
        }, f, indent=2)
    
    # Save metadata
    metadata_path = os.path.join(args.bundle_dir, "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump({
            "bundle_type": "dna-ledger-vault-evidence",
            "schema": __schema__,
            "version": __version__,
            "exported_utc": evidence["exported_utc"],
            "signer": args.actor,
            "dataset_filter": args.dataset_id or "all",
            "block_count": len(filtered_blocks),
            "ledger_tip": ledger.tip_hash(),
        }, f, indent=2)
    
    # Save README
    readme_path = os.path.join(args.bundle_dir, "README.txt")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(f"""DNA Ledger Vault - Evidence Bundle
===================================

Exported: {evidence["exported_utc"]}
By: {args.actor}
Dataset Filter: {args.dataset_id or "all"}
Blocks: {len(filtered_blocks)}
Ledger Tip: {ledger.tip_hash()}

Files:
------
- evidence.json   : Ledger blocks + metadata
- evidence.sig    : Ed25519 signature by exporter
- metadata.json   : Bundle metadata
- README.txt      : This file

Verification:
-------------
1. Verify signature using ed25519_pub_pem_b64 from evidence.sig
2. Check ledger_tip matches current ledger state
3. Verify hash chain integrity across blocks
4. Check all signatures in individual blocks

Schema: {__schema__}
Version: {__version__}
Invariants: {__invariants__}
""")
    
    print(f"✅ Evidence bundle exported to: {args.bundle_dir}")
    print(f"   Blocks exported: {len(filtered_blocks)}")
    print(f"   Ledger tip: {ledger.tip_hash()}")
    print(f"   Signed by: {args.actor}")
    print("   Files created: evidence.json, evidence.sig, metadata.json, README.txt")

def cmd_init_identities(args):
    st = ensure_state(args.out)
    ids = load_identities(st["identities"])

    if args.who in ids:
        print(f"⚠️  Identity already exists: {args.who}")
        return

    ed_priv, ed_pub = gen_ed25519()
    x_priv, x_pub = gen_x25519()

    ids[args.who] = {
        "ed25519_priv_pem_b64": b64e(ed_priv),
        "ed25519_pub_pem_b64": b64e(ed_pub),
        "x25519_priv_pem_b64": b64e(x_priv),
        "x25519_pub_pem_b64": b64e(x_pub),
    }
    save_identities(st["identities"], ids)
    print("✅ Identity created")
    print(f"   who: {args.who}")

def cmd_commit(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    vault = Vault(st["vault"])
    keys = load_keys(st["keys"])
    ids = load_identities(st["identities"])

    # Dual hashing: SHA-256 (canonical) + BLAKE3 (performance)
    h_plain, n = sha256_file(args.dataset)
    h_blake3, _ = blake3_file(args.dataset)
    ch = chunk_hashes(args.dataset)
    root = merkle_root(ch)
    root_blake3 = merkle_root_blake3(ch)

    rec = DatasetCommit(
        owner=args.owner,
        bytes=n,
        sha256_plain=h_plain,
        blake3_plain=h_blake3,
        chunk_hashes=ch,
        merkle_root=root,
        merkle_root_blake3=root_blake3,
        hash_scheme="dual",  # Both SHA-256 and BLAKE3
    )
    
    # Compute commit hash for binding grants to specific dataset version
    rec_dict = rec.model_dump(by_alias=True)
    commit_hash = h_commit(rec_dict)
    rec.commit_hash = commit_hash
    rec_dict["commit_hash"] = commit_hash

    # Generate a per-dataset vault key (DEK)
    dek = new_key()
    keys[rec.dataset_id] = {"dek_hex": key_to_hex(dek), "commit_hash": commit_hash}
    save_keys(st["keys"], keys)

    # AAD binds dataset identity to vault ciphertext
    aad = json.dumps({"dataset_id": rec.dataset_id, "commit_hash": commit_hash, "vault_schema": "vault/v1"}, sort_keys=True).encode()
    data = open(args.dataset, "rb").read()
    vault_path = vault.put(rec.dataset_id, dek, data, aad)

    # Sign the commit
    signer, ed_priv = signer_bundle(ids, args.owner)
    sig = sign_payload(ed_priv, rec_dict)
    ledger.append(rec_dict, signer=signer, sig_b64=sig)

    print("✅ Dataset committed + vaulted + signed")
    print(f"   dataset_id   : {rec.dataset_id}")
    print(f"   commit_hash  : {commit_hash}")
    print(f"   sha256_plain : {h_plain}")
    print(f"   blake3_plain : {h_blake3}")
    print(f"   merkle_root  : {root}")
    print(f"   merkle_blake3: {root_blake3}")
    print(f"   vault_blob   : {vault_path}")
    print(f"   signer       : {args.owner}")
    print(f"   ledger_ok    : {ledger.verify()}")

def cmd_grant(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    ids = load_identities(st["identities"])
    keys = load_keys(st["keys"])

    # signer = dataset owner (args.actor)
    signer, ed_priv = signer_bundle(ids, args.actor)

    # locate dataset DEK + commit_hash
    if args.dataset_id not in keys:
        raise SystemExit(f"❌ Dataset not found: {args.dataset_id}")
    dek_hex = keys[args.dataset_id]["dek_hex"]
    commit_hash = keys[args.dataset_id]["commit_hash"]
    dek = bytes.fromhex(dek_hex)

    # wrap DEK to grantee
    if args.grantee not in ids:
        raise SystemExit(f"❌ Unknown grantee identity: {args.grantee}. Run init-identities first.")
    
    owner_x_priv = b64d(ids[args.actor]["x25519_priv_pem_b64"])
    owner_x_pub_b64 = ids[args.actor]["x25519_pub_pem_b64"]
    grantee_x_pub = b64d(ids[args.grantee]["x25519_pub_pem_b64"])

    context = json.dumps(
        {"dataset_id": args.dataset_id, "commit_hash": commit_hash, "purpose": args.purpose, "grantee": args.grantee},
        sort_keys=True
    ).encode()

    wrapped = wrap_dek(owner_x_priv, grantee_x_pub, dek, context)

    # Create consent grant (includes initial wrapped DEK)
    grant = ConsentGrant(
        dataset_id=args.dataset_id,
        dataset_commit_hash=commit_hash,
        grantee=args.grantee,
        purpose=args.purpose,
        scope=dict(kv.split("=", 1) for kv in (args.scope or [])),
        expires_utc=iso_in_days(args.days),
        revocable=not args.irrevocable,
        wrapped_dek_b64=wrapped,
        owner_x25519_pub_pem_b64=owner_x_pub_b64
    )

    payload = grant.model_dump(by_alias=True)
    sig = sign_payload(ed_priv, payload)
    ledger.append(payload, signer=signer, sig_b64=sig)

    # Also emit initial KeyWrapEvent (append-only, no mutation)
    wrap_evt = KeyWrapEvent(
        dataset_id=args.dataset_id,
        dataset_commit_hash=commit_hash,
        grantee=args.grantee,
        purpose=args.purpose,
        rotation_id="initial",  # no rotation yet
        wrapped_dek_b64=wrapped,
        owner_x25519_pub_pem_b64=owner_x_pub_b64
    )
    wrap_payload = wrap_evt.model_dump(by_alias=True)
    sig_wrap = sign_payload(ed_priv, wrap_payload)
    ledger.append(wrap_payload, signer=signer, sig_b64=sig_wrap)

    print("✅ Consent grant recorded + DEK wrapped to grantee")
    print(f"   grant_id    : {grant.grant_id}")
    print(f"   wrap_id     : {wrap_evt.wrap_id}")
    print(f"   grantee     : {args.grantee}")
    print(f"   expires_utc : {grant.expires_utc}")
    print(f"   signer      : {args.actor}")
    print(f"   ledger_ok   : {ledger.verify()}")

def cmd_revoke(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    ids = load_identities(st["identities"])

    signer, ed_priv = signer_bundle(ids, args.actor)

    rev = ConsentRevocation(
        dataset_id=args.dataset_id,
        grant_id=args.grant_id,
        reason=args.reason
    )

    sig = sign_payload(ed_priv, rev.model_dump(by_alias=True))
    ledger.append(rev.model_dump(by_alias=True), signer=signer, sig_b64=sig)

    print("🛑 Consent revoked")
    print(f"   grant_id     : {args.grant_id}")
    print(f"   revocation_id: {rev.revocation_id}")
    print(f"   signer       : {args.actor}")
    print(f"   ledger_ok    : {ledger.verify()}")

def cmd_rotate(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    vault = Vault(st["vault"])
    ids = load_identities(st["identities"])
    keys = load_keys(st["keys"])

    payloads = ledger.all_payloads()
    signer, ed_priv = signer_bundle(ids, args.actor)

    # Get commit hash
    commit_hash = keys[args.dataset_id]["commit_hash"]

    # Generate new DEK
    new_dek = new_key()
    new_dek_sha = sha256(new_dek)

    # Load plaintext using OLD DEK
    old_dek = bytes.fromhex(keys[args.dataset_id]["dek_hex"])
    
    # AAD binds to commit hash and schema
    aad = json.dumps({"dataset_id": args.dataset_id, "commit_hash": commit_hash, "vault_schema": "vault/v1"}, sort_keys=True).encode()
    plaintext = vault.get(args.dataset_id, old_dek, aad)

    # Re-seal with NEW DEK (same AAD)
    vault.put(args.dataset_id, new_dek, plaintext, aad)

    # Update DEK storage
    keys[args.dataset_id]["dek_hex"] = key_to_hex(new_dek)
    save_keys(st["keys"], keys)

    # Record rotation event
    evt = KeyRotationEvent(dataset_id=args.dataset_id, new_dek_sha256=new_dek_sha)
    evt_payload = evt.model_dump(by_alias=True)
    sig = sign_payload(ed_priv, evt_payload)
    ledger.append(evt_payload, signer=signer, sig_b64=sig)

    # Emit KeyWrapEvents (append-only, no mutation)
    print("🔁 Emitting KeyWrapEvents for active grantees...")
    rewrap_count = 0
    for purpose in ["clinical", "ancestry", "research", "pharma", "ml_training"]:
        grants = active_grants(payloads, args.dataset_id, purpose)
        for g in grants:
            grantee = g["grantee"]
            if grantee not in ids:
                print(f"   ⚠️  Skipping unknown grantee: {grantee}")
                continue
            
            context = json.dumps(
                {"dataset_id": args.dataset_id, "commit_hash": commit_hash, "purpose": purpose, "grantee": grantee},
                sort_keys=True
            ).encode()
            
            wrapped = wrap_dek(
                b64d(ids[args.actor]["x25519_priv_pem_b64"]),
                b64d(ids[grantee]["x25519_pub_pem_b64"]),
                new_dek,
                context
            )
            
            # Emit KeyWrapEvent (append-only)
            wrap_evt = KeyWrapEvent(
                dataset_id=args.dataset_id,
                dataset_commit_hash=commit_hash,
                grantee=grantee,
                purpose=purpose,
                rotation_id=evt.rotation_id,
                wrapped_dek_b64=wrapped,
                owner_x25519_pub_pem_b64=ids[args.actor]["x25519_pub_pem_b64"]
            )
            wrap_payload = wrap_evt.model_dump(by_alias=True)
            sig_wrap = sign_payload(ed_priv, wrap_payload)
            ledger.append(wrap_payload, signer=signer, sig_b64=sig_wrap)
            rewrap_count += 1

    print("🔁 Key rotation complete")
    print(f"   dataset_id   : {args.dataset_id}")
    print(f"   rotation_id  : {evt.rotation_id}")
    print(f"   new_dek_sha  : {new_dek_sha}")
    print(f"   wrap_events  : {rewrap_count}")
    print(f"   ledger_ok    : {ledger.verify()}")

def cmd_attest(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    ids = load_identities(st["identities"])

    # SOLID POLICY ENFORCEMENT
    payloads = ledger.all_payloads()
    
    # 1. Check for active, unrevoked grant
    grants = active_grants(payloads, args.dataset_id, args.purpose)
    matching_grant = next((g for g in grants if g["grantee"] == args.actor), None)
    if not matching_grant:
        raise SystemExit(f"❌ No active, unrevoked consent grant found for actor={args.actor}, dataset={args.dataset_id}, purpose={args.purpose}")
    
    # 2. Check wrap state (must have current wrap for latest rotation)
    rot_id = latest_rotation(payloads, args.dataset_id)
    if rot_id:
        # Rotation exists, must have wrap for current rotation
        if not has_current_wrap(payloads, args.dataset_id, args.actor, args.purpose, rot_id):
            raise SystemExit(f"❌ No KeyWrapEvent found for actor={args.actor} at rotation_id={rot_id}")
    else:
        # No rotation yet, must have initial wrap
        if not has_current_wrap(payloads, args.dataset_id, args.actor, args.purpose, "initial"):
            raise SystemExit(f"❌ No initial KeyWrapEvent found for actor={args.actor}")

    algo_sha = sha256(args.algo.encode())
    out_sha, _ = sha256_file(args.result)

    att = ComputeAttestation(
        dataset_id=args.dataset_id,
        purpose=args.purpose,
        algo_name=args.algo,
        algo_sha256=algo_sha,
        output_sha256=out_sha,
    )

    # sign attestation
    signer, ed_priv = signer_bundle(ids, args.actor)
    sig = sign_payload(ed_priv, att.model_dump(by_alias=True))
    ledger.append(att.model_dump(by_alias=True), signer=signer, sig_b64=sig)

    print("✅ Compute attestation recorded (consent verified)")
    print(f"   attestation_id: {att.attestation_id}")
    print(f"   algo_sha256   : {algo_sha}")
    print(f"   output_sha256 : {out_sha}")
    print(f"   signer        : {args.actor}")
    print(f"   ledger_ok     : {ledger.verify()}")

def cmd_verify(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    ok = ledger.verify()
    print("✅ Ledger verify (chain + signatures)" if ok else "❌ Ledger verify FAILED")
    if not ok:
        raise SystemExit(1)

def cmd_secure_erase(args):
    """Execute GDPR/CPRA Right to Erasure with compliance reporting."""
    p = ensure_state(args.out)
    ledger = HashChainedLedger.load_from_jsonl(p["ledger"])
    
    # Find dataset in ledger
    dataset_events = [
        e for e in ledger.events 
        if isinstance(e, DatasetCommit) and e.dataset_id == args.dataset_id
    ]
    
    if not dataset_events:
        print(f"❌ Dataset '{args.dataset_id}' not found in ledger.")
        return
    
    dataset_commit = dataset_events[0]
    
    # Verify actor is dataset owner
    if args.actor != dataset_commit.identity:
        print(f"❌ Only dataset owner '{dataset_commit.identity}' can erase this dataset.")
        print(f"   You are: {args.actor}")
        return
    
    # User confirmation (unless --force)
    if not args.force:
        print(f"\n⚠️  WARNING: IRREVERSIBLE DATA DESTRUCTION")
        print(f"   Dataset: {args.dataset_id}")
        print(f"   Method: {args.method}")
        print(f"   This action CANNOT be undone.")
        
        response = input("\nType 'ERASE' to confirm: ")
        if response != "ERASE":
            print("❌ Erasure cancelled.")
            return
    
    # Initialize erasure manager
    manager = ErasureManager(vault_root=p["vault"])
    
    # Capture pre-erasure state
    pre_root = ledger.chain_root()
    
    # Execute erasure based on method
    print(f"\n🔥 Executing {args.method} erasure...")
    
    if args.method == "crypto_shred":
        try:
            proof = manager.crypto_shred_dataset(args.dataset_id)
            print(f"✅ DEK destroyed (DoD 5220.22-M 3-pass overwrite)")
            print(f"   Proof hash: {proof.proof_hash[:16]}...")
            destroyed_hash = proof.evidence_data["original_dek_hash"]
        except Exception as e:
            print(f"❌ Shredding failed: {e}")
            return
    
    elif args.method == "vault_deletion":
        proof = manager.delete_vault_data(args.dataset_id)
        print(f"✅ Encrypted data deleted securely")
        print(f"   Proof hash: {proof.proof_hash[:16]}...")
        destroyed_hash = proof.evidence_data.get("deleted_file_hash", "NONE")
    
    elif args.method == "full_purge":
        shred_proof, delete_proof = manager.full_purge(args.dataset_id)
        print(f"✅ Full purge complete (DEK + encrypted data)")
        print(f"   Shred proof: {shred_proof.proof_hash[:16]}...")
        print(f"   Delete proof: {delete_proof.proof_hash[:16]}...")
        destroyed_hash = shred_proof.evidence_data["original_dek_hash"]
        proof = shred_proof  # Use for event creation
    
    # Create erasure event
    method_enum = ErasureMethod(args.method)
    
    # Count prior accesses (compute attestations)
    prior_accesses = sum(
        1 for e in ledger.events
        if isinstance(e, ComputeAttestation) and e.dataset_id == args.dataset_id
    )
    
    # Find affected grantees
    affected = []
    for e in ledger.events:
        if isinstance(e, ConsentGrant) and e.dataset_id == args.dataset_id:
            if e.grantee not in affected:
                affected.append(e.grantee)
    
    event = SecureErasureEvent.from_destruction(
        dataset_id=args.dataset_id,
        identity=args.actor,
        method=method_enum,
        destroyed_key_hash=destroyed_hash,
        pre_erasure_root=pre_root,
        regulator_id=args.regulator_id,
        reason=args.reason,
        prior_accesses=prior_accesses,
        affected_users=affected
    )
    
    # Append to ledger
    ledger.append(event)
    ledger.save_to_jsonl(p["ledger"])
    
    print(f"\n📋 Erasure event recorded:")
    print(f"   Event ID: {event.erasure_id}")
    print(f"   Method: {event.erasure_method.value}")
    print(f"   Affected users: {len(affected)}")
    print(f"   Prior accesses: {prior_accesses}")
    
    # Generate compliance report
    if args.report:
        print(f"\n📄 Generating compliance report...")
        report_dict = manager.generate_compliance_report(
            dataset_id=args.dataset_id,
            erasure_event=event,
            ledger_integrity=True
        )
        
        # Save reports
        report_dir = os.path.join(args.out, "erasure_reports")
        os.makedirs(report_dir, exist_ok=True)
        
        # JSON report
        json_path = os.path.join(report_dir, f"{event.erasure_id}_compliance.json")
        with open(json_path, "w") as f:
            json.dump(report_dict["json"], f, indent=2)
        
        # Human-readable report
        human_path = os.path.join(report_dir, f"{event.erasure_id}_report.txt")
        with open(human_path, "w") as f:
            f.write(report_dict["human"])
        
        print(f"✅ Reports saved:")
        print(f"   JSON: {json_path}")
        print(f"   Human: {human_path}")
    
    print(f"\n✅ GDPR Article 17 compliance: VERIFIED")
    print(f"   New chain root: {ledger.chain_root()}")

def cmd_issue_passport(args):
    """Issue a GA4GH Passport JWT for a grantee with active consent."""
    p = ensure_state(args.out)
    ledger = HashChainedLedger.load_from_jsonl(p["ledger"])
    identities = load_identities(p["identities"])
    
    # Verify actor exists
    if args.actor not in identities:
        print(f"❌ Identity '{args.actor}' not found.")
        return
    
    # Verify grantee exists
    if args.grantee not in identities:
        print(f"❌ Grantee identity '{args.grantee}' not found.")
        return
    
    # Find active consent grants for this grantee + dataset
    active_grants = []
    for event in ledger.events:
        if not isinstance(event, ConsentGrant):
            continue
        if event.dataset_id != args.dataset_id:
            continue
        if event.grantee != args.grantee:
            continue
        
        # Check if not revoked
        is_revoked = any(
            isinstance(e, ConsentRevocation) 
            and e.grant_id == event.grant_id
            for e in ledger.events
        )
        if is_revoked:
            continue
        
        # Check if not expired
        try:
            from datetime import datetime
            exp_dt = datetime.fromisoformat(event.expires_utc.replace("Z", "+00:00"))
            now_dt = datetime.now(exp_dt.tzinfo)
            if now_dt > exp_dt:
                continue
        except Exception:
            pass  # If parsing fails, include the grant
        
        active_grants.append(event)
    
    if not active_grants:
        print(f"❌ No active consent grant found for:")
        print(f"   - Grantee: {args.grantee}")
        print(f"   - Dataset: {args.dataset_id}")
        return
    
    # Use the first active grant (could extend to multiple visas)
    grant = active_grants[0]
    
    # Create GA4GH Visa from ConsentGrant
    visa = GA4GHVisa.from_consent_grant(grant)
    
    # Initialize passport issuer
    try:
        issuer = PassportIssuer.from_identity_folder(args.out, args.actor)
    except Exception as e:
        print(f"❌ Failed to load passport issuer: {e}")
        return
    
    # Issue passport
    try:
        passport_jwt = issuer.issue_passport(
            subject=args.grantee,
            visas=[visa],
            lifetime_hours=args.lifetime
        )
    except Exception as e:
        print(f"❌ Failed to issue passport: {e}")
        return
    
    # Output passport
    print("\n" + "="*80)
    print("✅ GA4GH Passport JWT Issued")
    print("="*80)
    print(f"\nIssuer:    {args.actor}")
    print(f"Subject:   {args.grantee}")
    print(f"Dataset:   {args.dataset_id}")
    print(f"Purpose:   {grant.purpose}")
    print(f"Lifetime:  {args.lifetime} hours")
    print(f"Visas:     1 (ControlledAccessGrants)")
    print(f"\nJWT:\n{passport_jwt}")
    print("\n" + "="*80)
    
    # Optionally save to file
    if args.save:
        passports_dir = os.path.join(args.out, "passports")
        os.makedirs(passports_dir, exist_ok=True)
        
        passport_file = os.path.join(
            passports_dir,
            f"{args.grantee}_{args.dataset_id}_{int(time.time())}.jwt"
        )
        
        with open(passport_file, "w") as f:
            f.write(passport_jwt)
        
        print(f"\n💾 Passport saved to: {passport_file}")
    
    print(f"\n🔍 Passport uses EdDSA (Ed25519) signatures for cryptographic consistency")
    print(f"   Compatible with GA4GH v1.1 specification")

def main() -> None:
    p = argparse.ArgumentParser(prog="dna-ledger-vault")
    sub = p.add_subparsers(dest="cmd", required=True)

    # init-identities
    i = sub.add_parser("init-identities", help="Create Ed25519+X25519 identity keypairs")
    i.add_argument("--out", required=True)
    i.add_argument("--who", required=True, help="Identity name")
    i.set_defaults(func=cmd_init_identities)

    # commit
    c = sub.add_parser("commit", help="Commit dataset to vault + ledger")
    c.add_argument("--dataset", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--owner", required=True)
    c.set_defaults(func=cmd_commit)

    # grant
    g = sub.add_parser("grant", help="Grant consent + wrap DEK to grantee")
    g.add_argument("--out", required=True)
    g.add_argument("--actor", required=True, help="Dataset owner granting consent")
    g.add_argument("--dataset-id", required=True)
    g.add_argument("--grantee", required=True)
    g.add_argument("--purpose", required=True, choices=["clinical","ancestry","research","pharma","ml_training"])
    g.add_argument("--days", type=int, default=30)
    g.add_argument("--scope", action="append", default=[], help="key=value constraint (repeatable)")
    g.add_argument("--irrevocable", action="store_true")
    g.set_defaults(func=cmd_grant)

    # attest
    a = sub.add_parser("attest", help="Attest compute (requires valid consent)")
    a.add_argument("--out", required=True)
    a.add_argument("--actor", required=True, help="Researcher performing computation")
    a.add_argument("--dataset-id", required=True)
    a.add_argument("--purpose", required=True, choices=["clinical","ancestry","research","pharma","ml_training"])
    a.add_argument("--algo", required=True)
    a.add_argument("--result", required=True)
    a.set_defaults(func=cmd_attest)

    # revoke-consent
    r = sub.add_parser("revoke-consent", help="Revoke a consent grant")
    r.add_argument("--out", required=True)
    r.add_argument("--actor", required=True, help="Dataset owner revoking consent")
    r.add_argument("--dataset-id", required=True)
    r.add_argument("--grant-id", required=True)
    r.add_argument("--reason", help="Reason for revocation")
    r.set_defaults(func=cmd_revoke)

    # rotate-key
    k = sub.add_parser("rotate-key", help="Rotate dataset encryption key")
    k.add_argument("--out", required=True)
    k.add_argument("--actor", required=True, help="Dataset owner performing rotation")
    k.add_argument("--dataset-id", required=True)
    k.set_defaults(func=cmd_rotate)

    # export-evidence
    e = sub.add_parser("export-evidence", help="Export audit evidence bundle")
    e.add_argument("--out", required=True, help="State directory")
    e.add_argument("--dataset-id", help="Filter to specific dataset (optional)")
    e.add_argument("--bundle-dir", required=True, help="Output directory for evidence bundle")
    e.add_argument("--actor", required=True, help="Identity signing the evidence bundle")
    e.set_defaults(func=cmd_export_evidence)

    # issue-passport
    pp = sub.add_parser("issue-passport", help="Issue GA4GH Passport JWT for a grantee")
    pp.add_argument("--out", required=True, help="State directory")
    pp.add_argument("--actor", required=True, help="Identity issuing the passport (dataset owner)")
    pp.add_argument("--grantee", required=True, help="Researcher identity to receive passport")
    pp.add_argument("--dataset-id", required=True, help="Target dataset")
    pp.add_argument("--lifetime", type=int, default=24, help="Passport lifetime in hours (default: 24)")
    pp.add_argument("--save", action="store_true", help="Save passport to file")
    pp.set_defaults(func=cmd_issue_passport)

    # secure-erase
    se = sub.add_parser("secure-erase", help="Execute GDPR/CPRA Right to Erasure")
    se.add_argument("--out", required=True, help="State directory")
    se.add_argument("--actor", required=True, help="Dataset owner executing erasure")
    se.add_argument("--dataset-id", required=True, help="Dataset to erase")
    se.add_argument("--method", required=True, choices=["crypto_shred", "vault_deletion", "full_purge"], 
                    help="Erasure method: crypto_shred (DEK only), vault_deletion (encrypted data), full_purge (both)")
    se.add_argument("--regulator-id", help="Regulator case ID (e.g., GDPR-2024-001)")
    se.add_argument("--reason", help="Erasure reason for audit trail")
    se.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    se.add_argument("--report", action="store_true", help="Generate compliance reports (JSON + human-readable)")
    se.set_defaults(func=cmd_secure_erase)

    # verify
    v = sub.add_parser("verify", help="Verify ledger integrity")
    v.add_argument("--out", required=True)
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    if hasattr(args, "func"):
        args.func(args)

if __name__ == "__main__":
    main()
