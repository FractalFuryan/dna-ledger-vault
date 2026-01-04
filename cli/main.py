from __future__ import annotations
import argparse, os, json, time, base64
from dna_ledger.hashing import sha256_file, chunk_hashes, merkle_root, sha256
from dna_ledger.models import DatasetCommit, ConsentGrant, ComputeAttestation
from dna_ledger.ledger import HashChainedLedger
from dna_ledger.signing import gen_ed25519, sign_payload
from vault.crypto import new_key, key_to_hex, key_from_hex
from vault.store import Vault
from vault.wrap import gen_x25519, wrap_dek

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

def load_keys(path: str) -> dict:
    if os.path.exists(path):
        return json.load(open(path, "r", encoding="utf-8"))
    return {}

def save_keys(path: str, keys: dict):
    json.dump(keys, open(path, "w", encoding="utf-8"), indent=2, sort_keys=True)

def load_identities(path: str) -> dict:
    if os.path.exists(path):
        return json.load(open(path, "r", encoding="utf-8"))
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
    ed_pub = b64d(ids[who]["ed25519_pub_pem_b64"])
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

    h_plain, n = sha256_file(args.dataset)
    ch = chunk_hashes(args.dataset)
    root = merkle_root(ch)

    rec = DatasetCommit(owner=args.owner, bytes=n, sha256_plain=h_plain, chunk_hashes=ch, merkle_root=root)

    # Generate a per-dataset vault key (DEK). In production you'd wrap it with owner key / multisig.
    dek = new_key()
    keys[rec.dataset_id] = {"dek_hex": key_to_hex(dek)}
    save_keys(st["keys"], keys)

    # AAD binds dataset identity to vault ciphertext
    aad = json.dumps({"dataset_id": rec.dataset_id, "sha256_plain": h_plain}, sort_keys=True).encode()
    data = open(args.dataset, "rb").read()
    vault_path = vault.put(rec.dataset_id, dek, data, aad)

    # Sign the commit
    signer, ed_priv = signer_bundle(ids, args.owner)
    sig = sign_payload(ed_priv, rec.model_dump())
    ledger.append(rec.model_dump(), signer=signer, sig_b64=sig)

    print("✅ Dataset committed + vaulted + signed")
    print(f"   dataset_id   : {rec.dataset_id}")
    print(f"   sha256_plain : {h_plain}")
    print(f"   merkle_root  : {root}")
    print(f"   vault_blob   : {vault_path}")
    print(f"   signer       : {args.owner}")
    print(f"   ledger_ok    : {ledger.verify()}")

def cmd_grant(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    ids = load_identities(st["identities"])
    keys = load_keys(st["keys"])

    grant = ConsentGrant(
        dataset_id=args.dataset_id,
        grantee=args.grantee,
        purpose=args.purpose,
        scope=dict(kv.split("=", 1) for kv in (args.scope or [])),
        expires_utc=iso_in_days(args.days),
        revocable=not args.irrevocable,
    )

    # signer = dataset owner (args.actor)
    signer, ed_priv = signer_bundle(ids, args.actor)

    # locate dataset DEK
    if args.dataset_id not in keys:
        raise SystemExit(f"❌ Dataset not found: {args.dataset_id}")
    dek_hex = keys[args.dataset_id]["dek_hex"]
    dek = bytes.fromhex(dek_hex)

    # wrap DEK to grantee
    if args.grantee not in ids:
        raise SystemExit(f"❌ Unknown grantee identity: {args.grantee}. Run init-identities first.")
    
    owner_x_priv = b64d(ids[args.actor]["x25519_priv_pem_b64"])
    owner_x_pub_b64 = ids[args.actor]["x25519_pub_pem_b64"]
    grantee_x_pub = b64d(ids[args.grantee]["x25519_pub_pem_b64"])

    context = json.dumps(
        {"dataset_id": args.dataset_id, "purpose": args.purpose, "grantee": args.grantee},
        sort_keys=True
    ).encode()

    wrapped = wrap_dek(owner_x_priv, grantee_x_pub, dek, context)

    payload = grant.model_dump()
    payload["wrapped_dek_b64"] = wrapped
    payload["owner_x25519_pub_pem_b64"] = owner_x_pub_b64

    sig = sign_payload(ed_priv, payload)
    ledger.append(payload, signer=signer, sig_b64=sig)

    print("✅ Consent grant recorded + DEK wrapped to grantee")
    print(f"   grant_id    : {grant.grant_id}")
    print(f"   grantee     : {args.grantee}")
    print(f"   expires_utc : {grant.expires_utc}")
    print(f"   signer      : {args.actor}")
    print(f"   ledger_ok   : {ledger.verify()}")

def cmd_attest(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    ids = load_identities(st["identities"])

    # POLICY ENFORCEMENT: check for valid consent grant
    payloads = ledger.all_payloads()
    grant = find_valid_grant(payloads, args.dataset_id, args.actor, args.purpose)
    if not grant:
        raise SystemExit(f"❌ No valid consent grant found for actor={args.actor}, dataset={args.dataset_id}, purpose={args.purpose}")

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
    sig = sign_payload(ed_priv, att.model_dump())
    ledger.append(att.model_dump(), signer=signer, sig_b64=sig)

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

def main():
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

    # verify
    v = sub.add_parser("verify", help="Verify ledger integrity")
    v.add_argument("--out", required=True)
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    args.func(args)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
