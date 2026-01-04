from __future__ import annotations
import argparse, os, json, time
from dna_ledger.hashing import sha256_file, chunk_hashes, merkle_root, sha256
from dna_ledger.models import DatasetCommit, ConsentGrant, ComputeAttestation
from dna_ledger.ledger import HashChainedLedger
from vault.crypto import new_key, key_to_hex, key_from_hex
from vault.store import Vault

def iso_in_days(days: int) -> str:
    t = time.time() + days * 86400
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))

def ensure_state(out: str):
    os.makedirs(out, exist_ok=True)
    return {
        "ledger": os.path.join(out, "ledger.jsonl"),
        "vault": os.path.join(out, "vault"),
        "keys": os.path.join(out, "keys.json"),
    }

def load_keys(path: str) -> dict:
    if os.path.exists(path):
        return json.load(open(path, "r", encoding="utf-8"))
    return {}

def save_keys(path: str, keys: dict):
    json.dump(keys, open(path, "w", encoding="utf-8"), indent=2, sort_keys=True)

def cmd_commit(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    vault = Vault(st["vault"])
    keys = load_keys(st["keys"])

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

    ledger.append(rec.model_dump())
    print("✅ Dataset committed + vaulted")
    print(f"   dataset_id   : {rec.dataset_id}")
    print(f"   sha256_plain : {h_plain}")
    print(f"   merkle_root  : {root}")
    print(f"   vault_blob   : {vault_path}")
    print(f"   ledger_ok    : {ledger.verify()}")

def cmd_grant(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])

    grant = ConsentGrant(
        dataset_id=args.dataset_id,
        grantee=args.grantee,
        purpose=args.purpose,
        scope=dict(kv.split("=", 1) for kv in (args.scope or [])),
        expires_utc=iso_in_days(args.days),
        revocable=not args.irrevocable,
    )
    ledger.append(grant.model_dump())
    print("✅ Consent grant recorded")
    print(f"   grant_id   : {grant.grant_id}")
    print(f"   expires_utc: {grant.expires_utc}")
    print(f"   ledger_ok  : {ledger.verify()}")

def cmd_attest(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])

    algo_sha = sha256(args.algo.encode())
    out_sha, _ = sha256_file(args.result)

    att = ComputeAttestation(
        dataset_id=args.dataset_id,
        purpose=args.purpose,
        algo_name=args.algo,
        algo_sha256=algo_sha,
        output_sha256=out_sha,
    )
    ledger.append(att.model_dump())
    print("✅ Compute attestation recorded")
    print(f"   attestation_id: {att.attestation_id}")
    print(f"   algo_sha256   : {algo_sha}")
    print(f"   output_sha256 : {out_sha}")
    print(f"   ledger_ok     : {ledger.verify()}")

def cmd_verify(args):
    st = ensure_state(args.out)
    ledger = HashChainedLedger(st["ledger"])
    ok = ledger.verify()
    print("✅ Ledger verify" if ok else "❌ Ledger verify FAILED")
    if not ok:
        raise SystemExit(1)

def main():
    p = argparse.ArgumentParser(prog="dna-ledger-vault")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("commit")
    c.add_argument("--dataset", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--owner", required=True)
    c.set_defaults(func=cmd_commit)

    g = sub.add_parser("grant")
    g.add_argument("--out", required=True)
    g.add_argument("--dataset-id", required=True)
    g.add_argument("--grantee", required=True)
    g.add_argument("--purpose", required=True, choices=["clinical","ancestry","research","pharma","ml_training"])
    g.add_argument("--days", type=int, default=30)
    g.add_argument("--scope", action="append", default=[], help="key=value constraint (repeatable)")
    g.add_argument("--irrevocable", action="store_true")
    g.set_defaults(func=cmd_grant)

    a = sub.add_parser("attest")
    a.add_argument("--out", required=True)
    a.add_argument("--dataset-id", required=True)
    a.add_argument("--purpose", required=True, choices=["clinical","ancestry","research","pharma","ml_training"])
    a.add_argument("--algo", required=True)
    a.add_argument("--result", required=True)
    a.set_defaults(func=cmd_attest)

    v = sub.add_parser("verify")
    v.add_argument("--out", required=True)
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
