#!/usr/bin/env python3
"""Verify an R13 v2 capture off-host; never produce Phase4 authority."""
import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "r13-source"))
from r13_v2 import (NodePolicy, Refusal, canonical, is_boot, matches, ID,
                    public_pin, strict_json, verify_issued_challenge, verify_receipt)

SCHEMA = "arda.r13.github_capture_review.v3"
PIN = "3fc3be4f449f0954b74c20d5358019b2432f6331f250afdc0c61997b6fed8679"
MAX_CAPTURE = 32768

def result(reason, verified=False, *, boot_id=None, evidence_sha256=None):
    out = {
        "schema": SCHEMA, "status": "REFUSE",
        "reason": reason, "r13_receipt_verified": bool(verified),
        "r13_receipt_fresh": bool(verified),
        "independent_software_runtime_attestation": False,
        "phase4_verdict_verified": False,
        "hardware_rooted_os_grade_authorized": False,
        "production_cutover_authorized": False,
        "interlock": "KEEP_CLOSED",
    }
    if verified:
        out["boot_id"] = boot_id
        out["evidence_sha256"] = evidence_sha256
    return out

def expected_policy(root=ROOT):
    pub = serialization.load_pem_public_key(
        (root / "providers/public-r13/ak-public.pem").read_bytes())
    if not isinstance(pub, rsa.RSAPublicKey):
        raise Refusal("PINNED_AK_TYPE")
    pcrs = strict_json((root / "providers/public-r13/approved-pcrs.json").read_bytes())
    return NodePolicy(pub, pcrs)

def verify_capture(raw, *, node_id, verifier_id, now=None,
                   public_key_path=None, policy=None):
    if not matches(ID, node_id) or not matches(ID, verifier_id):
        raise Refusal("EXPECTED_IDENTITIES_MISSING")
    if len(raw) > MAX_CAPTURE:
        raise Refusal("CAPTURE_SIZE")
    cap = strict_json(raw)
    if type(cap) is not dict or set(cap) != {
            "schema", "issued_challenge", "evidence", "receipt"}:
        raise Refusal("CAPTURE_FIELDS")
    if cap["schema"] != "arda.r13.capture.v2":
        raise Refusal("CAPTURE_SCHEMA")
    pem = (public_key_path or ROOT / "providers/public-r13/verifier-public.pem").read_bytes()
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ed25519.Ed25519PublicKey) or public_pin(key) != PIN:
        raise Refusal("VERIFIER_PIN_MISMATCH")
    challenge = verify_issued_challenge(cap["issued_challenge"], key)
    if challenge["node_id"] != node_id or challenge["verifier_id"] != verifier_id:
        raise Refusal("EXPECTED_IDENTITY_MISMATCH")
    trusted_policy = policy if policy is not None else expected_policy()
    if challenge["policy_sha256"] != trusted_policy.sha256:
        raise Refusal("EXPECTED_POLICY_MISMATCH")
    evidence = cap["evidence"]
    receipt = cap["receipt"]
    # Server has verified the TPM quote before signing; this client verifies
    # the full issued challenge and receipt bindings, not quote provenance anew.
    payload = verify_receipt(receipt, key, challenge, evidence, now=now)
    if payload["ak_spki_sha256"] != trusted_policy.ak_sha256:
        raise Refusal("EXPECTED_AK_MISMATCH")
    if not is_boot(payload["boot_id"]):
        raise Refusal("EXPECTED_BOOT_FORMAT")
    return result("r13_hardware_receipt_verified_no_runtime_authority",
                  verified=True, boot_id=payload["boot_id"],
                  evidence_sha256=payload["evidence_sha256"])

def review_secret(secret, *, node_id, verifier_id, now=None):
    if not secret:
        return result("capture_secret_not_configured")
    if len(secret) > (MAX_CAPTURE + 2) // 3 * 4 + 8:
        return result("capture_secret_too_large")
    try:
        raw = base64.b64decode(secret, validate=True)
        if base64.b64encode(raw).decode("ascii") != secret:
            raise Refusal("CAPTURE_BASE64_CANONICAL")
        return verify_capture(raw, node_id=node_id, verifier_id=verifier_id, now=now)
    except (Refusal, ValueError, OSError, binascii.Error, TypeError) as exc:
        reason = exc.code if isinstance(exc, Refusal) else "CAPTURE_INVALID"
        return result(reason)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    out = review_secret(os.environ.get("ARDA_R13_CAPTURE_B64", ""),
                        node_id=os.environ.get("ARDA_R13_NODE_ID", ""),
                        verifier_id=os.environ.get("ARDA_R13_VERIFIER_ID", ""))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(canonical(out).decode("ascii") + "\n")
        f.flush()
        os.fsync(f.fileno())
    # Safe public report contains only metadata and never the archive/token.
    print(canonical(out).decode("ascii"))

if __name__ == "__main__":
    main()
