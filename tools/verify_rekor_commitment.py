#!/usr/bin/env python3
"""Verify ARDA transparency evidence offline. Never authorize admission."""

import argparse
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from arda_quorum.proposal import public_commitment
from arda_quorum.quorum import canonical, hex64, need, sha, strict_load, unbase64

SCHEMA = "arda.pq.rekor_policy.v1"
IDENTITY = (
    "https://github.com/Byron2306/arda-pq-witnesses/"
    ".github/workflows/arda-rekor-commitment.yml@refs/heads/main"
)
ISSUER = "https://token.actions.githubusercontent.com"
TRUST_TYPE = "application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"
BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
POLICY_FIELDS = {
    "schema", "certificate_identity", "oidc_issuer", "trust_config_sha256",
    "rekor_log_id_sha256",
}
CLOSED = {"production_authorized": False, "interlock": "KEEP_CLOSED"}
RESULT_SCHEMA = "arda.pq.rekor_diagnostic.v1"


def read_json(path, limit=1 << 20):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    need(0 < len(raw) <= limit, "rekor_input_size")
    value = strict_load(raw)
    need(type(value) is dict, "rekor_json_object_required")
    return raw, value


def load_policy(path, expected_sha256):
    raw, policy = read_json(path, limit=4096)
    need(hex64(expected_sha256) and sha(raw) == expected_sha256, "rekor_policy_pin")
    need(policy.keys() == POLICY_FIELDS and policy["schema"] == SCHEMA, "rekor_policy_fields")
    need(policy["certificate_identity"] == IDENTITY and policy["oidc_issuer"] == ISSUER,
         "rekor_signer_policy")
    need(hex64(policy["trust_config_sha256"]) and hex64(policy["rekor_log_id_sha256"]),
         "rekor_policy_digest_format")
    return policy


def log_id(entry):
    value = unbase64(entry["logId"]["keyId"], 32)
    need(len(value) == 32, "rekor_log_id_format")
    return value.hex()


def check_bundle(bundle, expected_log_id):
    need(bundle.get("mediaType") == BUNDLE_TYPE
         and type(bundle.get("messageSignature")) is dict
         and "dsseEnvelope" not in bundle, "rekor_message_signature_bundle_required")
    entries = bundle["verificationMaterial"]["tlogEntries"]
    need(type(entries) is list and len(entries) == 1, "rekor_exactly_one_entry")
    entry = entries[0]
    need(type(entry) is dict and entry.get("kindVersion") == {
        "kind": "hashedrekord", "version": "0.0.2",
    }, "rekor_entry_profile")
    need(log_id(entry) == expected_log_id, "rekor_log_id_mismatch")
    proof = entry.get("inclusionProof")
    need(type(proof) is dict and {"hashes", "logIndex", "rootHash", "treeSize"} <= proof.keys(),
         "rekor_inclusion_proof_required")
    checkpoint = proof.get("checkpoint")
    need(type(checkpoint) is dict and type(checkpoint.get("envelope")) is str
         and checkpoint["envelope"].strip(), "rekor_signed_checkpoint_required")
    # Bind the proof's size to the signed note as well as its root hash. Sigstore
    # authenticates this same note and checks the root and Merkle path.
    lines = checkpoint["envelope"].split("\n", 3)
    size = proof["treeSize"]
    need(type(size) is str and 1 <= len(size) <= 19
         and size.isascii() and size.isdecimal() and size[0] != "0"
         and len(lines) >= 3 and lines[1] == size,
         "rekor_checkpoint_tree_size_mismatch")


def verify(certificate_path, bundle_path, trust_path, policy_path, expected_policy_sha256):
    """The approved policy digest must come from the verifier's trusted caller."""
    policy = load_policy(policy_path, expected_policy_sha256)
    trust_raw, trust = read_json(trust_path)
    need(sha(trust_raw) == policy["trust_config_sha256"], "rekor_trust_pin")
    need(trust.get("mediaType") == TRUST_TYPE, "rekor_trust_config_profile")
    expected_log_id = policy["rekor_log_id_sha256"]
    logs = trust["trustedRoot"]["tlogs"]
    need(type(logs) is list and sum(log_id(entry) == expected_log_id for entry in logs) == 1,
         "rekor_log_not_in_trust_config")

    certificate_raw, certificate = read_json(certificate_path)
    need(certificate.keys() == {"proposal", "votes"}
         and type(certificate["proposal"]) is dict
         and type(certificate["votes"]) is list
         and len(certificate["votes"]) == 3
         and all(type(vote) is dict for vote in certificate["votes"]),
         "rekor_certificate_shape")
    need(certificate_raw == canonical(certificate), "rekor_certificate_canonical")
    commitment = public_commitment(certificate)
    commitment_raw = canonical(commitment)

    bundle_raw, bundle = read_json(bundle_path)
    check_bundle(bundle, expected_log_id)

    # Verify the same bytes we examined. Do not reopen caller-controlled inputs.
    with TemporaryDirectory(prefix="arda-rekor-") as directory:
        work = Path(directory)
        artifact = work / "public-commitment.json"
        bundle_file = work / "public-commitment.json.sigstore.json"
        trust_file = work / "trust.json"
        for path, raw in ((artifact, commitment_raw), (bundle_file, bundle_raw),
                          (trust_file, trust_raw)):
            path.write_bytes(raw)
        command = [
            sys.executable, "-I", "-m", "sigstore", "--trust-config", str(trust_file),
            "verify", "identity", "--offline", "--bundle", str(bundle_file),
            "--cert-identity", policy["certificate_identity"],
            "--cert-oidc-issuer", policy["oidc_issuer"], str(artifact),
        ]
        result = subprocess.run(command, cwd=work, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=45, check=False)
        need(result.returncode == 0, "sigstore_verification_refused")

    return {
        "schema": RESULT_SCHEMA, "transparency_verified": True, **CLOSED,
        "certificate_sha256": commitment["certificate_sha256"],
        "commitment_sha256": sha(commitment_raw), "bundle_sha256": sha(bundle_raw),
        "policy_sha256": expected_policy_sha256, "rekor_log_id_sha256": expected_log_id,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("certificate", "bundle", "trust-config", "policy", "policy-sha256"):
        parser.add_argument("--" + arg, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.certificate, args.bundle, args.trust_config,
                        args.policy, args.policy_sha256)
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError,
            OverflowError, OSError, subprocess.TimeoutExpired) as exc:
        reason = exc.args[0] if type(exc) is ValueError and len(exc.args) == 1 else None
        if not isinstance(reason, str) or not (
            reason.startswith("rekor_") or reason == "sigstore_verification_refused"
        ):
            reason = "rekor_verification_error"
        print(canonical({"schema": RESULT_SCHEMA, "transparency_verified": False,
                         **CLOSED, "reason": reason}).decode("ascii"))
        return 2
    print(canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
