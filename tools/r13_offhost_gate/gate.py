#!/usr/bin/env python3
"""Non-authoritative R13 off-host readiness gate.

Intentionally does NOT accept an R13 receipt as Phase 4 approval. A separate
signature-verifying reviewer, genuinely independent sensor and enrolled Phase 4
authority are required before an OS grade can be issued.
"""
import argparse
import json
import os
from pathlib import Path

SCHEMA = "arda.r13.github_offhost_gate.v1"
FALSE_CLAIMS = (
    "independent_software_runtime_attestation",
    "phase4_verdict_verified",
    "hardware_rooted_os_grade_authorized",
    "production_cutover_authorized",
)

def refusal(*, reason="no_independent_runtime_appraisal_or_authorized_phase4_issuer"):
    return {
        "schema": SCHEMA,
        "status": "REFUSE",
        "reason": reason,
        "github_hosted_execution": True,
        "r13_receipt_verified": False,
        "ssh_telemetry_is_independent_sensor": False,
        **{key: False for key in FALSE_CLAIMS},
        "interlock": "KEEP_CLOSED",
    }

def validate_result(result):
    if type(result) is not dict or result.get("schema") != SCHEMA:
        raise ValueError("INVALID_GATE_REPORT")
    if result.get("status") != "REFUSE" or result.get("interlock") != "KEEP_CLOSED":
        raise ValueError("AUTHORITY_PROMOTION_FORBIDDEN")
    if any(result.get(key) is not False for key in FALSE_CLAIMS):
        raise ValueError("AUTHORITY_PROMOTION_FORBIDDEN")
    if result.get("r13_receipt_verified") is not False:
        raise ValueError("UNVERIFIED_R13_CLAIM")
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = refusal()
    validate_result(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(result, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
