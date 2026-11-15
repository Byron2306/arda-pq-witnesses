"""Get an R13 v2 receipt over HTTPS from the dedicated Cloudflare Worker."""
import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from .quote_client import HANDLE, quote, read_boot, read_bounded
from .r13_v2 import (HEX64, ID, MAX_BODY, Refusal, canonical, encode, matches, need,
                    public_pin, qualifying_data, strict_json, verify_issued_challenge, verify_receipt)

ENDPOINT = "https://arda-r13-verifier.dio-workflows.workers.dev"
CHALLENGE = "/verify/phase4/v2/challenge"
PROOF = "/verify/phase4/v2"
ARCHIVE_SCHEMA = "arda.r13.capture.v2"
USER_AGENT = "ARDA-R13-Attest/2.0"


def token_from(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and not info.st_mode & 0o077, "TOKEN_FILE_PERMISSIONS")
        value = f.read(67).decode("ascii").removesuffix("\n")
    need(matches(HEX64, value), "TOKEN_FILE_FORMAT")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def post(token, path, data):
    need(matches(HEX64, token) and path in (CHALLENGE, PROOF), "CLIENT_TRANSPORT")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(
        ENDPOINT + path, data=canonical(data), method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token,
                 "User-Agent": USER_AGENT},
    )
    try:
        with opener.open(request, timeout=10) as response:
            need(response.headers.get_content_type() == "application/json", "RESPONSE_TYPE")
            return strict_json(response.read(MAX_BODY + 1))
    except urllib.error.HTTPError as exc:
        with exc:
            try:
                body = strict_json(exc.read(4096))
                detail = body.get("detail") if isinstance(body, dict) else None
                if matches(re.compile(r"[A-Z0-9_]{1,64}"), detail):
                    raise Refusal(f"HTTP_{exc.code}_{detail}") from None
            except Refusal as refusal:
                if refusal.code.startswith("HTTP_"):
                    raise
            raise Refusal(f"HTTP_{exc.code}") from None


def capture(args):
    need(matches(ID, args.node_id) and
         matches(ID, args.verifier_id) and matches(HEX64, args.policy_sha256) and
         matches(HEX64, args.verifier_spki_sha256) and matches(HANDLE, args.ak_handle),
         "CLIENT_CONFIGURATION")
    key = serialization.load_pem_public_key(read_bounded(args.verifier_public_key, 8192))
    need(isinstance(key, ed25519.Ed25519PublicKey) and public_pin(key) == args.verifier_spki_sha256,
         "VERIFIER_KEY_PIN_MISMATCH")
    need(not os.path.lexists(args.out), "OUTPUT_ALREADY_EXISTS")
    token = token_from(args.token_file)
    boot = read_boot()
    issued = post(token, CHALLENGE, {"boot_id": boot, "node_id": args.node_id})
    challenge = verify_issued_challenge(issued, key)
    need(challenge["verifier_id"] == args.verifier_id and challenge["node_id"] == args.node_id
         and challenge["boot_id"] == boot and challenge["policy_sha256"] == args.policy_sha256,
         "CHALLENGE_CONTEXT")
    need(challenge["issued_at"] <= int(time.time()) < challenge["expires_at"], "CHALLENGE_CLOCK")
    message, signature, pcrs = quote(args.ak_handle, qualifying_data(challenge))
    need(boot == read_boot(), "LOCAL_BOOT_CHANGED")
    evidence = {"challenge_id": challenge["challenge_id"], "boot_id": boot, "pcrs": pcrs,
                "quote_b64": encode(message), "signature_b64": encode(signature)}
    receipt = post(token, PROOF, evidence)
    verified = verify_receipt(receipt, key, challenge, evidence)
    need(boot == read_boot(), "LOCAL_BOOT_CHANGED")
    result = canonical({"schema": ARCHIVE_SCHEMA, "issued_challenge": issued, "evidence": evidence,
                        "receipt": receipt})
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(result + b"\n")
        f.flush()
        os.fsync(f.fileno())
    if args.check_replay:
        try:
            post(token, PROOF, evidence)
        except Refusal as exc:
            need(exc.code == "HTTP_409_CHALLENGE_UNAVAILABLE", "REPLAY_REFUSAL_NOT_CONFIRMED")
        else:
            raise Refusal("REPLAY_ACCEPTED")
    return verified


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--token-file", type=Path, required=True)
    p.add_argument("--check-replay", action="store_true", help="confirm the consumed challenge is refused")
    p.add_argument("--node-id", required=True)
    p.add_argument("--verifier-id", required=True)
    p.add_argument("--verifier-public-key", type=Path, required=True)
    p.add_argument("--verifier-spki-sha256", required=True)
    p.add_argument("--policy-sha256", required=True)
    p.add_argument("--ak-handle", required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    try:
        result = capture(args)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        p.exit(1, f"R13_V2_CAPTURE_REFUSED={exc}\n")
    print("R13_V2_EVIDENCE=PASS")
    if args.check_replay:
        print("R13_V2_REPLAY=REFUSED")
    print("R13_V2_BOOT_ID=" + result["boot_id"])
    print("R13_V2_EVIDENCE_SHA256=" + result["evidence_sha256"])
    print("R13_V2_INTERLOCK=KEEP_CLOSED")
    print("R13_V2_CAPTURE=" + str(args.out))


if __name__ == "__main__":
    main()
