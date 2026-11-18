#!/usr/bin/env python3
"""Enroll a GitHub-held Ed25519 key and sign only the reviewed Gen12 boot profile."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import zlib

REPO = "Byron2306/arda-pq-witnesses"
REPO_ID = "1458361210"
ENVIRONMENT = "arda-release-authority"
KEY_SECRET = "ARDA_GEN12_RELEASE_ED25519_PKCS8_B64"
TEMPLATE_SECRET = "ARDA_GEN12_RELEASE_TEMPLATE_ZLIB_B64"
TOKEN_SECRET = "ARDA_GEN12_ENROLLMENT_STORE_TOKEN"
TEMPLATE_PIN = "48305e55928ab79be3357f0343b13efbc8a6b905dec25ba27edc2ef9cc8bc5ec"
LEGACY_PEM_PIN = "b8119d39f6d27567f641f5d9a603074a30f31e4e55c2e06af536b9febaf69253"
DOMAIN = b"ARDA/BOOT-DEPLOYMENT/v1\0"
SCHEMA = "arda.gen12.detached-boot-signature.v1"
DER_KEY_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
DYNAMIC = {"deployment_id", "issued_at", "expires_at"}
CAP = 128 * 1024
MAX_LIFETIME = 30 * 86400
OPENSSL = "/usr/bin/openssl"
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def unique(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, "duplicate_json_key")
        out[k] = v
    return out


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def load_file(path, cap=CAP):
    with path.open("rb") as stream:
        raw = stream.read(cap + 1)
    require(0 < len(raw) <= cap, "file_size")
    return raw


def template(raw):
    require(sha(raw) == TEMPLATE_PIN, "reviewed_template_hash")
    p = parse(raw)
    require(canonical(p) == raw and not DYNAMIC.intersection(p), "template_shape")
    require(type(p["generation"]) is int and p["generation"] == 12
            and p["production_admission_authorized"] is False
            and p["schema"] == "arda.boot.deployment.v1"
            and p["boot_scope_path"] == "/sys/fs/cgroup/system.slice/arda-ring0.service"
            and p["manifest_id"] == "measured-b28567e939474e3ea436872aadd9e1c3"
            and len(p["artifacts"]) == 569, "gen12_boot_only")
    return p


def decode_template(encoded):
    require(0 < len(encoded) <= 48000, "template_secret_size")
    stream = zlib.decompressobj()
    raw = stream.decompress(base64.b64decode(encoded, validate=True), CAP + 1)
    require(len(raw) <= CAP and stream.eof and not stream.unused_data
            and not stream.unconsumed_tail, "template_secret_compression")
    return template(raw)


def protect_context(env, mode):
    workflow = {"enroll": "arda-release-authority-enroll.yml",
                "sign": "arda-release-gen12-continuity.yml"}[mode]
    pin = env.get("ARDA_RELEASE_APPROVED_COMMIT", "")
    require(env.get("GITHUB_ACTIONS") == "true"
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REPOSITORY") == REPO
            and env.get("GITHUB_REPOSITORY_ID") == REPO_ID
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_REF_PROTECTED") == "true"
            and env.get("GITHUB_WORKFLOW_REF") == f"{REPO}/.github/workflows/{workflow}@refs/heads/main"
            and re.fullmatch(r"[0-9a-f]{40}", pin)
            and env.get("GITHUB_SHA") == pin
            and env.get("ARDA_RELEASE_ENABLED") == "true", "unapproved_workflow_context")


def openssl(*args):
    result = subprocess.run([OPENSSL, *map(str, args)], env=CHILD_ENV, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=20)
    require(result.returncode == 0, "openssl_operation_failed")
    return result.stdout


def new_der():
    return openssl("genpkey", "-algorithm", "Ed25519", "-outform", "DER")


def write_new(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(data)


def write_der(path, der):
    require(len(der) == len(DER_KEY_PREFIX) + 32 and der.startswith(DER_KEY_PREFIX),
            "release_private_key_type")
    write_new(path, der)


def pem_from_der(path):
    pub = openssl("pkey", "-inform", "DER", "-in", path, "-pubout", "-outform", "DER")
    require(len(pub) == len(SPKI_PREFIX) + 32 and pub.startswith(SPKI_PREFIX), "release_public_key_type")
    return b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(pub) + b"\n-----END PUBLIC KEY-----\n"


def public_key_check(pem, pin):
    require(re.fullmatch(r"[0-9a-f]{64}", pin) and pin != LEGACY_PEM_PIN and sha(pem) == pin,
            "release_public_key_pin")
    lines = pem.splitlines()
    require(len(lines) == 3 and lines[0] == b"-----BEGIN PUBLIC KEY-----"
            and lines[2] == b"-----END PUBLIC KEY-----", "public_pem_shape")
    raw = base64.b64decode(lines[1], validate=True)
    require(len(raw) == len(SPKI_PREFIX) + 32 and raw.startswith(SPKI_PREFIX),
            "release_public_key_type")


def valid_window(fields, now):
    issued, expires = fields["issued_at"], fields["expires_at"]
    require(type(issued) is int and type(expires) is int and type(now) is int
            and 0 < expires - issued <= MAX_LIFETIME and issued <= now < expires,
            "deployment_time_window")


def issue(p, der, pin, valid_hours, temp=None, clock=None):
    # Revalidate even when called outside main() and before using the private key.
    p = template(canonical(p))
    require(re.fullmatch(r"[1-9][0-9]{0,2}", valid_hours)
            and int(valid_hours) <= 720, "release_lifetime")
    clock = clock or (lambda: int(time.time()))
    issued = clock()
    dynamic = {"deployment_id": secrets.token_hex(16), "issued_at": issued,
               "expires_at": issued + int(valid_hours) * 3600}
    payload = dict(p, **dynamic)
    with tempfile.TemporaryDirectory(dir=temp) as td:
        key, pub, msg, sig = (Path(td) / name for name in ("key.der", "key.pub.pem", "message", "signature"))
        write_der(key, der)
        pem = pem_from_der(key)
        public_key_check(pem, pin)
        write_new(pub, pem)
        write_new(msg, DOMAIN + canonical(payload))
        openssl("pkeyutl", "-sign", "-rawin", "-inkey", key, "-keyform", "DER",
                "-in", msg, "-out", sig)
        openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub, "-in", msg, "-sigfile", sig)
        signature = load_file(sig, 64)
        require(len(signature) == 64, "release_signature_length")
    valid_window(dynamic, clock())
    return {"schema": SCHEMA, "template_sha256": TEMPLATE_PIN,
            "public_pem_sha256": pin, "deployment_fields": dynamic,
            "signature_b64": base64.b64encode(signature).decode("ascii")}


def assemble(p, receipt, pem, pin, now):
    p = template(canonical(p))
    public_key_check(pem, pin)
    require(type(receipt) is dict and set(receipt) == {"schema", "template_sha256", "public_pem_sha256",
            "deployment_fields", "signature_b64"} and receipt["schema"] == SCHEMA
            and receipt["template_sha256"] == TEMPLATE_PIN
            and receipt["public_pem_sha256"] == pin, "detached_receipt_binding")
    fields = receipt["deployment_fields"]
    require(type(fields) is dict and fields.keys() == DYNAMIC and type(fields["deployment_id"]) is str
            and re.fullmatch(r"[0-9a-f]{32}", fields["deployment_id"]), "deployment_fields")
    valid_window(fields, now)
    sig = base64.b64decode(receipt["signature_b64"], validate=True)
    require(len(sig) == 64, "release_signature_length")
    payload = dict(p, **fields)
    with tempfile.TemporaryDirectory() as td:
        pub, msg, signature = (Path(td) / name for name in ("key.pub.pem", "message", "signature"))
        write_new(pub, pem)
        write_new(msg, DOMAIN + canonical(payload))
        write_new(signature, sig)
        openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub,
                "-in", msg, "-sigfile", signature)
    return {"payload": payload, "signature_b64": receipt["signature_b64"]}


def gh(token, *args, data=b""):
    # The setup bearer stays in this child's environment. Secret bytes pass through stdin.
    env = dict(CHILD_ENV, GH_TOKEN=token, GH_HOST="github.com", GH_PROMPT_DISABLED="1",
               HOME=os.environ["HOME"])
    result = subprocess.run(["gh", *args, "--repo", REPO], env=env, input=data,
                            capture_output=True, timeout=45)
    require(result.returncode == 0, "github_environment_secret_operation_failed")
    return result.stdout


def enroll(token, destination, temp, *, github=gh, generate=new_der):
    require(token, "missing_enrollment_store_token")
    require(not destination.exists(), "enrollment_output_already_exists")
    options = ("--app", "actions", "--env", ENVIRONMENT)
    existing = parse(github(token, "secret", "list", *options, "--json", "name"))
    require(type(existing) is list and all(type(x) is dict and type(x.get("name")) is str
            for x in existing), "github_secret_listing_invalid")
    require(not any(x["name"] == KEY_SECRET for x in existing), "release_key_already_enrolled")
    der = generate()
    with tempfile.TemporaryDirectory(dir=temp) as td:
        key = Path(td) / "enrollment-key.der"
        write_der(key, der)
        pem = pem_from_der(key)
    public_key_check(pem, sha(pem))
    # Publish the non-secret recovery metadata to the job log only after storage succeeds.
    github(token, "secret", "set", KEY_SECRET, *options, data=base64.b64encode(der))
    print("ARDA_GEN12_RELEASE_PUBLIC_PEM_SHA256=" + sha(pem), flush=True)
    print(pem.decode("ascii"), end="", flush=True)
    write_new(destination, pem)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("enroll", "sign"):
        sub.add_parser(mode).add_argument("--output", required=True, type=Path)
    encode = sub.add_parser("encode-template")
    encode.add_argument("--request", required=True, type=Path)
    verify = sub.add_parser("assemble")
    for name in ("request", "receipt", "public-key", "output"):
        verify.add_argument(f"--{name}", required=True, type=Path)
    verify.add_argument("--public-key-sha256", required=True)
    args = parser.parse_args()
    if args.mode in ("sign", "enroll"):
        protect_context(os.environ, args.mode)
        temp = Path(os.environ["RUNNER_TEMP"])
        if args.mode == "enroll":
            enroll(os.environ.pop(TOKEN_SECRET, ""), args.output, temp)
        else:
            p = decode_template(os.environ.pop(TEMPLATE_SECRET, ""))
            der = base64.b64decode(os.environ.pop(KEY_SECRET, ""), validate=True)
            result = issue(p, der, os.environ.get("ARDA_GEN12_RELEASE_PUBLIC_PEM_SHA256", ""),
                           os.environ.get("ARDA_GEN12_RELEASE_VALID_HOURS", ""), temp=temp)
            write_new(args.output, canonical(result) + b"\n")
            print("GEN12_BOOT_SIGNATURE=ISSUED PRODUCTION_ADMISSION_AUTHORIZED=false")
    else:
        p = template(canonical(parse(load_file(args.request))["boot_deployment_fields"]))
        if args.mode == "encode-template":
            encoded = base64.b64encode(zlib.compress(canonical(p), 9))
            require(len(encoded) <= 48000, "template_secret_size")
            sys.stdout.buffer.write(encoded)  # Feed directly into gh secret set via a pipe.
        else:
            result = assemble(p, parse(load_file(args.receipt, 4096)),
                              load_file(args.public_key, 8192), args.public_key_sha256, int(time.time()))
            write_new(args.output, canonical(result) + b"\n")
            print("GEN12_BOOT_ENVELOPE=VERIFIED PRODUCTION_ADMISSION_AUTHORIZED=false")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, OSError, KeyError, subprocess.SubprocessError, zlib.error, RecursionError) as exc:
        # Never render exception details that may contain input or secret values.
        print(f"ARDA_GEN12_RELEASE_REFUSED ({type(exc).__name__})", file=sys.stderr)
        sys.exit(1)
