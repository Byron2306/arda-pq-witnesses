"""Prepare separate Cloudflare secrets from operator-approved TPM enrollment."""
import argparse
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from attest_cloud import ENDPOINT
from quote_client import read_bounded
from r13_v2 import NodePolicy, canonical, encode, need, public_pin, strict_json

NODE = "lenovo-valinor"
VERIFIER = "cloudflare-r13-v2"


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def prepare(args):
    ak = serialization.load_pem_public_key(read_bounded(args.ak_public_pem, 8192))
    baseline = strict_json(read_bounded(args.approved_pcrs, 4096))
    policy = NodePolicy(ak, baseline)
    need(policy.ak_sha256 == args.ak_spki_sha256, "AK_PIN_MISMATCH")
    signer = ed25519.Ed25519PrivateKey.generate()
    public = signer.public_key()
    spki = ak.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    enrollment = dict(verifier_id=VERIFIER,node_id=NODE,ak_spki_b64=encode(spki),
                      ak_spki_sha256=policy.ak_sha256,pcrs=dict(policy.pcrs))
    pins = dict(endpoint=ENDPOINT,node_id=NODE,verifier_id=VERIFIER,
                verifier_spki_sha256=public_pin(public),policy_sha256=policy.sha256)
    token = secrets.token_hex(32)
    state = args.state_dir
    state.mkdir(mode=0o700, exist_ok=False)
    secrets_payload = {
        "R13_TOKEN":token,
        "R13_SIGNER_PKCS8_B64":encode(signer.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption())),
        "R13_ENROLLMENT":canonical(enrollment).decode("ascii"),
    }
    private_write(state/"deploy-secrets.json",canonical(secrets_payload)+b"\n")
    private_write(state/"verifier-public.pem",public.public_bytes(
        serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    private_write(state/"lenovo.token",token.encode("ascii")+b"\n")
    private_write(state/"pins.json",canonical(pins)+b"\n")
    return pins


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ak-public-pem",type=Path,required=True)
    parser.add_argument("--ak-spki-sha256",required=True)
    parser.add_argument("--approved-pcrs",type=Path,required=True)
    parser.add_argument("--state-dir",type=Path,required=True)
    args = parser.parse_args()
    try:
        pins = prepare(args)
    except (ValueError,OSError) as exc:
        parser.exit(1,f"R13_CLOUD_CONFIG_REFUSED={exc}\n")
    print("R13_CLOUD_CONFIG=PREPARED")
    print(canonical(pins).decode("ascii"))


if __name__ == "__main__":
    main()
