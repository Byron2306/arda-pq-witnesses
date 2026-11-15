# ARDA R13 v2 — Cloudflare verifier

A separate evidence-only Worker for the DIO Workflows Cloudflare account.
The Lenovo calls the Worker directly over HTTPS. No Acer, SSH tunnel, DNS
changes, home listener, or changes to the existing DIO gateways. This package
is not a replacement for Campaign D's loader, journal, or enforcement gates.

**The interlock stays closed.** A receipt verifies a point-in-time TPM quote
against one independently enrolled key and one approved seven-PCR tuple.
The TPM quote commits to a **client-reported Linux boot ID**, not a boot ID
independently established by the TPM. This does not prove the provenance of a
public key, reconstruct the event log, prove runtime BPF state, or authorize
cutover. No receipt is sent to the legacy verifier, Rekor, or a production
consumer.

## R1 after the first hardware test

R1 permanently sends the descriptive `User-Agent: ARDA-R13-Attest/2.0`.
The original client used Python's default User-Agent, which the Cloudflare
edge refused. The descriptive identifier worked during the live hardware
test. The change does not impersonate a browser, remove the bearer token,
or alter TLS or receipt checks. The Worker and deployment configuration
are unchanged. For an existing installation, do not redeploy the Worker
or create a new key just to install R1. Extract the package alongside the
old one and run its updated client from the new directory.

To gather a separate baseline candidate, boot the normal Debian/Valinor
entry when you have access to the boot menu and can recover the session.
Do not select the temporary GRUB TPM log-budget test entry. This package
does not modify GRUB, schedule a reboot, or select an entry for you.

Once on the normal boot, run the collector as your regular user after
`sudo -v`. It uses sudo only for the fixed read commands that need it:

```bash
cd "$HOME/arda-r13-cloudflare-r1"
sudo -v &&
python3 -B capture_normal_boot.py \
  --out "$HOME/r13-normal-boot-$(date +%Y%m%d-%H%M%S).tar.gz"
```

The archive is mode 0600 and contains only the current boot ID, kernel
release, kernel command line, boot-file digests, PCRs, and the firmware
event log. It does not include the token, deployment secrets, receipt
signer, or TPM key material. It reads PCRs before and after collection,
rejects the known test boot and snapshot drift, and reports zero values
without trying to change them. A different boot ID alone does not prove
you selected the normal entry. Review the event log and measurements
before approving the candidate. The disk hashes alone do not establish
what the bootloader measured. Keep the candidate separate from the
approved test policy and never pass it directly to `prepare_deploy.py`.
This collector sends nothing over the network.

## 1. Unpack and check

On the Lenovo or a trusted admin computer with Node 24+, Python 3.10+ and
the Python cryptography library. The Lenovo needs Debian tpm2-tools and
access to its TPM resource manager device for the quote.

```bash
tar -xzf "$HOME/Downloads/arda-r13-cloudflare-r1.tar.gz" -C "$HOME" &&
cd "$HOME/arda-r13-cloudflare-r1" &&
sha256sum --strict -c MANIFEST.sha256
```

If Python does not already have cryptography, use an isolated venv on the
admin computer with `python3 -m venv .venv` and install the contents of
`requirements.txt`. On Debian, the distro's `python3-cryptography` package
can supply the system Python dependency when needed for TPM access.

Run these checks locally. Wrangler's dry run does not deploy.

```bash
node --test worker.test.mjs
python3 -B -m unittest -v
WRANGLER_SEND_METRICS=false npx --yes wrangler@4.162.0 deploy --dry-run
```

For the local Worker integration test, set `R13_WRANGLER` to the absolute
path of a Wrangler 4.162.0 executable before running the Node test suite.
It boots a loopback-only local Worker with disposable software keys, uses the
actual SQLite Durable Object API, checks the signed receipt with Python, then
restarts Wrangler against the same temporary state and checks replay refusal.
It does not use a Cloudflare account or the Lenovo TPM.

## 2. Prepare enrollment without touching existing handles

This package does not provision TPM keys or modify PCRs. As already observed,
Lenovo's six existing handles do not provide the required restricted RSA
RSASSA/SHA-256 signing key. Use a separately provisioned persistent AK with
`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `restricted`, and signing
attributes. The client supports keys usable with the default empty object
authorization. Do not reuse or evict any existing handle. A trusted provisioning
record must bind the AK public fingerprint to this TPM. A PEM or a quote
from an unknown source is not enough to establish provenance.

Once the dedicated AK exists, export only its public material using
`tpm2_readpublic` and confirm its type and signing scheme against the provisioning
record. The approved baseline is a separate JSON file with exactly these
keys and lowercase 64-character SHA-256 hex values for the intended boot:
`"0"`, `"1"`, `"4"`, `"7"`, `"8"`, `"9"`, `"11"`. This specific profile
rejects all-zero measurements. Do not fill it from a failed quote, a mixed-boot
capture, or a PCR 11 replay result alone. No baseline is bundled.

With the public PEM, independently pinned SPKI hash, and approved baseline
available, run from the extracted directory:

```bash
state="$HOME/.local/state/arda-r13-cloudflare"
mkdir -p "$HOME/.local/state"
python3 -B prepare_deploy.py \
  --ak-public-pem "$HOME/lenovo-r13-ak-public.pem" \
  --ak-spki-sha256 "${AK_SPKI_SHA256:?set from trusted provisioning}" \
  --approved-pcrs "$HOME/lenovo-approved-pcrs.json" \
  --state-dir "$state"
```

The helper verifies the AK fingerprint and creates a new private directory.
It refuses to overwrite an existing one. It writes:
- `deploy-secrets.json` for the Worker only. Contains the new Ed25519 private
  signer, enrollment, and 256-bit client credential.
- `lenovo.token` for the Lenovo only. Do not paste it into chat or put it in
  command arguments or Git.
- `verifier-public.pem` and `pins.json` for the Lenovo. Transfer via a trusted
  channel, independently checking the printed public fingerprint and policy
  digest.

Do not use the Acer or any legacy signer. Keep the deploy secrets in a
protected admin location. The Lenovo needs only its token and the public
pin files, not the signer private key. If the Lenovo doubles as your admin
computer, separate deployment secrets from the runtime client account and
copy only those three client files to it. The Cloudflare account and anyone
able to change its deployed code or secrets are part of the trust boundary.

## 3. Deploy a separate Worker

Do this from your trusted admin computer in the extracted directory. Log in
yourself and check that Wrangler is targeting the account whose Workers use
`dio-workflows.workers.dev`. Confirm `arda-r13-verifier` is not already used by
an unrelated Worker. No API token needs to be shared.

```bash
npx --yes wrangler@4.162.0 login
npx --yes wrangler@4.162.0 whoami
state="$HOME/.local/state/arda-r13-cloudflare"
npx --yes wrangler@4.162.0 deploy --secrets-file "$state/deploy-secrets.json"
```

Expected URL: `https://arda-r13-verifier.dio-workflows.workers.dev`.
The Lenovo client is pinned to that HTTPS origin. It follows no redirects and
does not use system HTTP proxies. The Worker uses a SQLite Durable Object.
Secrets are uploaded as Worker bindings. No public health, upload, status or
v1 endpoint is installed. The two POST routes require the client credential,
and application observability is disabled in the supplied configuration.
The database retains challenge metadata, not raw quotes or PCR submissions.
Expired rows are cleaned up when issuing challenges. Stay on the Free plan
for the test and confirm edge limits on the deployed Worker. The local
runtime cannot establish the real Free-plan CPU budget or availability.

## 4. Verify the first Lenovo hardware receipt

In a private directory on the Lenovo, put the three client files from step 2.
Set `AK_HANDLE` from the trusted provisioning record. Run with an account
that can read the private token file and use `/dev/tpmrm0`. If privileged TPM
access is needed, use the host's trusted system Python with cryptography and
arrange token ownership for the identity actually running the client. Do not
loosen token-file permissions.

```bash
cd "$HOME/arda-r13-cloudflare-r1"
state="$HOME/.local/state/arda-r13-cloudflare-client"
verifier_pin=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verifier_spki_sha256"])' "$state/pins.json")
policy_pin=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["policy_sha256"])' "$state/pins.json")
python3 -B attest_cloud.py \
  --node-id lenovo-valinor --verifier-id cloudflare-r13-v2 \
  --verifier-public-key "$state/verifier-public.pem" \
  --verifier-spki-sha256 "$verifier_pin" --policy-sha256 "$policy_pin" \
  --ak-handle "${AK_HANDLE:?set from trusted provisioning}" \
  --token-file "$state/lenovo.token" --check-replay \
  --out "$HOME/r13-cloud-capture-$(date +%Y%m%d-%H%M%S).json"
```

Expect `R13_V2_EVIDENCE=PASS`, `R13_V2_REPLAY=REFUSED` and
`R13_V2_INTERLOCK=KEEP_CLOSED`. The private output archive contains the
challenge, quote evidence and receipt. Do not share it indiscriminately.
The Worker signs a challenge with a 120-second window and verifies the exact
PCR selection, signed PCR digest, quote qualification, RSA signature, and
whole approved tuple before atomically consuming the challenge and issuing a
receipt. A successful capture cannot be reused as fresh evidence after expiry.
A network or quota failure produces no authorization. Keep clocks in sync.
If the PCRs differ, diagnose the measurements before changing the baseline.

Docs:
- https://developers.cloudflare.com/durable-objects/get-started/
- https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
- https://developers.cloudflare.com/workers/wrangler/commands/workers/
