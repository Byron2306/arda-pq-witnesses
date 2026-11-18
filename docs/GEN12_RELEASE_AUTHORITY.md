# Gen12 boot continuity release authority

This is the separate Ed25519 role that the coordinated loader can read. It is not
the GitHub PQ build witness, the Hugging Face policy witness, the Cloudflare
release witness or R13 verifier, or Rekor's transparency proof. It signs one
pinned Gen12 boot-only template with `production_admission_authorized=false`.
It cannot issue a Gen14 envelope or a projection permit. Nothing here installs
a host profile, updates Ring-0, or decommissions Acer.

The signing template contains the private host binding and 569 reviewed artifact
digests. It is passed as a GitHub environment secret, not committed in the public
repository. The signing artifact contains only a detached signature, its
deployment ID and validity window, and the public-key and template pins. The
systemd consumer gets its usual full envelope only after local verification and
assembly.

## Protect the two environments before adding credentials

1. Protect `main` with reviewed changes. Create `arda-release-authority-enrollment`
   and `arda-release-authority` under Settings → Environments. For both, restrict
   deployment to the `main` branch, require a trusted reviewer separate from the
   workflow dispatcher, prevent self-review, and disable administrator bypass.
   Before approving a run, confirm the exact workflow, branch, and commit. These
   controls are administered on GitHub, not created by the workflow. Anyone
   who can change the environment configuration or approve arbitrary workflows
   in it is in this authority's trust boundary.
2. After the changes land, record the reviewed 40-character main commit in
   `ARDA_RELEASE_APPROVED_COMMIT` in both environments. Keep
   `ARDA_RELEASE_ENABLED` unset where the corresponding operation is not wanted.
3. In the enrollment environment only, set `ARDA_GEN12_ENROLLMENT_STORE_TOKEN`
   to a short-lived, fine-grained GitHub token restricted to this repository
   with **Environments** read/write. This is a setup credential, not a signing
   key. Set `ARDA_RELEASE_ENABLED=true` there and dispatch **ARDA Gen12 release
   key enrollment** on main. Do not provision the same secret concurrently
   through the UI or another workflow. The workflow lists existing secret
   names first and refuses to regenerate an existing key.
4. Obtain `gen12-release-authority.public.pem` from the approved run and
   independently compare its file SHA-256 with the run's reported
   `ARDA_GEN12_RELEASE_PUBLIC_PEM_SHA256`. Record the approved pin outside the
   later signature artifact. If the upload failed after storage, the
   successful enrollment step also logged the public PEM. The private key
   was generated on the GitHub runner and stored directly as
   `ARDA_GEN12_RELEASE_ED25519_PKCS8_B64` in the signing environment. Never use
   the existing Lenovo-held key. Remove the enrollment token from GitHub,
   revoke it at the issuer and unset the enrollment enable variable.
5. In the signing environment set `ARDA_GEN12_RELEASE_PUBLIC_PEM_SHA256` to the
   reviewed pin and `ARDA_GEN12_RELEASE_VALID_HOURS` to the intended test
   duration, from 1 to 720 hours. The profile must still be valid for any
   subsequent coordinated boot that uses it.

GitHub gives repository administrators control over these protections. This
separates signing from the Lenovo host, but it is not an HSM or organizational
separation from a GitHub administrator.

## Load the reviewed request and issue the detached signature

The signer now accepts only the **Gen12 pinned-link retry** template. The first
coordinated boot loaded and attached the expected BPF object, but the installed
bpftool reported a failure exit after printing the pinned link correctly.
The shared kernel readback fixes both the loader and downstream R13 observer.
The original release and deployed legacy runtime must not be changed. The
enrollment key is carried forward as-is, and enrollment should stay disabled.

Create the new release and the unsigned request separately using the verified
first envelope (`deployment.gen12.signed.json`) and the reviewed, patched
`arda-gate3-kernel` checkout. The preparation tool pins the first envelope's
bytes, the three repaired source files, and the resulting template. It copies
the 564 release-local files to their new signed paths, verifies the five
unchanged external paths, and does not create a live systemd override.

```bash
repo="$HOME/GitHub/EdgeK-BEAST/arda-gate3-kernel"
umask 077
sudo /usr/bin/python3 -I -B tools/prepare_gen12_link_retry.py \
  --baseline-envelope "$HOME/deployment.gen12.signed.json" \
  stage-release --review-runtime "$repo/reviewed-runtime"
/usr/bin/python3 -I -B tools/prepare_gen12_link_retry.py \
  --baseline-envelope "$HOME/deployment.gen12.signed.json" request \
  > "$HOME/arda-gen12-link-retry-request.json"
```

Pin `ARDA_RELEASE_APPROVED_COMMIT` to the new reviewed main commit before
re-enabling signing. The encoder checks the exact revised Gen12 payload and
prints the packed template. Pipe it directly to the signing environment from
an authenticated route with permission to modify its secrets. Do not paste it
into workflow dispatch inputs.

```bash
set -o pipefail
python3 -I -B tools/gen12_release_authority.py encode-template \
  --request "$HOME/arda-gen12-link-retry-request.json" |
  gh secret set ARDA_GEN12_RELEASE_TEMPLATE_ZLIB_B64 \
    --repo Byron2306/arda-pq-witnesses --env arda-release-authority
```

Set `ARDA_RELEASE_ENABLED=true` in the signing environment when ready. Dispatch
**ARDA Gen12 boot continuity signature** on main and have the reviewer approve
that run. Download the detached receipt from the run, then reconstruct the
envelope locally against the independently reviewed public-key pin.

```bash
python3 -I -B tools/gen12_release_authority.py assemble \
  --request "$HOME/arda-gen12-link-retry-request.json" \
  --receipt /path/to/gen12-continuity.detached.json \
  --public-key /path/to/gen12-release-authority.public.pem \
  --public-key-sha256 "$APPROVED_RELEASE_PEM_SHA256" \
  --output ./deployment.gen12-link-r1.signed.json
```

This command verifies the complete signature and validity window, writes a new
file without overwriting an existing one, and does not install anything. Confirm
the live Gen12 continuity readback and use the coordinated loader deployment
verifier on this complete staged release before the cold boot. Use the already
reviewed public anchor. Boot the coordinated runtime on Gen12 and capture
fresh R13 and Ring-0 evidence before preparing any Gen14 production admission.

## Offline tests

```bash
python3 -B -m unittest discover -s tests -p test_gen12_release_authority.py -v
```
