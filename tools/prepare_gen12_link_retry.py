#!/usr/bin/env python3
"""Derive and optionally stage only the reviewed Gen12 pinned-link retry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

OLD_ENVELOPE_SHA256 = "62135c13fdb81b3776d39351475b2d8c03fff9cd0568347e309f60165a6b9e5c"
OLD_TEMPLATE_SHA256 = "94663cd969e73f9950cf3c68fd8ce290d95bb0fd63fba13fb3902cc8e23a3a58"
NEW_TEMPLATE_SHA256 = "48305e55928ab79be3357f0343b13efbc8a6b905dec25ba27edc2ef9cc8bc5ec"
RELEASES = Path("/usr/lib/arda/releases")
OLD_PACKAGE = RELEASES / "campaign-d-6e3159ece165402e"
NEW_PACKAGE = RELEASES / "campaign-d-6e3159ece165402e-gen12-link-r1"
OLD_ROOT = OLD_PACKAGE / "arda_os"
NEW_ROOT = NEW_PACKAGE / "arda_os"
PATCHES = {
    "backend/services/coordinated_loader.py": (
        "2df8d663cf283ecd305fd7057ff0bd0fe7a517fefb5e6ae1724dbc453e94aa19",
        "bd78a765680c080fb24c161f221d4617708213222498fdfa12a403bd864c2052"),
    "backend/services/projection_bpf.py": (
        "a28dd8744db3a75c9691dbc61abb9e87d9563b98967eb8219656ce6bf94c78ad",
        "1a49382e9a5be570388f79617dd6df4f1bd39f1d64c65a7329c7db56c81a2698"),
    "backend/services/r13_observer.py": (
        "1b2b525bacbe097826314b5b5c63b1c06784677ae31838d83e5d0b044fdff282",
        "7792fcbfd487dc5add15abea71edcf5e99f645f097ebde9c37caaeafe8d8a4ca"),
}
CAP = 512 * 1024 * 1024
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def open_regular(path, *, root_owned, cap=CAP, allow_empty=False):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    stream = os.fdopen(os.open(path, flags), "rb")
    try:
        meta = os.fstat(stream.fileno())
        minimum = 0 if allow_empty else 1
        need(stat.S_ISREG(meta.st_mode) and minimum <= meta.st_size <= cap and
             (not root_owned or (meta.st_uid == 0 and meta.st_nlink == 1
                                 and not meta.st_mode & 0o022)), "unprotected input: " + str(path))
        return stream, meta
    except BaseException:
        stream.close()
        raise


def baseline(path):
    stream, _ = open_regular(path, root_owned=False, cap=256 * 1024)
    with stream:
        raw = stream.read(256 * 1024 + 1)
    need(sha(raw) == OLD_ENVELOPE_SHA256, "baseline envelope SHA-256 does not match")
    envelope = json.loads(raw)
    return {k: v for k, v in envelope["payload"].items()
            if k not in {"deployment_id", "issued_at", "expires_at"}}


def derive(previous):
    need(sha(canonical(previous)) == OLD_TEMPLATE_SHA256, "baseline deployment fields do not match")
    need(type(previous["generation"]) is int and previous["generation"] == 12
         and previous["production_admission_authorized"] is False, "only Gen12 boot continuity is in scope")
    after = dict(previous)
    after["bpf_object_path"] = str(NEW_ROOT / Path(previous["bpf_object_path"]).relative_to(OLD_ROOT))
    after["artifacts"] = {}
    different = set()
    for path, digest in previous["artifacts"].items():
        old = Path(path)
        if not old.is_relative_to(OLD_ROOT):
            after["artifacts"][path] = digest
            continue
        rel = old.relative_to(OLD_ROOT).as_posix()
        need(".." not in Path(rel).parts, "invalid staged artifact path")
        if rel in PATCHES:
            expected_old, new_digest = PATCHES[rel]
            need(digest == expected_old, "baseline source pin mismatch: " + rel)
            digest = new_digest
            different.add(rel)
        after["artifacts"][str(NEW_ROOT / rel)] = digest
    need(different == PATCHES.keys() and len(after["artifacts"]) == 569,
         "incomplete artifact inventory")
    need(sha(canonical(after)) == NEW_TEMPLATE_SHA256, "retry template SHA-256 does not match")
    return after


def verified_copy(source, digest, *, target=None, root_owned=True):
    # The signed inventory includes deliberately empty Python package markers.
    stream, meta = open_regular(source, root_owned=root_owned,
                                allow_empty=digest == EMPTY_SHA256)
    with stream:
        if target is None:
            observed = hashlib.file_digest(stream, "sha256").hexdigest()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as out:
                h = hashlib.sha256()
                total = 0
                while chunk := stream.read(1024 * 1024):
                    total += len(chunk)
                    need(total <= CAP, "oversized artifact")
                    h.update(chunk)
                    out.write(chunk)
                observed = h.hexdigest()
                # Review checkout cannot control installed permissions.
                mode = (stat.S_IMODE(meta.st_mode) & 0o755) if root_owned else 0o644
                os.fchmod(out.fileno(), mode)
                out.flush()
                os.fsync(out.fileno())
        need(observed == digest, "artifact SHA-256 mismatch: " + str(source))


def protected_directory(path):
    for candidate in (path, *path.parents):
        mode = candidate.lstat()
        need(stat.S_ISDIR(mode.st_mode) and mode.st_uid == 0 and not mode.st_mode & 0o022,
             "unprotected release directory: " + str(candidate))


def stage_release(previous, retry, review_runtime):
    need(os.geteuid() == 0, "stage-release requires root")
    protected_directory(RELEASES)
    protected_directory(OLD_ROOT)
    if os.path.lexists(NEW_PACKAGE):
        protected_directory(NEW_ROOT)
        expected = {Path(name) for name in retry["artifacts"] if Path(name).is_relative_to(NEW_PACKAGE)}
        observed = {path for path in NEW_PACKAGE.rglob("*") if path.is_symlink() or not path.is_dir()}
        need(expected == observed, "new release already exists with a different file inventory")
        for name, digest in retry["artifacts"].items():
            verified_copy(Path(name), digest)
        print("GEN12_LINK_RETRY_RELEASE=ALREADY_STAGED")
        return

    with tempfile.TemporaryDirectory(prefix=".gen12-link-r1.", dir=RELEASES) as tmp:
        scratch = Path(tmp)
        tree = scratch / "release"
        tree.mkdir()
        for name, digest in previous["artifacts"].items():
            old = Path(name)
            if not old.is_relative_to(OLD_ROOT):
                verified_copy(old, digest)
                continue
            rel = old.relative_to(OLD_ROOT)
            dest = tree / "arda_os" / rel
            if rel.as_posix() in PATCHES:
                verified_copy(old, digest)
                new = NEW_ROOT / rel
                verified_copy(review_runtime / rel, retry["artifacts"][str(new)],
                              target=dest, root_owned=False)
            else:
                verified_copy(old, digest, target=dest)
        need(not os.path.lexists(NEW_PACKAGE), "retry release appeared during copy")
        tree.rename(NEW_PACKAGE)
    fd = os.open(RELEASES, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print("GEN12_LINK_RETRY_RELEASE=STAGED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-envelope", type=Path, required=True)
    operations = parser.add_subparsers(dest="action", required=True)
    operations.add_parser("request")
    stage = operations.add_parser("stage-release")
    stage.add_argument("--review-runtime", type=Path, required=True)
    args = parser.parse_args()
    old = baseline(args.baseline_envelope)
    new = derive(old)
    if args.action == "request":
        sys.stdout.buffer.write(canonical({"boot_deployment_fields": new}) + b"\n")
    else:
        stage_release(old, new, args.review_runtime.resolve(strict=True))
        print("GEN12_LINK_RETRY_RELEASE_PATH=" + str(NEW_ROOT))
        print("GEN12_LINK_RETRY_TEMPLATE_SHA256=" + NEW_TEMPLATE_SHA256)
        print("LIVE_UNITS_CHANGED=no PRODUCTION_ADMISSION_AUTHORIZED=false")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"GEN12_LINK_RETRY_REFUSE={exc}") from None
