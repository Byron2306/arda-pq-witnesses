"""Read the current boot ID and quote via an existing persistent TPM key."""
from pathlib import Path
import re
import subprocess
import tempfile

from .r13_v2 import PCRS, PCR_SELECTION, is_boot, matches, need

BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
HANDLE = re.compile(r"0x81[0-9a-f]{6}")

def read_bounded(path, cap):
    with path.open("rb") as fp:
        result = fp.read(cap + 1)
    need(0 < len(result) <= cap, "FILE_SIZE")
    return result


def read_boot():
    boot = BOOT_ID.read_text(encoding="ascii").strip()
    need(is_boot(boot), "LOCAL_BOOT_ID")
    return boot


def quote(handle, qualification):
    need(matches(HANDLE, handle), "AK_PERSISTENT_HANDLE")
    need(type(qualification) is bytes and len(qualification) == 32, "QUOTE_QUALIFICATION_SIZE")
    with tempfile.TemporaryDirectory(prefix="arda-r13-v2-quote-") as temp:
        d = Path(temp)
        q, s, p = (d / name for name in ("quote.bin", "signature.tss", "pcrs.bin"))
        rc = subprocess.run(
            ["/usr/bin/tpm2_quote", "-T", "device:/dev/tpmrm0", "-c", handle,
             "-l", PCR_SELECTION, "-g", "sha256", "-f", "tss", "-F", "values",
             "-q", qualification.hex(), "-m", str(q), "-s", str(s), "-o", str(p)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=30, check=False,
        ).returncode
        need(rc == 0, "TPM_QUOTE_COMMAND_FAILED")
        raw = read_bounded(p, 32 * len(PCRS))
        need(len(raw) == 32 * len(PCRS), "TPM_PCR_RAW_LENGTH")
        pcrs = {str(n): raw[i*32:(i+1)*32].hex() for i, n in enumerate(PCRS)}
        return read_bounded(q, 4096), read_bounded(s, 1024), pcrs


