"""Explicit-device, current-boot PCR observations for production appraisal."""
from pathlib import Path
import re
import subprocess
import uuid

PCRS = frozenset({'0', '1', '4', '7', '8', '9', '11'})


def parse_pcr_output(text):
    rows = text.strip().splitlines()
    if not rows or rows[0].strip() != 'sha256:':
        raise ValueError('live_pcr_bank')
    result = {}
    for row in rows[1:]:
        if not row.strip():
            continue
        match = re.fullmatch(r'\s*(\d+)\s*:\s*0x([0-9a-fA-F]{64})\s*', row)
        if not match or match[1] in result:
            raise ValueError('live_pcr_row_or_duplicate')
        result[match[1]] = match[2].lower()
    if set(result) != PCRS:
        raise ValueError('live_pcr_selection')
    return result


def read_current_boot_context():
    path = Path('/proc/sys/kernel/random/boot_id')
    before = path.read_text(encoding='ascii').strip()
    if str(uuid.UUID(before)) != before or uuid.UUID(before).int == 0:
        raise ValueError('live_boot_identity')
    result = subprocess.run(
        ['/usr/bin/tpm2_pcrread', '-T', 'device:/dev/tpmrm0', 'sha256:0,1,4,7,8,9,11'],
        stdin=subprocess.DEVNULL, capture_output=True, check=True, text=True, timeout=20,
    )
    pcrs = parse_pcr_output(result.stdout)
    if path.read_text(encoding='ascii').strip() != before:
        raise ValueError('live_boot_changed')
    return {'boot_id': before, 'pcrs': pcrs}
