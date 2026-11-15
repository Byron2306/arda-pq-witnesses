import hashlib
import re
FIRMWARE_PCRS=(0,1,4,7,8,9)
ALL_PCRS=(*FIRMWARE_PCRS,11)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest_hex(value):
    if type(value) is int and 0 <= value < 2**256:
        return f'{value:064x}'
    if isinstance(value, str):
        candidate = value.lower().removeprefix('0x')
        if re.fullmatch('[0-9a-f]{64}', candidate):
            return candidate
    raise ValueError('INVALID_SHA256_DIGEST')

def parse_pcrs(text):
    if not text.strip().startswith('sha256:'):
        raise ValueError('PCR_BANK')
    result = {}
    for row in text.strip().splitlines()[1:]:
        if not row.strip():
            continue
        m = re.fullmatch(r'\s*(\d+)\s*:\s*0x([0-9a-fA-F]{64})\s*', row)
        if not m or int(m[1]) in result:
            raise ValueError('INVALID_OR_DUPLICATE_PCR_ROW')
        result[int(m[1])] = m[2].lower()
    if set(result) != set(ALL_PCRS):
        raise ValueError('PCR_SELECTION')
    return result

def assess(document, pcr_text, binding, boot, kernel, initrd):
    live = parse_pcrs(pcr_text)
    states = {pcr: bytes(32) for pcr in FIRMWARE_PCRS}
    count = {pcr: 0 for pcr in FIRMWARE_PCRS}
    artifacts = {'kernel': [], 'initrd': []}
    artifact_digests = {'kernel': [], 'initrd': []}
    for event in document['events']:
        pcr = int(event['PCRIndex'])
        if event.get('EventType') == 'EV_NO_ACTION':
            # This reviewed capture has no StartupLocality event. Refuse unfamiliar
            # locality handling rather than inventing a PCR0 initial state.
            if 'StartupLocality' in str(event):
                raise ValueError('STARTUP_LOCALITY_REQUIRES_REVIEW')
            continue
        if pcr not in states:
            continue
        digests = [d for d in event.get('Digests', []) if d.get('AlgorithmId') == 'sha256']
        if len(digests) != 1:
            raise ValueError('EVENT_SHA256_DIGEST_COUNT')
        digest = digest_hex(digests[0]['Digest'])
        states[pcr] = hashlib.sha256(states[pcr] + bytes.fromhex(digest)).digest()
        count[pcr] += 1
        data = event.get('Event', {})
        if pcr == 9 and event.get('EventType') == 'EV_IPL' and isinstance(data, dict):
            for label, path in [('kernel', kernel), ('initrd', initrd)]:
                if data.get('String', '').rstrip('\x00') == path:
                    artifacts[label].append(event.get('EventNum'))
                    artifact_digests[label].append(digest)
    results = {str(p): {'replay': states[p].hex(), 'live': live[p],
                        'extends': count[p], 'match': count[p] > 0 and states[p].hex() == live[p]}
               for p in FIRMWARE_PCRS}
    consistent = False
    try:
        expected = [
            {'label': 'manifest_digest', 'digest': binding['manifest_digest'].removeprefix('sha256:')},
            {'label': 'policy_generation', 'digest': sha(binding['policy_generation'].encode())},
        ]
        value = bytes(32)
        for component in expected:
            value = hashlib.sha256(value + bytes.fromhex(digest_hex(component['digest']))).digest()
        consistent = (binding['boot_id'] == boot and binding['components'] == expected
                      and value.hex() == binding['pcr_after'] == live[11]
                      and live[11] != '0' * 64)
    except (KeyError, TypeError, ValueError, AttributeError):
        pass
    return {'schema': 'arda.campaign_d.evidence_check.v1', 'boot_id': boot,
            'firmware_replay_matches': all(r['match'] for r in results.values()),
            'firmware_pcrs': results, 'pcr11_record_consistent': consistent,
            'pcr11_record_is_not_independent_attestation': True,
            'boot_artifact_event_numbers': artifacts,
            'boot_artifact_recorded_sha256': artifact_digests,
            'production_authorized': False, 'interlock': 'KEEP_CLOSED'}
