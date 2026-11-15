"""Renew hardware evidence without changing projection, ledger or PCR state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace
import uuid

from cryptography.hazmat.primitives import serialization
from .arda_bpf_authority import verify_attachment, BPFTOOL
from .deployment_profile import load_profile
from .firmware_evidence import assess, parse_pcrs
from .measured_identity import MeasuredProjectionGenerationStore
from .production_files import protected_bytes, protected_json, publish_json
from .projection_bpf import BpfProjectionAdapter, PIN_ROOT
from .projection_ctl import DATABASE
from .projection_journal import Journal, _need, TERMINAL
from .r13 import attest_cloud, r13_v2 as v2
from .software_binding import STATE

OUTPUT=Path('/var/lib/arda/r13-observation/current.json')


def verify_archive(archive, key, policy, *, boot, node, verifier, now):
    _need(archive.keys()=={'schema','issued_challenge','evidence','receipt'}
          and archive['schema']==attest_cloud.ARCHIVE_SCHEMA,'observation_archive_schema')
    challenge=v2.verify_issued_challenge(archive['issued_challenge'],key)
    evidence=archive['evidence']
    receipt=v2.verify_receipt(archive['receipt'],key,challenge,evidence,now=now)
    _need(receipt['boot_id']==boot and receipt['node_id']==node and receipt['verifier_id']==verifier
          and receipt['policy_sha256']==policy.sha256 and receipt['ak_spki_sha256']==policy.ak_sha256,
          'observation_approved_subject_policy')
    pcrs=v2.normalized_pcrs(evidence['pcrs'])
    v2.verify_quote(v2.decode(evidence['quote_b64'],4096,'QUOTE_ENCODING'),
        v2.decode(evidence['signature_b64'],1024,'SIGNATURE_ENCODING'),pcrs,
        v2.qualifying_data(challenge),policy)
    return receipt


def live_snapshot(journal, adapter, deployment):
    p=deployment.payload;deployment.check(int(time.time()))
    rows=journal.rows()
    _need(not any(r['boot_id']==journal.boot_id() and r['phase'] not in TERMINAL for r in rows),
          'observation_pending_writer')
    native=[op['details'] for row in rows if row['boot_id']==journal.boot_id() and row['phase']=='COMMITTED'
            for op in row['operations'] if op['kind']=='native_bootstrap']
    _need(len(native)==1 and native[0].get('loader_sha256')==p['artifacts'][p['loader_path']]
          and native[0].get('bpf_object_sha256')==p['artifacts'][p['bpf_object_path']],
          'observer_loaded_artifact_deployment_binding')
    maps=adapter.maps
    state={name:m.rows() for name,m in maps.items()}
    for m in maps.values():m.assert_pin_identity()
    _need(state['state_map'].get(bytes(4))==struct.pack('<I',3),'observer_mode_not_scoped')
    _need(state['lockdown_map'].get(bytes(4))==bytes(4),'observer_lockdown_active')
    primary=[]
    for key,value in state['active_generation_map'].items():
        scope=struct.unpack('<Q',key)[0];generation=struct.unpack('<Q',value)[0]
        _need(generation>0,'observer_quarantined_scope')
        matches=[r for r in rows if r['boot_id']==journal.boot_id() and r['phase']=='COMMITTED'
            and r['plan']['action'] in {'restore','activate','rollback'}
            and r['plan']['scope_id']==scope and r['plan']['generation']==generation
            and r['inventory'] and r['inventory'].get('rows')]
        _need(bool(matches),'observer_unjournaled_enrollment')
        row=matches[-1];plan=row['plan'];adapter.validate_observed_scope(plan)
        for name in ('measured_exec_map','verity_identity_map'):
            prefix=struct.pack('<QQ',scope,generation)
            actual={k:v for k,v in state[name].items() if k.startswith(prefix)}
            inventory={bytes.fromhex(item['key']):bytes.fromhex(item['value'])
                for item in row['inventory']['rows'] if item['map']==name
                and item['map_id']==maps[name].info['id']}
            _need(bool(inventory) and actual==inventory,'observer_cohort_inventory_mismatch')
        if all(plan[k]==p[k] for k in ('node_id','manifest_id','manifest_digest','generation')):
            _need(plan['scope_path']==p['boot_scope_path'],'observer_primary_role')
            primary.append(plan)
    _need(len(primary)==1,'observer_primary_scope_missing_or_ambiguous')
    for name in ('measured_exec_map','verity_identity_map'):
        capacity=maps[name].info['capacity']
        _need(capacity>=p['minimum_map_capacity'] and capacity-len(state[name])>=p['minimum_free_rows'],
              'observer_live_capacity_or_headroom')
    authority=verify_attachment(str(PIN_ROOT));_need(authority['verified'],'observer_kernel_authority')
    pin=json.loads(subprocess.check_output([BPFTOOL,'-j','link','show','pinned',str(PIN_ROOT/'authority_link')],timeout=10))
    _need(pin['id']==authority['link_id'] and pin['prog_id']==authority['program_id'],'observer_authority_pin')
    raw=subprocess.check_output(['/usr/bin/tpm2_pcrread','-T','device:/dev/tpmrm0',v2.PCR_SELECTION],text=True,timeout=10)
    return dict(boot_id=journal.boot_id(),primary=primary[0],authority=authority,
        pcrs={str(k):v for k,v in parse_pcrs(raw).items()},
        maps={name:dict(id=maps[name].info['id'],rows=sorted((k.hex(),v.hex()) for k,v in values.items()))
              for name,values in state.items()})


def observe(config_path):
    _need(os.geteuid()==0,'observer_requires_root')
    config,deployment,_=load_profile(config_path,now=int(time.time()));p=deployment.payload
    _need(config.get('generation_database',DATABASE)==DATABASE,'canonical_generation_database_required')
    r=config['r13']
    key=serialization.load_pem_public_key(protected_bytes(r['verifier_public_key'],8192))
    ak=serialization.load_pem_public_key(protected_bytes(r['ak_public_key'],8192))
    policy=v2.NodePolicy(ak,protected_json(r['approved_pcrs']))
    _need(v2.public_pin(key)==p['r13_verifier_spki_sha256'] and policy.ak_sha256==p['r13_ak_spki_sha256']
          and policy.sha256==p['r13_policy_sha256'],'observer_profile_r13_pin_binding')
    journal=Journal(read_only=True)
    with journal.locked():
        store=MeasuredProjectionGenerationStore(DATABASE,read_only=True);adapter=None
        try:
            adapter=BpfProjectionAdapter(store,read_only=True)
            before=live_snapshot(journal,adapter,deployment)
            # Replay the actual captured firmware bytes; observation never extends a PCR.
            import yaml
            eventlog=Path('/sys/kernel/security/tpm0/binary_bios_measurements').read_bytes()
            with tempfile.TemporaryDirectory(prefix='arda-r13-eventlog-') as tmp:
                source=Path(tmp)/'eventlog.bin';source.write_bytes(eventlog)
                document=yaml.safe_load(subprocess.check_output(['/usr/bin/tpm2_eventlog',str(source)],timeout=15))
            pcr_text='sha256:\n'+'\n'.join(f'{n}: 0x{value}' for n,value in before['pcrs'].items())
            report=assess(document,pcr_text,protected_json(STATE),before['boot_id'],p['kernel_path'],p['initrd_path'])
            _need(report['firmware_replay_matches'] and report['pcr11_record_consistent'],'observer_replay_or_binding')
            for label,name in [('kernel','kernel_path'),('initrd','initrd_path')]:
                _need(p['artifacts'][p[name]] in report['boot_artifact_recorded_sha256'][label],
                      'observer_disk_boot_artifact_correlation')
            history=OUTPUT.parent/'history';history.mkdir(mode=0o700,exist_ok=True)
            archive_path=history/(uuid.uuid4().hex+'.json')
            args=SimpleNamespace(token_file=Path(r['token_file']),node_id=p['r13_subject_node_id'],
                verifier_id='cloudflare-r13-v2',verifier_public_key=Path(r['verifier_public_key']),
                verifier_spki_sha256=p['r13_verifier_spki_sha256'],policy_sha256=policy.sha256,
                ak_handle='0x81000130',out=archive_path,check_replay=False)
            attest_cloud.capture(args)
            archive=protected_json(archive_path)
            receipt=verify_archive(archive,key,policy,boot=before['boot_id'],node=args.node_id,
                verifier=args.verifier_id,now=int(time.time()))
            after=live_snapshot(journal,adapter,deployment)
            _need(before==after and archive['evidence']['pcrs']==after['pcrs'],'observer_context_changed')
            return dict(schema='arda.r13.observation.v1',status='PASS',boot_id=before['boot_id'],
                expires_at=receipt['expires_at'],checked_at=int(time.time()),evidence_sha256=receipt['evidence_sha256'],
                archive=str(archive_path),deployment_sha256=deployment.sha256,
                hardware_quote_verified=True,firmware_replay_matches=True,
                production_authorized=False,interlock='KEEP_CLOSED',
                blockers=['INDEPENDENT_PRODUCTION_ADMISSION_NOT_INTEGRATED'])
        finally:
            if adapter is not None:adapter.close()
            store.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default='/etc/arda/production-profile.json');args=parser.parse_args()
    try:result=observe(args.config);code=0
    except Exception as exc:
        result=dict(schema='arda.r13.observation.v1',status='REFUSE',checked_at=int(time.time()),
            expires_at=0,error_type=type(exc).__name__,production_authorized=False,interlock='KEEP_CLOSED')
        code=1
    publish_json(OUTPUT,result)
    print(json.dumps(result,sort_keys=True,indent=2))
    return code


if __name__=='__main__':raise SystemExit(main())
