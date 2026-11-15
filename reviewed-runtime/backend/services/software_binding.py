"""One boot-scoped PCR11 binding, separate from periodic observation.

A partial extend remains a pending journal entry and requires operator recovery
or a fresh firmware boot. The service never guesses a missing extend or resets a
PCR. Existing final values are reused only with a matching same-boot receipt.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time

from .deployment_profile import load_profile
from .measured_identity import MeasuredProjectionGenerationStore
from .production_files import protected_json, publish_json
from .projection_bpf import BpfProjectionAdapter
from .projection_journal import Journal, _need
from .projection_ctl import DATABASE

STATE = Path('/var/lib/arda/attestation/state/pcr11_binding_state.json')


def components(manifest_digest, policy_generation):
    _need(re.fullmatch('sha256:[0-9a-f]{64}',manifest_digest) is not None,'binding_manifest_digest')
    return [dict(label='manifest_digest',digest=manifest_digest[7:]),
            dict(label='policy_generation',digest=hashlib.sha256(policy_generation.encode()).hexdigest())]


def chain(items):
    value=bytes(32)
    for item in items:value=hashlib.sha256(value+bytes.fromhex(item['digest'])).digest()
    return value.hex()


class Tpm:
    def read(self):
        raw=subprocess.check_output(['/usr/bin/tpm2_pcrread','-T','device:/dev/tpmrm0','sha256:11'],text=True,timeout=10)
        found=re.findall(r'^\s*11\s*:\s*0x([0-9A-Fa-f]{64})\s*$',raw,re.M)
        _need(len(found)==1,'pcr11_read_format')
        return found[0].lower()

    def extend(self,digest):
        subprocess.run(['/usr/bin/tpm2_pcrextend','-T','device:/dev/tpmrm0','11:sha256='+digest],
                       stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=10)


def bind_once(journal, plan, policy_generation, *, tpm, state_path=STATE, check_context):
    expected_components=components(plan['manifest_digest'],policy_generation)
    expected=chain(expected_components)
    identity=dict(boot_id=journal.boot_id(),manifest_id=plan['manifest_id'],
        manifest_digest=plan['manifest_digest'],policy_generation=policy_generation,
        components=expected_components,pcr_after=expected)
    with journal.locked():
        check_context()
        current=tpm.read()
        if current==expected:
            saved=protected_json(state_path,owner=os.geteuid())
            _need(all(saved.get(k)==v for k,v in identity.items()),'pcr11_unreceipted_or_wrong_boot')
            return dict(saved,binding_reused=True)
        _need(current=='00'*32,'pcr11_unexpected_nonzero_preserved')
        binding_plan=dict(plan,action='bind')
        with journal.bootstrap(binding_plan) as tx:
            tx.note('pcr11_binding_plan',identity)
            prefix=bytes(32)
            for item in expected_components:
                check_context()
                tx.note('pcr11_extend_before',item)
                tpm.extend(item['digest'])
                prefix=hashlib.sha256(prefix+bytes.fromhex(item['digest'])).digest()
                _need(tpm.read()==prefix.hex(),'pcr11_extend_readback')
            tx.prepared({'expected_pcr11':expected});tx.publish_intent()
            check_context()
            _need(tpm.read()==expected,'pcr11_final_readback')
            tx.published()
            receipt=dict(identity,transaction_id=tx.txid,updated_at=int(time.time()))
            tx.note('pcr11_receipt_before',{'path':str(state_path)})
            publish_json(state_path,receipt)
            tx.commit()
        return dict(receipt,binding_reused=False)


def run(config_path):
    _need(os.geteuid()==0,'software_binding_requires_root')
    config,deployment,_=load_profile(config_path,now=int(time.time()))
    _need(config.get('generation_database',DATABASE)==DATABASE,'canonical_generation_database_required')
    journal=Journal()
    with journal.locked():
        restore=protected_json('/run/arda/ring0-restore.json')
        row=[r for r in journal.rows() if r['txid']==restore.get('transaction_id')]
        _need(len(row)==1 and row[0]['phase']=='COMMITTED' and row[0]['boot_id']==journal.boot_id()
              and row[0]['plan']['action']=='restore','binding_requires_committed_boot_restore')
        plan=row[0]['plan'];deployment.check_plan(plan)
        store=MeasuredProjectionGenerationStore(DATABASE,read_only=True)
        adapter=None
        try:
            adapter=BpfProjectionAdapter(store,read_only=True)
            def context():
                deployment.check(int(time.time()))
                _need(journal.boot_id()==row[0]['boot_id'],'binding_boot_changed')
                adapter.validate_scope(plan)
                _need(adapter.active(plan['scope_id'])==plan['generation'],'binding_scope_not_active')
                record=store.get_record(plan['manifest_id'])
                _need(record['state']=='active' and record['payload'].get('boot_id')==journal.boot_id(),
                      'binding_active_ledger_boot')
            return bind_once(journal,plan,deployment.payload['policy_generation'],tpm=Tpm(),check_context=context)
        finally:
            if adapter is not None:adapter.close()
            store.close()


def main():
    import json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default='/etc/arda/production-profile.json')
    args=parser.parse_args()
    print(json.dumps(run(args.config),sort_keys=True,indent=2))


if __name__=='__main__':main()
