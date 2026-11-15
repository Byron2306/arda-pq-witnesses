"""Supervise the unchanged native loader through a locked, durable handoff.

Only a fresh pin namespace may be initialized. Existing pins/links are never
cleared or reset. Restoration publishes readiness after commit; this supervisor
pins the verified kernel link before downstream boot verification can succeed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import secrets
import signal
import subprocess
import time

from .arda_bpf_authority import verify_attachment, BPFTOOL
from .deployment_profile import load_profile
from .measured_identity import MeasuredProjectionGenerationStore
from .production_files import publish_json
from .projection_bpf import PIN_ROOT, PinnedMap, CONTRACTS, cgroup_kernel_id
from .projection_journal import Journal, _need


class NativeLines:
    def __init__(self, process):
        self.process, self.buffer = process, b''
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)

    def line(self, timeout, stopping=lambda: False):
        deadline = time.monotonic()+timeout
        while b'\n' not in self.buffer:
            if stopping(): raise InterruptedError('native_supervisor_stopping')
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise TimeoutError('native_loader_checkpoint_timeout')
            if not self.selector.select(min(remaining,0.2)):
                if self.process.poll() is not None: raise RuntimeError('native_loader_exited_before_checkpoint')
                continue
            chunk = os.read(self.process.stdout.fileno(),4096)
            if not chunk: raise RuntimeError('native_loader_output_closed')
            self.buffer += chunk
            if len(self.buffer)>1024*1024: raise ValueError('native_loader_output_unbounded')
        line,self.buffer=self.buffer.split(b'\n',1)
        return line.decode('utf-8',errors='replace')

    def close(self):self.selector.close()


def current_scope_path():
    rows=[line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::')]
    _need(len(rows)==1 and rows[0].startswith('/'), 'unified_boot_cgroup_required')
    return '/sys/fs/cgroup'+rows[0]


def native_map_checkpoint(minimum):
    ids={}
    for pin in CONTRACTS:
        m=PinnedMap(pin,read_only=True)
        try:
            ids[pin]=m.info['id']
            if pin in {'measured_exec_map','verity_identity_map'}:
                _need(m.info['capacity']>=minimum and not m.rows(), 'native_maps_not_fresh_or_expected_capacity')
            if pin=='active_generation_map':_need(not m.rows(),'native_selectors_not_empty')
            if pin=='state_map':_need(m.read(bytes(4))==b'\x03\0\0\0','native_mode_not_scoped')
            if pin=='lockdown_map':_need(m.read(bytes(4))==bytes(4),'native_lockdown_not_clear')
            if pin=='policy_state_map':_need(m.read(bytes(4))==bytes(16),'native_policy_not_fresh')
        finally:m.close()
    return ids


def supervise(config_path='/etc/arda/production-profile.json',ready_file=Path('/run/arda/ring0-ready')):
    _need(os.geteuid()==0,'native_supervisor_requires_root')
    config,deployment,_=load_profile(config_path,now=int(time.time()))
    p=deployment.payload
    scope_path=current_scope_path()
    _need(scope_path==p['boot_scope_path'],'native_boot_scope_not_deployment_role')
    scope_id=cgroup_kernel_id(scope_path)
    store=MeasuredProjectionGenerationStore(config.get('generation_database','/var/lib/arda/projection/arda_measured_generation.sqlite3'),read_only=True)
    try:record=store.get_record(p['manifest_id'])
    finally:store.close()
    _need(record is not None and record['state'] in {'staged','active','deactivated'}
          and record['manifest_digest']==p['manifest_digest'] and record['generation']==p['generation']
          and record['node_id']==p['node_id'],'native_boot_deployment_ledger_binding')
    plan=dict(action='restore',scope_id=scope_id,scope_path=scope_path,generation=p['generation'],
              prior_generation=None,node_id=p['node_id'],manifest_id=p['manifest_id'],manifest_digest=p['manifest_digest'])
    _need(not PIN_ROOT.exists() or not any(PIN_ROOT.iterdir()),'existing_pins_preserved_no_native_reinitialization')
    for path in (ready_file,Path(str(ready_file)+'.handoff.json'),Path(str(ready_file)+'.authority.json')):
        path.unlink(missing_ok=True)
    stopped=[False]
    def stop(signum,frame):stopped[0]=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    journal=Journal();process=None;reader=None
    try:
        secret=secrets.token_hex(32)
        with journal.bootstrap(plan,deployment=deployment) as tx:
            # Persist the immutable artifact identity before the native child can
            # create or initialize any map. Its phase remains pending at handoff.
            tx.note('native_bootstrap',{'loader_sha256':p['artifacts'][p['loader_path']],
                    'bpf_object_sha256':p['artifacts'][p['bpf_object_path']],
                    'deployment_sha256':deployment.sha256})
            process=subprocess.Popen([p['loader_path'],p['bpf_object_path'],'--pin-root',str(PIN_ROOT),
                '--enforcement-mode','scoped_strict','--defer-attach-until',str(ready_file)],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
            reader=NativeLines(process)
            deadline=time.monotonic()+40
            while True:
                line=reader.line(max(0,deadline-time.monotonic()),lambda:stopped[0]);print(line,flush=True)
                if line=='ARDA_LOADER: waiting for attachment gate '+str(ready_file):break
            ids=native_map_checkpoint(p['minimum_map_capacity'])
            tx.note('native_maps_ready',{'map_ids':ids,'pid':process.pid})
            tx.handoff(secret)
            handoff={'txid':tx.txid,'secret':secret,'plan':plan,'boot_id':tx.boot}
        publish_json(Path(str(ready_file)+'.handoff.json'),handoff,mode=0o600)
        deadline=time.monotonic()+75
        while True:
            line=reader.line(max(0,deadline-time.monotonic()),lambda:stopped[0]);print(line,flush=True)
            if line=='ARDA_LOADER: attached '+p['bpf_object_path']:break
        with journal.bootstrap(plan,deployment=deployment) as pin_tx:
            evidence=verify_attachment(str(PIN_ROOT))
            _need(evidence['verified'],'native_attachment_identity_not_verified')
            link_path=PIN_ROOT/'authority_link'
            _need(not link_path.exists(),'authority_link_pin_already_exists')
            pin_tx.note('authority_link_pin_before',{'link_id':evidence['link_id'],'path':str(link_path)})
            subprocess.run([BPFTOOL,'link','pin','id',str(evidence['link_id']),str(link_path)],
                stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=10)
            pinned=json.loads(subprocess.check_output([BPFTOOL,'-j','link','show','pinned',str(link_path)],timeout=10))
            _need(pinned['id']==evidence['link_id'] and pinned['prog_id']==evidence['program_id'],'authority_pin_readback')
            pin_tx.prepared({'authority_link_id':evidence['link_id']});pin_tx.publish_intent();pin_tx.published();pin_tx.commit()
        publish_json(Path(str(ready_file)+'.authority.json'),dict(evidence,boot_id=journal.boot_id(),transaction_id=pin_tx.txid))
        while process.poll() is None and not stopped[0]:
            try:process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:pass
        return 0 if stopped[0] else 1
    finally:
        if reader is not None:reader.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        # Never unlink authority_link or a map pin, including on failure/stop.


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default='/etc/arda/production-profile.json')
    parser.add_argument('--ready-file',type=Path,default=Path('/run/arda/ring0-ready'))
    args=parser.parse_args()
    try:return supervise(args.config,args.ready_file)
    except Exception as exc:
        print(json.dumps({'status':'REFUSE','error':str(exc),'interlock':'KEEP_CLOSED'}),flush=True)
        return 1


if __name__=='__main__':raise SystemExit(main())
