"""Operator entry point for journaled, scoped projection transitions."""
import argparse
import json
import os
from pathlib import Path
import time

from .deployment_profile import load_profile
from .measured_identity import MeasuredIdentityVerifier, MeasuredProjectionGenerationStore
from .production_files import protected_json, publish_json
from .projection_bpf import BpfProjectionAdapter, cgroup_kernel_id
from .projection_coordinator import ProjectionCoordinator
from .projection_journal import Journal, _need, verify_permit

DATABASE = '/var/lib/arda/projection/arda_measured_generation.sqlite3'
MANIFEST_DIR = Path('/var/lib/arda/projection')


def stage_manifest(manifest, scope_path, *, database=DATABASE, attestation=None):
    _need(os.geteuid()==0, 'root_operator_required')
    scope = cgroup_kernel_id(scope_path)
    _need(manifest.get('cgroup_kernel_id')==scope, 'stage_scope_binding')
    journal = Journal()
    with journal.locked():
        store = MeasuredProjectionGenerationStore(database)
        try:
            verifier = MeasuredIdentityVerifier(store)
            checked = verifier.preflight(manifest,attestation,commit_generation=False)
            _need(checked['ok'], 'manifest_preflight:'+','.join(checked['failures']))
            plan = dict(action='stage',scope_id=scope,scope_path=str(scope_path),
                generation=checked['generation'],prior_generation=None,node_id=checked['node_id'],
                manifest_id=checked['manifest_id'],manifest_digest=checked['manifest_digest'])
            destination = MANIFEST_DIR/(plan['manifest_id']+'.json')
            _need(not destination.exists(), 'canonical_manifest_already_exists')
            with journal.bootstrap(plan) as tx:
                tx.note('canonical_manifest_stage', {'path':str(destination)})
                publish_json(destination,manifest)
                result = verifier.stage_projection(checked,manifest)
                tx.prepared({'canonical_manifest':str(destination)})
                tx.publish_intent();tx.published();tx.commit()
            return dict(result,transaction_id=tx.txid,execution_authority_granted=False)
        finally:store.close()


def make_plan(action, manifest_id, scope_path, store, adapter):
    record=store.get_record(manifest_id)
    _need(record is not None,'manifest_record_missing')
    scope=cgroup_kernel_id(scope_path)
    return dict(action=action,scope_id=scope,scope_path=str(scope_path),
        generation=record['generation'],prior_generation=adapter.active(scope),
        node_id=record['node_id'],manifest_id=record['manifest_id'],manifest_digest=record['manifest_digest'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default='/etc/arda/production-profile.json')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('provision-journal')
    sub.add_parser('status')
    stage=sub.add_parser('stage');stage.add_argument('manifest');stage.add_argument('--scope-path',required=True)
    plan=sub.add_parser('plan');plan.add_argument('action',choices=['activate','rollback','quarantine','collect'])
    plan.add_argument('manifest_id');plan.add_argument('--scope-path',required=True)
    apply=sub.add_parser('apply');apply.add_argument('permit')
    recover=sub.add_parser('recover');recover.add_argument('txid')
    args=parser.parse_args()
    _need(os.geteuid()==0,'root_operator_required')
    if args.command=='stage':
        result=stage_manifest(protected_json(args.manifest),args.scope_path)
    elif args.command=='provision-journal':
        Journal();result={'journal_provisioned':True}
    elif args.command=='status':
        result={'transactions':Journal(read_only=True).rows()}
    else:
        journal=Journal(read_only=args.command=='plan')
        with journal.locked():
            store=MeasuredProjectionGenerationStore(DATABASE,read_only=args.command=='plan')
            adapter=None
            try:
                adapter=BpfProjectionAdapter(store,read_only=args.command=='plan')
                if args.command=='plan':result=make_plan(args.action,args.manifest_id,args.scope_path,store,adapter)
                elif args.command=='recover':result=ProjectionCoordinator(journal,adapter).recover(args.txid)
                else:
                    _,_,key=load_profile(args.config,now=int(time.time()))
                    envelope=protected_json(args.permit)
                    from .projection_journal import PLAN_FIELDS
                    plan={k:envelope['payload'][k] for k in PLAN_FIELDS}
                    permit=verify_permit(envelope,key,plan,journal.boot_id(),int(time.time()))
                    result=ProjectionCoordinator(journal,adapter).apply(plan,permit)
            finally:
                if adapter is not None:adapter.close()
                store.close()
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=='__main__':main()
