"""Scoped publication and conservative recovery over a durable journal.

The adapter is the actual kernel/ledger boundary in production. Tests substitute
that boundary only; the journal, signatures, locks and process crashes are real.
"""
from .projection_journal import _need


class ProjectionCoordinator:
    def __init__(self, journal, adapter):
        self.journal, self.adapter = journal, adapter

    def _inventory(self, plan, *, collection=False):
        matches = [r for r in self.journal.rows()
            if r['phase'] in ({'COMMITTED','QUARANTINED'} if collection else {'COMMITTED'}) and r['boot_id'] == self.journal.boot_id()
            and r['plan']['action'] in {'activate', 'rollback', 'restore'}
            and all(r['plan'][k] == plan[k] for k in
                    ('scope_id', 'scope_path', 'generation', 'manifest_id', 'manifest_digest', 'node_id'))
            and r['inventory'] is not None]
        _need(bool(matches), 'committed_owned_inventory_required')
        return matches[-1]['inventory']

    def apply(self, plan, permit):
        adapter = self.adapter
        try:
            with self.journal.transaction(plan, permit) as tx:
                adapter.validate_scope(plan)
                prior = adapter.active(plan['scope_id'])
                _need(prior == plan['prior_generation'], 'active_selector_precondition')
                action = plan['action']
                if action in {'activate', 'rollback'}:
                    if action == 'activate':
                        highwater = max([r['plan']['generation'] for r in self.journal.rows()
                            if r['txid'] != tx.txid and r['plan']['scope_id'] == plan['scope_id']
                            and r['plan']['action'] in {'activate','rollback','restore'}] + [prior or 0])
                        _need(plan['generation'] > highwater, 'nonmonotonic_projection_generation')
                    else:
                        retained_highwater = max([r['plan']['generation'] for r in self.journal.rows()
                            if r['txid'] != tx.txid and r['boot_id'] == self.journal.boot_id()
                            and r['plan']['scope_id'] == plan['scope_id']
                            and r['plan']['action'] in {'activate','rollback','restore'}
                            and r['phase'] == 'COMMITTED'] + [prior or 0])
                        _need(prior is not None and 0 < plan['generation'] <= retained_highwater
                              and (prior == 0 or plan['generation'] < prior), 'rollback_target_generation')
                        self._inventory(plan)
                    inventory = adapter.prepare(plan)
                    adapter.verify_prepared(plan, inventory)
                    tx.prepared(inventory)
                    adapter.validate_scope(plan)
                    _need(adapter.active(plan['scope_id']) == prior, 'selector_changed_during_preparation')
                    tx.publish_intent()
                    adapter.publish(plan['scope_id'], plan['generation'])
                    _need(adapter.active(plan['scope_id']) == plan['generation'], 'selector_publish_readback')
                    tx.published()
                    adapter.finalize(plan)
                    adapter.verify_final(plan)
                    tx.commit()
                elif action == 'quarantine':
                    _need(prior == plan['generation'], 'quarantine_target_not_active')
                    tx.prepared({'scope_id': plan['scope_id'], 'quarantine': True})
                    tx.publish_intent()
                    adapter.publish(plan['scope_id'], 0)
                    _need(adapter.active(plan['scope_id']) == 0, 'quarantine_readback')
                    tx.published()
                    adapter.deactivate(plan)
                    adapter.verify_deactivated(plan)
                    tx.commit()
                elif action == 'collect':
                    _need(prior != plan['generation'], 'cannot_collect_active_generation')
                    inventory = self._inventory(plan,collection=True)
                    tx.prepared(inventory)
                    tx.publish_intent()
                    adapter.collect(plan, inventory)
                    _need(adapter.active(plan['scope_id']) == prior, 'selector_changed_during_collection')
                    adapter.verify_collected(plan, inventory)
                    tx.published()
                    adapter.finish_collection(plan)
                    tx.commit()
                return {'txid': tx.txid, 'phase': tx.phase,
                        'scope_id': plan['scope_id'], 'generation': plan['generation'],
                        'enforcement_mode': 'scoped_strict'}
        finally:
            release = getattr(adapter, 'release_prepared', None)
            if release is not None:
                release()

    def recover(self, txid):
        adapter = self.adapter
        with self.journal.recovery(txid) as (tx, row):
            plan = row['plan']
            _need(plan['action'] in {'activate','rollback','quarantine','collect','restore'},
                  'dedicated_non_projection_recovery_required')
            adapter.validate_recovery_scope(plan, row)
            current = adapter.active(plan['scope_id'])
            phase = row.get('last_phase') or row['phase']
            if plan['action'] == 'collect':
                _need(current != plan['generation'], 'collection_generation_became_active')
                # A partial collection may leak inactive rows, never execution
                # authority. Keep the durable inventory for a fresh permitted retry.
                tx.close_recovery('RECOVERED')
            elif (phase in {'INTENT','PREPARED','PUBLISH_INTENT'}
                  and current == plan['prior_generation']):
                # Publication is not observed. Remove only newly created inactive
                # rows proven by the operation log; do not change the old selector.
                adapter.abort_prepared(plan, row)
                _need(adapter.active(plan['scope_id']) == current, 'abort_selector_changed')
                tx.close_recovery('ABORTED')
            else:
                # Generation zero is the kernel's explicit deny marker. Removing
                # a selector would unenroll the scope and is never a recovery action.
                adapter.publish(plan['scope_id'], 0)
                _need(adapter.active(plan['scope_id']) == 0, 'recovery_quarantine_failed')
                adapter.reconcile_quarantine(plan)
                tx.close_recovery('QUARANTINED')
            return {'txid': txid, 'phase': tx.phase, 'scope_id': plan['scope_id'],
                    'active_generation': adapter.active(plan['scope_id'])}
