"""Crash-recovery, stale-window and no-retry tests for V6 controller."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import v6_controller as v6

DEADLINE=1800000300

class Var:
    def __init__(self,value):self.value=value

class Client:
    def __init__(self):
        self.values={'ARDA_RELAY_STANDBY_ONLY':'1'}
        self.commands=[]
    def get_space_variables(self,space):
        return {k:Var(v) for k,v in self.values.items()}
    def add_space_variable(self,space,name,value):
        self.commands.append(('set',name))
        self.values[name]=value
    def delete_space_variable(self,space,name):
        self.commands.append(('delete',name))
        self.values.pop(name,None)

STANDBY={'status':'standby','ingest_enabled':False,'synthetic_test_enabled':False,
         'phase4_authorized':False,'interlock':'KEEP_CLOSED'}
def window(deadline=DEADLINE,backend='github-v6'):
    return {**STANDBY,'status':'test_window','synthetic_test_enabled':True,
            'test_deadline':deadline,'test_backend':backend}

class ControllerTests(unittest.TestCase):
    def test_stale_window_same_status_wrong_deadline_is_rejected(self):
        self.assertFalse(v6.active_window(window(DEADLINE+1),DEADLINE))
        self.assertFalse(v6.active_window(window(DEADLINE,'legacy'),DEADLINE))
        self.assertTrue(v6.active_window(window(),DEADLINE))
    def test_arm_does_not_open_test_window(self):
        client=Client();record={'phase':'NEW'}
        with patch.object(v6,'status',return_value=STANDBY):
            self.assertEqual(v6.prepare(client,record),'V6_BACKEND_ARMED=PASS')
        self.assertNotIn('ARDA_RELAY_TEST_UNTIL',client.values)
        self.assertEqual(record['phase'],'ARMED')
    def test_open_persists_intent_before_remote_mutation(self):
        client=Client();client.values['ARDA_RELAY_TEST_BACKEND']='github-v6'
        record={'phase':'ARMED'};observed=[]
        def persist():
            observed.append((record.copy(),dict(client.values)))
        with patch.object(v6,'status',return_value=STANDBY),patch.object(v6.time,'time',return_value=1800000000):
            self.assertEqual(v6.open_window(client,record,persist),'V6_WINDOW_REQUESTED=PASS')
        self.assertEqual(observed[0][0]['phase'],'OPEN_REQUESTED')
        self.assertNotIn('ARDA_RELAY_TEST_UNTIL',observed[0][1])
        self.assertEqual(client.values['ARDA_RELAY_TEST_UNTIL'],str(DEADLINE))
    def test_not_ready_does_not_generate_challenge(self):
        client=Client();client.values.update({
            'ARDA_RELAY_TEST_BACKEND':'github-v6',
            'ARDA_RELAY_TEST_UNTIL':str(DEADLINE)})
        record={'phase':'OPEN_REQUESTED','deadline':DEADLINE}
        with patch.object(v6,'status',return_value=window(DEADLINE-1)),patch.object(v6.time,'time',return_value=1800000000):
            with self.assertRaises(v6.Refuse):
                v6.check_ready(client,record)
        self.assertEqual(record['phase'],'OPEN_REQUESTED')
    def test_submit_uncertain_writes_attempt_and_refuses_retry(self):
        client=Client();client.values.update({
            'ARDA_RELAY_TEST_BACKEND':'github-v6',
            'ARDA_RELAY_TEST_UNTIL':str(DEADLINE)})
        record={'phase':'READY','deadline':DEADLINE}
        writes=[]
        class FailureOpener:
            def open(self,*args,**kwargs):
                self.snapshot=record.copy()
                raise TimeoutError('secret network detail')
        opener=FailureOpener()
        with tempfile.TemporaryDirectory() as tmp:
            token=Path(tmp)/'token';token.write_text('a'*64)
            with patch.object(v6,'TOKEN',token),patch.object(v6,'status',return_value=window()),patch.object(v6.time,'time',return_value=1800000000),patch.object(v6.urllib.request,'build_opener',return_value=opener):
                msg=v6.submit(client,record,lambda:writes.append(record.copy()))
                self.assertEqual(msg,'V6_DISPATCH=UNCERTAIN_NO_RETRY')
                self.assertEqual(writes[0]['phase'],'SUBMISSION_ATTEMPTED')
                self.assertEqual(opener.snapshot['phase'],'SUBMISSION_ATTEMPTED')
                with self.assertRaises(v6.Refuse):
                    v6.submit(client,record,lambda:None)
        self.assertEqual(record['phase'],'DISPATCH_UNCERTAIN')
    def test_cleanup_is_idempotent_and_requires_live_standby(self):
        client=Client();client.values.update({'ARDA_RELAY_TEST_UNTIL':str(DEADLINE),
                                            'ARDA_RELAY_TEST_BACKEND':'github-v6'})
        record={'phase':'DISPATCH_UNCERTAIN'}
        self.assertEqual(v6.close_window(client,record),'CLEANUP_CONFIGURED=PASS')
        self.assertEqual(v6.close_window(client,record),'CLEANUP_CONFIGURED=PASS')
        with patch.object(v6,'status',return_value=window()):
            with self.assertRaises(v6.Refuse):
                v6.verify_close(client,record)
        with patch.object(v6,'status',return_value=STANDBY):
            self.assertEqual(v6.verify_close(client,record),'FINAL_LIVE_STANDBY=PASS')
        self.assertEqual(record['phase'],'CLOSED')
    def test_journal_atomic_permissions_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'v6.json'
            v6.write_state({'phase':'SUBMISSION_ATTEMPTED','attempted_at':15},path)
            self.assertEqual(v6.read_state(path)['phase'],'SUBMISSION_ATTEMPTED')
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
    def test_health_metadata_not_exposed_outside_live_window(self):
        import gateway
        h=object.__new__(gateway.Handler)
        h.path='/health';h.test_until=DEADLINE;h.relay=None
        output=[];h.reply=lambda code,data:output.append((code,data))
        with patch('gateway.active',return_value=True),patch.dict('gateway.os.environ',{'ARDA_RELAY_TEST_BACKEND':'github-v6'}):
            h.do_GET()
        self.assertEqual(output[0][1]['test_deadline'],DEADLINE)
        self.assertEqual(output[0][1]['test_backend'],'github-v6')
        output.clear()
        with patch('gateway.active',return_value=False):
            h.do_GET()
        self.assertNotIn('test_deadline',output[0][1])
        self.assertNotIn('test_backend',output[0][1])
if __name__=='__main__':unittest.main()
