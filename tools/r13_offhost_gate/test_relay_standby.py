import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'providers/hf/r13-relay'))
import gateway

class StandbyTests(unittest.TestCase):
    def test_explicit_standby_skips_configuration_and_serves(self):
        fake_server=type('FakeServer',(),{'serve_forever':lambda self: None})
        with patch.dict(os.environ,{'ARDA_RELAY_STANDBY_ONLY':'1'},clear=True):
            with patch.object(gateway,'ThreadingHTTPServer',return_value=fake_server()) as server:
                with patch.object(gateway,'require_config',side_effect=AssertionError('must not read secrets')):
                    gateway.main()
        self.assertIsNone(gateway.Handler.relay)
        server.assert_called_once()
    def test_no_standby_without_configuration_refuses(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(RuntimeError,'MISSING_RELAY_CONFIGURATION'):
                gateway.require_config()
    def test_post_refuses_in_standby_without_auth_or_body(self):
        handler=object.__new__(gateway.Handler)
        handler.path='/v1/submit'
        handler.relay=None
        responses=[]
        handler.reply=lambda code,payload:responses.append((code,payload))
        handler.do_POST()
        self.assertEqual(responses[0][0],503)
        self.assertEqual(responses[0][1]['error'],'RELAY_STANDBY')
        self.assertEqual(responses[0][1]['interlock'],'KEEP_CLOSED')
