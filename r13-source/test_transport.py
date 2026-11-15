import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from attest_cloud import ENDPOINT, post, token_from


class TransportTests(unittest.TestCase):
    def test_https_authenticated_canonical_and_no_proxy_or_redirect(self):
        opener = unittest.mock.Mock()
        reply = io.BytesIO(b'{"ok":true}')
        reply.headers = unittest.mock.Mock()
        reply.headers.get_content_type.return_value = "application/json"
        opener.open.return_value = reply
        with patch("attest_cloud.urllib.request.build_opener", return_value=opener) as build:
            self.assertEqual(post("a"*64, "/verify/phase4/v2/challenge", {"node_id":"n","boot_id":"b"}), {"ok": True})
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, ENDPOINT+"/verify/phase4/v2/challenge")
            self.assertEqual(request.get_header("Authorization"), "Bearer " + "a"*64)
            self.assertEqual(request.get_header("User-agent"), "ARDA-R13-Attest/2.0")
            self.assertEqual(request.data, b'{"boot_id":"b","node_id":"n"}')
            proxy, redirect = build.call_args.args
            self.assertEqual(proxy.proxies, {})
            self.assertIsNone(redirect.redirect_request(None, None, 307, None, {}, "https://example.com"))

    def test_replay_http_refusal_is_preserved(self):
        err = urllib.error.HTTPError(ENDPOINT,409,"Conflict",{},io.BytesIO(b'{"detail":"CHALLENGE_UNAVAILABLE"}'))
        with patch("attest_cloud.urllib.request.build_opener") as build:
            build.return_value.open.side_effect = err
            with self.assertRaisesRegex(ValueError,"HTTP_409_CHALLENGE_UNAVAILABLE"):
                post("a"*64,"/verify/phase4/v2",{})

    def test_token_file_private_and_not_symlinked(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "token"
            p.write_text("a"*64+"\n")
            p.chmod(0o644)
            with self.assertRaisesRegex(ValueError,"TOKEN_FILE_PERMISSIONS"):
                token_from(p)
            p.chmod(0o600)
            self.assertEqual(token_from(p), "a"*64)
            link = p.with_name("link")
            link.symlink_to(p)
            with self.assertRaises(OSError):
                token_from(link)

if __name__ == "__main__":
    unittest.main()
