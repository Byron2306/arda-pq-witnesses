#!/usr/bin/env python3
"""Renew public enrollment proofs using an existing provider-held, fingerprint-pinned key.

Overlay for the accepted v4 image. No key generation, secret-store writes or votes.
"""
import argparse
import base64
import hmac
from http.server import BaseHTTPRequestHandler
import os
from pathlib import Path
import re
import sys
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from arda_quorum.crypto import Backends
from arda_quorum.enrollment import check_ceremony, check_record, registration_payload, secret_name, REGISTRATION_DOMAIN
from arda_quorum.provider_http import BoundedServer
from arda_quorum.provider_witness import OpenSSLSigner
from arda_quorum.quorum import canonical, strict_load, sha, hex64, need, PROFILES


class Renewal:
    def __init__(self, raw, ceremony_pin, provider, expected_key_sha256, environ, *, clock=None):
        try:
            need(type(raw) is bytes and 0 < len(raw) <= 16384, 'ceremony_size')
            need(hex64(ceremony_pin) and sha(raw) == ceremony_pin, 'ceremony_pin')
            self.ceremony = strict_load(raw)
            need(canonical(self.ceremony) == raw, 'canonical_ceremony')
            self.clock = clock or time.time
            check_ceremony(self.ceremony, self.now())
            need(provider in ('github', 'hf') and hex64(expected_key_sha256), 'existing_provider_key_pin')
            need(environ.get('ARDA_ALLOW_EXISTING_KEY_RENEWAL') == ceremony_pin, 'explicit_renewal_enable')
            need(environ.get('ARDA_IMAGE_DIGEST') == self.ceremony['image_digest'], 'image_binding')
            if provider == 'github':
                need(environ.get('GITHUB_ACTIONS') == 'true' and environ.get('GITHUB_REPOSITORY') == self.ceremony['identities'][provider], 'github_identity')
            else:
                need(environ.get('SPACE_ID') == self.ceremony['identities'][provider], 'space_identity')
            name = secret_name(provider, expected_key_sha256)
            encoded = environ.get(name)
            need(type(encoded) is str and 0 < len(encoded) <= 22000, 'existing_named_secret_required')
            alias = environ.get('ARDA_' + provider.upper() + '_SIGNER_PKCS8_B64')
            need(alias is None or alias == encoded, 'conflicting_legacy_secret')
            private = base64.b64decode(encoded, validate=True)
            need(base64.b64encode(private).decode() == encoded and 0 < len(private) <= 16384, 'canonical_private_key')
            self.signer = OpenSSLSigner(PROFILES[provider][1], private)
            need(sha(self.signer.public) == expected_key_sha256, 'existing_key_substitution')
            self.provider = provider
            self.key_pin = expected_key_sha256
            self.pin = ceremony_pin
            self.state = 'WAITING'
            self.record = None
            self.lock = threading.Lock()
        except Exception:
            raise ValueError('EXISTING_KEY_RENEWAL_REFUSED') from None

    def now(self):
        value = self.clock()
        need(type(value) in (int, float) and 0 < value < float('inf'), 'trusted_clock')
        return int(value)

    def trigger(self):
        need(self.lock.acquire(blocking=False), 'renewal_busy')
        try:
            start = self.now()
            check_ceremony(self.ceremony, start)
            if self.state == 'COMPLETE':
                return strict_load(canonical(self.record))
            need(self.state == 'WAITING', 'failed_renewal_requires_review')
            self.state = 'RUNNING'
            try:
                payload = registration_payload(self.ceremony, self.provider, self.signer.public, now=start)
                signature = self.signer.sign(REGISTRATION_DOMAIN + canonical(payload))
                end = self.now()
                need(start <= end, 'clock_rollback')
                record = dict(payload=payload, signature_b64=base64.b64encode(signature).decode())
                check_record(record, self.ceremony, now=end, backends=Backends())
                # Native verification takes time too. Recheck immediately before release.
                final = self.now()
                need(end <= final, 'clock_rollback')
                check_ceremony(self.ceremony, final)
                self.record = strict_load(canonical(record))
                self.state = 'COMPLETE'
                return strict_load(canonical(self.record))
            except Exception:
                self.state = 'FAILED'
                raise ValueError('EXISTING_KEY_RENEWAL_REFUSED') from None
        finally:
            self.lock.release()


def make_server(session, token, *, host='0.0.0.0', port=7860):
    need(session.provider == 'hf', 'hf_only_server')
    need(type(token) is str and re.fullmatch('[0-9a-f]{64}', token), 'client_token')
    credential = token.encode('ascii')

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def reply(self, status, body):
            raw = canonical(dict(body, production_authorized=False, interlock='KEEP_CLOSED'))
            self.close_connection = True
            self.send_response(status)
            for key, value in [('Content-Type', 'application/json'), ('Content-Length', str(len(raw))), ('Cache-Control', 'no-store'), ('Connection', 'close'), ('X-Content-Type-Options', 'nosniff')]:
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def refuse(self, status):
            self.reply(status, {'error': 'EXISTING_KEY_RENEWAL_REFUSED'})
        def do_GET(self):
            if self.path != '/healthz':
                return self.refuse(404)
            self.reply(200, dict(mode='existing_key_renewal_only', state=session.state, ceremony_sha256=session.pin, key_sha256=session.key_pin))
        def do_POST(self):
            if self.path != '/v1/renew-hf':
                return self.refuse(404)
            tokens = self.headers.get_all('X-ARDA-Setup-Token', [])
            try:
                authorized = len(tokens) == 1 and hmac.compare_digest(tokens[0].encode('ascii'), credential)
            except (UnicodeError, TypeError):
                authorized = False
            if not authorized:
                return self.refuse(401)
            types = self.headers.get_all('Content-Type', [])
            if len(types) != 1 or types[0] != 'application/json' or self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Encoding'):
                return self.refuse(415)
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not re.fullmatch('[0-9]{1,4}', lengths[0]):
                return self.refuse(400)
            size = int(lengths[0])
            if not 0 < size <= 1024:
                return self.refuse(413)
            try:
                raw = self.rfile.read(size)
                need(len(raw) == size, 'short_body')
                request = strict_load(raw)
                need(canonical(request) == raw and request == dict(action='renew_hf_registration', ceremony_sha256=session.pin, key_sha256=session.key_pin), 'renewal_request_binding')
            except Exception:
                return self.refuse(400)
            try:
                record = session.trigger()
            except Exception:
                return self.refuse(409)
            self.reply(200, {'registration': record})
        def method_refused(self):
            self.refuse(405)
        do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = method_refused
    return BoundedServer((host, port), Handler)


def verify_hf_response(raw, ceremony, expected_key_sha256, *, now):
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'response_size')
    need(hex64(expected_key_sha256), 'expected_key_pin')
    body = strict_load(raw)
    need(type(body) is dict and body.keys() == {'registration', 'production_authorized', 'interlock'} and body['production_authorized'] is False and body['interlock'] == 'KEEP_CLOSED', 'response_authority')
    record = body['registration']
    need(type(record) is dict and type(record.get('payload')) is dict and record['payload'].get('provider') == 'hf' and record['payload'].get('key_sha256') == expected_key_sha256, 'existing_hf_key_binding')
    check_record(record, ceremony, now=now, backends=Backends())
    return canonical(record)


def hf_client(args):
    import urllib.request
    from arda_quorum.enrollment_store import NoRedirect
    source = Path(args.ceremony)
    need(source.stat().st_size <= 16384, 'ceremony_size')
    raw = source.read_bytes()
    need(hex64(args.ceremony_sha256) and sha(raw) == args.ceremony_sha256, 'ceremony_pin')
    ceremony = strict_load(raw)
    need(canonical(ceremony) == raw and ceremony['identities']['hf'] == 'Byron230686/arda-pq-policy-witness', 'ceremony_binding')
    check_ceremony(ceremony, int(time.time()))
    need(hex64(args.expected_key_sha256), 'existing_key_pin')
    token = os.environ.get('ARDA_HF_SETUP_CLIENT_TOKEN')
    need(hex64(token), 'setup_token')
    headers = {'Content-Type': 'application/json', 'X-ARDA-Setup-Token': token, 'User-Agent': 'ARDA-existing-key-renewal-v1'}
    gateway = os.environ.get('HF_TOKEN')
    if gateway:
        need(len(gateway) <= 4096 and all(33 <= ord(c) <= 126 for c in gateway), 'gateway_token')
        headers['Authorization'] = 'Bearer ' + gateway
    output = Path(args.out_dir)
    output.mkdir(mode=0o700)  # Reserve a unique output directory before the request.
    request = urllib.request.Request('https://byron230686-arda-pq-policy-witness.hf.space/v1/renew-hf',
        data=canonical(dict(action='renew_hf_registration', ceremony_sha256=args.ceremony_sha256, key_sha256=args.expected_key_sha256)), headers=headers, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=90) as response:
        raw = response.read(65537)
        need(response.status == 200 and len(raw) <= 65536, 'renewal_response')
    # Retain the public response before native verification; never retry signing automatically.
    (output / 'response.json').write_bytes(raw)
    public = verify_hf_response(raw, ceremony, args.expected_key_sha256, now=int(time.time()))
    check_ceremony(ceremony, int(time.time()))
    (output / 'hf-registration.json').write_bytes(public)
    print('PUBLIC_REGISTRATION_SHA256=' + sha(public))
    print('KEY_SHA256=' + args.expected_key_sha256)
    print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    github = commands.add_parser('github')
    github.add_argument('--ceremony', required=True)
    github.add_argument('--ceremony-sha256', required=True)
    github.add_argument('--expected-key-sha256', required=True)
    github.add_argument('--out', required=True)
    commands.add_parser('hf-server')
    client = commands.add_parser('hf-client')
    client.add_argument('--ceremony', required=True)
    client.add_argument('--ceremony-sha256', required=True)
    client.add_argument('--expected-key-sha256', required=True)
    client.add_argument('--out-dir', required=True)
    args = parser.parse_args()
    try:
        if args.mode == 'hf-client':
            return hf_client(args)
        if args.mode == 'hf-server':
            session = Renewal(os.environ['ARDA_RENEWAL_CEREMONY_JSON'].encode(), os.environ['ARDA_ALLOW_EXISTING_KEY_RENEWAL'], 'hf', os.environ['ARDA_RENEWAL_EXPECTED_KEY_SHA256'], os.environ)
            server = make_server(session, os.environ.get('ARDA_HF_SETUP_CLIENT_TOKEN'))
            print('HF_EXISTING_KEY_RENEWAL_WAITING_FOR_AUTHENTICATED_REQUEST', flush=True)
            try:
                server.serve_forever()
            finally:
                server.server_close()
            return 0
        path = Path(args.ceremony)
        need(path.stat().st_size <= 16384, 'ceremony_size')
        session = Renewal(path.read_bytes(), args.ceremony_sha256, 'github', args.expected_key_sha256, os.environ)
        # Reserve the public output before signing; never overwrite a previous proof.
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            record = session.trigger()
            raw = canonical(record)
            stream.write(raw)
        print('PUBLIC_REGISTRATION_SHA256=' + sha(raw))
        print('KEY_SHA256=' + session.key_pin)
        print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED')
        return 0
    except Exception:
        print('EXISTING_KEY_RENEWAL_REFUSED', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
