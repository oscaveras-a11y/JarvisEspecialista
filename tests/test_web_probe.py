"""HTTPS protocol tests use only disposable CI fixtures, never external websites."""
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST='jarvis-fixture.test'
ADDRESS='93.184.216.34'

def grant(origin='https://example.com',paths=None):
    return {'version':1,'origin':origin,'paths':paths or ['/'],'allow_read':True,
            'authorization':'Synthetic fixture explicitly authorized',
            'expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}

class WebProbeTests(unittest.TestCase):
    def module(self):
        try:return importlib.import_module('cyber_core.web_probe')
        except ImportError:self.fail('Real HTTPS probe missing')

    def test_manifest_and_public_address_validation(self):
        m=self.module()
        approved=m.validate_grant(grant())
        self.assertEqual(approved['origin'],'https://example.com')
        for address in ('127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1','224.0.0.1','64:ff9b::7f00:1'):
            with self.subTest(address=address),self.assertRaises(ValueError):
                m.public_address(address)
        self.assertEqual(m.public_address('93.184.216.34'),'93.184.216.34')

    def test_invalid_scope_and_expired_or_ambiguous_grants(self):
        m=self.module()
        for origin in ('http://example.com','https://user:pass@example.com','https://example.com/extra',
                       'https://example.com?q=secret','https://example.com#x','https://example.com\n',
                       'https://127.0.0.1','https://example.com:80','https://example.com:0','https://example.com.'):
            with self.subTest(origin=origin),self.assertRaises(ValueError):
                m.validate_grant(grant(origin))
        for paths in (['//other.test'],['/../private'],['/%2e%2e'],['/?token=x'],['/a']*9):
            with self.subTest(paths=paths),self.assertRaises(ValueError):
                m.validate_grant(grant(paths=paths))
        for changes in ({'allow_read':False},{'expires_at':'2000-01-01T00:00:00Z'},
                        {'expires_at':'2030-01-01T00:00:00'},{'authorization':''},{'version':True}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                m.validate_grant({**grant(),**changes})
        with self.assertRaises(ValueError):
            m.parse_grant(b'{"version":1,"version":1}')
        for options in ({'body_bytes':True},{'body_bytes':0},{'seconds':float('nan')},{'seconds':301}):
            with self.assertRaises(ValueError):m.validate_options(**options)

    @unittest.skipUnless(os.environ.get('JARVIS_HTTPS_FIXTURE')=='1','requires isolated GitHub TLS fixture route')
    def test_real_tls_cli_core_redirect_size_and_certificate_validation(self):
        self.module()
        from cyber_core.service import Core
        from cyber_core.cli import main
        from cyber_core.operations import saved_operations
        from cyber_core.errors import CoreError
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);cert=root/'fixture.pem';key=root/'fixture.key'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                            '-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN='+HOST,
                            '-addext','subjectAltName=DNS:'+HOST],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            class Handler(BaseHTTPRequestHandler):
                paths=[]
                slow_started=threading.Event()
                slow_release=threading.Event()
                def log_message(self,*args):pass
                def do_GET(self):
                    type(self).paths.append(self.path)
                    self.send_response(302 if self.path=='/redirect' else 200)
                    if self.path=='/redirect':self.send_header('Location','https://outside.invalid/private')
                    if self.path in ('/truncated','/exact-truncated'):
                        self.send_header('Content-Length','2048')
                    if self.path=='/slow':
                        type(self).slow_started.set()
                    self.send_header('Content-Security-Policy',"default-src 'self'")
                    self.send_header('Set-Cookie','private-token=do-not-persist; Secure; HttpOnly; SameSite=Lax')
                    self.end_headers()
                    if self.path=='/slow':
                        type(self).slow_release.wait(5)
                    payload=(b'x'*8192 if self.path=='/large' else b'abc' if self.path=='/truncated'
                             else b'x'*1024 if self.path=='/exact-truncated' else b'synthetic-public-page')
                    try:self.wfile.write(payload)
                    except (BrokenPipeError,ConnectionResetError):pass
            server=ThreadingHTTPServer((ADDRESS,0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                manifest=root/'grant.json'
                manifest.write_text(json.dumps(grant(f'https://{HOST}:{server.server_port}',['/','/redirect','/large','/truncated','/exact-truncated'])))
                home=root/'store';core=Core(home,timeout=15)
                case=core.investigate('https-lab','Protocol verification',folder,'owner','Synthetic only')
                core.close()
                args=['--home',str(home),'web-probe',case,str(manifest),'--ca-file',str(cert),'--body-bytes','1024','--seconds','10']
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(args),0)
                operation=json.loads(output.getvalue())
                result=operation['analysis']
                self.assertEqual(result['status'],'partial')
                self.assertEqual(len(result['responses']),5)
                first,redirect,large,truncated,exact=result['responses']
                self.assertEqual(first['status'],200)
                self.assertEqual(first['body_sha256'],hashlib.sha256(b'synthetic-public-page').hexdigest())
                self.assertTrue(first['body_complete'])
                self.assertTrue(first['security_headers']['content-security-policy'])
                self.assertEqual(redirect['status'],302)
                self.assertFalse(redirect['redirect_followed'])
                self.assertFalse(large['body_complete'])
                self.assertEqual(large['body_bytes_hashed'],1024)
                for cut in (truncated,exact):
                    self.assertFalse(cut['body_complete'])
                    self.assertEqual(cut['incomplete_reason'],'premature_eof')
                    self.assertEqual(cut['hash_scope'],'response_body_prefix')
                self.assertEqual(Handler.paths,['/','/redirect','/large'])
                self.assertNotIn('do-not-persist',json.dumps(operation))
                self.assertNotIn('synthetic-public-page',json.dumps(operation))
                core=Core(home,timeout=15)
                try:
                    self.assertTrue(core.verify_audit(case))
                    self.assertEqual(saved_operations(core,case)[-1]['kind'],'web_probe')
                    self.assertIn('web_probe',core.report(case).read_text())
                    # With no supplied fixture CA, real certificate validation must fail.
                    from cyber_core.web_probe import run_probe
                    untrusted=run_probe(core,case,str(manifest),seconds=10,body_bytes=1024)
                    self.assertEqual(untrusted['analysis']['responses'][0]['error'],'tls_validation_failed')
                    self.assertEqual(Handler.paths,['/','/redirect','/large'])
                    # A trusted CA must not bypass hostname validation.
                    manifest.write_text(json.dumps(grant(f'https://{ADDRESS}:{server.server_port}')))
                    mismatch=run_probe(core,case,str(manifest),ca_file=str(cert),seconds=10)
                    self.assertEqual(mismatch['analysis']['responses'][0]['error'],'tls_validation_failed')
                    slow_grant=json.dumps(grant(f'https://{HOST}:{server.server_port}',['/slow']))
                    manifest.write_text(slow_grant)
                    def change_manifest():
                        if Handler.slow_started.wait(5):
                            manifest.write_text('{}')
                    mutator=threading.Thread(target=change_manifest);mutator.start()
                    try:
                        with self.assertRaises(CoreError):
                            run_probe(core,case,str(manifest),ca_file=str(cert),seconds=10)
                    finally:
                        Handler.slow_release.set();mutator.join(timeout=6)
                    self.assertFalse(mutator.is_alive())
                    manifest.write_text(slow_grant)
                    core.pause(case)
                    with self.assertRaises(CoreError):run_probe(core,case,str(manifest),ca_file=str(cert))
                    core.resume(case)
                    Handler.slow_started.clear();Handler.slow_release.clear()
                    errors=[]
                    def revoke_during_read():
                        if not Handler.slow_started.wait(5):
                            errors.append('fixture did not receive request')
                            return
                        other=Core(home)
                        try:other.revoke(case)
                        except Exception:errors.append('revocation failed')
                        finally:other.close()
                    revoker=threading.Thread(target=revoke_during_read);revoker.start()
                    try:
                        with self.assertRaises(CoreError):
                            run_probe(core,case,str(manifest),ca_file=str(cert),seconds=10)
                    finally:
                        Handler.slow_release.set();revoker.join(timeout=6)
                    self.assertEqual(errors,[])
                    self.assertFalse(revoker.is_alive())
                    events=[r['event'] for r in core.db.execute('SELECT event FROM audit WHERE case_id=?',(case,))]
                    self.assertIn('web_probe_interrupted',events)
                finally:core.close()
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)

    def test_mixed_dns_answer_is_rejected_before_connect(self):
        from unittest.mock import patch
        import socket
        m=self.module()
        answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))
                 for ip in ('93.184.216.34','127.0.0.1')]
        with patch('socket.getaddrinfo',return_value=answers):
            with self.assertRaises(ValueError):m.resolve_public('example.com',443)
