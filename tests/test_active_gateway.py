"""Only disposable synthetic fixtures are contacted."""
import copy
import importlib
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

def grant(origin='https://example.com'):
    return dict(version=1,origin=origin,allow_active=True,authorization='Synthetic only',
                expires_at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
                classes=['reflected_xss','sql_injection'],
                routes=[dict(path='/scan',methods=['GET','POST'],query_params=['q'],body_params=['input'])])

def module(): return importlib.import_module('cyber_core.pentest.active_gateway')

def request(g,raw):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5);sock.connect(g.socket_path);sock.sendall(raw)
        sock.shutdown(socket.SHUT_WR)
        chunks=[]
        while True:
            chunk=sock.recv(65536)
            if not chunk:break
            chunks.append(chunk)
            joined=b''.join(chunks)
            if b'\r\n\r\n' in joined:
                head,payload=joined.split(b'\r\n\r\n',1)
                lengths=[line.split(b':',1)[1] for line in head.split(b'\r\n') if line.lower().startswith(b'content-length:')]
                if lengths and len(payload)>=int(lengths[0]):break
        return b''.join(chunks)

class ActiveGrantTests(unittest.TestCase):
    def test_explicit_normalized_grant_and_unique_json(self):
        m=module();g=m.validate_active_grant(grant())
        self.assertEqual(g['routes'][0]['purpose'],'scan')
        for changes in ({'version':True},{'allow_active':False},{'classes':['other']},
                        {'origin':'https://127.0.0.1'},{'expires_at':'2000-01-01T00:00:00Z'},
                        {'extra':1}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                m.validate_active_grant({**grant(),**changes})
        for raw in (b'{"version":1,"version":1}',b'x'*16385):
            with self.assertRaises(ValueError):m.parse_active_grant(raw)
        g['routes'][0]['methods'].append('DELETE')
        self.assertEqual(grant()['routes'][0]['methods'],['GET','POST'])

    def test_route_policy_has_no_ambiguous_or_wildcard_keys(self):
        m=module()
        for path in ('//evil','/%2e%2e','/a/../b','/a?x','/a\\b','/*'):
            g=grant();g['routes'][0]['path']=path
            with self.subTest(path=path),self.assertRaises(ValueError):m.validate_active_grant(g)
        for field,value in (('methods',['CONNECT']),('methods',['get']),('query_params',['q','q']),
                            ('query_params',['*']),('purpose','unknown')):
            g=grant();g['routes'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):m.validate_active_grant(g)

    @unittest.skipUnless(hasattr(socket,'AF_UNIX') and os.name!='nt','Unix gateway')
    def test_rejects_framing_scope_and_secret_escape_before_upstream(self):
        m=module()
        bad=[b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n',
             b'GET https://example.com/scan HTTP/1.1\r\nHost: example.com\r\n\r\n',
             b'GET /%73can?q=x HTTP/1.1\r\nHost: example.com\r\n\r\n',
             b'GET /scan?q=x&q=y HTTP/1.1\r\nHost: example.com\r\n\r\n',
             b'GET /scan?unknown=SECRET-MARKER HTTP/1.1\r\nHost: example.com\r\n\r\n',
             b'GET /scan HTTP/1.1\r\nHost: evil.test\r\n\r\n',
             b'GET /scan HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n',
             b'POST /scan HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx',
             b'POST /scan HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx',
             b'POST /scan HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{"unknown":"x"}']
        with m.ActiveGateway(grant()) as g,patch.object(m,'resolve_public',side_effect=AssertionError('must not resolve')):
            for raw in bad:
                self.assertIn(request(g,raw).split(b' ')[1],(b'400',b'403',b'413'))
            self.assertEqual(g.counters['attempts'],0)
            self.assertNotIn('SECRET-MARKER',json.dumps(g.snapshot()))

    @unittest.skipUnless(hasattr(socket,'AF_UNIX') and os.name!='nt','Unix gateway')
    def test_scanner_cannot_send_session_only_routes(self):
        m=module();g=grant();g['routes'][0]['purpose']='login'
        with m.ActiveGateway(g) as gateway:
            self.assertIn(b'403',request(gateway,b'GET /scan HTTP/1.1\r\nHost: example.com\r\n\r\n'))
            self.assertEqual(gateway.counters['attempts'],0)

    @unittest.skipUnless(hasattr(socket,'AF_UNIX') and os.name!='nt','Unix gateway')
    def test_hanging_dns_obeys_control_and_cleanup(self):
        m=module();release=threading.Event();started=threading.Event();stop=threading.Event()
        def lookup(*args):
            started.set();release.wait(5);return ['93.184.216.34']
        try:
            with m.ActiveGateway(grant(),control=stop.is_set) as g,patch.object(m,'resolve_public',side_effect=lookup):
                result=[]
                worker=threading.Thread(target=lambda:result.append(request(g,b'GET /scan HTTP/1.1\r\nHost: example.com\r\n\r\n')))
                worker.start();self.assertTrue(started.wait(2));stop.set();worker.join(2)
                self.assertFalse(worker.is_alive(),'DNS must not defeat control')
                self.assertIn(b'403',result[0])
        finally:release.set()

    @unittest.skipUnless(os.environ.get('JARVIS_HTTPS_FIXTURE')=='1','isolated GitHub TLS route')
    def test_real_tls_secrets_redirect_budget_stop_and_dns(self):
        m=module();host='jarvis-fixture.test';address='93.184.216.34'
        with tempfile.TemporaryDirectory() as folder:
            cert=Path(folder)/'cert.pem';key=Path(folder)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),
                            '-out',str(cert),'-days','1','-subj','/CN='+host,
                            '-addext','subjectAltName=DNS:'+host],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            class Handler(BaseHTTPRequestHandler):
                seen=[]
                def log_message(self,*args):pass
                def do_GET(self):
                    type(self).seen.append((self.path,self.headers.get('Authorization')))
                    if self.path.startswith('/scan?q=framing'):
                        self.send_response(200);self.send_header('Content-Length','13,13');self.end_headers();self.wfile.write(b'SECRET-MARKER');return
                    if self.path.startswith('/scan?q=headers'):
                        self.send_response(200);self.send_header('X-One','x'*40000);self.send_header('X-Two','x'*40000);self.end_headers();return
                    if self.path.startswith('/scan?q=large'):
                        self.send_response(200);self.send_header('Content-Length','8192');self.end_headers();self.wfile.write(b'x'*8192);return
                    self.send_response(302);self.send_header('Location','https://127.0.0.1/private')
                    self.send_header('Set-Cookie','session=SECRET-MARKER')
                    self.send_header('Content-Length','13');self.end_headers();self.wfile.write(b'SECRET-MARKER')
            server=ThreadingHTTPServer((address,0),Handler)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
            server.socket=ctx.wrap_socket(server.socket,server_side=True)
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
            origin=f'https://{host}:{server.server_port}'
            raw=f'GET /scan?q=SECRET-MARKER HTTP/1.1\r\nHost: {host}:{server.server_port}\r\nAuthorization: hostile\r\n\r\n'.encode()
            try:
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text(),request_headers=lambda method,path:{'Authorization':'Bearer SECRET-MARKER'},max_requests=1) as g:
                    self.assertIn(b'302',request(g,raw));self.assertIn(b'429',request(g,raw))
                    self.assertEqual(g.counters['attempts'],1)
                    self.assertEqual(Handler.seen,[('/scan?q=SECRET-MARKER','Bearer SECRET-MARKER')])
                    self.assertNotIn('SECRET-MARKER',json.dumps(g.snapshot()))
                    self.assertTrue(g.observations[0]['tls']['certificate_sha256'])
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text(),control=lambda:True) as g:
                    self.assertIn(b'403',request(g,raw));self.assertEqual(g.counters['attempts'],0)
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text(),body_bytes=8) as g:
                    self.assertIn(b'502',request(g,raw))
                    self.assertEqual(g.observations[0]['error'],'response_body_limit')
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text()) as g:
                    result=g.perform('GET','/scan?q=private',headers={'Authorization':'Bearer private'})
                    self.assertEqual(result['status'],302)
                    self.assertEqual(result['body'],b'SECRET-MARKER')
                    self.assertNotIn('SECRET-MARKER',json.dumps(g.snapshot()))
                with m.ActiveGateway(grant(origin)) as g:
                    self.assertIn(b'502',request(g,raw))
                    self.assertEqual(g.counters['completed'],0)
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text()) as g:
                    real_resolve=m.resolve_public;calls=[]
                    def delayed_resolve(*args):
                        calls.append(time.monotonic())
                        if len(calls)==1:time.sleep(.65)
                        return real_resolve(*args)
                    with patch.object(m,'resolve_public',side_effect=delayed_resolve):
                        g.perform('GET','/scan')
                        began=time.monotonic();g.perform('GET','/scan')
                        self.assertGreaterEqual(time.monotonic()-began,.45,'interval measured from upstream send')
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text()) as g:
                    huge=raw.replace(b'q=SECRET-MARKER',b'q=headers')
                    self.assertIn(b'502',request(g,huge))
                    self.assertLessEqual(g.observations[0]['wire_bytes'],65537,'oversize headers must be bounded while reading')
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text()) as g:
                    self.assertIn(b'502',request(g,raw.replace(b'q=SECRET-MARKER',b'q=framing')))
                    self.assertEqual(g.observations[0]['error'],'response_framing')
                answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,server.server_port)) for ip in (address,'127.0.0.1')]
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text()) as g,patch('socket.getaddrinfo',return_value=answers):
                    self.assertIn(b'502',request(g,raw));self.assertEqual(g.counters['attempts'],1)
            finally:server.shutdown();server.server_close();t.join(2)
