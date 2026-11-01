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
                answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,server.server_port)) for ip in (address,'127.0.0.1')]
                with m.ActiveGateway(grant(origin),ca_pem=cert.read_text()) as g,patch('socket.getaddrinfo',return_value=answers):
                    self.assertIn(b'502',request(g,raw));self.assertEqual(g.counters['attempts'],1)
            finally:server.shutdown();server.server_close();t.join(2)
