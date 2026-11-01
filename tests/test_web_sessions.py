"""Synthetic credentials only. Transport uses real in-process HTTP, no external sites."""
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

FOUND = importlib.util.find_spec('cyber_core.pentest.web_sessions')
if FOUND:
    from cyber_core.pentest.web_sessions import SessionBroker, SessionError

class Handler(BaseHTTPRequestHandler):
    lost = False
    vulnerable = False
    def log_message(self, *args): pass
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        good = (b'synthetic-password' in raw)
        body = b'{}'
        self.send_response(200 if good else 401)
        if good: self.send_header('Set-Cookie', 'sid=synthetic-alice; Path=/; Secure; Max-Age=30')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        auth = self.headers.get('Authorization', '') + self.headers.get('Cookie', '')
        alice = 'synthetic-alice' in auth
        bob = 'synthetic-bob' in auth
        if self.path == '/check':
            ok = (alice or bob) and not self.lost
            status, body = (200, json.dumps({'authenticated': ok}).encode())
        else:
            status = 200
            body = json.dumps({'resource':'synthetic-owned' if alice or self.vulnerable else 'other'}).encode()
        self.send_response(status); self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)

class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
    def setUp(self):
        self.assertIsNotNone(FOUND, 'Session broker capability is missing')
        Handler.lost = Handler.vulnerable = False
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'operator-material.json'
        self.grant = {'origin':'https://synthetic.test', 'expires_at':time.time()+300, 'routes':[
            {'path':'/login','methods':['POST'],'purpose':'login'},
            {'path':'/check','methods':['GET'],'purpose':'check'},
            {'path':'/resource','methods':['GET'],'purpose':'access'},
            {'path':'/scan','methods':['GET'],'purpose':'scan'}]}
        check = {'path':'/check','status':200,'json_marker':{'field':'authenticated','value':True}}
        self.material = {'version':1,'profiles':{
            'anonymous':{'kind':'anonymous'},
            'alice':{'kind':'bearer','token':'synthetic-alice','check':check},
            'bob':{'kind':'bearer','token':'synthetic-bob','check':check},
            'cookie':{'kind':'cookie','cookies':[{'name':'sid','value':'synthetic-alice','path':'/','secure':True,'expires':time.time()+60}], 'check':check},
            'form':{'kind':'form','login':{'path':'/login','fields':{'password':'synthetic-password'}},'check':check},
            'json':{'kind':'json','login':{'path':'/login','fields':{'password':'synthetic-password'}},'check':check}}}
    def transport(self, method, path, headers, body):
        # The production host gateway is responsible for TLS/pinning/scope and shared budgets.
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=2)
        try:
            conn.request(method, path, body=body, headers=headers)
            response=conn.getresponse()
            return {'status':response.status,'headers':response.getheaders(),'body':response.read(1048577)}
        finally: conn.close()
    def broker(self, transport=None):
        self.path.write_text(json.dumps(self.material), encoding='utf-8')
        return SessionBroker(self.grant, self.path, transport=transport or self.transport)
    def test_profiles_login_and_isolation(self):
        broker=self.broker()
        for name in ('alice','bob','cookie','form','json'):
            profile=broker.isolated_profile(name)
            self.assertTrue(profile.login())
            headers=profile.get_headers('/scan')
            self.assertTrue(set(headers) <= {'Authorization','Cookie'})
            self.assertTrue(headers)
        self.assertEqual(broker.isolated_profile('anonymous').get_headers('/scan'),{})
        self.assertNotEqual(broker.isolated_profile('alice').login(), None)
    def test_session_loss_blocks_credentials(self):
        profile=self.broker().isolated_profile('alice'); self.assertTrue(profile.login())
        Handler.lost=True
        with self.assertRaises(SessionError): profile.get_headers('/scan')
        self.assertFalse(profile.authenticated)
    def test_mutation_and_scope_fail_closed(self):
        broker=self.broker(); profile=broker.isolated_profile('alice'); profile.login()
        with self.assertRaises(SessionError): profile.get_headers('https://evil.test/scan')
        self.path.write_text('synthetic-secret-mutation')
        with self.assertRaises(SessionError): profile.get_headers('/scan')
    def test_secrets_absent_in_errors_and_representations(self):
        def broken(*args): raise RuntimeError('synthetic-password synthetic-alice')
        profile=self.broker(broken).isolated_profile('form')
        try: profile.login()
        except SessionError as exc:
            self.assertNotIn('synthetic-',str(exc)); self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__, 'Raw transport exceptions must be detached')
        else: self.fail('Failed transport must block')
        self.assertNotIn('synthetic-',repr(profile))
    def test_cookie_path_expiry_and_domain(self):
        self.material['profiles']['cookie']['cookies'][0]['path']='/resource'
        profile=self.broker().isolated_profile('cookie')
        self.assertEqual(profile._headers('/scan'),{})
        self.assertIn('Cookie',profile._headers('/resource'))
        self.material['profiles']['cookie']['cookies'][0]['domain']='evil.test'
        with self.assertRaises(SessionError): self.broker()
    def test_expired_and_unsupported_and_large_material(self):
        self.grant['expires_at']=time.time()-1
        with self.assertRaises(SessionError): self.broker()
        self.grant['expires_at']=time.time()+30
        self.material['profiles']['alice']['kind']='oauth'
        with self.assertRaises(SessionError): self.broker()
        self.path.write_bytes(b'x'*16385)
        with self.assertRaises(SessionError): SessionBroker(self.grant,self.path,transport=self.transport)
    def test_access_positive_control_and_http200_are_distinct(self):
        broker=self.broker()
        case={'path':'/resource','allowed':['alice'],'profiles':['alice','bob','anonymous'],
              'status':200,'json_marker':{'field':'resource','value':'synthetic-owned'}}
        rows=broker.assess_access(case)
        self.assertEqual([r['level'] for r in rows],['observation','alert','alert'])
        Handler.vulnerable=True
        rows=broker.assess_access(case)
        self.assertEqual([r['level'] for r in rows],['observation','confirmed_failure','confirmed_failure'])
        case['json_marker']['value']='missing'
        self.assertTrue(all(r['level']=='alert' for r in broker.assess_access(case)))
        self.assertNotIn('synthetic-',json.dumps(rows))
    def test_missing_checker_expiry_isolation_and_immutable_grant(self):
        config=self.material['profiles']['alice']
        checker=config.pop('check')
        with self.assertRaises(SessionError): self.broker()
        config['check']=checker
        broker=self.broker()
        self.grant['routes'].append({'path':'/outside','methods':['GET'],'purpose':'scan'})
        with self.assertRaises(SessionError): broker.isolated_profile('alice').get_headers('/outside')
        one=broker.isolated_profile('form'); two=broker.isolated_profile('form')
        one.login()
        self.assertNotEqual(one._headers('/scan'),two._headers('/scan'))
        self.material['profiles']['cookie']['cookies'][0]['expires']=time.time()-1
        with self.assertRaises(SessionError): self.broker().isolated_profile('cookie').login()
    def test_duplicate_json_and_no_secret_persistence(self):
        broker=self.broker()
        self.assertTrue(broker.isolated_profile('alice').login())
        self.assertEqual(list(Path(self.temp.name).iterdir()),[self.path])
        self.path.write_text('{"version":1,"version":1,"profiles":{}}')
        with self.assertRaises(SessionError): SessionBroker(self.grant,self.path,transport=self.transport)
    def test_bounded_response_and_redirect(self):
        for response in ({'status':302,'headers':[('Location','https://evil.test')],'body':b''},
                         {'status':200,'headers':[],'body':b'x'*1048577}):
            profile=self.broker(lambda *args:response).isolated_profile('alice')
            with self.assertRaises(SessionError): profile.login()

if __name__ == '__main__': unittest.main()
