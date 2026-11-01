"""Active scanner contracts; real execution only on disposable GitHub Linux TLS."""
import importlib
import json
import os
from pathlib import Path
import ssl
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import parse_qs,urlsplit
from unittest.mock import patch

def grant(port=4443,kind='reflected_xss',path='/reflect'):
    return {'version':1,'origin':f'https://jarvis-fixture.test:{port}',
        'routes':[{'path':path,'methods':['GET'],'query_params':['q'],'body_params':[],'purpose':'scan'}],
        'classes':[kind],'allow_active':True,'authorization':'Disposable fixture only',
        'expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}

class WebActiveTests(unittest.TestCase):
    def module(self):
        try:return importlib.import_module('cyber_core.pentest.active')
        except ImportError:self.fail('Scoped active adapter missing')

    def test_driver_plan_uses_only_declared_routes_and_rule_classes(self):
        m=self.module();g=grant()
        p=m.driver_plan(g)
        self.assertEqual(p['rule_ids'],['40012'])
        self.assertEqual(p['seeds'],[{'path':'/reflect','method':'GET','query_params':['q'],'body_params':[]}])
        g['routes'].append({'path':'/login','methods':['POST'],'query_params':[],'body_params':['password'],'purpose':'login'})
        self.assertEqual(len(m.driver_plan(g)['seeds']),1)
        g['classes']=['sql_injection']
        self.assertEqual(m.driver_plan(g)['rule_ids'],['40018'])

    def test_projection_never_exports_payloads_and_rejects_extra_scope(self):
        m=self.module();g=grant()
        alert={'pluginId':'40012','risk':'High','confidence':'Medium','method':'GET',
               'url':'http://127.0.0.1:8081/reflect?q=PRIVATE_PAYLOAD','param':'q',
               'evidence':'PRIVATE_BODY','attack':'PRIVATE_PAYLOAD'}
        result=m.project_alerts([alert,{**alert,'url':'https://outside.invalid/reflect?q=x'},
            {**alert,'url':'http://127.0.0.1:8081/reflect?outside=x'},
            {**alert,'pluginId':'40019'},{**alert,'method':'DELETE'}],g)
        self.assertEqual(len(result['findings']),1)
        self.assertEqual(result['rejected'],4)
        self.assertEqual(result['findings'][0]['path'],'/reflect')
        self.assertEqual(result['findings'][0]['classification'],'suspected')
        self.assertEqual(len(result['findings'][0]['parameter_sha256']),64)
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertNotIn('PAYLOAD',json.dumps(result))

    def test_active_container_has_no_network_or_docker_socket(self):
        m=self.module()
        cmd=m.active_command('/usr/bin/docker','jarvis-active-'+'a'*32,
            Path(tempfile.gettempdir())/'gateway.sock',Path(tempfile.gettempdir())/'input',120)
        for flag in ('--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
                     '--memory=1g','--pids-limit=128','--cpus=1','--pull=never'):
            self.assertIn(flag,cmd)
        self.assertTrue(any('@sha256:' in s for s in cmd))
        self.assertFalse(any('docker.sock' in s for s in cmd if s.startswith('type=bind')))
        self.assertTrue(any('gateway.sock' in s for s in cmd if s.startswith('type=bind')))

    def test_campaign_requires_active_grant_and_does_not_retry_unknown_effects(self):
        self.module()
        from cyber_core.pentest import campaigns
        with self.assertRaises(ValueError):
            campaigns.validate_plan({'version':1,'stages':['dast_active']})
        p=campaigns.validate_plan({'version':1,'stages':['dast_active'],'active_grant':'active.json'})
        self.assertEqual(p['active_grant'],'active.json')
        from cyber_core.service import Core
        from cyber_core.errors import CoreError
        with tempfile.TemporaryDirectory() as f:
            root=Path(f);(root/'active.json').write_text(json.dumps(grant()))
            (root/'campaign.json').write_text(json.dumps(p))
            core=Core(root/'store',timeout=10)
            try:
                case=core.investigate('active','Unknown effects',root,'owner','Synthetic only')
                c=campaigns.create(core,case,root/'campaign.json')
                with patch('cyber_core.pentest.active.run_active',side_effect=CoreError('synthetic interruption')):
                    with self.assertRaises(CoreError):campaigns.work(core,case,c['campaign_id'])
                snapshot=campaigns.show(core,case,c['campaign_id'])
                self.assertEqual(snapshot['stages'][0]['state'],'blocked')
                before=snapshot['stages'][0]['attempts']
                after=campaigns.work(core,case,c['campaign_id'])
                self.assertEqual(after['stages'][0]['attempts'],before)
                self.assertEqual(after['stages'][0]['state'],'blocked')
            finally:core.close()

    def test_seed_readiness_waits_for_exact_history_method_using_reads_only(self):
        from cyber_core.pentest.active_readiness import wait_seed
        tick=[0.0];reads=[]
        def clock():return tick[0]
        def pause(seconds):tick[0]+=seconds
        def api(component,kind,action,**params):
            self.assertEqual((component,kind,action),('core','view','childNodes'))
            reads.append(params['url'])
            if not params['url']:
                return {'childNodes':[{'uri':'http://127.0.0.1:8081','method':'GET','hrefId':'1','isLeaf':False}]}
            node={'uri':'http://127.0.0.1:8081/submit','method':'GET','hrefId':'1','isLeaf':True}
            if tick[0]>=0.2:node.update(method='POST',hrefId='7')
            return {'childNodes':[node]}
        wait_seed(api,'http://127.0.0.1:8081/submit','POST','7',1,clock=clock,pause=pause)
        self.assertGreaterEqual(tick[0],0.2)
        self.assertGreater(len(reads),2)
        with self.assertRaises(TimeoutError):
            wait_seed(api,'http://127.0.0.1:8081/missing','GET','8',tick[0]+0.1,clock=clock,pause=pause)

    def test_cli_dispatch_reaches_each_new_adapter(self):
        import io
        from contextlib import redirect_stdout
        from cyber_core.cli import main
        commands=[
            ('web-active',['CASE','grant.json'],'cyber_core.pentest.active.run_active'),
            ('web-session-check',['CASE','grant.json','--session-material','private.json','--profile','alice'],'cyber_core.pentest.active.run_session_check'),
            ('web-access',['CASE','grant.json','matrix.json','--session-material','private.json'],'cyber_core.pentest.active.run_access'),
            ('crypto-inspect',['CASE','specimen.bin'],'cyber_core.reverse_engineering.crypto_inspect.run_crypto_inspect'),
            ('web-passive',['CASE','grant.json'],'cyber_core.pentest.passive.run_passive')]
        with tempfile.TemporaryDirectory() as folder:
            for command,args,adapter in commands:
                with self.subTest(command=command),patch(adapter,return_value={'adapter':command}) as called:
                    with redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(main(['--home',folder,command,*args]),0)
                    self.assertEqual(json.loads(output.getvalue()),{'adapter':command})
                    called.assert_called_once()

    def test_expired_active_lease_blocks_unknown_effects(self):
        from cyber_core.pentest import campaigns
        from cyber_core.service import Core
        with tempfile.TemporaryDirectory() as f:
            root=Path(f);(root/'active.json').write_text(json.dumps(grant()))
            (root/'campaign.json').write_text(json.dumps({'version':1,'stages':['dast_active'],'active_grant':'active.json'}))
            core=Core(root/'store',timeout=10)
            try:
                case=core.investigate('active','Crashed worker',root,'owner','Synthetic')
                c=campaigns.create(core,case,root/'campaign.json')
                options={'seconds':10,'body_bytes':65536,'max_requests':128,'profile':'anonymous'}
                campaigns._update(core,case,c,0,{'state':'running','lease_until':0,'attempts':1,
                    'token':'b'*32,'receipt':'a'*32,'options':options},'stage_started')
                with patch('cyber_core.pentest.active.run_active',side_effect=AssertionError('must not repeat unknown effects')):
                    result=campaigns.work(core,case,c['campaign_id'])
                self.assertEqual(result['stages'][0]['state'],'blocked')
                self.assertEqual(result['stages'][0]['attempts'],1)
                resumed=campaigns.resume_active(core,case,c['campaign_id'],reason='Reviewed synthetic effects')
                self.assertEqual(resumed['stages'][0]['state'],'planned')
                self.assertEqual(resumed['stages'][0]['attempts'],1)
            finally:core.close()

    @unittest.skipUnless(os.environ.get('JARVIS_ACTIVE_REAL')=='1','real ZAP and scoped Unix/TLS fixture on GitHub Linux')
    def test_real_zap_active_findings_retest_sessions_access_and_controls(self):
        m=self.module()
        from cyber_core.service import Core
        from cyber_core.errors import CoreError
        from cyber_core.operations import saved_operations
        with tempfile.TemporaryDirectory() as f:
            root=Path(f);cert=root/'ca.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),
                '-out',str(cert),'-days','1','-subj','/CN=jarvis-fixture.test',
                '-addext','subjectAltName=DNS:jarvis-fixture.test'],check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            class Handler(BaseHTTPRequestHandler):
                seen=[];fixed=False
                def log_message(self,*args):pass
                def response(self,status,payload,*,cookie=False,media='text/html'):
                    self.send_response(status);self.send_header('Content-Type',media)
                    self.send_header('Content-Length',str(len(payload)))
                    if cookie:self.send_header('Set-Cookie','sid=PRIVATE_COOKIE; Secure; HttpOnly; SameSite=Lax; Path=/')
                    self.end_headers()
                    try:self.wfile.write(payload)
                    except OSError:pass
                def do_POST(self):
                    path=urlsplit(self.path).path
                    length=int(self.headers.get('Content-Length','0'));body=self.rfile.read(length)
                    type(self).seen.append((path,'POST'))
                    allowed=path=='/login' and parse_qs(body.decode()).get('password')==['PRIVATE_PASSWORD']
                    self.response(200 if allowed else 403,b'{}',cookie=allowed,media='application/json')
                def do_GET(self):
                    parsed=urlsplit(self.path);path=parsed.path
                    type(self).seen.append((path,'GET'))
                    if path=='/check':
                        authenticated=('sid=PRIVATE_COOKIE' in self.headers.get('Cookie','') or
                                       self.headers.get('Authorization')=='Bearer PRIVATE_BEARER')
                        return self.response(200 if authenticated else 401,
                            b'{"user":"alice"}' if authenticated else b'{}',media='application/json')
                    if path=='/item':
                        allowed='sid=PRIVATE_COOKIE' in self.headers.get('Cookie','')
                        return self.response(200 if allowed else 403,
                            b'{"resource":"fixture-alice"}' if allowed else b'{}',media='application/json')
                    value=parse_qs(parsed.query,keep_blank_values=True).get('q',['jarvis-test'])[0]
                    if path=='/reflect':
                        import html
                        value=html.escape(value,quote=True) if type(self).fixed else value
                        return self.response(200,('<html><body>'+value+'</body></html>').encode())
                    if path=='/sql':
                        db=sqlite3.connect(':memory:')
                        db.execute('CREATE TABLE records(name TEXT,value TEXT)')
                        db.execute("INSERT INTO records VALUES('jarvis-test','synthetic-result')")
                        try:
                            rows=(db.execute('SELECT value FROM records WHERE name=?',(value,)) if type(self).fixed else
                                  db.execute("SELECT value FROM records WHERE name='"+value+"'")).fetchall()
                            text=str(rows)
                        except sqlite3.Error as exc:text='sqlite3.OperationalError: SQLITE_ERROR: '+str(exc)
                        finally:db.close()
                        return self.response(200,('<html><body>'+text+'</body></html>').encode())
                    self.response(404,b'not found')
            server=ThreadingHTTPServer(('93.184.216.34',0),Handler)
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key)
            server.socket=tls.wrap_socket(server.socket,server_side=True)
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            core=Core(root/'store',timeout=240);manifest=root/'active.json'
            try:
                case=core.investigate('active','Synthetic active verification',root,'owner','Disposable CI only')
                g=grant(server.server_port);manifest.write_text(json.dumps(g))
                vulnerable=m.run_active(core,case,manifest,ca_file=cert,seconds=180)
                def verified_scan(operation,path):
                    analysis=operation['analysis'];scanner=analysis['scanner'];snapshot=analysis['gateway']
                    self.assertIn(analysis['status'],('completed','partial'),json.dumps(analysis,sort_keys=True))
                    self.assertNotIn('error',scanner);self.assertEqual(scanner['scan_count'],1)
                    denied=snapshot['counters']['rejected']
                    self.assertLessEqual(denied,1)
                    self.assertEqual(denied,snapshot['counters'].get('rejected_reason_route_or_method',0))
                    self.assertTrue(all(o['path']==path and 'error' not in o for o in snapshot['observations']))
                    return analysis
                va=verified_scan(vulnerable,'/reflect')
                self.assertIn(va['status'],('completed','partial'),json.dumps(va,sort_keys=True))
                self.assertNotIn('error',va['scanner'])
                self.assertEqual(va['scanner']['scan_count'],1)
                if va['status']=='partial':
                    self.assertGreater(va['gateway']['counters'].get('rejected_reason_route_or_method',0),0)
                self.assertTrue(all(o['path']=='/reflect' for o in va['gateway']['observations']))
                self.assertTrue(va['scanner']['egress_blocked'])
                self.assertTrue(any(x['rule_id']=='40012' for x in va['findings']))
                self.assertLessEqual(va['gateway']['counters']['requests'],128)
                Handler.fixed=True
                corrected=m.run_active(core,case,manifest,ca_file=cert,seconds=180,retest_of=vulnerable['id'])
                verified_scan(corrected,'/reflect')
                self.assertNotIn('error',corrected['analysis']['scanner'])
                self.assertEqual(corrected['analysis']['scanner']['scan_count'],1)
                self.assertFalse(any(x['rule_id']=='40012' for x in corrected['analysis']['findings']))
                self.assertEqual(corrected['retest_of'],vulnerable['id'])
                self.assertNotEqual(corrected['id'],vulnerable['id'])
                # Real SQLite error-based SQL injection, separate scan policy.
                Handler.fixed=False
                sql=grant(server.server_port,'sql_injection','/sql');manifest.write_text(json.dumps(sql))
                injection=m.run_active(core,case,manifest,ca_file=cert,seconds=180)
                verified_scan(injection,'/sql')
                self.assertTrue(any(x['rule_id']=='40018' for x in injection['analysis']['findings']))
                Handler.fixed=True
                safe_sql=m.run_active(core,case,manifest,ca_file=cert,seconds=180,retest_of=injection['id'])
                verified_scan(safe_sql,'/sql')
                self.assertFalse(any(x['rule_id']=='40018' for x in safe_sql['analysis']['findings']))
                Handler.fixed=False
                # Host-only form login/cookies and bearer sessions share the same gateway.
                g=grant(server.server_port)
                for path,methods,purpose,params in (('/login',['POST'],'login',['username','password']),
                    ('/check',['GET'],'check',[]),('/item',['GET'],'access',[])):
                    g['routes'].append({'path':path,'methods':methods,'purpose':purpose,'query_params':[],
                                        'body_params':params})
                manifest.write_text(json.dumps(g));material=root/'private-session.json'
                material.write_text(json.dumps({'version':1,'profiles':{
                    'alice':{'kind':'form','login':{'path':'/login','fields':{'username':'alice','password':'PRIVATE_PASSWORD'}},
                        'check':{'path':'/check','status':200,'json_marker':{'field':'user','value':'alice'}}},
                    'bob':{'kind':'bearer','token':'PRIVATE_BEARER',
                        'check':{'path':'/check','status':200,'json_marker':{'field':'user','value':'alice'}}},
                    'visitor':{'kind':'anonymous'}}}))
                checked=m.run_session_check(core,case,manifest,material,profile='alice',ca_file=cert,seconds=30)
                self.assertEqual(checked['analysis']['status'],'completed')
                authenticated=m.run_active(core,case,manifest,ca_file=cert,seconds=180,
                    session_material=material,profile='alice')
                self.assertTrue(authenticated['analysis']['profile']['authenticated'])
                self.assertNotIn('error',authenticated['analysis']['scanner'])
                self.assertEqual(authenticated['analysis']['scanner']['scan_count'],1)
                self.assertTrue(any(x['rule_id']=='40012' for x in authenticated['analysis']['findings']))
                matrix=root/'matrix.json';matrix.write_text(json.dumps({'version':1,'cases':[
                    {'path':'/item','allowed':['alice'],'profiles':['alice','bob','visitor'],'status':200,
                     'json_marker':{'field':'resource','value':'fixture-alice'}}]}))
                access=m.run_access(core,case,manifest,matrix,material,ca_file=cert,seconds=60)
                self.assertEqual(access['analysis']['status'],'completed')
                self.assertTrue(all(r['level']=='observation' for r in access['analysis']['cases'][0]['results']))
                # Result store/audit/report contain none of the supplied secret material.
                exported=json.dumps(saved_operations(core,case))+core.report(case).read_text()
                exported+=json.dumps([dict(r) for r in core.db.execute('SELECT data FROM audit')])
                for marker in ('PRIVATE_PASSWORD','PRIVATE_COOKIE','PRIVATE_BEARER'):
                    self.assertNotIn(marker,exported)
                self.assertTrue(core.verify_audit(case))
                # Revoke/paused before publication must reject, preserving existing operations.
                count=len(saved_operations(core,case));real=m.save_active_result
                def paused(*args,**kw):core.pause(case);return real(*args,**kw)
                with patch.object(m,'save_active_result',side_effect=paused):
                    with self.assertRaises(CoreError):
                        m.run_session_check(core,case,manifest,material,profile='alice',ca_file=cert,seconds=30)
                self.assertEqual(len(saved_operations(core,case)),count)
            finally:core.close();server.shutdown();server.server_close();worker.join(timeout=3)

if __name__=='__main__':unittest.main()
