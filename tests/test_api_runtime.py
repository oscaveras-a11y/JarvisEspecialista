"""Only synthetic data; real TLS fixture stays on loopback inside GitHub runners."""
import copy
import importlib
import json
import os
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

def specification():
    return {'openapi':'3.0.3','paths':{'/items':{'get':{
        'security':[{'bearer':[]}],
        'responses':{'200':{'description':'ok','content':{'application/json':{
            'schema':{'type':'object','required':['resource','count'],'additionalProperties':False,
                      'properties':{'resource':{'type':'string'},'count':{'type':'integer','minimum':0}}}}}},
                     '401':{'description':'denied'},'403':{'description':'denied'}}}}},
        'components':{'securitySchemes':{'bearer':{'type':'http','scheme':'bearer'}}}}

def grant(port=4443):
    return {'version':1,'origin':f'https://jarvis-api.test:{port}','paths':['/items'],
            'allow_read':True,'authorization':'Synthetic loopback lab only','expires_at':'2099-01-01T00:00:00Z'}

def matrix():
    return {'version':1,'synthetic_only':True,'cases':[
        {'path':'/items','allowed':['alice'],'resource':'fixture-alice'}]}

class ApiRuntimeTests(unittest.TestCase):
    def module(self):
        try:return importlib.import_module('cyber_core.pentest.api_runtime')
        except ImportError:self.fail('Synthetic API runtime adapter missing')

    def compare(self,body=b'{"resource":"fixture-alice","count":1}',**kw):
        return self.module().compare_response(specification(),'/items',200,
            {'content-type':'application/json'},body,kw.pop('complete',True),**kw)

    def test_supported_contract_and_precise_failures(self):
        self.assertEqual(self.compare()['level'],'observation')
        bad=self.compare(b'{"resource":"fixture-alice","count":true}')
        self.assertEqual(bad['level'],'confirmed_failure')
        self.assertIn('schema_type',bad['codes'])
        self.assertIn('schema_required',self.compare(b'{"count":1}')['codes'])
        self.assertIn('schema_minimum',self.compare(b'{"resource":"fixture-alice","count":-1}')['codes'])
        self.assertIn('schema_additional_property',self.compare(b'{"resource":"fixture-alice","count":1,"other":1}')['codes'])

    def test_unsupported_schema_is_alert_never_pass(self):
        m=self.module()
        for schema in ({'oneOf':[{'type':'string'}]},{'type':'string','pattern':'x'},
                       {'type':'integer','minimum':'bad'},{'type':['string','null']},
                       {'type':'object','required':'count'},{'$ref':'https://outside.invalid/schema'},
                       {'type':'object','properties':{'count':{'format':'int64'}}}):
            d=specification();d['paths']['/items']['get']['responses']['200']['content']['application/json']['schema']=schema
            with self.subTest(schema=schema):
                r=m.compare_response(d,'/items',200,{'content-type':'application/json'},b'{}',True)
                self.assertEqual(r['level'],'alert')
                self.assertIn('unsupported_schema',r['codes'])

    def test_incomplete_encoded_and_unknown_responses_are_alerts(self):
        m=self.module();d=specification()
        self.assertEqual(self.compare(complete=False)['level'],'alert')
        self.assertIn('incomplete_body',self.compare(complete=False)['codes'])
        r=m.compare_response(d,'/items',200,{'content-type':'application/json','content-encoding':'gzip'},b'junk',True)
        self.assertEqual(r['level'],'alert')
        self.assertIn('encoded_body',r['codes'])
        self.assertIn('undeclared_status',m.compare_response(d,'/items',500,{},b'',True)['codes'])
        self.assertIn('invalid_json',self.compare(b'{"count":NaN}')['codes'])
        self.assertIn('invalid_json',self.compare(b'{"count":1,"count":2}')['codes'])

    def test_valid_json_beyond_analysis_limits_is_alert_not_contract_failure(self):
        m=self.module();d=specification()
        schema=d['paths']['/items']['get']['responses']['200']['content']['application/json']
        schema['schema']={'type':'object'}
        bodies=[b'{"x":'+b'['*32+b'0'+b']'*32+b'}',
                b'{"x":['+b'0,'*50000+b'0]}',b'{"x":1e1000}',b'{"x":'+b'9'*5000+b'}']
        for body in bodies:
            with self.subTest(size=len(body)):
                r=m.compare_response(d,'/items',200,{'content-type':'application/json'},body,True)
                self.assertEqual(r['level'],'alert')
                self.assertIn('body_analysis_limit',r['codes'])

    def test_response_parser_rejects_trailing_member_injection(self):
        m=self.module();d=specification()
        d['paths']['/items']['get']['responses']['200']['content']['application/json']['schema']={'type':'integer'}
        r=m.compare_response(d,'/items',200,{'content-type':'application/json'},b'1,"ignored":2',True)
        self.assertEqual(r['level'],'confirmed_failure')
        self.assertIn('invalid_json',r['codes'])

    def test_matrix_requires_explicit_synthetic_profiles_and_granted_paths(self):
        m=self.module()
        self.assertEqual(len(m.validate_matrix(json.dumps(matrix()).encode(),grant())['cases']),1)
        for mutate in (
            lambda d:d.update(synthetic_only=False),
            lambda d:d.update(token='PRIVATE'),
            lambda d:d['cases'][0].update(path='/outside'),
            lambda d:d['cases'][0].update(allowed=['admin']),
            lambda d:d['cases'][0].update(allowed=[]),
            lambda d:d['cases'][0].update(resource='not-synthetic'),
            lambda d:d['cases'].append(copy.deepcopy(d['cases'][0]))):
            d=matrix();mutate(d)
            with self.subTest(d=d),self.assertRaises(ValueError):
                m.validate_matrix(json.dumps(d).encode(),grant())
        g=grant();g['origin']='https://example.com'
        with self.assertRaises(ValueError):m.validate_matrix(json.dumps(matrix()).encode(),g)

    def test_access_confirmation_requires_positive_control_and_resource_evidence(self):
        m=self.module()
        def row(profile,status=200,resource=True):
            return {'profile':profile,'status':status,'resource_match':resource,
                    'body_complete':True,'contract':{'level':'observation','codes':[]}}
        case=matrix()['cases'][0]
        self.assertEqual(m.assess_access(case,[row('alice'),row('bob')])[1]['level'],'confirmed_failure')
        self.assertEqual(m.assess_access(case,[row('alice',500),row('bob')])[1]['level'],'alert')
        self.assertEqual(m.assess_access(case,[row('alice'),row('bob',200,False)])[1]['level'],'alert')
        self.assertEqual(m.assess_access(case,[row('alice'),row('bob',403,False)])[1]['level'],'observation')
        self.assertEqual(m.assess_access(case,[row('alice'),row('anonymous')])[1]['category'],'authentication')

    @unittest.skipUnless(os.environ.get('JARVIS_API_TLS')=='1','real loopback TLS fixture in GitHub Linux')
    def test_real_tls_core_campaign_evidence_resume_and_controls(self):
        m=self.module()
        from cyber_core.service import Core
        from cyber_core.pentest import campaigns
        from cyber_core.operations import saved_operations
        from cyber_core.errors import CoreError
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);cert=root/'ca.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                '-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=jarvis-api.test',
                '-addext','subjectAltName=DNS:jarvis-api.test'],check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            class Handler(BaseHTTPRequestHandler):
                seen=[]
                broken=False
                slow=False
                slow_started=threading.Event()
                release=threading.Event()
                def log_message(self,*args):pass
                def do_GET(self):
                    token=self.headers.get('Authorization','')
                    type(self).seen.append((self.path,token))
                    good=token=='Bearer synthetic-alice'
                    status=200 if good or type(self).broken else 403
                    payload=b'{"resource":"fixture-alice","count":1}' if status==200 else b'{}'
                    self.send_response(status);self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(payload)))
                    self.send_header('Set-Cookie','PRIVATE_SENTINEL')
                    self.end_headers()
                    if type(self).slow:
                        type(self).slow_started.set();type(self).release.wait(4)
                    try:self.wfile.write(payload)
                    except OSError:pass
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                (root/'api.json').write_text(json.dumps(specification()))
                (root/'grant.json').write_text(json.dumps(grant(server.server_port)))
                (root/'matrix.json').write_text(json.dumps(matrix()))
                plan={'version':1,'stages':['api','authentication'],'api_spec':'api.json',
                      'api_matrix':'matrix.json','web_grant':'grant.json','ca_file':'ca.pem','seconds':15}
                (root/'campaign.json').write_text(json.dumps(plan))
                core=Core(root/'store',timeout=20)
                case=core.investigate('lab','Synthetic API',folder,'owner','Synthetic only')
                try:
                    c=campaigns.create(core,case,str(root/'campaign.json'))
                    r=campaigns.work(core,case,c['campaign_id'])
                    op=next(x for x in saved_operations(core,case) if x['kind']=='api')
                    self.assertEqual(len(op['analysis']['responses']),4)
                    self.assertTrue(op['analysis']['runtime_tested'])
                    self.assertFalse(op['analysis']['full_pentest_completed'])
                    self.assertFalse(op['analysis']['confirmed_failures'])
                    self.assertEqual(r['stages'][0]['coverage'],'exercised')
                    self.assertEqual(r['stages'][1]['state'],'unavailable')
                    n=len(Handler.seen)
                    self.assertEqual(campaigns.work(core,case,c['campaign_id'])['id'],r['id'])
                    self.assertEqual(len(Handler.seen),n)
                    exported=json.dumps(op)
                    for secret in ('PRIVATE_SENTINEL','synthetic-alice','fixture-alice','"count"'):
                        self.assertNotIn(secret,exported)
                    self.assertTrue(core.verify_audit(case))
                    self.assertIn('api',core.report(case).read_text())
                    Handler.broken=True
                    args=[core,case,str(root/'api.json'),str(root/'grant.json'),str(root/'matrix.json')]
                    broken=m.run_api(*args,ca_file=str(cert),seconds=15)
                    self.assertEqual(len(broken['analysis']['confirmed_failures']),3)
                    # Real certificate validation; no trust bypass or redirect behavior.
                    untrusted=m.run_api(*args,ca_file=None,seconds=15)
                    self.assertFalse(untrusted['analysis']['confirmed_failures'])
                    self.assertTrue(all(x.get('error')=='tls_validation_failed' for x in untrusted['analysis']['responses']))
                    # Receipt survives campaign publication failure and Core reopening.
                    c2=campaigns.create(core,case,str(root/'campaign.json'))
                    core.db.execute("""CREATE TRIGGER synthetic_api_failure BEFORE INSERT ON operation_results
                        WHEN NEW.kind='pentest_campaign' AND json_extract(NEW.data,'$.event')='stage_completed'
                        BEGIN SELECT RAISE(FAIL,'synthetic failure'); END""");core.db.commit()
                    with self.assertRaises(CoreError):campaigns.work(core,case,c2['campaign_id'])
                    n=len(Handler.seen)
                    core.db.execute('DROP TRIGGER synthetic_api_failure');core.db.commit()
                    home=core.home;core.close();core=Core(home,timeout=20);args[0]=core
                    resumed=campaigns.work(core,case,c2['campaign_id'])
                    self.assertEqual(resumed['stages'][0]['state'],'completed')
                    self.assertEqual(len(Handler.seen),n)
                    # Supervisor interrupts a real blocking response; no late operation published.
                    Handler.slow=True;Handler.slow_started.clear();Handler.release.clear()
                    count_before=len(saved_operations(core,case));began=time.monotonic()
                    def cancelled():
                        if Handler.slow_started.is_set():raise CoreError('Synthetic cancellation')
                    try:
                        with self.assertRaises(CoreError):
                            m.run_api(*args,ca_file=str(cert),seconds=15,control_check=cancelled)
                        self.assertTrue(Handler.slow_started.is_set())
                        self.assertLess(time.monotonic()-began,5)
                        self.assertEqual(len(saved_operations(core,case)),count_before)
                    finally:
                        Handler.slow=False;Handler.release.set()
                    # Lifecycle guard executes inside save transaction, not only before it.
                    from cyber_core import operations
                    original=operations.save_operation
                    def pause_before_save(target,case_id,kind,data,**kwargs):
                        target.pause(case_id)
                        return original(target,case_id,kind,data,**kwargs)
                    before=len(saved_operations(core,case))
                    with patch.object(operations,'save_operation',side_effect=pause_before_save):
                        with self.assertRaises(CoreError):m.run_api(*args,ca_file=str(cert),seconds=15)
                    self.assertEqual(len(saved_operations(core,case)),before)
                    core.resume(case)
                    (root/'matrix.json').write_text('{}')
                    with self.assertRaises(CoreError):campaigns.work(core,case,c['campaign_id'])
                    self.assertTrue(core.verify_audit(case))
                finally:core.close()
            finally:server.shutdown();server.server_close();thread.join(timeout=3)
