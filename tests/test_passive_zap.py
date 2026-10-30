"""Passive ZAP tests: synthetic messages only; execution exclusively in GitHub."""
import importlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
from datetime import datetime,timedelta,timezone

def grant(port=4443):
    return {'version':1,'origin':f'https://jarvis-fixture.test:{port}','paths':['/unsafe','/safe'],
            'allow_read':True,'authorization':'Disposable GitHub fixture',
            'expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}

class PassiveTests(unittest.TestCase):
    def module(self):
        try:return importlib.import_module('cyber_core.pentest.passive')
        except ImportError:self.fail('Scoped passive ZAP adapter missing')

    def test_cookie_attributes_never_export_names_or_values(self):
        m=self.module()
        result=m.cookie_metadata([('Set-Cookie','PRIVATE_NAME=PRIVATE_VALUE; Secure; HttpOnly; SameSite=Lax'),
            ('Set-Cookie','other=SECRET; SameSite=None'),('Set-Cookie','broken')])
        self.assertEqual(result,{'total':3,'secure':1,'httponly':1,'samesite_lax':1,
            'samesite_strict':0,'samesite_none':1,'samesite_missing':0,'malformed':1})
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertNotIn('SECRET',json.dumps(result))

    def test_alert_projection_scope_validation_and_deduplication(self):
        m=self.module();g=grant()
        base={'pluginId':'10021','risk':'1','confidence':'2','method':'GET',
              'url':g['origin']+'/unsafe','evidence':'PRIVATE_SECRET','param':'PRIVATE_NAME',
              'description':'PRIVATE_DESCRIPTION'}
        r=m.sanitize_alerts([base,dict(base),{**base,'url':'https://outside.invalid/unsafe'},
            {**base,'url':g['origin']+'/unsafe?secret=PRIVATE_SECRET'},
            {**base,'pluginId':'PRIVATE_SECRET'},{**base,'method':'POST'}],g)
        self.assertEqual(len(r['findings']),1)
        self.assertEqual(r['rejected'],4)
        self.assertEqual(r['findings'][0],{'rule_id':'10021','risk':1,'confidence':2,
            'method':'GET','path':'/unsafe','classification':'suspected'})
        self.assertNotIn('PRIVATE',json.dumps(r))
        self.assertNotIn('outside',json.dumps(r))
        for field,value in (('risk',True),('risk','9'),('confidence','9'),('pluginId','1\nSECRET')):
            self.assertEqual(m.sanitize_alerts([{**base,field:value}],g)['rejected'],1)
        self.assertGreater(m.sanitize_alerts([base]*129,g)['omitted'],0)

    def test_offline_container_command_has_hard_containment(self):
        m=self.module()
        cmd=m.container_command('/usr/bin/docker','jarvis-zap-'+'a'*32,Path('/tmp/input'),
                                Path('/tmp/driver.py'),120)
        for flag in ('--network=none','--read-only','--cap-drop=ALL',
                     '--security-opt=no-new-privileges','--pull=never','--pids-limit=128',
                     '--memory=1g','--cpus=1'):
            self.assertIn(flag,cmd)
        self.assertTrue(any('@sha256:' in s for s in cmd))
        self.assertFalse(any('docker.sock' in s for s in cmd if s.startswith('type=bind,')))
        with self.assertRaises(ValueError):
            m.container_command('/usr/bin/docker','bad name',Path('/tmp/input'),Path('/tmp/driver.py'),120)

    def test_dast_stage_requires_grant_and_retains_unavailable_state(self):
        self.module()
        from cyber_core.pentest import campaigns
        with self.assertRaises(ValueError):
            campaigns.validate_plan({'version':1,'stages':['dast_passive']})
        p=campaigns.validate_plan({'version':1,'stages':['dast_passive'],'web_grant':'grant.json'})
        from cyber_core.service import Core
        with tempfile.TemporaryDirectory() as f:
            root=Path(f);(root/'grant.json').write_text(json.dumps(grant()))
            (root/'campaign.json').write_text(json.dumps(p))
            core=Core(root/'store',timeout=10)
            try:
                case=core.investigate('passive','No backend',root,'owner','Synthetic')
                c=campaigns.create(core,case,root/'campaign.json')
                with patch('cyber_core.pentest.passive.backend',return_value=None):
                    result=campaigns.work(core,case,c['campaign_id'])
                stage=result['stages'][0]
                self.assertEqual(stage['state'],'unavailable')
                self.assertEqual(stage['coverage'],'unsupported_automation')
                self.assertFalse(result['full_pentest_completed'])
                self.assertTrue(core.verify_audit(case))
            finally:core.close()


    def test_real_zap_named_risk_levels_are_projected(self):
        m=self.module();g=grant()
        alert={'pluginId':'10010','risk':'Low','confidence':'Medium','method':'GET','url':g['origin']+'/unsafe'}
        r=m.sanitize_alerts([alert],g)
        self.assertEqual(r['rejected'],0)
        self.assertEqual(r['findings'][0]['risk'],1)
        self.assertEqual(r['findings'][0]['confidence'],2)

    def test_expired_stage_budget_cannot_publish_unavailable(self):
        import time
        m=self.module()
        from cyber_core.service import Core
        from cyber_core.errors import CoreError
        from cyber_core.operations import saved_operations
        with tempfile.TemporaryDirectory() as f:
            root=Path(f);path=root/'grant.json';path.write_text(json.dumps(grant()))
            core=Core(root/'store',timeout=10)
            try:
                case=core.investigate('passive','Expired budget',root,'owner','Synthetic')
                def late_backend(*args):
                    time.sleep(.08);return None
                with patch.object(m,'backend',side_effect=late_backend):
                    with self.assertRaises(CoreError):
                        m.run_passive(core,case,path,seconds=.05)
                self.assertFalse(any(o['kind']=='dast_passive' for o in saved_operations(core,case)))
            finally:core.close()

    @unittest.skipUnless(os.environ.get('JARVIS_ZAP_REAL')=='1','real ZAP and synthetic TLS in GitHub Linux')
    def test_real_zap_tls_core_receipt_controls_and_redaction(self):
        m=self.module()
        from cyber_core.service import Core
        from cyber_core.pentest import campaigns
        from cyber_core.errors import CoreError
        from cyber_core.operations import saved_operations
        with tempfile.TemporaryDirectory() as f:
            root=Path(f);cert=root/'ca.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),
                '-out',str(cert),'-days','1','-subj','/CN=jarvis-fixture.test',
                '-addext','subjectAltName=DNS:jarvis-fixture.test'],check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            class Handler(BaseHTTPRequestHandler):
                seen=[]
                def log_message(self,*args):pass
                def do_POST(self):
                    type(self).seen.append('POST');self.send_error(405)
                def do_GET(self):
                    type(self).seen.append(self.path)
                    self.send_response(302 if self.path=='/redirect' else 200)
                    self.send_header('Content-Type','text/html; charset=utf-8')
                    if self.path=='/safe':
                        self.send_header('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'")
                        self.send_header('X-Frame-Options','DENY')
                        self.send_header('X-Content-Type-Options','nosniff')
                        self.send_header('Strict-Transport-Security','max-age=31536000')
                        self.send_header('Set-Cookie','PRIVATE_NAME=PRIVATE_VALUE; Secure; HttpOnly; SameSite=Strict')
                    else:self.send_header('Set-Cookie','PRIVATE_NAME=PRIVATE_VALUE')
                    if self.path=='/redirect':self.send_header('Location','https://outside.invalid/private')
                    body=b'<!doctype html><html><title>Synthetic</title><body>PRIVATE_BODY</body></html>'
                    self.send_header('Content-Length',str(len(body)));self.end_headers()
                    try:self.wfile.write(body)
                    except OSError:pass
            server=ThreadingHTTPServer(('93.184.216.34',0),Handler)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
            server.socket=ctx.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            g=grant(server.server_port);manifest=root/'grant.json'
            manifest.write_text(json.dumps(g))
            plan={'version':1,'stages':['dast_passive'],'web_grant':'grant.json',
                  'ca_file':'ca.pem','seconds':180,'body_bytes':65536}
            (root/'campaign.json').write_text(json.dumps(plan))
            core=Core(root/'store',timeout=200)
            try:
                case=core.investigate('passive','Synthetic HTTPS and offline ZAP',root,'owner','CI only')
                c=campaigns.create(core,case,root/'campaign.json')
                with patch.object(campaigns,'_complete',side_effect=CoreError('synthetic checkpoint failure')):
                    with self.assertRaises(CoreError):campaigns.work(core,case,c['campaign_id'],max_seconds=200)
                ops=[o for o in saved_operations(core,case) if o['kind']=='dast_passive']
                self.assertEqual(len(ops),1);op=ops[0];a=op['analysis']
                self.assertEqual(a['status'],'completed')
                self.assertTrue(a['scanner']['queue_complete']);self.assertEqual(a['scanner']['messages'],2)
                self.assertEqual(a['scanner']['version'],'2.17.0')
                self.assertTrue(a['scanner']['addons'])
                self.assertEqual(a['scanner']['network'],'none')
                self.assertTrue(a['scanner']['egress_blocked'])
                self.assertTrue(any(x['rule_id']=='10010' and x['path']=='/unsafe' for x in a['findings']))
                self.assertFalse(any(x['rule_id']=='10010' and x['path']=='/safe' for x in a['findings']))
                self.assertEqual(a['responses'][0]['cookies']['httponly'],0)
                self.assertEqual(a['responses'][1]['cookies']['httponly'],1)
                before=list(Handler.seen)
                core.close();core=Core(root/'store',timeout=200)
                resumed=campaigns.work(core,case,c['campaign_id'],max_seconds=200)
                self.assertEqual(Handler.seen,before)
                self.assertEqual(resumed['stages'][0]['operation_id'],op['id'])
                self.assertFalse(resumed['full_pentest_completed'])
                report=core.report(case).read_text()
                dbrows=json.dumps([dict(r) for r in core.db.execute('SELECT data FROM audit')])
                for output in (json.dumps(op),report,dbrows):
                    for secret in ('PRIVATE_NAME','PRIVATE_VALUE','PRIVATE_BODY'):
                        self.assertNotIn(secret,output)
                self.assertTrue(core.verify_audit(case))
                from cyber_core.pentest.passive import run_passive
                with patch('cyber_core.pentest.passive.scan',side_effect=AssertionError('must not run')):
                    untrusted=run_passive(core,case,manifest,seconds=10)
                self.assertEqual(untrusted['analysis']['status'],'partial')
                self.assertEqual(untrusted['analysis']['responses'][0]['error'],'tls_validation_failed')
                g['paths']=['/safe'];manifest.write_text(json.dumps(g))
                real_save=m.save_result
                def pause_publish(*args,**kwargs):
                    core.pause(case);return real_save(*args,**kwargs)
                with patch.object(m,'save_result',side_effect=pause_publish):
                    with self.assertRaises(CoreError):run_passive(core,case,manifest,ca_file=cert,seconds=180)
                self.assertEqual(len([o for o in saved_operations(core,case) if o['kind']=='dast_passive']),2)
                core.resume(case)
                manifest.write_text('{}')
                with self.assertRaises(CoreError):campaigns.work(core,case,c['campaign_id'])
            finally:
                core.close();server.shutdown();server.server_close();thread.join(timeout=3)

if __name__=='__main__':unittest.main()
