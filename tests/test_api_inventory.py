"""Synthetic OpenAPI descriptions: no network or target code execution."""
import importlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout

def spec():
    return {'openapi':'3.0.3','info':{'title':'synthetic','version':'1'},
            'paths':{'/items':{'get':{'responses':{'200':{'description':'ok'}}},
                               'post':{'security':[],'responses':{'201':{'description':'ok'}}}},
                     '/items/{id}':{'get':{'responses':{'200':{'description':'ok'}}}}},
            'security':[{'bearer':[]}],
            'components':{'securitySchemes':{'bearer':{'type':'http','scheme':'bearer'}}}}

def grant():
    return {'version':1,'origin':'https://example.com','paths':['/items'],
            'allow_read':True,'authorization':'Synthetic only','expires_at':'2099-01-01T00:00:00Z'}

class ApiInventoryTests(unittest.TestCase):
    def module(self):
        try:return importlib.import_module('cyber_core.pentest.openapi')
        except ImportError:self.fail('OpenAPI inventory adapter missing')

    def analyze(self, document=None, **kwargs):
        return self.module().analyze(json.dumps(spec() if document is None else document).encode(),grant(),**kwargs)

    def test_methods_security_override_and_exact_scope(self):
        r=self.analyze()
        rows={(v['path'],v['method']):v for v in r['operations']}
        self.assertEqual(rows['/items','GET']['security'],'declared_required')
        self.assertEqual(rows['/items','POST']['security'],'declared_anonymous')
        self.assertTrue(rows['/items','GET']['read_probe_eligible'])
        self.assertFalse(rows['/items','POST']['read_probe_eligible'])
        self.assertFalse(rows['/items/{id}','GET']['read_probe_eligible'])
        self.assertEqual(rows['/items/{id}','GET']['scope'],'template_requires_explicit_binding')
        self.assertFalse(r['runtime_tested'])

    def test_servers_override_and_no_implicit_host_trust(self):
        d=spec();d['servers']=[{'url':'https://elsewhere.example/api'}]
        d['paths']['/items']['get']['servers']=[{'url':'/'}]
        r=self.analyze(d)
        rows={(v['path'],v['method']):v for v in r['operations']}
        self.assertTrue(rows['/items','GET']['read_probe_eligible'])
        self.assertFalse(rows['/items','POST']['read_probe_eligible'])
        self.assertIn('server_outside_scope',r['quality_flags'])

    def test_internal_refs_resolve_external_and_cycles_are_partial(self):
        d=spec();d['paths']={'/items':{'$ref':'#/components/pathItems/Item'}}
        d['components']['pathItems']={'Item':{'get':{'responses':{}}}}
        self.assertEqual(self.analyze(d)['operations'][0]['method'],'GET')
        for ref in ('https://example.com/private.json','#/components/pathItems/Loop'):
            d['paths']['/items']={'$ref':ref}
            d['components']['pathItems']['Loop']={'$ref':'#/components/pathItems/Loop'}
            r=self.analyze(d)
            self.assertEqual(r['status'],'partial');self.assertEqual(r['operations'],[])
            self.assertIn('unresolved_reference',r['quality_flags'])

    def test_unsupported_versions_and_non_json_are_explicit(self):
        d=spec();d['openapi']='3.2.0'
        r=self.analyze(d);self.assertEqual(r['status'],'unsupported')
        with self.assertRaises(ValueError):self.module().analyze(b'openapi: 3.0.3',grant())

    def test_limits_duplicates_depth_and_invalid_security(self):
        m=self.module()
        for data in (b'{"openapi":"3.0.3","openapi":"3.1.0"}',b'['*80+b'0'+b']'*80,
                     b'{"openapi":NaN}',b'{"paths":'):
            with self.subTest(data=data[:40]),self.assertRaises(ValueError):m.analyze(data,grant())
        with self.assertRaises(ValueError):self.analyze(max_bytes=10)
        with self.assertRaises(ValueError):self.analyze(max_operations=True)
        r=self.analyze(max_operations=1)
        self.assertEqual(len(r['operations']),1);self.assertEqual(r['operations_omitted'],2)
        self.assertEqual(r['status'],'partial')
        d=spec();d['security']=[{'missing':[]}]
        r=self.analyze(d)
        self.assertEqual(r['operations'][0]['security'],'unknown')
        self.assertIn('invalid_security_declaration',r['quality_flags'])

    def test_examples_credentials_and_arbitrary_text_not_echoed(self):
        d=spec();d['info']['description']='PRIVATE_SENTINEL'
        d['paths']['/items']['get']['description']='PRIVATE_SENTINEL'
        d['components']['securitySchemes']['bearer']['description']='PRIVATE_SENTINEL'
        d['paths']['/items']['get']['responses']['200']['content']={'application/json':{'example':{'token':'PRIVATE_SENTINEL'}}}
        r=self.analyze(d);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(r))

    def test_cancellation_and_output_budget(self):
        def stop():raise RuntimeError('cancelled')
        with self.assertRaises(RuntimeError):self.analyze(check=stop)
        with self.assertRaises(ValueError):self.analyze(output_bytes=100)

    def test_cli_and_campaign_real_core_round_trip(self):
        m=self.module()
        from cyber_core.service import Core
        from cyber_core.cli import main
        from cyber_core.pentest import campaigns
        from cyber_core.errors import CoreError
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);scope=root/'scope';scope.mkdir()
            description=scope/'api.json';description.write_text(json.dumps(spec()))
            permission=scope/'grant.json';permission.write_text(json.dumps(grant()))
            manifest=scope/'campaign.json';manifest.write_text(json.dumps(
                {'version':1,'stages':['api_inventory'],'api_spec':'api.json','web_grant':'grant.json'}))
            core=Core(root/'store');case=core.investigate('lab','API inventory',str(scope),'owner','Synthetic only')
            home=core.home;core.close()
            with redirect_stdout(io.StringIO()) as out:
                code=main(['--home',str(home),'api-inventory',case,str(description),'--grant',str(permission)])
            self.assertEqual(code,0)
            self.assertEqual(json.loads(out.getvalue())['kind'],'api_inventory')
            core=Core(home)
            try:
                created=campaigns.create(core,case,str(manifest))
                r=campaigns.work(core,case,created['campaign_id'])
                self.assertEqual(r['stages'][0]['coverage'],'inventoried')
                self.assertFalse(r['full_pentest_completed'])
                self.assertEqual(campaigns.work(core,case,created['campaign_id'])['id'],r['id'])
                self.assertTrue(core.verify_audit(case))
                self.assertIn('api_inventory',core.report(case).read_text())
                description.write_text('{}')
                with self.assertRaises(CoreError):campaigns.work(core,case,created['campaign_id'])
                core.pause(case)
                with self.assertRaises(CoreError):m.run_inventory(core,case,str(description),str(permission))
            finally:core.close()

    def test_server_controls_are_rejected_before_url_normalization(self):
        # urlsplit otherwise strips leading C0/space and embedded TAB/CR/LF.
        invalid=[]
        for c in [chr(n) for n in range(33)]+[chr(127)]:
            invalid.extend([c+'https://example.com/',
                            'https://exa'+c+'mple.com/',
                            'https://example.com/'+c,
                            '/'+c])
        for url in invalid:
            with self.subTest(url=repr(url)):
                d=spec();d['servers']=[{'url':url}]
                r=self.analyze(d)
                self.assertEqual(r['status'],'partial')
                self.assertIn('unsupported_server_url',r['quality_flags'])
                self.assertTrue(all(v['scope']=='server_not_mapped' for v in r['operations']))
                self.assertTrue(all(v['mapped_path'] is None for v in r['operations']))
                self.assertTrue(all(not v['read_probe_eligible'] for v in r['operations']))

    def test_valid_server_mapping_preserves_precedence(self):
        for url in ('/','https://example.com/','https://example.com:443/'):
            with self.subTest(url=url):
                d=spec();d['servers']=[{'url':url}]
                r=self.analyze(d)
                self.assertEqual(r['status'],'completed')
                self.assertTrue(r['operations'][0]['read_probe_eligible'])
        d=spec();d['servers']=[{'url':'https://example.com/\n'}]
        d['paths']['/items']['servers']=[{'url':'/'}]
        d['paths']['/items']['get']['servers']=[{'url':'/\t'}]
        rows={(v['path'],v['method']):v for v in self.analyze(d)['operations']}
        self.assertFalse(rows['/items','GET']['read_probe_eligible'])
        self.assertTrue(rows['/items','POST']['scope']=='exact_granted_path')
