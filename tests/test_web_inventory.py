"""Synthetic HTML inventory: no scripts, form submissions or network."""
import hashlib
import importlib
import json
import unittest

class InventoryTests(unittest.TestCase):
    def make(self,page='/',allowed=None,**kwargs):
        try:module=importlib.import_module('cyber_core.web_inventory')
        except ImportError:self.fail('Bounded web inventory parser missing')
        return module.Inventory('https://example.com',page,allowed or ['/','/save'],**kwargs)

    def parse(self,html,**kwargs):
        scanner=self.make(**kwargs);scanner.feed(html.encode())
        return scanner.finish()

    def test_routes_forms_and_secret_values_are_redacted(self):
        r=self.parse('<a href="/save?token=private-query">Save</a><form action="/save?key=private-action" method="POST"><input name="password" type="password" value="private-value"><input name="csrf_token" value="private-csrf"></form>')
        self.assertEqual(r['status'],'completed',r['quality_flags'])
        self.assertEqual(r['routes'][0],{'path':'/save','query_removed':True})
        form=r['forms'][0]
        self.assertEqual(form['method'],'POST')
        self.assertTrue(form['action_in_scope'])
        self.assertEqual(form['action_path'],'/save')
        self.assertEqual(form['fields'][0]['kind'],'password')
        self.assertEqual(form['fields'][0]['name_sha256'],hashlib.sha256(b'password').hexdigest())
        self.assertTrue(form['csrf_related_name_observed'])
        text=json.dumps(r)
        for value in ('private-query','private-action','private-value','private-csrf','csrf_token'):
            self.assertNotIn(value,text)

    def test_late_base_is_applied_to_earlier_relative_references(self):
        r=self.parse('<a href="save">Link</a><base href="/root/">',allowed=['/','/root/save'])
        self.assertEqual(r['routes'][0]['path'],'/root/save')

    def test_external_base_and_missing_form_action_are_distinguished(self):
        r=self.parse('<base href="https://outside.invalid/"><a href="save">Outside</a><form><input name="x"></form>')
        self.assertEqual(r['routes'],[])
        self.assertGreater(r['references_out_of_scope'],0)
        self.assertEqual(r['forms'][0]['action_path'],'/')

    def test_out_of_scope_and_active_schemes_are_not_persisted(self):
        html=''.join('<a href="'+u+'">x</a>' for u in (
            'javascript:alert(1)','data:text/html,private-data','file:///private',
            'https://u:private-password@example.com/save','https://127.0.0.1/metadata',
            'https://outside.invalid/private-path','/not-approved'))
        r=self.parse(html)
        self.assertEqual(r['routes'],[])
        self.assertEqual(r['references_out_of_scope'],7)
        self.assertNotIn('private',json.dumps(r))

    def test_limits_and_omissions_are_explicit(self):
        html=('<a href="/save">x</a>'*40+
              ('<form action="/save">'+('<input name="x">'*20)+'</form>')*5)
        r=self.parse(html)
        self.assertEqual(r['status'],'partial')
        self.assertEqual(len(r['forms']),2)
        self.assertGreater(r['forms_omitted'],0)
        self.assertGreater(r['references_omitted'],0)
        self.assertEqual(len(r['forms'][0]['fields']),8)
        self.assertGreater(r['forms'][0]['fields_omitted'],0)

    def test_utf8_can_be_split_between_every_byte(self):
        scanner=self.make()
        for byte in '<form action="/save"><input name="ação" value="敏感"></form>'.encode():
            scanner.feed(bytes([byte]))
        r=scanner.finish()
        self.assertEqual(r['status'],'completed',r['quality_flags'])
        self.assertEqual(r['forms'][0]['fields'][0]['name_sha256'],hashlib.sha256('ação'.encode()).hexdigest())
        self.assertNotIn('敏感',json.dumps(r))

    def test_invalid_encoding_and_incomplete_body_are_partial(self):
        scanner=self.make();scanner.feed(b'<form>\xff')
        self.assertEqual(scanner.finish()['status'],'partial')
        scanner=self.make();scanner.feed(b'<form action="/save">')
        r=scanner.finish(body_complete=False)
        self.assertEqual(r['status'],'partial')
        self.assertIn('body_incomplete',r['quality_flags'])

    def test_unsupported_form_association_and_nested_forms_are_partial(self):
        for html in ('<input name="x" form="external"><form id="external"></form>',
                     '<form><form action="/save"><input name="x"></form></form>'):
            with self.subTest(html=html):
                self.assertEqual(self.parse(html)['status'],'partial')

    def test_input_budget_and_closed_parser_reject_further_data(self):
        scanner=self.make(max_bytes=32)
        with self.assertRaises(ValueError):scanner.feed(b'x'*33)
        scanner=self.make();scanner.finish()
        with self.assertRaises(ValueError):scanner.feed(b'x')

    def test_route_queries_deduplicate_without_retaining_values(self):
        r=self.parse('<a href="/save?a=secret-one">a</a><a href="/save?b=secret-two#fragment">b</a>')
        self.assertEqual(r['routes'],[{'path':'/save','query_removed':True}])
        self.assertNotIn('secret',json.dumps(r))

    def test_textarea_and_title_contents_are_not_inventory_markup(self):
        r=self.parse('<form action="/save"><textarea name="comment"><input name="csrf_token"><a href="/save">private text</textarea></form>')
        self.assertEqual(r['routes'],[])
        self.assertEqual([f['kind'] for f in r['forms'][0]['fields']],['textarea'])
        self.assertFalse(r['forms'][0]['csrf_related_name_observed'])
        r=self.parse('<title><base href="https://outside.invalid/"><a href="/save">private</title><a href="/save">real</a>')
        self.assertEqual(r['routes'],[{'path':'/save','query_removed':False}])

    def test_submission_overrides_are_explicitly_partial(self):
        r=self.parse('<form action="/save"><button formaction="https://outside.invalid/" formmethod="post">Send</button></form>')
        self.assertEqual(r['status'],'partial')
        self.assertIn('submission_overrides_unsupported',r['quality_flags'])

    def test_invalid_or_omitted_base_and_form_actions_do_not_fallback_as_verified(self):
        with self.subTest('invalid base'):
            r=self.parse('<base href="https://["><a href="save">x</a>')
            self.assertEqual(r['status'],'partial')
            self.assertEqual(r['routes'],[])
        with self.subTest('omitted base'):
            r=self.parse('<base href="'+('x'*2049)+'"><a href="save">x</a>')
            self.assertEqual(r['status'],'partial')
            self.assertEqual(r['routes'],[])
        with self.subTest('omitted form action'):
            r=self.parse('<form action="'+('x'*2049)+'"><input name="x"></form>')
            self.assertFalse(r['forms'][0]['action_in_scope'])
            self.assertIsNone(r['forms'][0]['action_path'])

    def test_maximum_inventory_records_fit_supervised_output_budget(self):
        paths=['/'+str(i)+'x'*250 for i in range(8)]
        html=''.join('<a href="'+p+'">x</a>' for p in paths)
        html+=('<form action="'+paths[0]+'">'+''.join('<input type="password" name="field'+str(i)+'">' for i in range(8))+'</form>')*2
        r=self.parse(html,page=paths[0],allowed=paths)
        self.assertLess(len(json.dumps({'responses':[{'inventory':r}]*8}).encode()),55000)
