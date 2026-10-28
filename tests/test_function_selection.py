"""Selection validation contracts independent of optional Ghidra installation."""
import importlib
import unittest
from cyber_core.errors import CoreError

class FunctionSelectionTests(unittest.TestCase):
    def api(self):
        try:
            return importlib.import_module('cyber_core.reverse_engineering.selected')
        except ImportError:
            self.fail('Targeted function analysis is not implemented')

    def test_valid_selection_preserves_entry_addresses(self):
        api = self.api()
        result = api.selection(names=['fixture_target'], addresses=[4096], ranges=[[4096,8192]],
                               max_functions=4, max_references=20, decompile_seconds=5)
        self.assertEqual(result['names'], ['fixture_target'])
        self.assertEqual(result['addresses'], [4096])
        self.assertEqual(result['ranges'], [[4096,8192]])
        self.assertEqual(result['max_functions'], 4)

    def test_invalid_or_unbounded_selection_is_rejected(self):
        api = self.api()
        for fields in ({}, {'names':['']}, {'names':['x'*257]}, {'addresses':[True]},
                       {'addresses':[-1]}, {'ranges':[[4,4]]}, {'ranges':[[8,4]]},
                       {'names':['x'],'max_functions':129},
                       {'names':['x'],'max_references':0},
                       {'names':['x'],'decompile_seconds':61}):
            with self.subTest(fields=fields), self.assertRaises(CoreError):
                api.selection(**fields)

class SelectedOutputBudgetTests(unittest.TestCase):
    def test_unicode_output_retains_a_bounded_explicit_partial_result(self):
        from cyber_core.reverse_engineering import selected
        import json
        self.assertTrue(callable(getattr(selected,'encode_result',None)),
                        'Selected analysis needs a byte-bounded output encoder')
        ref = {'from':'00401000','to':'00403000','type':'READ',
               'symbol':'界'*256,'direction':'outgoing','call':False}
        raw = {'backend_version':'12.1.4','language_id':'x86:LE:64:default',
               'compiler_spec':'gcc','image_base':'00400000','analysis_timed_out':False,
               'functions_truncated':False,'selection_scan_truncated':False,
               'visited_functions':8,'matched_functions':8,'name_matches':{'target':8},
               'functions':[{'address':'00401000','name':'target','status':'decompiled',
                             'pseudocode':'return 1;','error':'','pseudocode_truncated':False,
                             'references':[dict(ref) for _ in range(128)],
                             'references_truncated':False} for _ in range(8)]}
        options = selected.selection(names=['target'],max_references=128)
        normalized = selected.normalize(raw,options)
        result = {**normalized,'status':'completed','input_sha256':'0'*64}
        encoded = selected.encode_result(result)
        self.assertLessEqual(len(encoded.encode('utf-8'))+1,1048576)
        bounded = json.loads(encoded)
        self.assertEqual(bounded['status'],'partial')
        self.assertTrue(bounded['output_truncated'])
        self.assertTrue(bounded['functions_truncated'])
        self.assertGreater(len(bounded['functions']),0)
        self.assertLess(len(bounded['functions']),8)
        self.assertEqual(bounded['matched_functions'],8)
        self.assertEqual(len(result['functions']),8)
        small = json.loads(selected.encode_result(result,output_bytes=4096))
        self.assertEqual(small['functions'],[])
        self.assertEqual(small['status'],'partial')

if __name__ == '__main__':
    unittest.main()
