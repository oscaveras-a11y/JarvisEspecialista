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

if __name__ == '__main__':
    unittest.main()
