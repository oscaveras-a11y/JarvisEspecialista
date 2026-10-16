import tempfile
import unittest
from pathlib import Path

from cyber_core.errors import CoreError
from cyber_core.automotive import analyze_can, compare_can


class CanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def log(self, text, name='log'):
        path = Path(self.temp.name) / name
        path.write_bytes(text.encode('ascii'))
        return path

    def test_counts_timing_and_identity(self):
        path = self.log('(1.000000) can0 123#AA\n(1.100000) can0 123#BB\n(1.300000) can0 123#AA\n(1.000000) can1 00000123#\n')
        before = path.read_bytes()
        result = analyze_can(path)
        self.assertEqual(result['frame_count'], 4)
        stream = result['streams'][0]
        self.assertEqual(stream['payload_counts'], {'AA': 2, 'BB': 1})
        self.assertAlmostEqual(stream['interarrival_seconds']['mean'], .15)
        self.assertAlmostEqual(stream['interarrival_seconds']['jitter'], .1)
        self.assertEqual(result['streams'][1]['id_format'], 'extended')
        self.assertEqual(path.read_bytes(), before)

    def test_bad_records(self):
        for record in ['(NaN) can0 123#AA', '(inf) can0 123#AA', '(-1.0) can0 123#AA', '(1.0) can0 123#AA', '(1.000000) can0 800#AA', '(1.000000) can0 20000000#AA', '(1.000000) can0 123#A', '(1.000000) can0 123#GG', '(1.000000) can0 123#' + 'AA'*9, '(1.000000) can0 123#R8', '(1.000000) can0 123##1AA', '(1.000000) can0 20000001#AA', 'garbage']:
            with self.subTest(record=record), self.assertRaises(CoreError):
                analyze_can(self.log(record))

    def test_limits_and_empty(self):
        path = self.log('(1.000000) can0 123#AA\n'*2)
        for options in [{'max_frames': 1}, {'max_bytes': 1}, {'max_frames': 0}, {'max_bytes': -1}, {'max_frames': True}]:
            with self.subTest(options=options), self.assertRaises(CoreError):
                analyze_can(path, **options)
        with self.assertRaises(CoreError):
            analyze_can(self.log(''))

    def test_regressions_and_duplicates(self):
        result = analyze_can(self.log('(2.000000) can0 123#AA\n(1.000000) can0 123#AA\n(1.000000) can0 123#AA'))
        stream = result['streams'][0]
        self.assertEqual(stream['timestamp_regressions'], 1)
        self.assertEqual(stream['duplicate_timestamps'], 1)
        self.assertIsNone(stream['interarrival_seconds'])
        self.assertIsNone(stream['rate_hz'])

    def test_compare(self):
        a = self.log('(1.000000) can0 123#AA\n(2.000000) can0 123#AA\n(2.000000) can1 124#BB', 'a')
        b = self.log('(1.000000) can0 123#CC\n(2.000000) can0 125#AA', 'b')
        result = compare_can(a, b)
        self.assertEqual(result['common'][0]['count_delta'], -1)
        self.assertTrue(result['common'][0]['payload_distribution_changed'])
        self.assertEqual(result['only_first'][0]['channel'], 'can1')
        self.assertEqual(result['only_second'][0]['id'], '125')

    def test_bounded_samples(self):
        text = '\n'.join(f'(1.{n:06}) can0 123#{n:04X}' for n in range(30))
        stream = analyze_can(self.log(text))['streams'][0]
        self.assertEqual(len(stream['sample_payloads']), 8)
        self.assertEqual(sum(stream['payload_counts'].values()), 30)

    def test_crlf_empty_frames_and_finite_serialization(self):
        import json
        result = analyze_can(self.log('(0.000000) can0 000#\r\n(0.000000) can0 000#\r\n'))
        self.assertEqual(result['streams'][0]['dlc_counts'], {'0': 2})
        self.assertIsNone(result['streams'][0]['rate_hz'])
        json.dumps(result, allow_nan=False)

    def test_missing_non_ascii_and_truncated(self):
        with self.assertRaises(CoreError):
            analyze_can(Path(self.temp.name) / 'missing')
        path = self.log('(1.000000) can0 123#AA')
        path.write_bytes(b'\xff')
        with self.assertRaises(CoreError):
            analyze_can(path)
        for text in ['(1.000000) can0', '(1.000000) can0 123#A', '(1.000000) can0 123#00_8']:
            with self.subTest(text=text), self.assertRaises(CoreError):
                analyze_can(self.log(text))

    def test_distribution_normalization_and_extended_identity(self):
        a = self.log('(1.000000) can0 123#AA', 'a')
        b = self.log('(1.000000) can0 123#AA\n(2.000000) can0 123#AA\n(2.000000) can0 00000123#AA', 'b')
        result = compare_can(a, b)
        self.assertFalse(result['common'][0]['payload_distribution_changed'])
        self.assertEqual(result['only_second'][0]['id'], '00000123')


if __name__ == '__main__':
    unittest.main()
