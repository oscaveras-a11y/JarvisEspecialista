from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from cyber_core.service import Core, CoreError
from cyber_core.cryptanalysis.assessment import assess


def zip_header(flag=0, method=8, extra=b''):
    return struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, flag, method, 0, 0, 0, 0, 0, 1, len(extra)) + b'a' + extra


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / 'wrong-extension.txt'

    def inspect(self, data, **kwargs):
        self.file.write_bytes(data)
        return assess(self.file, **kwargs)

    def test_recognizes_multiple_families_without_key(self):
        samples = [(b'%PDF-1.7\n', 'pdf'), (b'7z\xbc\xaf\x27\x1c' + bytes(26), '7z'),
                   (b'Rar!\x1a\x07\x01\x00' + bytes(24), 'rar5'),
                   (b'Rar!\x1a\x07\x00' + bytes(24), 'rar4'),
                   (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + bytes(504), 'ole-cfb'),
                   (b'LUKS\xba\xbe\x00\x02' + bytes(4096), 'luks'),
                   (b'Salted__' + bytes(24), 'openssl-salted'),
                   (b'CCAES1' + bytes(28), 'ccaes1'),
                   (b'\x1f\x8b\x08' + bytes(30), 'gzip'),
                   (b'SQLite format 3\x00' + bytes(100), 'sqlite'),
                   (b'\x7fELF' + bytes(60), 'elf'),
                   (b'MZ' + bytes(62), 'dos-pe'),
                   (b'\x89PNG\r\n\x1a\n' + bytes(32), 'png'),
                   (b'\xff\xd8\xff\xe0' + bytes(32), 'jpeg')]
        for data, family in samples:
            with self.subTest(family=family):
                report = self.inspect(data)
                self.assertEqual(report['format_id'], family)
                self.assertFalse(report['recovery_demonstrated'])
                self.assertTrue(report['next_steps'])

    def test_entropy_does_not_prove_encryption(self):
        result = self.inspect(bytes(range(256)) * 4, entropy=8)
        self.assertEqual(result['encryption_evidence'], 'not_established')
        self.assertEqual(result['format_id'], 'unknown')
        self.assertTrue(any('entropy' in text.lower() for text in result['limitations']))

    def test_zip_encryption_flags_and_aes_extra(self):
        extra = struct.pack('<HHH2sBH', 0x9901, 7, 2, b'AE', 3, 8)
        result = self.inspect(zip_header(flag=1, method=99, extra=extra))
        self.assertEqual(result['encryption_evidence'], 'header_declares_encryption')
        self.assertEqual(result['details']['first_member_aes_strength_bits'], 256)
        self.assertEqual(result['details']['coverage'], 'first_local_header_only')

    def test_clear_zip_member_does_not_clear_entire_archive(self):
        result = self.inspect(zip_header())
        self.assertEqual(result['encryption_evidence'], 'not_established')
        self.assertFalse(result['details']['first_member_encrypted_flag'])
        self.assertIn('Other members', ' '.join(result['limitations']))

    def test_truncated_zip_is_reported_not_crashed(self):
        result = self.inspect(b'PK\x03\x04\x00')
        self.assertEqual(result['format_id'], 'zip')
        self.assertEqual(result['metadata_status'], 'truncated_or_outside_sample')

    def test_fake_pdf_marker_is_only_a_hint(self):
        result = self.inspect(b'%PDF-1.7\nstream\n/Encrypt\nendstream')
        self.assertEqual(result['encryption_evidence'], 'marker_only')
        self.assertFalse(result['format_validated'])

    def test_sample_limit_is_enforced(self):
        result = self.inspect(b'%PDF-1.7\n' + bytes(5000), max_sample=128)
        self.assertEqual(result['sample_bytes'], 128)
        self.assertTrue(result['sample_truncated'])


class BatchRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.core = Core(self.root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('client-demo', 'Unknown files, no key supplied', str(self.inputs), 'owner', 'Explicit authorized recovery assessment', recovery=True)

    def test_batch_works_without_key_and_persists_in_report(self):
        (self.inputs / 'a.bin').write_bytes(b'%PDF-1.7\n')
        (self.inputs / 'b.bin').write_bytes(b'CCAES1' + bytes(28))
        batch = self.core.assess_recovery(self.case, self.inputs)
        self.assertEqual(len(batch['results']), 2)
        self.assertEqual({r['recovery_assessment']['format_id'] for r in batch['results']}, {'pdf', 'ccaes1'})
        self.assertTrue(all(t['status'] == 'done' for t in self.core.tasks(self.case)))
        self.assertEqual(self.core.get(self.case)['recovery_attempts'], 0)
        self.assertIn('recovery_assessment', self.core.report(self.case).read_text())
        self.assertTrue(self.core.verify_audit(self.case))

    def test_file_limit_rejects_before_queueing(self):
        for name in ('a', 'b', 'c'):
            (self.inputs / name).write_bytes(b'x')
        with self.assertRaises(CoreError):
            self.core.assess_recovery(self.case, self.inputs, max_files=2)
        self.assertFalse(self.core.tasks(self.case))

    def test_explicit_recovery_authorization_is_required(self):
        path = self.inputs / 'a'
        path.write_bytes(b'x')
        case = self.core.investigate('x', 'x', str(self.inputs), 'owner', 'Static only')
        with self.assertRaises(CoreError):
            self.core.assess_recovery(case, path)

    def test_outside_scope_is_rejected(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'secret').write_bytes(b'secret')
        with self.assertRaises(CoreError):
            self.core.assess_recovery(self.case, outside)

    def test_queued_assessment_rechecks_revocation(self):
        path = self.inputs / 'a'
        path.write_bytes(b'x')
        batch = self.core.assess_recovery(self.case, path, queue_only=True)
        self.assertEqual(len(batch['tasks']), 1)
        self.core.revoke(self.case)
        with self.assertRaises(CoreError):
            self.core.run_one(self.case)
        self.assertFalse(self.core.results(self.case))

    def test_recursive_scan_is_opt_in_and_bounded(self):
        sub = self.inputs / 'sub'
        sub.mkdir()
        (sub / 'a').write_bytes(b'x')
        self.assertEqual(self.core.assess_recovery(self.case, self.inputs)['results'], [])
        batch = self.core.assess_recovery(self.case, self.inputs, recursive=True)
        self.assertEqual(len(batch['results']), 1)

    def test_queued_batch_size_limit_survives_input_growth_and_resume(self):
        path = self.inputs / 'growing'
        path.write_bytes(b'x')
        self.core.assess_recovery(self.case, path, queue_only=True, max_total_bytes=4)
        path.write_bytes(b'x' * 64)
        other = Core(self.root / 'state')
        self.addCleanup(other.close)
        with self.assertRaises(CoreError):
            other.run_one(self.case)
        self.assertFalse(other.results(self.case))

    def test_pause_preserves_accurate_pending_count(self):
        for name in ('a', 'b', 'c'):
            (self.inputs / name).write_bytes(b'x')
        original = self.core.run_one

        def pause_after_one(*args, **kwargs):
            result = original(*args, **kwargs)
            self.core.pause(self.case)
            return result

        with patch.object(self.core, 'run_one', side_effect=pause_after_one):
            batch = self.core.assess_recovery(self.case, self.inputs)
        self.assertEqual(len(batch['results']), 1)
        self.assertEqual(len(batch['pending_tasks']), 2)
        self.assertEqual(batch['failures'], [])
