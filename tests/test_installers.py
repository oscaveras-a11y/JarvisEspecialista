"""NSIS extraction contracts use generated lab installers only."""
import hashlib
import importlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

def module(test):
    try:
        return importlib.import_module('cyber_core.installers')
    except ImportError:
        test.fail('NSIS static extraction module is not implemented')

class InstallerContracts(unittest.TestCase):
    def test_unsafe_archive_paths_are_rejected(self):
        api = module(self)
        for value in ('../VisionFT.exe', '/VisionFT.exe', 'C:/VisionFT.exe',
                      'Firmwares/../x', 'Firmwares/a:vftw', 'CON', 'a\\b',
                      'Firmwares/a. ', 'a//b', '-x'):
            with self.subTest(path=value), self.assertRaises(Exception):
                api.safe_member(value)

    def test_nsis_listing_validates_size_and_collisions(self):
        api = module(self)
        text = '7-Zip lab\nType = Nsis\n----------\nPath = VisionFT.exe\nSize = 3\n\n'
        self.assertEqual(api.parse_listing(text, 10, 100)[0]['size'], 3)
        for bad in (text.replace('Size = 3', 'Size = -1'),
                    text + 'Path = visionft.EXE\nSize = 3\n\n',
                    text.replace('Type = Nsis', 'Type = zip')):
            with self.assertRaises(Exception):
                api.parse_listing(bad, 10, 100)

@unittest.skipUnless(os.environ.get('CYBER_REQUIRE_NSIS') == '1', 'Real NSIS runner')
class RealInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / 'scope'
        self.scope.mkdir()
        (self.scope / 'desktop').write_bytes(b'MZ synthetic desktop only')
        (self.scope / 'firmware').write_bytes(b'FTW2 synthetic unknown-layout bytes')
        (self.scope / 'excluded').write_bytes(b'synthetic excluded file')
        script = self.scope / 'fixture.nsi'
        script.write_text('Name "Lab"\nOutFile "lab.exe"\nSetCompressor /SOLID lzma\n'
                         'Section\nSetOutPath "$INSTDIR"\n'
                         'File /oname=VisionFT.exe "desktop"\n'
                         'File /oname=excluded.txt "excluded"\n'
                         'SetOutPath "$INSTDIR\\Firmwares"\n'
                         'File /oname=lab.vftw "firmware"\nSectionEnd\n')
        subprocess.run([shutil.which('makensis'), '-V1', str(script)], cwd=self.scope, check=True)
        self.source = self.scope / 'lab.exe'
        self.expected = hashlib.sha256(self.source.read_bytes()).hexdigest()
        from cyber_core.service import Core
        self.core = Core(self.root / 'state', timeout=180)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('lab', 'NSIS static extraction', str(self.scope), 'owner', 'Synthetic lab')
        self.exe = str(Path(shutil.which('7z')).resolve())

    def test_selected_extraction_hashes_and_core_report(self):
        api = module(self)
        result = api.inspect_installer(self.core, self.case, self.source, seven_zip=self.exe,
                                       extract=True, max_extracted_bytes=1024*1024)
        records = {x['member']: x for x in result['installer']['extracted']}
        self.assertEqual(set(records), {'VisionFT.exe', 'Firmwares/lab.vftw'})
        for name, fixture in (('VisionFT.exe', 'desktop'), ('Firmwares/lab.vftw', 'firmware')):
            raw = (self.scope / fixture).read_bytes()
            record = records[name]
            self.assertEqual(record['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(Path(record['path']).read_bytes(), raw)
            self.assertEqual(record['origin_sha256'], self.expected)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.expected)
        self.assertTrue(self.core.verify_audit(self.case))
        self.assertIn('nsis_installer', self.core.report(self.case).read_text())
        self.assertIn('7-Zip', result['installer']['tool_version'])

    def test_list_only_and_extraction_limit(self):
        api = module(self)
        result = api.inspect_installer(self.core, self.case, self.source, seven_zip=self.exe)
        self.assertEqual(result['installer']['extracted'], [])
        with self.assertRaises(Exception):
            api.inspect_installer(self.core, self.case, self.source, seven_zip=self.exe,
                                  extract=True, max_extracted_bytes=1)
        self.assertFalse(list((self.core.home / 'cases' / self.case).glob('nsis-stage-*')))

if __name__ == '__main__':
    unittest.main()
