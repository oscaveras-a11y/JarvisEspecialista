"""NSIS extraction contracts use generated lab installers only."""
import hashlib
import importlib
import os
from pathlib import Path
import sys
import time
from cyber_core.errors import CoreError
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
            with self.subTest(path=value), self.assertRaises(CoreError):
                api.safe_member(value)

    def test_missing_solid_size_stays_unknown_and_duplicate_fields_fail(self):
        api = module(self)
        listing = '7-Zip lab\nType = Nsis\n----------\nPath = Firmwares/a.vftw\nSize = \nOffset = 0\n\n'
        self.assertIsNone(api.parse_listing(listing, 10, 100)[0]['size'])
        for bad in (listing.replace('Size = \n', ''),
                    listing.replace('Offset = 0', 'Size = 3'),
                    listing.replace('Offset = 0', 'Symbolic Link = outside')):
            with self.assertRaises(CoreError):
                api.parse_listing(bad, 10, 100)

    def test_cli_wires_installer_limits(self):
        from cyber_core.cli import parser
        args = parser().parse_args(['installer','case','input','--seven-zip','/usr/bin/7z','--extract'])
        self.assertEqual(args.command, 'installer')
        self.assertTrue(args.extract)
        self.assertEqual(args.max_extracted_bytes, 1073741824)

    def test_nsis_listing_validates_size_and_collisions(self):
        api = module(self)
        text = '7-Zip lab\nType = Nsis\n----------\nPath = VisionFT.exe\nSize = 3\n\n'
        self.assertEqual(api.parse_listing(text, 10, 100)[0]['size'], 3)
        for bad in (text.replace('Size = 3', 'Size = -1'),
                    text + 'Path = visionft.EXE\nSize = 3\n\n',
                    text.replace('Type = Nsis', 'Type = zip')):
            with self.assertRaises(CoreError):
                api.parse_listing(bad, 10, 100)

@unittest.skipUnless(sys.platform == 'linux', 'Linux resource-limited backend')
class InstallerProcessLimits(unittest.TestCase):
    def test_output_stderr_and_deadline_fail_closed(self):
        module(self)
        from cyber_core.installers.child import run
        for program, maximum, seconds in (
            ("import sys;sys.stdout.write('x'*10000)", 32, 5),
            ("import sys;sys.stderr.write('x'*100000)", 32, 5),
            ("import time;time.sleep(2)", 32, .1),
        ):
            with self.subTest(program=program), tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(CoreError):
                    run([sys.executable,'-I','-c',program], Path(folder),
                        time.monotonic()+seconds, maximum, 128*1024*1024)

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

    def test_real_listing_contract(self):
        api = module(self)
        listing = subprocess.check_output([self.exe,'l','-slt','-sccUTF-8','--',str(self.source)], text=True)
        print('SYNTHETIC_NSIS_LISTING_BEGIN', flush=True)
        print(listing, flush=True)
        print('SYNTHETIC_NSIS_LISTING_END', flush=True)
        api.parse_listing(listing, 1000, 2*1024**3)

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
        with self.assertRaises(CoreError):
            api.inspect_installer(self.core, self.case, self.source, seven_zip=self.exe,
                                  extract=True, max_extracted_bytes=1)
        self.assertFalse(list((self.core.home / 'cases' / self.case).glob('nsis-stage-*')))

if __name__ == '__main__':
    unittest.main()
