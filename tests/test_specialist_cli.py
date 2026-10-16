import json,subprocess,sys,tempfile,unittest
from pathlib import Path
class SpecialistCLITests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.inputs=self.root/'inputs';self.inputs.mkdir()
  self.home=self.root/'state'
  self.case=self.cli('investigate','--project','lab','--objective','Specialist controls','--scope',str(self.inputs),'--owner','owner','--authorization','Synthetic offline tests')['id']
 def cli(self,*args):
  r=subprocess.run([sys.executable,'-m','cyber_core','--home',str(self.home),*args],capture_output=True,text=True,timeout=60)
  self.assertEqual(r.returncode,0,r.stderr)
  return json.loads(r.stdout)
 def test_firmware_and_can_with_report(self):
  file=self.inputs/'control.hex';file.write_text(':0400000001020304F2\n:00000001FF\n')
  r=self.cli('analyze-firmware',self.case,str(file))
  self.assertEqual(r['firmware']['format'],'intel_hex');self.assertTrue(r['copy_verified'])
  log=self.inputs/'can.log';log.write_text('(1.000000) can0 123#0102\n(1.010000) can0 123#0304\n')
  self.assertEqual(self.cli('analyze-can',self.case,str(log))['can']['frame_count'],2)
  self.assertIn('intel_hex',Path(self.cli('report',self.case)['path']).read_text())
 def test_compare_sources_stays_in_scope(self):
  a=self.inputs/'a.bin';b=self.inputs/'b.bin'
  a.write_bytes(b'abc');b.write_bytes(b'axc')
  r=self.cli('analyze-firmware',self.case,str(a),'--compare-to',str(b))
  self.assertEqual(r['firmware_comparison']['differing_bytes'],1)
  self.assertTrue(r['secondary']['copy_verified'])
  self.assertEqual(a.read_bytes(),b'abc');self.assertEqual(b.read_bytes(),b'axc')
 def test_scientific_resolution(self):
  file=self.inputs/'known.bin';file.write_bytes(b'abc')
  task=self.cli('analyze-file',self.case,str(file))['task_id']
  hyp=self.cli('hypothesis','add',self.case,'--statement','Control has three bytes','--author','a')['id']
  checks=self.inputs/'checks.json';checks.write_text('[{"field":"size","op":"eq","value":3}]')
  exp=self.cli('experiment','plan',self.case,hyp,'--name','Size','--criterion','Three bytes','--author','a','--tool','analyze-file','--assertions-file',str(checks))['id']
  run=self.cli('experiment','evaluate',self.case,exp,'--task',task,'--operator','a')['id']
  self.cli('experiment','review',self.case,run,'--reviewer','b','--decision','accepted','--reason','Independent check')
  r=self.cli('verify',self.case,'--state','RESOLVIDO','--actor','owner','--reason','Known size')
  self.assertTrue(r['validated'])
  self.assertEqual(self.cli('history','--query','three')['matches'][0]['id'],self.case)
