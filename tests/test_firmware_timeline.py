"""Synthetic evidence only: no electoral or proprietary data."""
import importlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout

A='a'*64
B='b'*64

def event(number,digest=A,**extra):
    return dict(id=str(number),device='synthetic-device',component='main',
                source='synthetic-log',time=f'2026-01-01T00:00:{number:02d}+00:00',
                kind='measurement',sha256=digest,**extra)

def raw(events):
    return b''.join(json.dumps(e).encode()+b'\n' for e in events)

class FirmwareTimelineTests(unittest.TestCase):
    def analyze(self,events,**options):
        try:
            module=importlib.import_module('cyber_core.forensics.firmware_timeline')
        except ImportError:
            self.fail('Firmware timeline analyzer missing')
        return module.analyze(io.BytesIO(raw(events)),**options)

    def test_recorded_change_and_return_links_all_three_events(self):
        r=self.analyze([event(1),event(2,B),event(3)])
        self.assertEqual(r['patterns'][0]['events'],['1','2','3'])
        self.assertEqual(r['patterns'][0]['classification'],'recorded_change_and_return')
        self.assertEqual(r['authenticity'],'not_verified')
        self.assertEqual(r['conclusion'],'insufficient_to_determine_fraud')
        self.assertTrue(r['pending'])
        self.assertTrue(r['hypotheses'])

    def test_final_original_alone_does_not_exclude_temporary_change(self):
        r=self.analyze([event(3)])
        self.assertEqual(r['patterns'],[])
        self.assertEqual(r['conclusion'],'insufficient_to_determine_fraud')

    def test_normal_operation_and_access_are_not_firmware_change(self):
        access=event(2);access['kind']='access';access.pop('sha256')
        r=self.analyze([event(1),access,event(3)])
        self.assertEqual(r['patterns'],[])
        self.assertEqual(r['event_counts']['access'],1)

    def test_devices_and_components_are_not_mixed(self):
        middle=event(2,B);middle['component']='radio'
        self.assertEqual(self.analyze([event(1),middle,event(3)])['patterns'],[])
        middle['component']='main';middle['device']='other'
        self.assertEqual(self.analyze([event(1),middle,event(3)])['patterns'],[])

    def test_timezones_are_normalized(self):
        middle=event(2,B);middle['time']='2025-12-31T21:00:02-03:00'
        self.assertEqual(len(self.analyze([event(1),middle,event(3)])['patterns']),1)

    def test_overlapping_clock_uncertainty_prevents_order_claim(self):
        middle=event(2,B,uncertainty_ms=2000)
        r=self.analyze([event(1),middle,event(3)])
        self.assertEqual(r['patterns'],[])
        self.assertIn('ambiguous_clock_order',r['quality_flags'])

    def test_sequence_gaps_reordering_and_explicit_gap_are_visible(self):
        first=event(1,sequence=1)
        second=event(2,B,sequence=3)
        third=event(3,sequence=2)
        gap=event(4);gap['kind']='log_gap';gap.pop('sha256')
        r=self.analyze([first,second,third,gap])
        self.assertIn('sequence_gap',r['quality_flags'])
        self.assertIn('sequence_reversal',r['quality_flags'])
        self.assertIn('declared_log_gap',r['quality_flags'])

    def test_timestamp_reversal_is_reported_even_if_sorted_for_analysis(self):
        r=self.analyze([event(3),event(1),event(2,B)])
        self.assertIn('input_time_reversal',r['quality_flags'])
        self.assertEqual(len(r['patterns']),1)

    def test_duplicate_ids_and_invalid_fields_are_rejected(self):
        for events in ([event(1),event(1)], [dict(event(1),sha256='bad')],
                       [dict(event(1),time='2026-01-01T00:00:01')],
                       [dict(event(1),uncertainty_ms=-1)],
                       [dict(event(1),sequence=True)],
                       [dict(event(1),kind='unknown')]):
            with self.subTest(events=events),self.assertRaises(ValueError):
                self.analyze(events)

    def test_truncation_duplicate_json_keys_and_budget_limits(self):
        module=importlib.import_module('cyber_core.forensics.firmware_timeline')
        for data in (b'{"id":', b'{"id":"a","id":"b"}\n'):
            with self.assertRaises(ValueError):
                module.analyze(io.BytesIO(data))
        for options in ({'max_events':2},{'max_bytes':32},{'max_line_bytes':32}):
            with self.subTest(options=options),self.assertRaises(ValueError):
                self.analyze([event(1),event(2,B),event(3)],**options)
        for options in ({'max_events':True},{'max_seconds':float('nan')},{'max_seconds':0}):
            with self.assertRaises(ValueError):
                self.analyze([event(1)],**options)

    def test_output_is_bounded_and_omissions_explicit(self):
        r=self.analyze([event(i,A if i%2 else B) for i in range(1,50)],max_findings=2)
        self.assertEqual(len(r['patterns']),2)
        self.assertGreater(r['patterns_omitted'],0)

    def test_cancellation_callback_is_checked_while_reading(self):
        module=importlib.import_module('cyber_core.forensics.firmware_timeline')
        count=0
        def check():
            nonlocal count
            count+=1
            if count==3: raise RuntimeError('synthetic cancellation')
        with self.assertRaises(RuntimeError):
            module.analyze(io.BytesIO(raw([event(1),event(2,B),event(3)])),check=check)

    def test_core_cli_persists_evidence_hash_audit_and_report(self):
        from cyber_core.service import Core
        from cyber_core.cli import main
        from cyber_core.operations import saved_operations
        with tempfile.TemporaryDirectory() as folder:
            scope=Path(folder)/'scope';scope.mkdir()
            evidence=scope/'events.jsonl';evidence.write_bytes(raw([event(1),event(2,B),event(3)]))
            home=Path(folder)/'store'
            core=Core(home)
            case=core.investigate('lab','Firmware timeline',str(scope),'owner','Synthetic offline evidence')
            core.close()
            with redirect_stdout(io.StringIO()) as output:
                code=main(['--home',str(home),'firmware-timeline',case,str(evidence)])
            self.assertEqual(code,0)
            result=json.loads(output.getvalue())
            self.assertEqual(result['kind'],'firmware_timeline')
            import hashlib
            self.assertEqual(result['evidence']['sha256'],hashlib.sha256(evidence.read_bytes()).hexdigest())
            core=Core(home)
            try:
                self.assertTrue(core.verify_audit(case))
                self.assertEqual(saved_operations(core,case)[-1]['analysis']['patterns'][0]['events'],['1','2','3'])
                self.assertIn('firmware_timeline',core.report(case).read_text())
                core.pause(case)
                from cyber_core.forensics.firmware_timeline import run_timeline
                from cyber_core.errors import CoreError
                with self.assertRaises(CoreError):run_timeline(core,case,str(evidence))
            finally:core.close()

    def test_non_utf8_input_is_rejected(self):
        module=importlib.import_module('cyber_core.forensics.firmware_timeline')
        for encoding in ('utf-16','utf-32'):
            with self.subTest(encoding=encoding),self.assertRaises(ValueError):
                module.analyze(io.BytesIO(json.dumps(event(1)).encode(encoding)))
