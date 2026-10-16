"""End-to-end synthetic demonstration. All operational files stay in a temp folder."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cyber_core.errors import CoreError
from cyber_core.service import Core


def main():
    root = Path(tempfile.mkdtemp(prefix='cyber-core-synthetic-'))
    inputs = root / 'inputs'
    inputs.mkdir()
    source = inputs / 'synthetic.bin'
    binary = b'\x7fELF' + bytes(range(256)) * 128
    source.write_bytes(binary)
    digest = hashlib.sha256(binary).hexdigest()
    core = Core(root / 'protected-state')
    steps = []
    try:
        case = core.investigate('synthetic-laboratory', 'Validate static analysis and known-key recovery', str(inputs), 'synthetic-operator', 'Explicit authorization for generated laboratory files, including AES recovery', recovery=True)
        steps.append('investigation_created_with_explicit_authorization')
        core.enqueue(case, source)
        core.pause(case)
        core.close()
        core = None
        env = dict(os.environ)
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
        for command in (['resume', case], ['run', case]):
            run = subprocess.run([sys.executable, '-m', 'cyber_core', '--home', str(root / 'protected-state'), *command], capture_output=True, text=True, env=env, timeout=90)
            if run.returncode:
                raise RuntimeError('New-process resume failed: ' + run.stderr)
        core = Core(root / 'protected-state')
        steps.append('paused_closed_reopened_and_resumed_in_new_processes')
        result = core.results(case)[0]
        assert result['sha256'] == digest
        assert source.read_bytes() == binary
        assert result['format'] == 'ELF signature'
        assert 7.99 < result['entropy'] <= 8
        assert core.hypotheses(case) and core.checkpoints(case)
        assert core.run_one(case) is None
        steps.extend(['signature_identified', 'sha256_verified', 'entropy_measured', 'hypothesis_and_experiment_recorded', 'results_and_checkpoint_persisted', 'original_unchanged_and_no_duplicate'])
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        plaintext = b'%PDF-1.7\nSynthetic authorized recovery.\n'
        encrypted = inputs / 'synthetic.ccaes'
        encrypted.write_bytes(b'CCAES1' + nonce + AESGCM(key).encrypt(nonce, plaintext, b'CCAES1'))
        recovered = core.recover(case, encrypted, key, expected_sha256=hashlib.sha256(plaintext).hexdigest(), expected_format='PDF signature')
        assert Path(recovered['output']).read_bytes() == plaintext
        steps.append('aes256_gcm_authenticated_and_plaintext_sha256_verified')
        refused = core.investigate('synthetic-laboratory', 'Static only', str(inputs), 'synthetic-operator', 'No recovery permission')
        rejected = []
        for label, target, file, material in [('no_recovery_authorization', refused, encrypted, key), ('wrong_key', case, encrypted, b'x' * 32), ('invalid_key_length', case, encrypted, b'x')]:
            try:
                core.recover(target, file, material)
            except CoreError:
                rejected.append(label)
            else:
                raise AssertionError('Unauthorized or invalid recovery accepted')
        try:
            core.investigate('x', 'x', '', 'owner', 'authorization')
        except CoreError:
            rejected.append('missing_scope')
        else:
            raise AssertionError('Missing scope accepted')
        assert len(rejected) == 4
        assert core.verify_audit(case)
        assert key.hex() not in repr(core.audit(case))
        report = core.report(case)
        steps.extend(['unauthorized_and_invalid_recovery_rejected', 'audit_integrity_verified_and_secret_not_logged', 'technical_report_generated'])
        output = {'case': case, 'passed_steps': steps, 'rejected': rejected, 'analysis': result,
                  'recovery': recovered, 'report': str(report), 'synthetic_artifacts': str(root),
                  'state': core.get(case)['state'], 'platform_complete': False}
        print(json.dumps(output, indent=2))
        return 0
    finally:
        if core:
            core.close()


if __name__ == '__main__':
    raise SystemExit(main())
