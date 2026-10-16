from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import time
import unittest
from cyber_core.memory import audit
from cyber_core.service import Core


class DelayedReads:
    """Widen the real scheduling window after the predecessor query."""
    def __init__(self, connection):
        self.connection = connection

    @property
    def in_transaction(self):
        return self.connection.in_transaction

    def execute(self, sql, values=()):
        cursor = self.connection.execute(sql, values)
        if sql.startswith('SELECT digest'):
            time.sleep(.1)
        return cursor


class AuditConcurrencyTests(unittest.TestCase):
    def test_append_only_writers_keep_a_single_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = root / 'inputs'
            scope.mkdir()
            core = Core(root / 'state')
            case = core.investigate('x', 'x', str(scope), 'owner', 'lab')
            ready = threading.Barrier(2)

            def append(index):
                other = Core(root / 'state')
                try:
                    ready.wait(timeout=10)
                    with other.db:
                        audit(DelayedReads(other.db), case, 'parallel', {'writer': index})
                finally:
                    other.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(append, n) for n in range(2)]
                for future in futures:
                    future.result(timeout=30)
            try:
                self.assertTrue(core.verify_audit(case))
                self.assertEqual(sum(a['event'] == 'parallel' for a in core.audit(case)), 2)
            finally:
                core.close()
