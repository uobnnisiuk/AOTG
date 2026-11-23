"""Finite, offline evidence chain using the public PR38 adapter and reader only.

This fixture exercises local flush/fsync and independent file re-open, NOT
private worker integration, production durability, collection, or real restore.
No process/service/model/remote operation is performed.
"""

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_SOURCE = Path(__file__).resolve().parents[1] / "docs" / "field-notes" / "memory-context-candidate"
sys.path.insert(0, str(_SOURCE))
from observation_journal import ObservationJournal  # noqa: E402
from verify_observation_journal import JournalIntegrityError, verify_stream  # noqa: E402


class _FsyncedFixture:
    """Test-only text stream: fsync after each journal flush, with a fault seam."""

    def __init__(self, path, *, fail_write_number=None):
        self.file = path.open("w", encoding="ascii", newline="\n")
        self.writes = 0
        self.syncs = 0
        self.fail_write_number = fail_write_number

    def write(self, value):
        self.writes += 1
        if self.writes == self.fail_write_number:
            raise OSError("synthetic-guard-write-failure")
        return self.file.write(value)

    def flush(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        self.syncs += 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.file.close()


def _stub_receipt(path):
    """A durable *synthetic* notification, never a machine restore result."""
    record = {"status": "incomplete", "synthetic_restore_stub_called": True,
              "real_machine_restored": False, "runtime_qualified": False}
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    with path.open("wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return raw


class OfflineDurableJournalPipelineTests(unittest.TestCase):
    RUN = "offline-synthetic-rejection"

    def _start_and_observe(self, j):
        j.start({"phase": "startup-anchor", "anchor": {"pswpout": 115}}, 0)
        j.observed({"phase": "observed", "sequence": 0,
                    "sample": {"pswpout": 158}}, 0, force=True)

    def test_synthetic_guard_stop_fsync_readback_and_stub_receipt(self):
        with tempfile.TemporaryDirectory(prefix="aotg-public-evidence-") as directory:
            root = Path(directory)
            journal_path = root / "observations.jsonl"
            receipt_path = root / "synthetic-restore.jsonl"
            context_reads = []
            with _FsyncedFixture(journal_path) as stream:
                j = ObservationJournal(stream, origin=0, deadline=10, run_id=self.RUN)
                self._start_and_observe(j)
                j.verdict({"phase": "guard-result", "sequence": 0,
                           "guard_verdict": "rejected"}, 0)
                self.assertEqual(j.stopped_reason, "guard-rejected")
                self.assertIsNone(j.context_after_primary_flush(
                    lambda _: context_reads.append("forbidden")))
                self.assertEqual((stream.writes, stream.syncs), (3, 3))
            _stub_receipt(receipt_path)

            # Reopen the actual test files; do not inspect an in-memory buffer.
            raw = journal_path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            with journal_path.open("rb") as source:
                result = verify_stream(source, expected_run_id=self.RUN)
            self.assertEqual(hashlib.sha256(journal_path.read_bytes()).hexdigest(), digest)
            self.assertEqual((result["rows"], result["primary_ticks"],
                              result["context_rows"]), (3, 1, 0))
            self.assertTrue(result["rejected_guard_recorded"])
            self.assertTrue(result["structure_consistent"])
            self.assertFalse(result["runtime_qualified"])
            self.assertFalse(result["authorizes_retry"])
            self.assertEqual(context_reads, [])
            self.assertEqual(len(raw.splitlines()), 3)
            receipt = json.loads(receipt_path.read_bytes())
            self.assertTrue(receipt["synthetic_restore_stub_called"])
            self.assertFalse(receipt["real_machine_restored"])
            self.assertEqual(receipt["status"], "incomplete")
            with self.assertRaises(JournalIntegrityError):
                verify_stream(io.BytesIO(raw), expected_run_id="another-run")
            tampered = raw.replace(b'"pswpout":158', b'"pswpout":159', 1)
            self.assertNotEqual(tampered, raw)
            with self.assertRaises(JournalIntegrityError):
                verify_stream(io.BytesIO(tampered), expected_run_id=self.RUN)

    def test_failed_guard_write_does_not_become_recovered_evidence(self):
        with tempfile.TemporaryDirectory(prefix="aotg-public-writefault-") as directory:
            root = Path(directory)
            journal_path = root / "observations.jsonl"
            receipt_path = root / "synthetic-restore.jsonl"
            context_reads = []
            recovery_calls = []
            with _FsyncedFixture(journal_path, fail_write_number=3) as stream:
                j = ObservationJournal(stream, origin=0, deadline=10, run_id=self.RUN)
                try:
                    self._start_and_observe(j)
                    with self.assertRaisesRegex(OSError, "synthetic-guard-write-failure"):
                        j.verdict({"phase": "guard-result", "sequence": 0,
                                   "guard_verdict": "rejected"}, 0)
                finally:
                    recovery_calls.append("synthetic-only")
                    _stub_receipt(receipt_path)
                self.assertEqual((stream.writes, stream.syncs), (3, 2))
                self.assertEqual(j.stopped_reason, "observation-write-failed")
                self.assertIsNone(j.context_after_primary_flush(
                    lambda _: context_reads.append("forbidden")))
            self.assertEqual(recovery_calls, ["synthetic-only"])
            self.assertEqual(context_reads, [])
            persisted = journal_path.read_bytes()
            self.assertEqual(len(persisted.splitlines()), 2)
            self.assertNotIn(b"guard-result", persisted)
            with self.assertRaises(JournalIntegrityError):
                verify_stream(io.BytesIO(persisted), expected_run_id=self.RUN)
            receipt = json.loads(receipt_path.read_bytes())
            self.assertEqual(receipt["status"], "incomplete")
            self.assertFalse(receipt["real_machine_restored"])
            self.assertFalse(receipt["runtime_qualified"])


if __name__ == "__main__":
    unittest.main()
