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


@unittest.skipUnless(sys.platform.startswith("linux") and getattr(os, "geteuid", lambda: 0)() != 0,
                     "Archived collector requires a nonroot Linux identity")
class OfflineCollectorJournalChainTests(unittest.TestCase):
    """Actual archived collector/receiver with synthetic files and transport only.

    Nested summary is a fixture, not private worker persistence. The manifest
    is an independent synthetic oracle, not an authenticated runtime receipt.
    """

    def test_stopped_journal_and_summary_recovered_once_without_promotion(self):
        import importlib.util

        from observation_evidence_join import join_observation

        collector = _SOURCE.parent / "comparison-collector"
        index = json.loads((collector / "source-index.json").read_bytes())
        entries = {x["path"]: x for x in index["files"]}
        for name in ("collector_remote.py", "collect_comparison.py", "test_collector.py"):
            raw = (collector / name).read_bytes()
            self.assertEqual(len(raw), entries[name]["bytes"], name)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             entries[name]["published_sha256"], name)
        spec = importlib.util.spec_from_file_location(
            "_aotg_archive_collector_fixture", collector / "test_collector.py")
        module = importlib.util.module_from_spec(spec)
        old_path = sys.path[:]
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path[:] = old_path

        for case, expected in (
            ("consistent", "strict-chain-and-accounting-consistent"),
            ("producer-contradiction", "summary-unresolved-reservation"),
            ("summary-substituted", "summary-manifest-mismatch"),
            ("log-cap-exact", "strict-chain-and-accounting-consistent"),
            ("log-cap-over", "strict-chain-and-accounting-consistent"),
        ):
            with self.subTest(case=case):
                fixture = module.Fixture()
                try:
                    fixture.setUp()
                    self._run_case(module.R, fixture, join_observation, case, expected)
                finally:
                    fixture.doCleanups()

    def _run_case(self, protocol, fixture, join, case, expected):
        journal_path = fixture.path("task/resource-observations.jsonl")
        context_reads = []
        with _FsyncedFixture(journal_path) as stream:
            journal = ObservationJournal(stream, origin=0, deadline=10,
                                         run_id=fixture.request["run_id"])
            journal.start({"phase": "startup-anchor", "anchor": {"pswpout": 115}}, 0)
            journal.observed({"phase": "observed", "sequence": 0,
                              "sample": {"pswpout": 158}}, 0, force=True)
            journal.verdict({"phase": "guard-result", "sequence": 0,
                             "guard_verdict": "rejected"}, 0)
            journal.context_after_primary_flush(lambda _: context_reads.append("forbidden"))
            self.assertEqual((stream.writes, stream.syncs), (3, 3))
            adapter = journal.summary()
        self.assertEqual(context_reads, [])
        original = journal_path.read_bytes()
        self.assertEqual(original.count(b"\n"), 3)
        if case == "producer-contradiction":
            adapter["reserved_rows"] = 1
        adapter_bytes = protocol.canon(adapter)
        # Independent synthetic oracle fixed BEFORE collection.
        manifest = {
            "artifact": "aotg-observation-recovery-manifest", "version": 1,
            "run_id": fixture.request["run_id"],
            "plan_sha256": fixture.request["worker_plan_sha256"],
            "journal": {"sha256": protocol.sha(original), "bytes": len(original), "rows": 3},
            "adapter_summary": {"sha256": protocol.sha(adapter_bytes),
                                "bytes": len(adapter_bytes)},
        }
        if case == "summary-substituted":
            adapter["reserved_rows"] = 1
        fixture.summary.update(status="stopped", arms=[], synthetic_adapter_summary=adapter)
        outer = protocol.canon(fixture.summary)
        fixture.path("task/summary.json").write_bytes(outer)
        # No completed arms: missing records remain incomplete.
        for label, _, _ in protocol.inventory():
            if label.startswith(("task/arm-", "task/done-")):
                fixture.path(label).unlink()
        # Preserve evidence of a stopped run, even when either private log
        # exceeds the collector's fixed per-file budget. Never truncate a log
        # and treat the retained prefix as a complete capture.
        log_bodies = {}
        if case in ("log-cap-exact", "log-cap-over"):
            caps = {label: cap for label, cap, _ in protocol.inventory()}
            size = 262144 + int(case == "log-cap-over")
            for name, fill in (("server-private.log", b"S"), ("engine-private.log", b"E")):
                label = f"task/arm-000/logs/{name}"
                self.assertEqual(caps[label], 262144)
                log_bodies[label] = fill * size
                fixture.path(label).write_bytes(log_bodies[label])
                fixture.path(label).chmod(0o600)
        rows, remote = fixture.capture()
        self.assertEqual(remote["status"], "incomplete")
        self.assertEqual(remote["complete_files"], 5 + (len(log_bodies) if case == "log-cap-exact" else 0))
        self.assertEqual(remote["attempted_files"], 517)
        result = fixture.run_local(rows)
        self.assertEqual(result["transport_attempts"], 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("remote_collection_incomplete", result["errors"])
        self.assertFalse(result["independent_restoration_verified"])
        self.assertFalse(result["quality_accepted"])
        self.assertFalse(result["adoption_accepted"])
        capture = result["capture"]
        self.assertEqual(capture["final"], remote)
        self.assertEqual(capture["header"]["run_id"], manifest["run_id"])
        self.assertEqual(capture["header"]["worker_plan_sha256"], manifest["plan_sha256"])
        entries = {x["label"]: x for x in capture["files"]}
        output = fixture.root / "output"

        def recovered(label):
            entry = entries[label]
            self.assertEqual(entry["status"], "captured")
            self.assertTrue(entry["local_file"].endswith(".raw"))
            raw = (output / entry["local_file"]).read_bytes()
            self.assertEqual((len(raw), protocol.sha(raw)), (entry["bytes"], entry["sha256"]))
            return raw

        for label, body in log_bodies.items():
            self.assertEqual(fixture.path(label).read_bytes(), body)
            entry = entries[label]
            if case == "log-cap-exact":
                self.assertEqual(recovered(label), body)
                self.assertEqual(entry["read_bytes"], len(body))
            else:
                self.assertEqual(entry["status"], "incomplete")
                self.assertEqual(entry["reason"], "file_byte_limit")
                self.assertEqual((entry["read_bytes"], entry["bytes"]), (0, 0))
                self.assertIsNone(entry["sha256"])
                self.assertEqual(entry["partial_sha256"], protocol.sha(b""))
                self.assertTrue(entry["local_file"].endswith(".partial"))
                self.assertEqual((output / entry["local_file"]).read_bytes(), b"")

        received_journal = recovered("task/resource-observations.jsonl")
        received_outer = recovered("task/summary.json")
        self.assertEqual(received_journal, original)
        self.assertEqual(entries["task/resource-observations.jsonl"]["records"], 3)
        self.assertEqual(received_outer, outer)
        self.assertEqual(remote["protected_before"], remote["protected_after"])
        self.assertEqual(remote["protected_before"]["worker_summary_sha256"],
                         protocol.sha(received_outer))
        # Canonicalizing the nested object is only a test representation,
        # not a standalone adapter-summary file receipt.
        recovered_summary = protocol.canon(json.loads(received_outer)["synthetic_adapter_summary"])
        joined = join(received_journal, recovered_summary, trusted_manifest=manifest,
                      expected_run_id=fixture.request["run_id"],
                      expected_plan_sha256=fixture.request["worker_plan_sha256"])
        self.assertEqual(joined["reason"], expected, joined)
        self.assertEqual(joined["status"], "joined-observation-consistent"
                         if expected == "strict-chain-and-accounting-consistent" else "incomplete")
        for key in ("runtime_qualified", "independent_restore_verified",
                    "quality_accepted", "authorizes_retry", "root_cause_proven"):
            self.assertIs(joined[key], False)


if __name__ == "__main__":
    unittest.main()
