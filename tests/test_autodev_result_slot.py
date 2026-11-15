import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aotg.autodev.coordinator import Result
from aotg.autodev.result_slot import LocalResultSlot, ResultSlotError

STAMP = "2026-01-01T10:00:00+00:00"
BASE, HEAD = "1" * 40, "2" * 40
CLAIM = Result("claim_started", "reserved", "UOB-50", STAMP, BASE).redacted()
DRAFT = Result("draft_pr", "draft-verified", "UOB-50", STAMP, BASE, HEAD, 5).redacted()


class ResultSlotTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.parent = Path(tmp.name).resolve() / "private-results"
        self.parent.mkdir(mode=0o700)
        self.path = self.parent / "latest.json"
        self.slot = LocalResultSlot(self.path)

    def test_fixed_slot_replaces_then_reads_back(self):
        with self.assertRaises(ResultSlotError):
            self.slot.read()
        self.slot.write(CLAIM)
        self.assertEqual(CLAIM, self.slot.read())
        self.slot.write(DRAFT)
        self.assertEqual(DRAFT, self.slot.read())
        self.assertEqual([self.path], list(self.parent.iterdir()))

    def test_accepts_all_coordinator_execution_results(self):
        cases = {
            "blocked": ["candidate-rejected", "prepublication-changed", "worker-timeout"],
            "unknown": [
                "claim-result-unconfirmed", "branch-unconfirmed",
                "worker-result-unconfirmed", "prepublication-state-unconfirmed",
                "draft-unconfirmed", "result-unconfirmed",
            ],
        }
        for status, reasons in cases.items():
            for reason in reasons:
                with self.subTest(reason=reason):
                    result = {**CLAIM, "status": status, "reason": reason}
                    self.slot.write(result)
                    self.assertEqual(result, self.slot.read())

    def test_rejects_unredacted_or_inconsistent_results(self):
        self.slot.write(CLAIM)
        original = self.path.read_bytes()
        for overrides in (
            {"extra": "example non-public info"},
            {"reason": "another-free-text-reason"},
            {"reason": "C:/private/run.log"},
            {"issue": "../report"},
            {"base": ""},
            {"status": ["claim_started"]},
            {"status": "draft_pr", "reason": "draft-verified"},
            {"time_utc": "2026-01-01T19:00:00+09:00"},
            {"time_utc": "2026-01-01T10:00:00.001+00:00"},
            {"head": BASE, "pr": 5},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ResultSlotError):
                self.slot.write({**CLAIM, **overrides})
        with self.assertRaises(ResultSlotError):
            self.slot.write({**DRAFT, "pr": True})
        self.assertEqual(original, self.path.read_bytes())

    def test_corrupt_old_state_blocks_replacement(self):
        for invalid in (
            b'{"status":"blocked"}',
            b"w" * 1025,
            json.dumps(CLAIM, indent=2).encode(),
            f'{json.dumps(CLAIM)[:-1]},"status":"claim_started"}}'.encode(),
        ):
            with self.subTest(invalid=invalid[:30]):
                self.path.touch(mode=0o600)
                self.path.write_bytes(invalid)
                with self.assertRaises(ResultSlotError):
                    self.slot.read()
                with self.assertRaises(ResultSlotError):
                    self.slot.write(CLAIM)
                self.assertEqual(invalid, self.path.read_bytes())
                self.path.unlink()

    def test_stale_lock_or_pending_update_blocks_without_deletion(self):
        self.slot.write(CLAIM)
        for path in (self.slot.lock, self.slot.pending):
            with self.subTest(path=path.name):
                path.touch(mode=0o600)
                with self.assertRaises(ResultSlotError):
                    self.slot.read()
                with self.assertRaises(ResultSlotError):
                    self.slot.write(DRAFT)
                self.assertTrue(path.is_file())
                path.unlink()
                self.assertEqual(CLAIM, self.slot.read())

    def test_failed_atomic_replace_preserves_original(self):
        self.slot.write(CLAIM)
        with patch("aotg.autodev.result_slot.os.replace", side_effect=OSError):
            with self.assertRaises(ResultSlotError):
                self.slot.write(DRAFT)
        self.assertEqual(CLAIM, self.slot.read())
        self.assertEqual([self.path], list(self.parent.iterdir()))

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics")
    def test_private_modes_and_no_link_targets(self):
        self.slot.write(CLAIM)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.path.chmod(0o644)
        with self.assertRaises(ResultSlotError):
            self.slot.write(DRAFT)
        self.path.chmod(0o600)
        other = self.parent / "other.json"
        other.symlink_to(self.path)
        linked = LocalResultSlot(other)
        with self.assertRaises(ResultSlotError):
            linked.write(DRAFT)
        self.assertEqual(CLAIM, self.slot.read())
        self.parent.chmod(0o755)
        with self.assertRaises(ResultSlotError):
            self.slot.read()

    def test_does_not_create_missing_directory(self):
        path = self.parent / "missing" / "latest.json"
        with self.assertRaises(ResultSlotError):
            LocalResultSlot(path).write(CLAIM)
        self.assertFalse(path.parent.exists())


if __name__ == "__main__":
    unittest.main()
