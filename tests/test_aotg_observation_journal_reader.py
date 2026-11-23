"""Independent synthetic, no real guard, model, recovery or service calls."""
import importlib
import io
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "docs" / "field-notes" / "memory-context-candidate"
sys.path.insert(0, str(ROOT))
journal = importlib.import_module("observation_journal")
reader = importlib.import_module("verify_observation_journal")


class IndependentJournalReaderTests(unittest.TestCase):
    def fixture(self, *, rejected=False, context=True):
        stream = io.StringIO()
        j = journal.ObservationJournal(stream, origin=0, deadline=10, run_id="synthetic")
        j.start({"phase": "startup-anchor"}, 0)
        j.observed({"phase": "observed", "sequence": 0, "sample": {"pswpout": 115}}, 0, force=True)
        j.verdict({"phase": "guard-result", "sequence": 0,
                   "guard_verdict": "rejected" if rejected else "passed"}, 0)
        if not rejected and context:
            j.context_after_primary_flush(lambda clk: {"status": "incomplete", "psi": None}, clock=lambda: 0)
        return stream.getvalue().encode("ascii")

    def check(self, content):
        return reader.verify_stream(io.BytesIO(content), expected_run_id="synthetic")

    def assert_invalid(self, data):
        with self.assertRaises(reader.JournalIntegrityError):
            self.check(data)

    def test_passed_context_linkage_but_never_runtime_qualified(self):
        out = self.check(self.fixture())
        self.assertEqual((out["rows"], out["primary_ticks"], out["context_rows"]), (4, 1, 1))
        self.assertTrue(out["structure_consistent"])
        self.assertFalse(out["runtime_qualified"])
        self.assertFalse(out["authorizes_retry"])

    def test_rejected_guard_has_no_context_and_is_not_completion(self):
        out = self.check(self.fixture(rejected=True))
        self.assertTrue(out["rejected_guard_recorded"])
        self.assertTrue(out["run_id_bound"])
        self.assertEqual(out["context_rows"], 0)
        self.assertNotEqual(out["status"], "complete")

    def test_missing_guard_or_selected_context_rejected(self):
        rows = self.fixture().splitlines(keepends=True)
        self.assert_invalid(b"".join(rows[:2]))
        self.assert_invalid(b"".join(rows[:3]))
        self.assert_invalid(b"")

    def test_tamper_pre_guard_sample_breaks_digest(self):
        self.assert_invalid(self.fixture().replace(b"115", b"158", 1))

    def test_mismatched_context_hash_or_run_id(self):
        raw = self.fixture()
        self.assert_invalid(raw.replace(b"synthetic", b"wrong", 1))
        context_hash = raw.splitlines(keepends=True)[3]
        self.assert_invalid(raw.replace(context_hash, context_hash.replace(b'"primary_sha256":"', b'"primary_sha256":"f', 1)))

    def test_duplicate_guard_and_context_after_rejection(self):
        rows = self.fixture().splitlines(keepends=True)
        self.assert_invalid(b"".join(rows[:3] + rows[2:]))
        self.assert_invalid(self.fixture(rejected=True) + rows[3])

    def test_wrong_order_wrong_sequence_and_skipped_context(self):
        rows = self.fixture().splitlines(keepends=True)
        self.assert_invalid(b"".join([rows[0], rows[2], rows[1], rows[3]]))
        self.assert_invalid(self.fixture().replace(b'"sequence":0', b'"sequence":1', 1))

    def test_noncanonical_duplicate_keys_and_nan_refused(self):
        row = self.fixture().splitlines(keepends=True)
        self.assert_invalid(b'{"phase":"startup-anchor","phase":"startup-anchor"}\n'+b"".join(row[1:]))
        self.assert_invalid(b'{"phase":"startup-anchor","x":NaN}\n'+b"".join(row[1:]))
        self.assert_invalid(b'{ "phase":"startup-anchor"}\n'+b"".join(row[1:]))

    def test_truncation_and_oversized_phase_refused(self):
        self.assert_invalid(self.fixture()[:-1])
        self.assert_invalid(b'{"phase":"startup-anchor","pad":"'+b"x"*2048+b'"}\n')

    def test_anchor_only_is_incomplete_not_consistent(self):
        raw = self.fixture(rejected=True).splitlines(keepends=True)
        self.assert_invalid(raw[0])

    def test_rejected_guard_from_other_run_is_not_trusted(self):
        raw = self.fixture(rejected=True)
        with self.assertRaisesRegex(reader.JournalIntegrityError, "run-id"):
            reader.verify_stream(io.BytesIO(raw), expected_run_id="other-run")

    def test_unbound_or_tampered_primary_id_is_rejected(self):
        rows = self.fixture(rejected=True).splitlines(keepends=True)
        for index in range(3):
            changed = rows.copy()
            changed[index] = changed[index].replace(b'"run_id":"synthetic"', b'"run_id":"wrong"')
            self.assertNotEqual(changed[index], rows[index])
            with self.subTest(index=index):
                self.assert_invalid(b"".join(changed))

    def test_legacy_primary_without_run_id_is_not_promoted(self):
        rows = self.fixture(rejected=True).splitlines(keepends=True)
        for index in range(3):
            changed = rows.copy()
            changed[index] = changed[index].replace(b',"run_id":"synthetic"', b"")
            self.assertNotEqual(changed[index], rows[index])
            with self.subTest(index=index):
                self.assert_invalid(b"".join(changed))

    def test_wrong_stream_type_and_missing_trusted_run_id(self):
        with self.assertRaises(reader.JournalIntegrityError):
            reader.verify_stream(io.StringIO("{}\n"), expected_run_id="synthetic")
        with self.assertRaises(ValueError):
            reader.verify_stream(io.BytesIO(self.fixture()), expected_run_id="")


if __name__ == "__main__":
    unittest.main()
