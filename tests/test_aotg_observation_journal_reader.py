"""Independent synthetic, no real guard, model, recovery or service calls."""
import importlib
import io
import pathlib
import sys
import unittest
from dataclasses import replace
from unittest import mock

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

    def check(self, content, **trusted):
        return reader.verify_stream(io.BytesIO(content), expected_run_id="synthetic", **trusted)

    def assert_invalid(self, data, **trusted):
        with self.assertRaises(reader.JournalIntegrityError):
            self.check(data, **trusted)

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

    def test_capacity_refusal_ends_chain_and_forbids_later_primary(self):
        stream = io.StringIO()
        j = journal.ObservationJournal(stream, origin=0, deadline=10, run_id="synthetic")
        j.start({"phase": "startup-anchor"}, 0)
        # Primary+guard fit; the full optional context reservation does not.
        j.limits = replace(j.limits, max_bytes=8_192)
        j.observed({"phase": "observed", "sequence": 0}, 0, force=True)
        with self.assertRaisesRegex(journal.BudgetStop, "aggregate-byte-cap"):
            j.verdict({"phase": "guard-result", "sequence": 0, "guard_verdict": "passed"}, 0)
        raw = stream.getvalue().encode("ascii")
        self.assertEqual(len(raw.splitlines()), 3)
        self.assertIn(b"context-capacity-refused", raw)
        # Explicit trusted test configuration: never mistake this fixture
        # for the published production max_bytes=128MiB.
        with self.assertRaisesRegex(reader.JournalIntegrityError, "capacity-refusal-unproven"):
            self.check(raw)
        out = self.check(raw, trusted_max_bytes=8_192)
        self.assertEqual(out["primary_ticks"], 1)
        self.assertFalse(out["rejected_guard_recorded"])
        self.assertFalse(out["runtime_qualified"])
        # A valid-looking next primary is still forbidden after terminal stop.
        extra = self.fixture(rejected=True).splitlines(keepends=True)[1]
        with self.assertRaisesRegex(reader.JournalIntegrityError, "record-after-terminal-guard"):
            self.check(raw + extra, trusted_max_bytes=8_192)
        # A first-tick claim that the attempt quota was exhausted is unbound.
        spoofed = raw.replace(b"context-capacity-refused", b"context-attempt-quota")
        with self.assertRaisesRegex(reader.JournalIntegrityError, "context-attempt-quota-unproven"):
            self.check(spoofed)

    def test_attempt_quota_stop_ends_chain_even_when_guard_passed(self):
        # Lower only the *synthetic* quota in this unit fixture to exercise
        # a reachable quota stop without thousands of artificial samples.
        stream = io.StringIO()
        j = journal.ObservationJournal(stream, origin=0, deadline=10, run_id="synthetic")
        j.start({"phase": "startup-anchor"}, 0)
        with mock.patch.object(journal, "MAX_CONTEXT_ATTEMPTS", 1):
            j.observed({"phase": "observed", "sequence": 0}, 0, force=True)
            j.verdict({"phase": "guard-result", "sequence": 0, "guard_verdict": "passed"}, 0)
            j.context_after_primary_flush(lambda _: {"status": "incomplete"}, clock=lambda: 0)
            j.observed({"phase": "observed", "sequence": 1}, 2.1)
            with self.assertRaisesRegex(journal.BudgetStop, "context-attempt-quota"):
                j.verdict({"phase": "guard-result", "sequence": 1, "guard_verdict": "passed"}, 2.1)
        raw = stream.getvalue().encode("ascii")
        self.assertEqual(len(raw.splitlines()), 6)
        self.assertIn(b"context-attempt-quota", raw)
        with mock.patch.object(reader, "MAX_CONTEXT", 1):
            out = self.check(raw)
            self.assertEqual((out["primary_ticks"], out["context_rows"]), (2, 1))
            self.assertFalse(out["rejected_guard_recorded"])
            self.assertFalse(out["authorizes_retry"])
            extra = self.fixture(rejected=True).splitlines(keepends=True)[1]
            with self.assertRaisesRegex(reader.JournalIntegrityError, "record-after-terminal-guard"):
                self.check(raw + extra)
        # The production quota has not been met by this reduced fixture.
        with self.assertRaisesRegex(reader.JournalIntegrityError, "context-attempt-quota-unproven"):
            self.check(raw)

    def test_capacity_refusal_verified_at_exact_reservation_boundary(self):
        stream = io.StringIO()
        j = journal.ObservationJournal(stream, origin=0, deadline=10, run_id="synthetic")
        j.start({"phase": "startup-anchor"}, 0)
        j.observed({"phase": "observed", "sequence": 0}, 0, force=True)
        # At the guard decision the writer still reserves the FULL guard cap,
        # plus the entire optional context cap (rather than actual guard bytes).
        reservation = j.bytes + journal.GUARD_LINE_BYTES + journal.CONTEXT_LINE_BYTES
        j.limits = replace(j.limits, max_bytes=reservation - 1)
        with self.assertRaisesRegex(journal.BudgetStop, "aggregate-byte-cap"):
            j.verdict({"phase": "guard-result", "sequence": 0, "guard_verdict": "passed"}, 0)
        raw = stream.getvalue().encode("ascii")
        self.assertIn(b"context-capacity-refused", raw)
        self.assertEqual(len(raw.splitlines()), 3)
        with self.assertRaisesRegex(reader.JournalIntegrityError, "context-capacity-refusal-unproven"):
            self.check(raw)  # Default production caps make this claim impossible.
        out = self.check(raw, trusted_max_bytes=reservation - 1)
        self.assertEqual(out["status"], "incomplete-unverified-runtime")
        self.assertFalse(out["root_cause_proven"])
        with self.assertRaisesRegex(reader.JournalIntegrityError, "context-capacity-refusal-unproven"):
            self.check(raw, trusted_max_bytes=reservation)  # Full reservation fits.
        extra = self.fixture(rejected=True).splitlines(keepends=True)[1]
        with self.assertRaisesRegex(reader.JournalIntegrityError, "record-after-terminal-guard"):
            self.check(raw + extra, trusted_max_bytes=reservation - 1)

    def test_capacity_row_limit_and_untrusted_limit_rejected(self):
        stream = io.StringIO()
        j = journal.ObservationJournal(stream, origin=0, deadline=10, run_id="synthetic")
        j.start({"phase": "startup-anchor"}, 0)
        j.observed({"phase": "observed", "sequence": 0}, 0, force=True)
        j.limits = replace(j.limits, max_rows=3)
        with self.assertRaisesRegex(journal.BudgetStop, "aggregate-row-cap"):
            j.verdict({"phase": "guard-result", "sequence": 0, "guard_verdict": "passed"}, 0)
        raw = stream.getvalue().encode("ascii")
        self.assertEqual(self.check(raw, trusted_max_rows=3)["primary_ticks"], 1)
        with self.assertRaisesRegex(reader.JournalIntegrityError, "context-capacity-refusal-unproven"):
            self.check(raw)
        with self.assertRaisesRegex(reader.JournalIntegrityError, "context-capacity-refusal-unproven"):
            self.check(raw, trusted_max_rows=4)
        for illegal in (0, -1, True, reader.MAX_BYTES + 1, 1.5):
            with self.subTest(illegal=illegal), self.assertRaises(ValueError):
                self.check(raw, trusted_max_bytes=illegal)

    def test_wrong_stream_type_and_missing_trusted_run_id(self):
        with self.assertRaises(reader.JournalIntegrityError):
            reader.verify_stream(io.StringIO("{}\n"), expected_run_id="synthetic")
        with self.assertRaises(ValueError):
            reader.verify_stream(io.BytesIO(self.fixture()), expected_run_id="")


if __name__ == "__main__":
    unittest.main()
