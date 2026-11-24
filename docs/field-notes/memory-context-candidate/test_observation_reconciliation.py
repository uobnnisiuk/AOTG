"""Synthetic reconciliation controls using the actual public adapter only."""
import io
import json
import unittest

import observation_journal as J
import observation_reconciliation as R


class ReconciliationTests(unittest.TestCase):
    def make(self, stream=None):
        stream = io.StringIO() if stream is None else stream
        j = J.ObservationJournal(stream, origin=0, deadline=5340, run_id="synthetic")
        j.start({"phase": "startup-anchor"}, 0)
        return j, stream

    def report(self, j, stream, summary=None, raw=None, run_id="synthetic"):
        if summary is None:
            summary = json.dumps(j.summary()).encode("ascii")
        if raw is None:
            raw = stream.getvalue().encode("ascii")
        out = R.reconcile(raw, summary, expected_run_id=run_id)
        self.assertIs(out["runtime_qualified"], False)
        self.assertIs(out["quality_accepted"], False)
        return out

    def observed(self, j):
        j.observed({"phase": "observed", "sequence": 0}, 0, force=True)

    def test_normal_accounting(self):
        j, s = self.make()
        self.observed(j)
        j.verdict({"phase": "guard-result", "sequence": 0, "guard_verdict": "passed"}, 0)
        j.context_after_primary_flush(lambda _: {}, clock=lambda: 0)
        out = self.report(j, s)
        self.assertEqual(out["status"], "accounting-consistent")
        self.assertEqual(out["flush_confirmed_rows"], 4)

    def test_rejection_accounting_not_quality(self):
        j, s = self.make()
        self.observed(j)
        j.verdict({"phase": "guard-result", "sequence": 0, "guard_verdict": "rejected"}, 0)
        self.assertEqual(j.stopped_reason, "guard-rejected")
        self.assertEqual(self.report(j, s)["status"], "accounting-consistent")

    def test_short_write_retains_uncertainty(self):
        class Short(io.StringIO):
            def write(self, value):
                return super().write(value if not self.getvalue() else value[:5])
        j, s = self.make(Short())
        with self.assertRaisesRegex(RuntimeError, "short-observation-write"):
            self.observed(j)
        out = self.report(j, s)
        self.assertEqual(out["reason"], "unconfirmed-admission")
        self.assertEqual(out["unconfirmed_admitted_rows"], 1)

    def test_exception_before_write_retains_uncertainty(self):
        class Broken(io.StringIO):
            def write(self, value):
                if self.getvalue():
                    raise OSError("synthetic")
                return super().write(value)
        j, s = self.make(Broken())
        with self.assertRaises(OSError):
            self.observed(j)
        self.assertEqual(self.report(j, s)["reason"], "unconfirmed-admission")

    def test_flush_failure_visible_bytes_not_confirmation(self):
        class Broken(io.StringIO):
            def flush(self):
                if self.getvalue().count("\n") > 1:
                    raise OSError("synthetic")
        j, s = self.make(Broken())
        with self.assertRaises(OSError):
            self.observed(j)
        out = self.report(j, s)
        self.assertEqual(out["reason"], "unconfirmed-admission")
        self.assertEqual(out["admitted_bytes"], out["recovered_bytes"])
        self.assertEqual(out["flush_confirmed_rows"], 1)

    def test_missing_or_oversize_summary(self):
        j, s = self.make()
        for value in (b"", b"x" * (R.MAX_SUMMARY + 1)):
            self.assertEqual(self.report(j, s, summary=value)["reason"],
                             "missing-or-oversize-summary")

    def test_contradictory_counters_and_bool_rejected(self):
        j, s = self.make()
        for name, value, reason in (
            ("unconfirmed_admitted_rows", 1, "contradictory-accounting"),
            ("flush_confirmed_rows", True, "invalid-accounting-counter"),
            ("admitted_bytes", R.MAX_BYTES + 1, "invalid-accounting-counter"),
        ):
            altered = {**j.summary(), name: value}
            self.assertEqual(self.report(j, s, summary=json.dumps(altered).encode())["reason"], reason)

    def test_missing_or_extra_recovered_bytes(self):
        j, s = self.make()
        raw = s.getvalue().encode()
        for altered in (raw[:-1], raw + b"x"):
            self.assertEqual(self.report(j, s, raw=altered)["reason"], "recovered-byte-count-mismatch")

    def test_confirmed_prefix_invalid_json_or_wrong_run(self):
        j, s = self.make()
        raw = s.getvalue().encode()
        self.assertEqual(self.report(j, s, raw=b"!" + raw[1:])["reason"], "invalid-confirmed-json")
        self.assertEqual(self.report(j, s, run_id="elsewhere")["reason"], "confirmed-run-id-mismatch")

    def test_duplicate_summary_key_and_status_mismatch(self):
        j, s = self.make()
        summary = json.dumps(j.summary()).encode()
        duplicate = b'{"rows":1,' + summary[1:]
        self.assertEqual(self.report(j, s, summary=duplicate)["reason"], "invalid-summary-json")
        altered = {**j.summary(), "status": "passed"}
        self.assertEqual(self.report(j, s, summary=json.dumps(altered).encode())["reason"],
                         "invalid-summary-status")

    def test_same_length_tamper_not_claimed_as_authenticated(self):
        j, s = self.make()
        self.observed(j)
        raw = s.getvalue().encode().replace(b'"sequence":0', b'"sequence":9')
        # Accounting is not the as-yet unimplemented raw journal join.
        self.assertEqual(self.report(j, s, raw=raw)["status"], "accounting-consistent")
