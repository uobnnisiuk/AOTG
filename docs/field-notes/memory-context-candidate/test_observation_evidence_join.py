"""Positive/negative synthetic controls for the public observation-only join."""
import hashlib
import io
import json
import unittest
from unittest.mock import patch

import observation_journal as J
import observation_evidence_join as G
import verify_observation_journal as V

RUN = "synthetic"
PLAN = "a" * 64


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def metadata(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def manifest(raw, summary):
    return {"artifact": "aotg-observation-recovery-manifest", "version": 1,
            "run_id": RUN, "plan_sha256": PLAN,
            "journal": {**metadata(raw), "rows": raw.count(b"\n")},
            "adapter_summary": metadata(summary)}


def fixture(rejected=False, anchor_only=False, stream=None):
    stream = io.StringIO() if stream is None else stream
    j = J.ObservationJournal(stream, origin=0, deadline=10, run_id=RUN)
    j.start({"phase": "startup-anchor"}, 0)
    if not anchor_only:
        j.observed({"phase": "observed", "sequence": 0}, 0, force=True)
        j.verdict({"phase": "guard-result", "sequence": 0,
                   "guard_verdict": "rejected" if rejected else "passed"}, 0)
        if not rejected:
            j.context_after_primary_flush(lambda _: {}, clock=lambda: 0)
    return stream.getvalue().encode("ascii"), encode(j.summary())


class EvidenceJoinTests(unittest.TestCase):
    def check(self, raw, summary, m=None, run=RUN, plan=PLAN):
        result = G.join_observation(raw, summary,
                                    trusted_manifest=manifest(raw, summary) if m is None else m,
                                    expected_run_id=run, expected_plan_sha256=plan)
        for key in ("runtime_qualified", "independent_restore_verified",
                    "quality_accepted", "authorizes_retry", "root_cause_proven"):
            self.assertIs(result[key], False)
        return result

    def test_complete_passed_observation_only(self):
        raw, summary = fixture()
        out = self.check(raw, summary)
        self.assertEqual(out["status"], "joined-observation-consistent")
        self.assertIsNone(out["terminal_stop_reason"])

    def test_rejected_terminal_matches_summary_not_runtime(self):
        raw, summary = fixture(rejected=True)
        out = self.check(raw, summary)
        self.assertEqual(out["status"], "joined-observation-consistent")
        self.assertEqual(out["terminal_stop_reason"], "guard-rejected")

    def test_same_length_primary_hash_tamper_even_with_matching_manifest(self):
        raw, summary = fixture(rejected=True)
        records = raw.splitlines(keepends=True)
        guard = json.loads(records[2])
        original = guard["primary_sha256"]
        guard["primary_sha256"] = ("0" if original[0] != "0" else "1") + original[1:]
        tampered = b"".join(records[:2]) + encode(guard) + b"\n"
        self.assertEqual(len(tampered), len(raw))
        self.assertEqual(self.check(tampered, summary)["reason"],
                         "strict-journal:guard-primary-binding")

    def test_extra_after_terminal_even_with_matching_counters(self):
        raw, summary = fixture(rejected=True)
        extra = encode({"phase": "observed", "sequence": 1, "run_id": RUN}) + b"\n"
        s = json.loads(summary)
        for key in ("rows", "admitted_rows", "flush_confirmed_rows"):
            s[key] += 1
        for key in ("bytes", "admitted_bytes", "flush_confirmed_bytes"):
            s[key] += len(extra)
        self.assertEqual(self.check(raw + extra, encode(s))["reason"],
                         "strict-journal:record-after-terminal-guard")

    def test_rejected_but_summary_says_not_stopped(self):
        raw, summary = fixture(rejected=True)
        s = {**json.loads(summary), "stopped_reason": None,
             "status": "incomplete-unverified-runtime"}
        self.assertEqual(self.check(raw, encode(s))["reason"], "terminal-summary-mismatch")

    def test_anchor_only(self):
        raw, summary = fixture(anchor_only=True)
        self.assertEqual(self.check(raw, summary)["reason"],
                         "strict-journal:missing-startup-verdict-or-selected-context")

    def test_original_manifest_rejects_truncation_or_summary_substitution(self):
        raw, summary = fixture()
        m = manifest(raw, summary)
        self.assertEqual(self.check(raw[:-1], summary, m)["reason"], "journal-manifest-mismatch")
        _, other = fixture(rejected=True)
        self.assertEqual(self.check(raw, other, m)["reason"], "summary-manifest-mismatch")

    def test_run_plan_and_manifest_types(self):
        raw, summary = fixture()
        m = manifest(raw, summary)
        self.assertEqual(self.check(raw, summary, m, run="other")["reason"],
                         "manifest-run-plan-mismatch")
        self.assertEqual(self.check(raw, summary, m, plan="b" * 64)["reason"],
                         "manifest-run-plan-mismatch")
        m["journal"]["rows"] = True
        self.assertEqual(self.check(raw, summary, m)["reason"], "invalid-manifest-artifact")

    def test_missing_summary(self):
        raw, summary = fixture()
        self.assertEqual(self.check(raw, b"", manifest(raw, summary))["reason"],
                         "invalid-recovered-summary")

    def test_flush_failure_visible_bytes_still_incomplete(self):
        class Broken(io.StringIO):
            def flush(self):
                if self.getvalue().count("\n") > 1:
                    raise OSError("synthetic")
        stream = Broken()
        j = J.ObservationJournal(stream, origin=0, deadline=10, run_id=RUN)
        j.start({"phase": "startup-anchor"}, 0)
        with self.assertRaises(OSError):
            j.observed({"phase": "observed", "sequence": 0}, 0, force=True)
        self.assertEqual(self.check(stream.getvalue().encode(), encode(j.summary()))["reason"],
                         "accounting:unconfirmed-admission")

    def test_nonterminal_stop_and_mismatched_summary_counter(self):
        raw, summary = fixture()
        s = json.loads(summary)
        stopped = {**s, "stopped_reason": "worker-deadline", "status": "incomplete-stopped"}
        self.assertEqual(self.check(raw, encode(stopped))["reason"], "terminal-summary-mismatch")
        self.assertEqual(self.check(raw, encode({**s, "primary_ticks": True}))["reason"],
                         "summary-chain-counter-mismatch")

    def test_terminal_context_quota_matches_exact_reason(self):
        stream = io.StringIO()
        j = J.ObservationJournal(stream, origin=0, deadline=10, run_id=RUN)
        j.start({"phase": "startup-anchor"}, 0)
        # Reduced quota is a synthetic test seam only; production caps unchanged.
        with patch.object(J, "MAX_CONTEXT_ATTEMPTS", 1), patch.object(V, "MAX_CONTEXT", 1):
            j.observed({"phase": "observed", "sequence": 0}, 0, force=True)
            j.verdict({"phase": "guard-result", "sequence": 0, "guard_verdict": "passed"}, 0)
            j.context_after_primary_flush(lambda _: {}, clock=lambda: 0)
            j.observed({"phase": "observed", "sequence": 1}, 2.1)
            with self.assertRaisesRegex(J.BudgetStop, "context-attempt-quota"):
                j.verdict({"phase": "guard-result", "sequence": 1, "guard_verdict": "passed"}, 2.1)
            raw, summary = stream.getvalue().encode(), encode(j.summary())
            self.assertEqual(self.check(raw, summary)["terminal_stop_reason"], "context-attempt-quota")
            self.assertEqual(self.check(raw, summary)["status"], "joined-observation-consistent")
            s = {**json.loads(summary), "stopped_reason": "aggregate-byte-cap"}
            self.assertEqual(self.check(raw, encode(s))["reason"], "terminal-summary-mismatch")
        self.assertEqual(self.check(raw, summary)["reason"], "strict-journal:context-attempt-quota-unproven")

    def test_finalized_summary_rejects_attempt_mismatch_and_missing(self):
        raw, summary = fixture()
        original = json.loads(summary)
        for value in (0, 2, True, "1", None):
            with self.subTest(value=value):
                self.assertEqual(self.check(raw, encode({**original, "context_attempts": value}))["reason"],
                                 "summary-chain-counter-mismatch")
        del original["context_attempts"]
        self.assertEqual(self.check(raw, encode(original))["reason"], "summary-chain-counter-mismatch")

    def test_finalized_summary_rejects_unresolved_reservations(self):
        raw, summary = fixture()
        for key in ("reserved_rows", "reserved_bytes"):
            for value in (1, 16384, False, -1, None):
                with self.subTest(key=key, value=value):
                    self.assertEqual(self.check(raw, encode({**json.loads(summary), key: value}))["reason"],
                                     "summary-unresolved-reservation")

    def test_fixed_quotas_and_reported_forced_bounds(self):
        raw, summary = fixture()
        for key in ("primary_hard_quota", "context_hard_quota", "forced_hard_quota"):
            for value in (True, 0, json.loads(summary)[key] + 1, None):
                with self.subTest(key=key, value=value):
                    self.assertEqual(self.check(raw, encode({**json.loads(summary), key: value}))["reason"],
                                     "summary-fixed-quota-mismatch")
        for value in (True, -1, 2, 66, None):
            with self.subTest(forced=value):
                self.assertEqual(self.check(raw, encode({**json.loads(summary), "forced_samples": value}))["reason"],
                                 "summary-forced-count-out-of-bounds")

    def test_skip_counts_bound_to_guard_schedule(self):
        stream = io.StringIO()
        j = J.ObservationJournal(stream, origin=0, deadline=10, run_id=RUN)
        j.start({"phase": "startup-anchor"}, 0)
        for seq, now, verdict in ((0, 0, "passed"), (1, 0.2, "passed"), (2, 0.4, "rejected")):
            j.observed({"phase": "observed", "sequence": seq}, now, force=True)
            j.verdict({"phase": "guard-result", "sequence": seq, "guard_verdict": verdict}, now)
            if verdict == "passed":
                j.context_after_primary_flush(lambda _: {}, clock=lambda: now)
        raw, summary = stream.getvalue().encode("ascii"), encode(j.summary())
        self.assertEqual(self.check(raw, summary)["status"], "joined-observation-consistent")
        for key in ("context_skipped_interval", "context_skipped_guard"):
            self.assertEqual(self.check(raw, encode({**json.loads(summary), key: 0}))["reason"],
                             "summary-chain-counter-mismatch")
        rows = raw.splitlines(keepends=True)
        guard = json.loads(rows[-1])
        guard["context_schedule"]["interval_skips"] = 0
        changed = b"".join(rows[:-1]) + encode(guard) + b"\n"
        self.assertEqual(len(changed), len(raw))
        self.assertEqual(self.check(changed, summary)["reason"], "strict-journal:guard-interval-skip-count")
