"""Verify the released pilot composition through mocked remote services."""

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from aotg.autodev.coordinator import Candidate, Draft, Readiness
from aotg.autodev.ledger import Ledger, ReservationBlocked
from aotg.autodev.pilot_runtime import (
    BOOTSTRAP_PATHS,
    PilotAttemptBoundary,
    PilotError,
    PilotPorts,
    PilotRelease,
    run_approved_pilot,
)
from aotg.autodev.queue import (
    OWNER,
    ApprovedScope,
    GitHubSnapshot,
    IssueSnapshot,
    scope_digest,
)
from aotg.autodev.result_slot import LocalResultSlot
from aotg.autodev.worker import CandidateRejected, WorkerError

BASE = "1" * 40
HEAD = "2" * 40
NEW_BASE = "3" * 40
REVISION = "4" * 64
BRANCH = "autodev/uob-50"
NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
SCOPE = ApprovedScope("UOB-50", 7, REVISION, tuple(sorted(BOOTSTRAP_PATHS)), ("UOB-49",), "")
APPROVED = replace(SCOPE, approval_sha=scope_digest(SCOPE))
READY = Readiness(True, True, True, True)


class GitHub:
    def __init__(self):
        self.base = BASE
        self.refs = {}
        self.open_prs = ()
        self.actions = []
        self.observations = 0
        self.change_after_first_read = False

    def snapshot(self):
        self.observations += 1
        if self.observations == 2 and self.change_after_first_read:
            self.base = NEW_BASE
        return GitHubSnapshot(self.base, self.open_prs, ("main", *self.refs), True, True)

    def read_issue(self, number):
        return SimpleNamespace(number=number, author=OWNER, state="open")

    def reserve_branch(self, branch, base):
        self.actions.append("reserved")
        self.refs[branch] = base

    def branch_head(self, branch):
        return self.refs.get(branch)

    def publish_draft(self, scope, candidate):
        assert scope == APPROVED
        assert self.refs[BRANCH] == candidate.head
        self.actions.append("draft")
        self.open_prs = (8,)
        return 8

    def read_draft(self, number):
        return Draft(number, BRANCH, BASE, HEAD, True)


class PilotRuntimeTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        self.ledger = Ledger(folder / "ledger")
        self.slot = LocalResultSlot(folder / "receipt.json")
        self.release = PilotRelease(BASE, APPROVED.approval_sha, NOW - timedelta(minutes=1),
                                    NOW + timedelta(minutes=5))
        self.github = GitHub()
        self.linear = Mock()
        self.linear.snapshot.return_value = (
            (IssueSnapshot("UOB-50", 7, REVISION, ("UOB-49",), True),), ("UOB-49",)
        )
        self.worker = Mock()
        self.candidate = Candidate(BASE, HEAD, ("aotg/offline_bench.py",), True)
        self.worker.implement.return_value = self.candidate
        self.worker.artifact_for.return_value = SimpleNamespace(
            candidate=self.candidate, changes=SimpleNamespace(patch=b"+print(1)\n")
        )
        self.push = Mock(side_effect=self._push)
        self.ports = PilotPorts(self.github, self.linear, APPROVED, self.worker, self.push, base=BASE)

    def set_boundary(self, *, seconds=2400, quiet=True, now=NOW):
        self.elapsed_clock = Mock(return_value=10_000_000_000)
        self.utc_clock = Mock(return_value=now)
        self.quiet = Mock(return_value=quiet)
        self.enterContext(patch("aotg.autodev.pilot_runtime.monotonic_ns", self.elapsed_clock))
        self.enterContext(patch("aotg.autodev.pilot_runtime._utc_now", self.utc_clock))
        boundary = PilotAttemptBoundary.from_deadline(
            self.elapsed_clock.return_value + seconds * 1_000_000_000, self.quiet,
        )
        boundary.constrain_authorization(self.release.issued_at, self.release.expires_at)
        self.ports = PilotPorts(
            self.github, self.linear, APPROVED, self.worker, self.push, base=BASE, boundary=boundary,
        )
        return boundary

    def advance(self, seconds):
        self.elapsed_clock.return_value += seconds * 1_000_000_000

    def _push(self, artifact, scope, branch, *, branch_head):
        self.assertEqual(scope, APPROVED)
        self.assertEqual(branch, BRANCH)
        self.assertEqual(branch_head(branch), BASE)
        self.github.actions.append("pushed")
        self.github.refs[branch] = artifact.candidate.head

    def run_pilot(self, *, release=None, readiness=READY, now=NOW):
        return run_approved_pilot(self.ledger, self.ports, self.slot, release, readiness, now=now)

    def advance_during_fresh_snapshot(self, utc, seconds):
        original_snapshot = self.github.snapshot

        def snapshot():
            observed = original_snapshot()
            if self.github.observations == 3:
                self.utc_clock.return_value = utc
                self.advance(seconds)
            return observed

        self.github.snapshot = snapshot

    def test_no_release_or_readiness_cannot_reserve(self):
        self.assertEqual(self.run_pilot().reason, "deployment-gate")
        self.assertEqual(self.run_pilot(release=self.release, readiness=Readiness()).reason,
                         "deployment-gate")
        self.assertEqual(self.github.actions, [])
        self.worker.implement.assert_not_called()
        self.assertFalse(self.slot.path.exists())

    def test_stale_release_or_shifted_main_stops(self):
        expired = replace(self.release, expires_at=NOW)
        self.assertEqual(self.run_pilot(release=expired).reason, "deployment-gate")
        self.github.observations = 0
        self.github.change_after_first_read = True
        self.assertEqual(self.run_pilot(release=self.release).status, "unknown")
        self.assertEqual(self.github.actions, [])
        self.push.assert_not_called()

    def test_only_exact_pilot_scope_is_accepted(self):
        altered = replace(APPROVED, allowed_paths=("docs/other.md",))
        altered = replace(altered, approval_sha=scope_digest(altered))
        with self.assertRaises(PilotError):
            PilotPorts(self.github, self.linear, altered, self.worker, self.push, base=BASE)

    def test_one_attempt_writes_verified_draft_and_receipt(self):
        result = self.run_pilot(release=self.release)
        self.assertEqual((result.status, result.head, result.pr), ("draft_pr", HEAD, 8))
        self.assertEqual(self.github.actions, ["reserved", "pushed", "draft"])
        self.assertEqual(self.slot.read(), result.redacted())
        self.assertEqual(self.run_pilot(release=self.release).reason, "open-pr")
        self.worker.implement.assert_called_once()

    def test_candidate_rejection_records_failure_and_allows_a_later_issue(self):
        self.worker.implement.side_effect = CandidateRejected("private model output")
        result = self.run_pilot(release=self.release)
        self.assertEqual((result.status, result.reason), ("blocked", "candidate-rejected"))
        self.assertEqual(self.github.actions, ["reserved"])
        self.push.assert_not_called()
        self.assertEqual(self.slot.read(), result.redacted())
        self.assertNotIn("private model output", str(self.slot.read()))
        self.ledger.check("UOB-51", NOW + timedelta(days=2))
        with self.assertRaises(ReservationBlocked):
            self.ledger.check("UOB-50", NOW + timedelta(days=2))

    def test_uncertain_worker_failure_keeps_the_queue_blocked(self):
        self.worker.implement.side_effect = WorkerError("environment unavailable")
        result = self.run_pilot(release=self.release)
        self.assertEqual((result.status, result.reason), ("unknown", "worker-result-unconfirmed"))
        self.push.assert_not_called()
        self.assertNotIn("environment unavailable", str(self.slot.read()))
        with self.assertRaises(ReservationBlocked) as blocked:
            self.ledger.check("UOB-51", NOW + timedelta(days=2))
        self.assertEqual(blocked.exception.reason, "active")

    def test_unverifiable_artifact_does_not_push(self):
        self.worker.artifact_for.return_value = SimpleNamespace(
            candidate=replace(self.candidate, head=NEW_BASE)
        )
        result = self.run_pilot(release=self.release)
        self.assertEqual((result.status, result.reason), ("unknown", "draft-unconfirmed"))
        self.assertEqual(self.github.actions, ["reserved"])
        self.assertEqual(self.slot.read(), result.redacted())
        self.push.assert_not_called()

    def test_private_network_literal_blocks_before_push(self):
        artifact = self.worker.artifact_for.return_value
        artifact.changes.patch = b"+example = '192.168.0.1'\n"
        self.assertEqual(self.run_pilot(release=self.release).status, "unknown")
        self.assertEqual(self.github.actions, ["reserved"])
        self.push.assert_not_called()

    def test_live_worker_budget_subtracts_setup_and_publication(self):
        self.set_boundary()
        reserve = self.github.reserve_branch

        def slow_reserve(*args):
            reserve(*args)
            self.advance(40)

        self.github.reserve_branch = slow_reserve
        result = self.run_pilot(release=self.release)
        self.assertEqual(result.status, "draft_pr")
        self.assertEqual(self.worker.implement.call_args.kwargs["timeout_seconds"], 140)

    def test_unverified_live_host_stops_before_observation_or_reservation(self):
        for quiet in (False, 1, None):
            with self.subTest(quiet=quiet):
                self.set_boundary(quiet=quiet)
                result = self.run_pilot(release=self.release)
                self.assertEqual(result.reason, "deployment-gate")
        self.assertEqual(self.github.observations, 0)
        self.assertFalse(self.ledger.root.exists())
        self.worker.implement.assert_not_called()

    def test_callback_failure_closes_attempt_even_if_host_recovers(self):
        boundary = self.set_boundary()
        self.quiet.side_effect = (RuntimeError("host inventory unavailable"), True)
        self.assertEqual(self.run_pilot(release=self.release).reason, "deployment-gate")
        with self.assertRaises(PilotError):
            boundary.require_quiet()
        self.quiet.assert_called_once()
        self.push.assert_not_called()

    def test_elapsed_deadline_before_publication_preserves_claim(self):
        self.set_boundary()

        def late_worker(*args, **kwargs):
            self.advance(300)
            return self.candidate

        self.worker.implement.side_effect = late_worker
        result = self.run_pilot(release=self.release)
        self.assertEqual((result.status, result.reason), ("unknown", "result-unconfirmed"))
        self.assertEqual(self.github.actions, ["reserved"])
        self.assertEqual(self.slot.read()["status"], "claim_started")
        self.assertTrue((self.ledger.root / "UOB-50.reservation.json").exists())
        self.assertFalse((self.ledger.root / "UOB-50.outcome.json").exists())
        self.push.assert_not_called()

    def test_expiry_after_exact_push_stops_draft_and_terminal_receipt(self):
        self.set_boundary()

        def late_push(*args, **kwargs):
            self._push(*args, **kwargs)
            self.advance(300)

        self.push.side_effect = late_push
        result = self.run_pilot(release=self.release)
        self.assertEqual(result.reason, "result-unconfirmed")
        self.assertEqual(self.github.actions, ["reserved", "pushed"])
        self.push.assert_called_once()
        self.assertEqual(self.slot.read()["status"], "claim_started")
        self.assertFalse((self.ledger.root / "UOB-50.outcome.json").exists())

    def test_host_busy_after_candidate_stops_publication(self):
        self.set_boundary()

        def interrupted_worker(*args, **kwargs):
            self.quiet.return_value = False
            return self.candidate

        self.worker.implement.side_effect = interrupted_worker
        self.assertEqual(self.run_pilot(release=self.release).reason, "result-unconfirmed")
        self.assertEqual(self.github.actions, ["reserved"])
        self.assertEqual(self.slot.read()["status"], "claim_started")
        self.push.assert_not_called()

    def test_utc_window_closes_before_the_launcher_deadline(self):
        boundary = self.set_boundary()
        self.utc_clock.return_value = self.release.expires_at
        with self.assertRaises(TimeoutError):
            boundary.remaining()
        self.utc_clock.return_value = NOW
        with self.assertRaises(PilotError):
            boundary.require_quiet()

    def test_wall_clock_rollback_cannot_extend_authorized_monotonic_window(self):
        boundary = self.set_boundary()
        self.utc_clock.return_value = NOW - timedelta(seconds=5)
        self.advance(300)
        with self.assertRaises(TimeoutError):
            boundary.remaining()

    def test_invalid_absolute_launch_deadlines(self):
        with patch("aotg.autodev.pilot_runtime.monotonic_ns", return_value=100):
            for deadline in (True, 100, 99, 100 + 2401 * 1_000_000_000):
                with self.subTest(deadline=deadline), self.assertRaises(PilotError):
                    PilotAttemptBoundary.from_deadline(deadline, lambda: True)

    def test_live_reservation_after_jst_midnight_uses_fresh_time(self):
        invoked = NOW.replace(hour=14, minute=59, second=59)
        started = invoked + timedelta(seconds=2)
        self.release = replace(
            self.release, issued_at=invoked - timedelta(minutes=1), expires_at=invoked + timedelta(minutes=5),
        )
        for index, hours in enumerate((7, 3), start=1):
            prior = self.ledger.reserve(f"UOB-{index}", invoked - timedelta(hours=hours))
            self.ledger.finish(prior, "success")
        with self.assertRaisesRegex(ReservationBlocked, "daily-limit"):
            self.ledger.check(APPROVED.issue, invoked)

        self.set_boundary(now=invoked)
        self.advance_during_fresh_snapshot(started, seconds=2)
        result = self.run_pilot(release=self.release, now=invoked)
        self.assertEqual(result.status, "draft_pr")
        self.assertEqual(result.time_utc, started.isoformat(timespec="seconds"))
        record = self.ledger.root / f"{APPROVED.issue}.reservation.json"
        self.assertEqual(json.loads(record.read_bytes())["started_at"], started.isoformat(timespec="microseconds"))
        self.assertEqual(self.slot.read(), result.redacted())

    def test_live_reservation_rejects_clock_rollback(self):
        self.set_boundary()
        self.advance_during_fresh_snapshot(NOW - timedelta(seconds=1), seconds=1)
        result = self.run_pilot(release=self.release)
        self.assertEqual(result.reason, "deployment-gate")
        self.assertFalse(self.ledger.root.exists())
        self.assertEqual(self.github.actions, [])
        self.worker.implement.assert_not_called()

    def test_exact_release_is_rechecked_at_live_reservation(self):
        self.set_boundary()
        release = replace(self.release, expires_at=NOW + timedelta(seconds=1))
        self.advance_during_fresh_snapshot(release.expires_at, seconds=1)
        result = self.run_pilot(release=release)
        self.assertEqual(result.reason, "deployment-gate")
        self.assertFalse(self.ledger.root.exists())
        self.assertEqual(self.github.actions, [])
        self.worker.implement.assert_not_called()
