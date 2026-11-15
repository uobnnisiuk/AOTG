"""Verify the released pilot composition through mocked remote services."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from aotg.autodev.coordinator import Candidate, Draft, Readiness
from aotg.autodev.ledger import Ledger
from aotg.autodev.pilot_runtime import (
    BOOTSTRAP_PATHS,
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

    def _push(self, artifact, scope, branch, *, branch_head):
        self.assertEqual(scope, APPROVED)
        self.assertEqual(branch, BRANCH)
        self.assertEqual(branch_head(branch), BASE)
        self.github.actions.append("pushed")
        self.github.refs[branch] = artifact.candidate.head

    def run_pilot(self, *, release=None, readiness=READY):
        return run_approved_pilot(self.ledger, self.ports, self.slot, release, readiness, now=NOW)

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
