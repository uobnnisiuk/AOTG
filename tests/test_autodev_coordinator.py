"""Exercise the coordinator with independent fake workers and remote evidence."""

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from aotg.autodev.coordinator import Candidate, Coordinator, Draft, Readiness, Snapshot
from aotg.autodev.ledger import Ledger
from aotg.autodev.queue import (
    ApprovedScope,
    GitHubSnapshot,
    IssueSnapshot,
    scope_digest,
)
from aotg.autodev.result_slot import LocalResultSlot

BASE = "1" * 40
HEAD = "2" * 40
REVISION = "3" * 64
ISSUE = "UOB-50"
BRANCH = "autodev/uob-50"
PATH = "tests/test_offline_benchmark.py"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class FakeGitHub:
    def __init__(self):
        scope = ApprovedScope(ISSUE, 7, REVISION, (PATH,), ("UOB-49",), "")
        self.approval = replace(scope, approval_sha=scope_digest(scope))
        self.branches = {"main": BASE}
        self.open_prs = ()
        self.writes = []
        self.draft = None
        self.ambiguous_publish = False

    def snapshot(self):
        issue = IssueSnapshot(ISSUE, 7, REVISION, ("UOB-49",), True)
        github = GitHubSnapshot(
            self.branches["main"], self.open_prs, tuple(self.branches), True, True
        )
        return Snapshot((self.approval,), (issue,), ("UOB-49",), github, True)

    def reserve_branch(self, branch, base):
        self.writes.append("reserve")
        self.branches[branch] = base

    def branch_head(self, branch):
        return self.branches.get(branch)

    def publish_draft(self, scope, candidate):
        self.writes.append("draft")
        self.branches[BRANCH] = candidate.head
        self.draft = Draft(8, BRANCH, candidate.base, candidate.head, True)
        self.open_prs = (8,)
        if self.ambiguous_publish:
            raise TimeoutError("test-only output")
        return 8

    def read_draft(self, number):
        return self.draft


class FakeWorker:
    def __init__(self):
        self.calls = []
        self.candidate = Candidate(BASE, HEAD, (PATH,), True)
        self.failure = None

    def implement(self, scope, base, *, timeout_seconds):
        self.calls.append((scope.issue, base, timeout_seconds))
        if self.failure is not None:
            raise self.failure
        return self.candidate


class FakeSlot:
    def __init__(self):
        self.events = []
        self.stale = False

    def write(self, result):
        self.events.append(result)

    def read(self):
        return {} if self.stale else self.events[-1]


class CoordinatorTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "private-ledger"
        self.github = FakeGitHub()
        self.worker = FakeWorker()
        self.slot = FakeSlot()
        self.coordinator = Coordinator(Ledger(self.root), self.github, self.worker, self.slot)
        self.readiness = Readiness(True, True, True, True)

    def test_shadow_and_missing_approval_do_not_write(self):
        self.assertEqual(self.coordinator.run_once(NOW).reason, "shadow-eligible")
        result = self.coordinator.run_once(NOW, execute=True)
        self.assertEqual(result.reason, "deployment-gate")
        self.assertFalse(self.root.exists())
        self.assertEqual(self.github.writes, [])
        self.assertEqual(self.worker.calls, [])
        self.assertEqual(self.slot.events, [])

    def test_verified_draft_and_write_order(self):
        result = self.coordinator.run_once(NOW, execute=True, readiness=self.readiness)
        self.assertEqual(result.status, "draft_pr")
        self.assertEqual(result.head, HEAD)
        self.assertEqual(self.github.writes, ["reserve", "draft"])
        self.assertEqual(self.worker.calls, [(ISSUE, BASE, 2400)])
        self.assertEqual([e["status"] for e in self.slot.events], ["claim_started", "draft_pr"])
        self.assertEqual(self.slot.events[-1], result.redacted())

    def test_disallowed_diff_never_publishes(self):
        self.worker.candidate = Candidate(BASE, HEAD, (".github/workflows/ci.yml",), True)
        result = self.coordinator.run_once(NOW, execute=True, readiness=self.readiness)
        self.assertEqual(result.reason, "candidate-rejected")
        self.assertEqual(self.github.writes, ["reserve"])

    def test_open_pr_and_stale_result_stop_before_worker(self):
        self.github.open_prs = (12,)
        self.assertEqual(self.coordinator.run_once(NOW).status, "blocked")
        self.assertEqual(self.github.writes, [])
        self.github.open_prs = ()
        self.slot.stale = True
        result = self.coordinator.run_once(NOW, execute=True, readiness=self.readiness)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(self.github.writes, ["reserve"])
        self.assertEqual(self.worker.calls, [])

    def test_ambiguous_remote_write_is_never_retried(self):
        self.github.ambiguous_publish = True
        result = self.coordinator.run_once(NOW, execute=True, readiness=self.readiness)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.reason, "draft-unconfirmed")
        next_result = self.coordinator.run_once(NOW, execute=True, readiness=self.readiness)
        self.assertEqual(next_result.status, "blocked")
        self.assertEqual(self.github.writes, ["reserve", "draft"])

    def test_worker_timeout_is_recorded_without_exception_details(self):
        self.worker.failure = TimeoutError("test-only output")
        result = self.coordinator.run_once(NOW, execute=True, readiness=self.readiness)
        self.assertEqual(result.reason, "worker-timeout")
        self.assertNotIn("test-only output", str(self.slot.events))
        self.assertEqual(self.github.writes, ["reserve"])

    def test_main_changed_during_worker_blocks_publication(self):
        original = self.worker.implement

        def moved(*args, **kwargs):
            self.github.branches["main"] = "4" * 40
            return original(*args, **kwargs)

        self.worker.implement = moved
        result = self.coordinator.run_once(NOW, execute=True, readiness=self.readiness)
        self.assertEqual(result.reason, "prepublication-changed")
        self.assertEqual(self.github.writes, ["reserve"])

    def test_concurrent_external_pr_after_publish_is_reported_as_unknown(self):
        result_directory = self.root.with_name("private-results")
        result_directory.mkdir(mode=0o700)
        slot = LocalResultSlot(result_directory / "latest.json")
        self.coordinator.slot = slot
        publish = self.github.publish_draft

        def concurrent(*args):
            number = publish(*args)
            self.github.open_prs += (9,)
            return number

        self.github.publish_draft = concurrent
        result = self.coordinator.run_once(NOW, execute=True, readiness=self.readiness)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.reason, "draft-unconfirmed")
        self.assertEqual(result.pr, 8)
        self.assertEqual(slot.read(), result.redacted())
        self.assertEqual(self.github.writes, ["reserve", "draft"])
