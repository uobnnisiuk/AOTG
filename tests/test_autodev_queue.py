import unittest
from dataclasses import replace

from aotg.autodev.queue import (
    ApprovedScope,
    GitHubSnapshot,
    IssueSnapshot,
    scope_digest,
    select_candidate,
    valid_change_path,
)

MAIN = "a" * 40
REVISION = "1" * 64


def approved(issue="UOB-50", github_issue=5, **fields):
    fields = {
        "revision": REVISION,
        "allowed_paths": ("aotg/benchmarks.py", "tests/test_benchmarks.py"),
        "dependencies": ("UOB-49",),
        **fields,
    }
    scope = ApprovedScope(issue, github_issue, approval_sha="", **fields)
    return replace(scope, approval_sha=scope_digest(scope))


def observed(scope):
    return IssueSnapshot(scope.issue, scope.github_issue, scope.revision, scope.dependencies, True)


class QueueSelectionTests(unittest.TestCase):
    def setUp(self):
        self.scope = approved()
        self.issue = observed(self.scope)
        self.github = GitHubSnapshot(MAIN, (), ("main",), True, True)

    def select(self, **overrides):
        evidence = {
            "approvals": (self.scope,),
            "issues": (self.issue,),
            "done_issues": ("UOB-49",),
            "github": self.github,
            "linear_complete": True,
            **overrides,
        }
        return select_candidate(**evidence)

    def test_returns_one_eligible_scope_and_exact_main(self):
        second = approved("UOB-53", 6)
        result = self.select(approvals=(second, self.scope), issues=(observed(second), self.issue))
        self.assertEqual("eligible", result.status)
        self.assertEqual(self.scope, result.scope)
        self.assertEqual(MAIN, result.main_sha)

    def test_initial_pr_and_all_open_prs_including_drafts_hold_selection(self):
        initial = replace(self.github, initial_pr_merged=False, open_pr_numbers=(1,))
        draft = replace(self.github, open_pr_numbers=(5,))
        self.assertEqual("awaiting_initial_work", self.select(github=initial).status)
        self.assertEqual("open-pr", self.select(github=draft).reason)

    def test_invalid_github_snapshots_fail_closed(self):
        for fields in (
            {"complete": False},
            {"complete": 1},
            {"repo": "someone/AOTG"},
            {"main_sha": "abcd"},
            {"main_sha": "0" * 40},
            {"open_pr_numbers": (True,)},
            {"open_pr_numbers": (1,)},
            {"branch_names": ("another-branch",)},
            {"branch_names": ("main", "main")},
            {"branch_names": ("main", "autodev//uob-50")},
        ):
            with self.subTest(fields=fields):
                self.assertEqual("unknown", self.select(github=replace(self.github, **fields)).status)

    def test_partial_or_contradictory_linear_snapshot_is_unknown(self):
        self.assertEqual("unknown", self.select(linear_complete=False).status)
        self.assertEqual("unknown", self.select(issues=(self.issue, self.issue)).status)
        self.assertEqual("unknown", self.select(done_issues=("UOB-49", "UOB-50")).status)
        self.assertEqual("unknown", self.select(issues=()).status)
        self.assertEqual("unknown", self.select(issues=(replace(self.issue, eligible="open"),)).status)

    def test_status_distinguishes_empty_ineligible_and_blocked(self):
        self.assertEqual("empty_queue", self.select(approvals=()).status)
        self.assertEqual("empty_queue", self.select(issues=(replace(self.issue, eligible=False),)).status)
        blocked = self.select(done_issues=())
        self.assertEqual(("blocked", "dependencies-incomplete"), (blocked.status, blocked.reason))
        self.assertIsNone(blocked.scope)

    def test_claim_collision_stops_instead_of_retrying_previous_attempt(self):
        next_scope = approved("UOB-53", 6)
        for name in ("autodev/uob-50", "AutoDev/UOB-50", "autodev/uob-50/elsewhere", "autodev"):
            with self.subTest(name=name):
                result = self.select(
                    approvals=(self.scope, next_scope),
                    issues=(self.issue, observed(next_scope)),
                    github=replace(self.github, branch_names=("main", name)),
                )
                self.assertEqual(("blocked", "candidate-already-claimed"), (result.status, result.reason))

    def test_approval_is_not_inferred_from_issue_scope_or_labels(self):
        self.assertEqual("empty_queue", self.select(approvals=()).status)
        invalid = (
            {"approved_by": "another-user"},
            {"repo": "someone/AOTG"},
            {"kind": "live"},
            {"approval_sha": ""},
            {"revision": "2" * 64},
            {"allowed_paths": (".github/workflows/ci.yml",)},
            {"allowed_paths": ("aotg/benchmarks.py", "aotg/BENCHMARKS.py")},
        )
        for fields in invalid:
            with self.subTest(fields=fields):
                self.assertEqual("unverified-approval", self.select(approvals=(replace(self.scope, **fields),)).reason)
        self.assertEqual("ambiguous-approval", self.select(approvals=(self.scope, self.scope)).reason)

    def test_current_scope_and_both_issue_identities_must_match(self):
        for fields in (
            {"revision": "2" * 64},
            {"github_issue": 6},
            {"dependencies": ()},
        ):
            with self.subTest(fields=fields):
                result = self.select(issues=(replace(self.issue, **fields),))
                self.assertEqual(("blocked", "approval-scope-changed"), (result.status, result.reason))

    def test_operational_experiment_and_policy_issues_stay_outside_queue(self):
        for issue, gh in (("UOB-52", 8), ("UOB-54", 9), ("UOB-56", 10), ("UOB-59", 4), ("UOB-90", 2)):
            with self.subTest(issue=issue, gh=gh):
                held = approved(issue, gh)
                result = self.select(approvals=(held,), issues=(observed(held),))
                self.assertEqual("separate-approval-required", result.reason)


class ScopePathTests(unittest.TestCase):
    def test_allows_literal_safe_paths(self):
        for path in ("README.md", "aotg/benchmarks.py", "docs/bench.md", "tests/fixtures/aotg/case.json"):
            with self.subTest(path=path):
                self.assertTrue(valid_change_path(path))

    def test_rejects_nonportable_or_out_of_scope_paths(self):
        for path in (
            "",
            "/aotg/benchmarks.py",
            "../aotg/benchmarks.py",
            "aotg//benchmarks.py",
            "aotg/../benchmarks.py",
            "aotg/.hidden/benchmarks.py",
            r"aotg\benchmarks.py",
            "aotg/test*.py",
            "aotg/benchmarks.py:stream",
            "aotg/con.py",
            "aotg/autodev/queue.py",
            "aotg/sitecustomize.py",
            "tests/conftest.py",
            "tests/evidence/case.json",
            ".github/workflows/ci.yml",
            "docs/setup.ps1",
        ):
            with self.subTest(path=path):
                self.assertFalse(valid_change_path(path))


if __name__ == "__main__":
    unittest.main()