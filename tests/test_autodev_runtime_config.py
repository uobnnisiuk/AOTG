"""Test the offline approval registry and CLI before any model or remote writes."""

import json
import os
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import patch

from aotg.autodev.__main__ import shadow
from aotg.autodev.queue import (
    OWNER,
    POLICY,
    REPOSITORY,
    ApprovedScope,
    GitHubSnapshot,
    IssueSnapshot,
    scope_digest,
)
from aotg.autodev.runtime_config import ConfigError, load_approvals, parse_approvals

BASE = "a" * 40
REVISION = "b" * 64
PATH = "docs/example.md"
SCOPE = ApprovedScope("UOB-50", 10, REVISION, (PATH,), ("UOB-49",), "")
APPROVAL = replace(SCOPE, approval_sha=scope_digest(SCOPE))


def registry(*scopes):
    return json.dumps({
        "version": 1, "policy": POLICY, "repo": REPOSITORY,
        "scopes": [{
            "issue": s.issue, "github_issue": s.github_issue, "revision": s.revision,
            "allowed_paths": s.allowed_paths, "dependencies": s.dependencies,
            "approval_sha": s.approval_sha,
        } for s in scopes],
    })


class ConfigTests(TestCase):
    def test_registry_binds_revision_paths_and_identity(self):
        self.assertEqual(parse_approvals(registry(APPROVAL)), (APPROVAL,))
        self.assertEqual(parse_approvals(registry()), ())
        with self.assertRaises(ConfigError):
            parse_approvals(registry(replace(APPROVAL, allowed_paths=("docs/changed.md",))))
        with self.assertRaises(ConfigError):
            parse_approvals(registry(APPROVAL, APPROVAL))

    def test_registry_rejects_unknown_and_duplicate_fields(self):
        for content in (
            registry().replace('"version": 1', '"version": true'),
            registry().replace('"version": 1', '"version": 1, "version": 1'),
            registry().replace('"scopes": []', '"scopes": [], "commands": []'),
        ):
            with self.subTest(content=content), self.assertRaises(ConfigError):
                parse_approvals(content)

    @skipUnless(os.name == "posix", "WSL owner-mode check")
    def test_reads_private_file_only(self):
        with TemporaryDirectory() as name:
            root = Path(name)
            path = root / "approvals.json"
            path.write_text(registry(APPROVAL), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(load_approvals(path), (APPROVAL,))
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ConfigError):
                load_approvals(link)
            path.chmod(0o644)
            with self.assertRaises(ConfigError):
                load_approvals(path)


class ShadowTests(TestCase):
    def setUp(self):
        self.args = SimpleNamespace(
            github_cli=Path("gh"), approvals=Path("approvals.json"),
            linear_authorization=Path("linear.auth"), ledger=Path("ledger"),
        )
        self.inventory = GitHubSnapshot(BASE, (), ("main",), True, True)
        self.github = self._patch("GitHubRuntime").return_value
        self.github.snapshot.return_value = self.inventory
        self.github.read_issue.return_value = SimpleNamespace(number=10, author=OWNER, state="open")
        self.load = self._patch("load_approvals")
        self.load.return_value = (APPROVAL,)
        self._patch("load_linear_authorization").return_value = "test-only"
        self.intake = self._patch("LinearIntake").return_value
        self.intake.snapshot.return_value = (
            (IssueSnapshot("UOB-50", 10, REVISION, ("UOB-49",), True),), ("UOB-49",)
        )
        self.ledger = self._patch("Ledger").return_value

    def _patch(self, name):
        patcher = patch("aotg.autodev.__main__." + name)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def test_matching_scope_checks_ledger_without_reserving(self):
        self.assertEqual(shadow(self.args)["reason"], "shadow-eligible")
        self.ledger.check.assert_called_once()
        self.ledger.reserve.assert_not_called()
        self.github.reserve_branch.assert_not_called()

    def test_open_pr_short_circuits_private_inputs(self):
        self.github.snapshot.return_value = replace(self.inventory, open_pr_numbers=(9,))
        self.assertEqual(shadow(self.args)["reason"], "open-pr")
        self.load.assert_not_called()

    def test_empty_registry_does_not_require_or_consume_credentials(self):
        self.load.return_value = ()
        self.assertEqual(shadow(self.args)["status"], "empty_queue")
        self.intake.snapshot.assert_not_called()
        self.ledger.check.assert_not_called()

    def test_untrusted_github_issue_cannot_enter_queue(self):
        self.github.read_issue.return_value.author = "outside-contributor"
        self.assertEqual(shadow(self.args)["reason"], "unverified-github-issue")
        self.ledger.check.assert_not_called()
