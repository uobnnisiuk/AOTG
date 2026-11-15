"""Offline checks for the isolated Git handoff and non-force publication gate."""

import os
import subprocess
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import Mock, patch

from aotg.autodev.candidate_git import (
    _REMOTE,
    CandidateGitError,
    _push_https,
    _write_gate,
    build_candidate,
    push_candidate,
)
from aotg.autodev.queue import ApprovedScope, scope_digest
from aotg.autodev.worker import (
    ChangeSet,
    WorkerError,
    _git,
    capture_changes,
    prepare_checkout,
)

_BRANCH = "autodev/uob-50"


def _scope(paths, revision="1" * 64):
    source = ApprovedScope("UOB-50", 7, revision, paths, ("UOB-49",), "")
    return replace(source, approval_sha=scope_digest(source))


class CandidateGitTests(TestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.source = self.root / "source"
        template = self.root / "template"
        self.source.mkdir()
        template.mkdir()
        _git(self.source, "init", "--initial-branch=main", f"--template={template}")
        (self.source / "docs").mkdir()
        (self.source / "docs" / "remove.md").write_bytes(b"old content\n")
        (self.source / "docs" / "baseline.md").write_bytes(b"baseline\n")
        _git(self.source, "add", "--", "docs")
        _git(self.source, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
             "commit", "--no-gpg-sign", "-m", "Initial test tree")
        self.base = _git(self.source, "rev-parse", "HEAD")
        self.generated = prepare_checkout(self.source, self.root / "generated", self.base)
        self.proposed = self.root / "publication"
        self.scope = _scope(("docs/baseline.md", "docs/new.md", "docs/remove.md"))

    def _build(self):
        files = self.generated.path / "docs"
        (files / "baseline.md").write_bytes(b"changed\n")
        (files / "new.md").write_bytes(b"new content")
        (files / "remove.md").unlink()
        changes = capture_changes(self.generated, self.scope.allowed_paths)
        return build_candidate(self.source, self.proposed, self.base, changes, self.scope)

    def _publish(self, artifact, read, scope=None):
        push_candidate(
            artifact, self.scope if scope is None else scope, _BRANCH, branch_head=read,
            git=Path("not-run-git"), gh=Path("not-run-gh"),
        )

    def test_commit_contains_exact_changes_with_expected_parent(self):
        artifact = self._build()
        candidate = artifact.candidate
        self.assertEqual(candidate.paths, ("docs/baseline.md", "docs/new.md", "docs/remove.md"))
        self.assertTrue(candidate.local_checks_passed)
        self.assertEqual(_git(artifact.checkout, "rev-list", "--parents", "-n", "1", candidate.head),
                         f"{candidate.head} {self.base}")
        self.assertEqual(_git(artifact.checkout, "show", candidate.head + ":docs/new.md"), "new content")
        self.assertEqual(_git(self.source, "status", "--porcelain"), "")
        self.assertNotEqual(artifact.checkout, self.generated.path)

    def test_extra_file_hiding_behind_approved_filename_does_not_build(self):
        files = self.generated.path / "docs"
        (files / "baseline.md").write_bytes(b"changed\n")
        (files / "nonapproved.md").write_bytes(b"hidden\n")
        full = capture_changes(self.generated, ("docs/baseline.md", "docs/nonapproved.md"))
        forged = ChangeSet(("docs/baseline.md",), full.patch)
        with self.assertRaises(WorkerError):
            build_candidate(self.source, self.proposed, self.base, forged, self.scope)

    def test_invalid_scope_stops_before_checkout(self):
        forged = replace(self.scope, approval_sha="0" * 64)
        with self.assertRaises(CandidateGitError):
            build_candidate(self.source, self.proposed, self.base, ChangeSet((), b""), forged)
        self.assertFalse(self.proposed.exists())

    @patch("aotg.autodev.candidate_git._push_https")
    def test_postcommit_tampering_never_reaches_remote(self, remote):
        artifact = self._build()
        (artifact.checkout / "docs" / "baseline.md").write_bytes(b"tampered\n")
        with self.assertRaises(WorkerError):
            self._publish(artifact, Mock())
        remote.assert_not_called()

    @patch("aotg.autodev.candidate_git._push_https")
    def test_unexpected_local_config_never_reaches_remote(self, remote):
        artifact = self._build()
        _git(artifact.checkout, "config", "--local", "url.https://outside.invalid/.insteadOf", _REMOTE)
        with self.assertRaises(CandidateGitError):
            self._publish(artifact, Mock())
        remote.assert_not_called()

    @patch("aotg.autodev.candidate_git._push_https")
    def test_moved_reservation_stops_before_push(self, remote):
        artifact = self._build()
        read = Mock(return_value="9" * 40)
        with self.assertRaises(CandidateGitError):
            self._publish(artifact, read)
        read.assert_called_once_with(_BRANCH)
        remote.assert_not_called()

    @patch("aotg.autodev.candidate_git._push_https")
    def test_one_push_then_exact_readback(self, remote):
        artifact = self._build()
        read = Mock(side_effect=(self.base, artifact.candidate.head))
        self._publish(artifact, read)
        self.assertEqual(read.call_count, 2)
        remote.assert_called_once()

    @patch("aotg.autodev.candidate_git._push_https")
    def test_interrupted_push_never_retries(self, remote):
        artifact = self._build()
        remote.side_effect = CandidateGitError("test lost response")
        read = Mock(side_effect=(self.base, self.base))
        with self.assertRaises(CandidateGitError):
            self._publish(artifact, read)
        remote.assert_called_once()
        remote.reset_mock()
        read = Mock(side_effect=(self.base, artifact.candidate.head))
        self._publish(artifact, read)
        remote.assert_called_once()

    @patch("aotg.autodev.candidate_git._push_https")
    def test_same_paths_different_approval_cannot_be_used(self, remote):
        artifact = self._build()
        with self.assertRaises(CandidateGitError):
            self._publish(artifact, Mock(), _scope(self.scope.allowed_paths, "2" * 64))
        remote.assert_not_called()


@skipUnless(os.name == "posix", "POSIX Git pre-push executable")
class AdvertisedBaseTests(TestCase):
    def test_gate_accepts_one_exact_ordinary_update(self):
        base, head = "a" * 40, "b" * 40
        expected = f"{head} {head} refs/heads/{_BRANCH} {base}\n"
        with TemporaryDirectory() as name:
            directory = Path(name)
            _write_gate(directory, _BRANCH, base, head)
            for sample, url, allowed in (
                (expected, _REMOTE, True),
                (expected.replace(base, "c" * 40), _REMOTE, False),
                (expected.replace(base, "0" * 40), _REMOTE, False),
                (expected + expected, _REMOTE, False),
                (expected, "https://outside.invalid", False),
                ("", _REMOTE, False),
            ):
                with self.subTest(allowed=allowed, sample=sample, url=url):
                    completed = subprocess.run(
                        [str(directory / "pre-push"), "test", url], input=sample,
                        text=True, capture_output=True, check=False, timeout=5,
                    )
                    self.assertEqual(completed.returncode == 0, allowed)

    @patch("aotg.autodev.candidate_git._trusted_executable")
    @patch("aotg.autodev.candidate_git.subprocess.run")
    def test_transport_has_pinned_url_and_no_force_or_ambient_tokens(self, run, binary):
        binary.side_effect = (Path("/usr/bin/git"), Path("/trusted/bin/gh"))
        artifact = SimpleNamespace(
            checkout=Path("/private/trusted/checkout"),
            candidate=SimpleNamespace(head="a" * 40, base="b" * 40),
        )

        def inspect(argv, **kwargs):
            self.assertFalse(kwargs["shell"])
            self.assertTrue(kwargs["check"])
            self.assertEqual(argv[-2:], [_REMOTE, "a" * 40 + ":refs/heads/" + _BRANCH])
            self.assertNotIn("--force", " ".join(argv))
            self.assertNotIn("--all", argv)
            self.assertNotIn("--no-verify", argv)
            self.assertIn("credential.helper=", argv)
            self.assertIn("http.followRedirects=false", argv)
            self.assertIn("protocol.allow=never", argv)
            self.assertNotIn("GIT_CONFIG_COUNT", kwargs["env"])
            self.assertNotIn("GH_TOKEN", kwargs["env"])
            hooks = next(arg.partition("=")[2] for arg in argv if arg.startswith("core.hooksPath="))
            self.assertTrue((Path(hooks) / "pre-push").is_file())

        run.side_effect = inspect
        with patch.dict(os.environ, {"GH_TOKEN": "synthetic", "GIT_CONFIG_COUNT": "1"}):
            _push_https(artifact, _BRANCH, Path("/usr/bin/git"), Path("/trusted/bin/gh"), None)
        run.assert_called_once()
