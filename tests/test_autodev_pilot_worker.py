"""Exercise the pilot worker with temporary repositories and a fake isolated runner."""

import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, skipUnless
from unittest.mock import Mock, patch

from aotg.autodev.candidate_git import build_candidate
from aotg.autodev.coordinator import Candidate
from aotg.autodev.pilot_worker import (
    PILOT_CONTRACT,
    PILOT_PATHS,
    PILOT_PROMPT,
    PilotWorker,
)
from aotg.autodev.queue import ApprovedScope, scope_digest
from aotg.autodev.worker import WorkerError

SCOPE = ApprovedScope("UOB-50", 7, "a" * 64, PILOT_PATHS, ("UOB-49",), "")
SCOPE = replace(SCOPE, approval_sha=scope_digest(SCOPE))


def _run_git(path, *args):
    return subprocess.run(
        ("git", "-C", str(path), *args), check=True, capture_output=True, text=True,
    ).stdout.strip()


@skipUnless(shutil.which("git"), "Git is required for workspace isolation tests")
class PilotWorkerTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        self.source = root / "source"
        self.source.mkdir()
        self.run_root = root / "private"
        self.run_root.mkdir(mode=0o700)
        for folder in ("aotg", "tests", "docs"):
            (self.source / folder).mkdir()
            (self.source / folder / "existing.txt").write_bytes(b"baseline\n")
        _run_git(self.source, "init", "-q", "-b", "main")
        _run_git(self.source, "add", ".")
        _run_git(self.source, "-c", "user.name=Tests", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic baseline")
        self.base = _run_git(self.source, "rev-parse", "HEAD")
        self.runner = Mock()
        self.runner.preflight.side_effect = self.preflight
        self.preflighted = None
        self.runner.generate.side_effect = self.generate
        self.runner.verify.side_effect = self.verify
        self.build = Mock(side_effect=self.build_candidate)
        self.worker = PilotWorker(self.source, self.run_root, self.runner, build=self.build)

    def preflight(self, checkout, *, timeout_seconds):
        self.assertGreater(timeout_seconds, 0)
        self.preflighted = checkout

    def generate(self, checkout, prompt, *, timeout_seconds):
        self.assertEqual(self.preflighted, checkout)
        self.assertEqual(prompt, PILOT_PROMPT)
        self.assertGreater(timeout_seconds, 0)
        for name in PILOT_PATHS:
            (checkout / name).write_bytes(b"Example pilot output\n")

    def verify(self, checkout, *, timeout_seconds, contract):
        self.assertEqual(self.preflighted, checkout)
        self.assertEqual(contract, PILOT_CONTRACT)
        self.assertGreater(timeout_seconds, 0)
        for name in PILOT_PATHS:
            self.assertEqual((checkout / name).read_bytes(), b"Example pilot output\n")

    def build_candidate(self, source, checkout, base, changes, scope):
        self.assertEqual(source, self.source)
        self.assertEqual((base, scope), (self.base, SCOPE))
        return build_candidate(source, checkout, base, changes, scope)

    def test_generation_verification_and_publication_use_separate_workspaces(self):
        cand = self.worker.implement(SCOPE, self.base, timeout_seconds=60)
        self.assertEqual(cand, Candidate(self.base, cand.head, PILOT_PATHS, True))
        generation = self.runner.generate.call_args.args[0]
        verification = self.runner.verify.call_args.args[0]
        artifact = self.worker.artifact_for(cand)
        self.assertEqual([call.args[0] for call in self.runner.preflight.call_args_list],
                         [generation, verification])
        self.assertEqual(len({generation, verification, artifact.checkout}), 3)
        self.assertFalse(any((self.source / path).exists() for path in PILOT_PATHS))
        self.assertEqual(_run_git(self.source, "status", "--porcelain"), "")
        with self.assertRaises(WorkerError):
            self.worker.artifact_for(replace(cand, head="c" * 40))
        with self.assertRaises(WorkerError):
            self.worker.implement(SCOPE, self.base, timeout_seconds=60)
        self.runner.generate.assert_called_once()

    def test_generated_out_of_scope_changes_cannot_enter_verification(self):
        def generate(checkout, prompt, *, timeout_seconds):
            self.generate(checkout, prompt, timeout_seconds=timeout_seconds)
            (checkout / "docs/existing.txt").write_bytes(b"outside scope\n")

        self.runner.generate.side_effect = generate
        with self.assertRaises(WorkerError):
            self.worker.implement(SCOPE, self.base, timeout_seconds=60)
        self.runner.verify.assert_not_called()
        self.build.assert_not_called()

    def test_verification_mutation_cannot_enter_publication(self):
        def modify(checkout, **kwargs):
            self.verify(checkout, **kwargs)
            (checkout / PILOT_PATHS[0]).write_bytes(b"post-check mutation\n")

        self.runner.verify.side_effect = modify
        with self.assertRaisesRegex(WorkerError, "changed during verification"):
            self.worker.implement(SCOPE, self.base, timeout_seconds=60)
        self.build.assert_not_called()

    def test_block_invalid_approval_project_paths_and_duration(self):
        for changes in (
            {"github_issue": 8}, {"issue": "UOB-52"}, {"dependencies": ()},
            {"allowed_paths": ("README.md",)}, {"approved_by": "other"},
        ):
            scope = replace(SCOPE, **changes)
            scope = replace(scope, approval_sha=scope_digest(scope))
            with self.subTest(changes=changes), self.assertRaises(WorkerError):
                self.worker.implement(scope, self.base, timeout_seconds=60)
        for timeout in (True, float("nan"), float("inf"), 0, 2401):
            with self.subTest(timeout=timeout), self.assertRaises(WorkerError):
                self.worker.implement(SCOPE, self.base, timeout_seconds=timeout)
        self.assertEqual(list(self.run_root.iterdir()), [])
        self.runner.preflight.assert_not_called()

    def test_all_phases_share_the_same_deadline(self):
        self.runner.verify.side_effect = TimeoutError("internal detail")
        with patch("aotg.autodev.pilot_worker.monotonic", side_effect=(0, 1, 2, 3, 4, 5)):
            with self.assertRaises(TimeoutError):
                self.worker.implement(SCOPE, self.base, timeout_seconds=10)
        self.assertEqual(self.runner.preflight.call_args_list[0].kwargs["timeout_seconds"], 9)
        self.assertEqual(self.runner.generate.call_args.kwargs["timeout_seconds"], 8)
        self.assertEqual(self.runner.preflight.call_args_list[1].kwargs["timeout_seconds"], 6)
        self.assertEqual(self.runner.verify.call_args.kwargs["timeout_seconds"], 5)
        self.build.assert_not_called()

    def test_roots_cannot_overlap_candidate_source(self):
        nested = self.source / "nested"
        nested.mkdir()
        worker = PilotWorker(self.source, nested, self.runner, build=self.build)
        with self.assertRaises(WorkerError):
            worker.implement(SCOPE, self.base, timeout_seconds=60)
        self.runner.preflight.assert_not_called()
