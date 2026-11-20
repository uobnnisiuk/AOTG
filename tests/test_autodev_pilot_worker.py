"""Exercise the pilot worker with temporary repositories and a fake isolated runner."""

import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns
from unittest import TestCase, skipUnless
from unittest.mock import MagicMock, Mock, patch

from aotg.autodev.candidate_git import build_candidate
from aotg.autodev.coordinator import Candidate
from aotg.autodev.pilot_runtime import PilotAttemptBoundary, PilotError
from aotg.autodev.pilot_worker import (
    PILOT_CONTRACT,
    PILOT_PATHS,
    PILOT_PROMPT,
    PilotWorker,
)
from aotg.autodev.queue import ApprovedScope, scope_digest
from aotg.autodev.worker import CandidateRejected, WorkerError

SCOPE = ApprovedScope("UOB-50", 7, "a" * 64, PILOT_PATHS, ("UOB-49",), "")
SCOPE = replace(SCOPE, approval_sha=scope_digest(SCOPE))


def _run_git(path, *args):
    return subprocess.run(
        ("git", "-C", str(path), *args), check=True, capture_output=True, text=True,
    ).stdout.strip()


class ContractRejection(Exception):
    """The exception a trusted runner injects into the fixed grader script."""


class PilotContractTests(TestCase):
    @staticmethod
    def run_contract(responses, *, readable=True):
        processes = []
        reads = []
        for payload, code in responses:
            manager = MagicMock()
            child = manager.__enter__.return_value
            child.poll.return_value = code
            child.wait.return_value = code
            processes.append(manager)
            reads.extend((payload, b""))
        with (
            patch("subprocess.Popen", side_effect=processes),
            patch("select.select", return_value=([True] if readable else [], [], [])),
            patch("os.read", side_effect=reads),
        ):
            exec(PILOT_CONTRACT, {"RejectCandidate": ContractRejection})
        return [process.__enter__.return_value.stdin.write.call_args.args[0] for process in processes]

    def test_complete_valid_fixture_outputs_pass(self):
        statuses = (
            ("pass", 0), ("missing_observations", 0), ("timeout", 0),
            ("malformed", 2), ("malformed", 2), ("malformed", 2), ("assertion_mismatch", 0),
        )
        catalog = json.loads((Path(__file__).parent / "fixtures/benchmark/catalog.json").read_bytes())
        responses = []
        expected_result_changes = []
        for case, key in (("cpp-half-open-interval", "assertions"),
                          ("csharp-atomic-batch", "assertion_sequences")):
            observations = next(item[key] for item in catalog["cases"] if item["id"] == case)
            pending = [observations]
            scalar_count = 0
            while pending:
                item = pending.pop()
                if type(item) is dict:
                    pending.extend(item.values())
                elif type(item) is list:
                    pending.extend(item)
                else:
                    scalar_count += 1
            responses.extend(
                (json.dumps({"version": 1, "case": case, "status": status}).encode("utf-8"), code)
                for status, code in statuses + (("assertion_mismatch", 0),) * scalar_count
            )
            for index, item in enumerate(observations):
                positions = [None] if key == "assertions" else range(len(item["operations"]))
                for position in positions:
                    changed = json.loads(json.dumps(observations))
                    result = changed[index] if position is None else changed[index]["operations"][position]
                    result["result"] = not result["result"]
                    expected_result_changes.append({"observations": changed})
        requests = self.run_contract(responses)
        decoded = [json.loads(request) for request in requests if request != b"broken-json"]
        for changed in expected_result_changes:
            self.assertIn(changed, decoded)

    def test_complete_wrong_result_is_definitively_rejected(self):
        expected = {"version": 1, "case": "cpp-half-open-interval", "status": "pass"}
        for observed in (
            [],
            {**expected, "status": "assertion_mismatch"},
            {**expected, "version": True},
            {**expected, "version": 1.0},
            {**expected, "unexpected": []},
        ):
            with self.subTest(observed=observed), self.assertRaises(ContractRejection):
                self.run_contract([(json.dumps(observed).encode("utf-8"), 0)])

    def test_complete_invalid_output_is_definitively_rejected(self):
        for payload in (
            b"",
            b'{"version": 1',
            b'{"version": 1, "version": 1}',
            b'{"version": NaN}',
            b'debug\n{"version": 1, "case": "cpp-half-open-interval", "status": "pass"}',
            bytes([255]),
            b"[" * 1024,
        ):
            with self.subTest(payload=payload), self.assertRaises(ContractRejection):
                self.run_contract([(payload, 0)])

    def test_output_over_the_limit_remains_unknown(self):
        with self.assertRaises(SystemExit):
            self.run_contract([(b" " * 1025, 0)])

    def test_signal_unexpected_exit_and_read_timeout_are_not_definitive(self):
        payload = b'{"version": 1, "case": "cpp-half-open-interval", "status": "wrong"}'
        for code, readable in ((-9, True), (1, True), (3, True), (0, False)):
            with self.subTest(code=code, readable=readable), self.assertRaises(SystemExit):
                self.run_contract([(payload, code)], readable=readable)


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

    def test_incomplete_candidate_is_rejected_without_publication(self):
        def generate_partial(checkout, prompt, *, timeout_seconds):
            self.assertEqual(self.preflighted, checkout)
            self.assertEqual(prompt, PILOT_PROMPT)
            for name in PILOT_PATHS[:-1]:
                (checkout / name).write_bytes(b"partial candidate output")

        self.runner.generate.side_effect = generate_partial
        with self.assertRaises(CandidateRejected):
            self.worker.implement(SCOPE, self.base, timeout_seconds=60)
        self.runner.verify.assert_not_called()
        self.build.assert_not_called()

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

    def test_host_is_rechecked_after_preflight_before_model(self):
        quiet = Mock(return_value=True)
        boundary = PilotAttemptBoundary.from_deadline(monotonic_ns() + 300_000_000_000, quiet)

        def preflight(checkout, *, timeout_seconds):
            self.preflight(checkout, timeout_seconds=timeout_seconds)
            quiet.return_value = False

        self.runner.preflight.side_effect = preflight
        worker = PilotWorker(self.source, self.run_root, self.runner, build=self.build, boundary=boundary)
        with self.assertRaises(PilotError):
            worker.implement(SCOPE, self.base, timeout_seconds=60)
        self.runner.preflight.assert_called_once()
        self.runner.generate.assert_not_called()
        self.runner.verify.assert_not_called()
        self.build.assert_not_called()

    def test_roots_cannot_overlap_candidate_source(self):
        nested = self.source / "nested"
        nested.mkdir()
        worker = PilotWorker(self.source, nested, self.runner, build=self.build)
        with self.assertRaises(WorkerError):
            worker.implement(SCOPE, self.base, timeout_seconds=60)
        self.runner.preflight.assert_not_called()
