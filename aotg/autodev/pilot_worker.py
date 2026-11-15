"""Prepare and verify an isolated candidate for the fixed offline benchmark pilot."""

import math
import os
import re
from pathlib import Path
from tempfile import mkdtemp
from time import monotonic
from typing import Protocol

from .candidate_git import CandidateArtifact, build_candidate
from .coordinator import Candidate
from .ledger import LedgerError, _validate_path
from .pilot_runtime import BOOTSTRAP_PATHS, PilotAttemptBoundary, _is_first_scope
from .queue import ApprovedScope
from .worker import (
    MAX_RUNTIME_SECONDS,
    CandidateRejected,
    WorkerError,
    _git_bytes,
    capture_changes,
    prepare_checkout,
)

PILOT_PATHS = tuple(sorted(BOOTSTRAP_PATHS))

# Derived from the reviewed software-only GitHub #7 scope. Prompt text is never
# read from a live issue, a candidate file, or the broader Linear benchmark.
PILOT_PROMPT = """Implement only the UOB-50 offline benchmark pilot from AOTG GitHub #7.
Use the existing synthetic cpp-half-open-interval assertions and csharp-atomic-batch
assertion_sequences in tests/fixtures/benchmark/catalog.json. Compare values,
types, and order exactly. Use Python's standard library only. Add exactly
aotg/offline_bench.py, tests/test_offline_bench.py, and docs/offline-bench.md.

The required command is python -m aotg.offline_bench --case CASE --catalog FILE.
Read one JSON object from stdin. For C++, observations is the assertions array;
for C#, it is the assertion_sequences array, preserving group and operation
order. Complete matching observations give pass. Complete well-formed but
different observations give assertion_mismatch. Absent or partial observations
give missing_observations. The object {"timeout": true} gives timeout. Invalid
JSON or invalid types give malformed. Compare JSON types strictly, including
the difference between booleans and integers. Never include observations in
the output. Emit {"version": 1, "case": CASE, "status": STATUS} as JSON on stdout.
Use exit 0 for grade results and 2 for malformed input.

Add tests for both cases and mismatched, missing, timed-out and malformed inputs.
Document the command and format. Keep existing fixtures, assertions and CI
intact. Do not access any model, network, service, firmware, compiler download,
nonpublic evidence, credentials or external file. Do not commit or push.
"""

# Executed by the isolated verifier as a fixed stdin script, outside the
# candidate's test files. Only the candidate CLI child interprets its code.
PILOT_CONTRACT = """import copy
import json
import os
import select
import subprocess
import sys
from pathlib import Path
from time import monotonic

catalog_path = "tests/fixtures/benchmark/catalog.json"
cases = {
    case["id"]: case for case in json.loads(Path(catalog_path).read_bytes())["cases"]
}

def unique_fields(items):
    data = {}
    for key, value in items:
        if key in data:
            raise ValueError("Duplicate pilot result field")
        data[key] = value
    return data

def check(case, request, expected_status, code=0):
    if len(request) > 4096:
        raise SystemExit("Pilot contract input exceeded its bound")
    argv = [sys.executable, "-EBsS", "-m", "aotg.offline_bench",
            "--case", case, "--catalog", catalog_path]
    deadline = monotonic() + 10
    output = bytearray()
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as child:
        try:
            child.stdin.write(request)
            child.stdin.close()
            while len(output) <= 1024:
                seconds = deadline - monotonic()
                if seconds <= 0 or not select.select([child.stdout], [], [], seconds)[0]:
                    raise SystemExit("Pilot grading command timed out")
                chunk = os.read(child.stdout.fileno(), 1025 - len(output))
                if not chunk:
                    break
                output.extend(chunk)
            if len(output) > 1024 or child.wait(timeout=max(0, deadline - monotonic())) != code:
                raise SystemExit("Unexpected pilot result envelope")
        finally:
            if child.poll() is None:
                child.kill()

    data = json.loads(output, object_pairs_hook=unique_fields)
    if (type(data) is not dict or type(data.get("version")) is not int
            or data != {"version": 1, "case": case, "status": expected_status}):
        raise SystemExit("Unexpected pilot grading result")

def encoded(value):
    return json.dumps(value).encode("utf-8")

for case, key in (("cpp-half-open-interval", "assertions"),
                  ("csharp-atomic-batch", "assertion_sequences")):
    observations = cases[case][key]
    check(case, encoded({"observations": observations}), "pass")
    check(case, encoded({"observations": observations[:-1]}), "missing_observations")
    check(case, encoded({"timeout": True}), "timeout")
    check(case, b"broken-json", "malformed", code=2)
    check(case, encoded({"observations": "not an array"}), "malformed", code=2)
    invalid = copy.deepcopy(observations)
    result = invalid[0] if key == "assertions" else invalid[0]["operations"][0]
    result["result"] = 1 if result["result"] else 0
    check(case, encoded({"observations": invalid}), "malformed", code=2)
    reordered = copy.deepcopy(observations)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    check(case, encoded({"observations": reordered}), "assertion_mismatch")
"""


class PilotRunner(Protocol):
    """Trusted wrapper for tools running under an externally verified boundary."""

    def preflight(self, checkout: Path, *, timeout_seconds: float) -> None: ...
    def generate(self, checkout: Path, prompt: str, *, timeout_seconds: float) -> None: ...
    def verify(self, checkout: Path, *, timeout_seconds: float, contract: str) -> None: ...


class PilotWorker:
    """Use distinct generated, verification, and publication workspaces."""

    def __init__(
        self, source: Path, run_root: Path, runner: PilotRunner, *, build=build_candidate,
        boundary: PilotAttemptBoundary | None = None,
    ):
        self.source = Path(source)
        self.run_root = Path(run_root)
        self.runner = runner
        self.build = build
        self.boundary = boundary
        self._started = False
        self._artifact = None

    def implement(self, scope: ApprovedScope, base: str, *, timeout_seconds: int | float) -> Candidate:
        if not _is_first_scope(scope):
            raise WorkerError("Worker requires the exact approved offline pilot")
        if (not isinstance(base, str) or not re.fullmatch(r"(?!0{40})[0-9a-f]{40}", base)
                or isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= MAX_RUNTIME_SECONDS):
            raise WorkerError("Invalid pilot base or execution budget")
        if self._started:
            raise WorkerError("Worker already handled one attempt")
        self._started = True
        deadline = monotonic() + timeout_seconds
        source, run_root = _separate_roots(self.source, self.run_root)
        run = Path(mkdtemp(prefix="aotg-pilot-", dir=run_root))
        generated = prepare_checkout(source, run / "generation", base)
        self.runner.preflight(generated.path, timeout_seconds=self._remaining_work(deadline))
        self.runner.generate(generated.path, PILOT_PROMPT, timeout_seconds=self._remaining_work(deadline))
        _remaining(deadline)
        changes = capture_changes(generated, PILOT_PATHS)
        if changes.paths != PILOT_PATHS or any(name in PILOT_PATHS for name, _, _ in generated.baseline):
            raise CandidateRejected("Pilot candidate must add all three approved files")

        verifier = prepare_checkout(source, run / "verification", base)
        _git_bytes(
            verifier.path, "-c", f"core.hooksPath={os.devnull}", "apply", "--whitespace=error",
            input_data=changes.patch,
        )
        if capture_changes(verifier, PILOT_PATHS) != changes:
            raise WorkerError("Verification workspace does not match the generated patch")
        self.runner.preflight(verifier.path, timeout_seconds=self._remaining_work(deadline))
        self.runner.verify(
            verifier.path, timeout_seconds=self._remaining_work(deadline), contract=PILOT_CONTRACT,
        )
        _remaining(deadline)
        if capture_changes(verifier, PILOT_PATHS) != changes:
            raise WorkerError("The candidate changed during verification")

        artifact = self.build(source, run / "publication", base, changes, scope)
        _remaining(deadline)
        if type(artifact) is not CandidateArtifact:
            raise WorkerError("The verified candidate artifact could not be confirmed")
        candidate = artifact.candidate
        if (type(candidate) is not Candidate
                or artifact.checkout != run / "publication" or artifact.changes != changes
                or artifact.approval_sha != scope.approval_sha
                or artifact.baseline.path != artifact.checkout or artifact.baseline.base_sha != base
                or candidate.base != base or candidate.paths != PILOT_PATHS
                or not isinstance(candidate.head, str) or not re.fullmatch(r"(?!0{40})[0-9a-f]{40}", candidate.head)
                or candidate.head == base or candidate.local_checks_passed is not True):
            raise WorkerError("The verified candidate artifact could not be confirmed")
        self._artifact = artifact
        return candidate

    def _remaining_work(self, deadline):
        if self.boundary is None:
            return _remaining(deadline)
        return min(self.boundary.worker_seconds(), _remaining(deadline))

    def artifact_for(self, candidate: Candidate) -> CandidateArtifact:
        if (self._artifact is None or type(candidate) is not Candidate
                or candidate != self._artifact.candidate):
            raise WorkerError("No verified artifact matches this candidate")
        return self._artifact


def _remaining(deadline):
    seconds = deadline - monotonic()
    if seconds <= 0:
        raise TimeoutError("Pilot exhausted its shared execution deadline")
    return seconds


def _separate_roots(source, run_root):
    try:
        if (not source.is_absolute() or not run_root.is_absolute()
                or source.resolve(strict=True) != source or run_root.resolve(strict=True) != run_root
                or source.is_relative_to(run_root) or run_root.is_relative_to(source)):
            raise WorkerError("A separate private pilot directory is required")
        _validate_path(run_root, directory=True)
    except (OSError, LedgerError, RuntimeError) as exc:
        raise WorkerError("A separate private pilot directory is required") from exc
    return source, run_root
