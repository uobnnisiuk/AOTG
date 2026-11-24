"""Run the published, synthetic-only observation suite under normal CI discovery."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_CANDIDATE = (Path(__file__).resolve().parents[1] / "docs" / "field-notes"
              / "memory-context-candidate")
_INDEXED = {
    "capacity_envelope.py",
    "serialized_budget.py",
    "diagnostic_triage.py",
    "resource_context.py",
    "observation_journal.py",
    "test_resource_context.py",
    "test_observation_journal.py",
    "test_private_integration.py",
    "memory-context-integration.patch",
    "README.md",
    "capacity-result.json",
}


@unittest.skipUnless(sys.platform.startswith("linux"), "Published suite requires Linux/WSL (POSIX no-follow)")
class PublicObservationSuiteTests(unittest.TestCase):
    def test_indexed_synthetic_suite(self):
        # Verify the complete published input index before executing any candidate code.
        index = json.loads((_CANDIDATE / "source-index.json").read_bytes())
        entries = index["files"]
        self.assertEqual(len(entries), len(_INDEXED))
        self.assertEqual({entry["path"] for entry in entries}, _INDEXED)
        for entry in entries:
            name = entry["path"]
            raw = (_CANDIDATE / name).read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(len(raw), entry["bytes"], name)
            self.assertEqual(digest, entry["sha256"], name)
            print(f"observation-suite input {name}: {len(raw)} bytes sha256={digest}", flush=True)

        # Same isolated interpreter flags as the README, from a fresh working directory.
        # No private runner, fixture, device, service or field execution is requested.
        with tempfile.TemporaryDirectory() as cwd:
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(_CANDIDATE / "test_observation_journal.py")],
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )
        print(result.stdout, flush=True)
        print(f"observation-suite exit={result.returncode}", flush=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertRegex(result.stdout, r"(?m)^Ran 67 tests in ")
        self.assertRegex(result.stdout, r"(?m)^OK$")
