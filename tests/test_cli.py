"""Integration tests for the public CLI and its artifact handoffs."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DryRunCliTest(unittest.TestCase):
    def cli(self, *args):
        result = subprocess.run(
            [sys.executable, "-X", "utf8", "-m", "aotg", *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            encoding="utf-8",
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return result.stdout

    def test_mock_fixtures_to_verified_kit(self):
        for name in ("evo-linux.json", "k8-mock.json"):
            with self.subTest(fixture=name), tempfile.TemporaryDirectory() as folder:
                fixture = ROOT / "tests/fixtures" / name
                output = Path(folder) / "results"
                plan = output / "plan.json"
                run = output / "run.json"
                decision = output / "decision.json"
                kit = output / "kit.json"

                manifest = self.cli("inspect", "--manifest", fixture)
                self.assertEqual(json.loads(manifest), json.loads(fixture.read_bytes()))
                self.cli("plan", "--manifest", fixture, "--output", plan)
                self.cli("bench", "--plan", plan, "--output", run)
                self.cli("compare", "--run", run, "--output", decision)
                self.cli("build-kit", "--run", run, "--decision", decision, "--output", kit)
                verification = json.loads(self.cli("verify-kit", "--kit", kit, "--run", run))
                self.assertIs(verification["verified"], True)

    def test_resume_reproduces_uninterrupted_report(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            fixture = ROOT / "tests/fixtures/evo-linux.json"
            plan = output / "plan.json"
            partial = output / "partial.json"
            resumed = output / "resumed.json"
            uninterrupted = output / "uninterrupted.json"

            self.cli("plan", "--manifest", fixture, "--output", plan)
            self.cli("bench", "--plan", plan, "--output", partial, "--trial-budget", 2)
            original_checkpoint = partial.read_bytes()
            self.cli("bench", "--plan", plan, "--output", resumed, "--resume", partial)
            self.cli("bench", "--plan", plan, "--output", uninterrupted)

            self.assertEqual(original_checkpoint, partial.read_bytes())
            self.assertEqual(json.loads(resumed.read_bytes()), json.loads(uninterrupted.read_bytes()))


if __name__ == "__main__":
    unittest.main()
