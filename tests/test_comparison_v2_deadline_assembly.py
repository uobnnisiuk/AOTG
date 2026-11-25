"""Offline deadline adoption candidate; the frozen archive is never rewritten.

The supervisor receipts and all arm observations are synthetic, not host
measurements. This exercises the real archived assembler and both decisions
with a separate, staged gate. No runner, controller, model or service is run.
"""
import hashlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "docs/field-notes/comparison-v2-runtime/assessment-component"
PINS = {
    "aotg/__init__.py": "c4328d19744befda05683d5d703db8f15979394a",
    "aotg/artifacts.py": "84676ce8435b28b7ff52c835815bfecd8d0bbf4d",
    "aotg/field_evidence.py": "1d547a18c5ec45080c2a1bb4d2b835d295792b37",
    "aotg/field_client.py": "d8b0c176225425b60b439812a60c47f2c0ebb378",
    "aotg/quality.py": "dd71740f9a9d454142a532e9fea6c3da7354f240",
    "aotg/field_sandbox.py": "1f61ce684e19c3051c3f4b18e2a3d0b70cf3c170",
    "aotg/field_selftest.py": "183b33aee2c4d0048a1447ced352bd187a9dc940",
    "aotg/field_proxy.py": "b0ccb8bcee3ae6ac2e731aed40db78f7249962de",
    "tools/assemble_field_evidence.py": "dab6787e24e0014fb1cc3a886eb62a3a67b8b676",
    "tools/io_capture_diagnostics.py": "777957dc9c3c3968517cd1dd315ba074d1048be5",
    "tools/tool_roundtrip_diagnostics.py": "713a9622f9363d518bdd53a07417bd302ff7a30b",
    "tests/test_field_assessment_assemble.py": "31f7c7f39ee5392bf5c8a99a8a64dc591f6b13ec",
    "tests/fixtures/assessment/native-driver.md": "bae1ae76cadfe42761ab0445fcb0a976e834ce99",
    "tests/fixtures/benchmark/catalog.json": "3ae824fbc1b6da454c4e8ff9d17c9b7ee37c88f2",
}
ASSEMBLER = "tools/assemble_field_evidence.py"
FIXTURE = "tests/test_field_assessment_assemble.py"
NS = 1_000_000_000

# Candidate source is evaluated only with the pinned assembler in the isolated
# synthetic test. The authority must come from an external trusted observer;
# hashes establish association, not observer authentication or actual elapsed time.
# Inclusive boundary matches the archived runner's strict > deadline policy.
GATE_SOURCE = '''
def external_deadline_gate(authority, client, spec):
    value = authority.value
    need(type(client.get("max_seconds")) is int and client["max_seconds"] == 5400,
         "external_deadline_plan_invalid")
    need("deadline_supervision" in value, "external_deadline_evidence_missing")
    receipt = authority.file(value["deadline_supervision"])
    need(isinstance(receipt, dict), "external_deadline_receipt_invalid")
    inventory = value["job_inventory"]
    launch = authority.file(inventory["launch"])
    completion = authority.file(inventory["completion"])
    need(receipt.get("artifact") == "aotg-synthetic-independent-deadline"
         and type(receipt.get("version")) is int and receipt["version"] == 1
         and receipt.get("run_id") == client["run_id"]
         and receipt.get("client_plan_sha256") == digest(client)
         and receipt.get("client_plan_raw_sha256") == spec["client_plan"]["sha256"]
         and receipt.get("runner_sha256") == client["runner_sha256"]
         and type(receipt.get("pid")) is int and receipt["pid"] == launch["pid"]
         and receipt.get("pid_start_ticks") == launch["pid_start_ticks"]
         and receipt.get("launch_sha256") == inventory["launch"]["sha256"]
         and receipt.get("completion_sha256") == inventory["completion"]["sha256"]
         and receipt.get("summary_sha256") == value["client_summary_sha256"],
         "external_deadline_identity_mismatch")
    need(receipt.get("clock") == "CLOCK_MONOTONIC"
         and isinstance(receipt.get("start_domain"), str)
         and 0 < len(receipt["start_domain"]) <= 128
         and receipt.get("end_domain") == receipt["start_domain"],
         "external_deadline_clock_invalid")
    start, end, limit = (receipt.get(key) for key in
                         ("start_ns", "end_ns", "deadline_ns"))
    need(all(type(item) is int for item in (start, end, limit))
         and 0 <= start <= end and limit == start + client["max_seconds"] * 1000000000,
         "external_deadline_clock_invalid")
    need(end <= limit, "external_deadline_exceeded")
    need(receipt.get("outcome") == "exited"
         and type(receipt.get("exit_code")) is int
         and receipt["exit_code"] == completion["exit_code"] == 0,
         "external_deadline_exit_unconfirmed")
    return True


'''


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def load_source(name, path, source):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
    "Archived assessment requires POSIX directory descriptors",
)
class DeadlineAssemblyTests(unittest.TestCase):
    def test_external_deadline_controls_both_decisions(self):
        with tempfile.TemporaryDirectory(prefix="aotg-deadline-assembly-") as tmp:
            root = Path(tmp)
            staged = root / "candidate"
            for relative, pin in PINS.items():
                raw = (ARCHIVE / relative).read_bytes()
                self.assertEqual(git_blob(raw), pin, relative)
                target = staged / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            source = (staged / ASSEMBLER).read_text()
            fixture_source = (staged / FIXTURE).read_text()
            # The old fixture omitted max_seconds. Freeze it before the fixture
            # computes any plan/summary/authority binding; no post hoc rewrite.
            anchor = '"proxy_capture_version": 2, "output_root":'
            self.assertEqual(fixture_source.count(anchor), 1)
            fixture_source = fixture_source.replace(
                anchor, '"max_seconds": 5400, ' + anchor, 1
            )
            gate_anchor = "def jobs_gate(reader, authority, client, spec):"
            call_anchor = "        jobs_gate(reader, authority, client, spec)\n"
            self.assertEqual(source.count(gate_anchor), 1)
            self.assertEqual(source.count(call_anchor), 1)
            candidate_source = source.replace(gate_anchor, GATE_SOURCE + gate_anchor, 1)
            candidate_source = candidate_source.replace(
                call_anchor, call_anchor + "        external_deadline_gate(authority, client, spec)\n", 1
            )
            old_modules = dict(sys.modules)
            try:
                fixture = load_source("_deadline_fixture", staged / FIXTURE, fixture_source)
                candidate = load_source("_deadline_candidate", staged / ASSEMBLER, candidate_source)
                evidence = root / "synthetic-evidence"
                evidence.mkdir()
                f = fixture.Fixture(evidence)
                self.check_controls(f, fixture.a, candidate)
            finally:
                for name in list(sys.modules):
                    if name.startswith("_aotg_private_assessment"):
                        if name in old_modules:
                            sys.modules[name] = old_modules[name]
                        else:
                            del sys.modules[name]
            # Both original repository files and their staged copies remain pinned.
            for relative, pin in PINS.items():
                self.assertEqual(git_blob((ARCHIVE / relative).read_bytes()), pin)
                self.assertEqual(git_blob((staged / relative).read_bytes()), pin)

    def check_controls(self, f, original, candidate):
        inventory = f.authority["job_inventory"]
        captured = {item["path"]: item["sha256"] for item in f.authority["captured_files"]}
        launch = json.loads(Path(inventory["launch"]["path"]).read_text())
        completion = json.loads(Path(inventory["completion"]["path"]).read_text())
        after = json.loads(Path(inventory["after"]["path"]).read_text())
        self.assertEqual(f.client["max_seconds"], 5400)
        self.assertEqual(len(f.field["schedule"]), 32)
        self.assertEqual(f.ksummary["status"], original.COMPLETE)
        self.assertFalse(f.ksummary["total_deadline_exceeded"])

        def receipt_for(seconds, *, wall_seconds=None):
            wall = seconds if wall_seconds is None else wall_seconds
            inventory["completion"] = f.trusted(
                "exit.json", {**completion, "observed_utc": f.utc(wall)}
            )
            inventory["after"] = f.trusted(
                "jobs-after.json", {**after, "observed_utc": f.utc(wall + 1)}
            )
            return {
                "artifact": "aotg-synthetic-independent-deadline", "version": 1,
                "run_id": f.client["run_id"],
                "client_plan_sha256": original.digest(f.client),
                "client_plan_raw_sha256": f.client_d["sha256"],
                "runner_sha256": f.client["runner_sha256"],
                "pid": launch["pid"], "pid_start_ticks": launch["pid_start_ticks"],
                "launch_sha256": inventory["launch"]["sha256"],
                "completion_sha256": inventory["completion"]["sha256"],
                "summary_sha256": f.authority["client_summary_sha256"],
                "clock": "CLOCK_MONOTONIC",
                "start_domain": "synthetic-supervisor-boot",
                "end_domain": "synthetic-supervisor-boot",
                "start_ns": NS, "end_ns": NS + seconds * NS,
                "deadline_ns": NS + f.client["max_seconds"] * NS,
                "outcome": "exited", "exit_code": 0,
            }

        def bind(receipt):
            if receipt is None:
                f.authority.pop("deadline_supervision", None)
            else:
                f.authority["deadline_supervision"] = f.trusted("deadline.json", receipt)

        def run():
            return candidate.assemble(f.spec, candidate.Reader(), f.authority)

        def check(result, reason=None):
            expected = "adopt" if reason is None else "incomplete"
            for key in ("decision", "observation_decision"):
                self.assertEqual(result[key]["status"], expected, result["global_errors"])
                if reason is None:
                    self.assertIsNotNone(result[key]["selected_candidate_id"])
                else:
                    self.assertIsNone(result[key]["selected_candidate_id"])
            self.assertEqual(len(result["run"]["trials"]), len(f.field["schedule"]))
            if reason is None:
                self.assertEqual(result["global_errors"], [])
            else:
                self.assertIn(reason, [item["reason"] for item in result["global_errors"]])
                self.assertFalse(any(row["status"] == "passed" for row in result["run"]["trials"]))
            self.assertFalse(result["goal_complete"])
            self.assertFalse(result["measurement_generated"])
            self.assertFalse(result["deployment_verified"])

        # Old end-to-end counterexample, not merely the local jobs_gate:
        # all normal arm records remain, but client exit is beyond the budget.
        bind(receipt_for(5401))
        check(original.assemble(f.spec, original.Reader(), f.authority))
        for seconds in (5399, 5400, 5401, 10800):
            with self.subTest(seconds=seconds):
                bind(receipt_for(seconds))
                check(run(), None if seconds <= 5400 else "external_deadline_exceeded")
        # Wall-clock order alone cannot rescue an expired monotonic deadline.
        bind(receipt_for(5401, wall_seconds=5399))
        check(run(), "external_deadline_exceeded")
        baseline = receipt_for(5399)
        bind(None)
        check(run(), "external_deadline_evidence_missing")
        changes = (
            ("run_id", "other", "external_deadline_identity_mismatch"),
            ("client_plan_sha256", "0" * 64, "external_deadline_identity_mismatch"),
            ("client_plan_raw_sha256", "0" * 64, "external_deadline_identity_mismatch"),
            ("runner_sha256", "0" * 64, "external_deadline_identity_mismatch"),
            ("pid", launch["pid"] + 1, "external_deadline_identity_mismatch"),
            ("pid_start_ticks", "999", "external_deadline_identity_mismatch"),
            ("launch_sha256", "0" * 64, "external_deadline_identity_mismatch"),
            ("completion_sha256", "0" * 64, "external_deadline_identity_mismatch"),
            ("summary_sha256", "0" * 64, "external_deadline_identity_mismatch"),
            ("clock", "wall", "external_deadline_clock_invalid"),
            ("end_domain", "other-boot", "external_deadline_clock_invalid"),
            ("end_ns", 0, "external_deadline_clock_invalid"),
            ("start_ns", True, "external_deadline_clock_invalid"),
            ("deadline_ns", baseline["deadline_ns"] + 1, "external_deadline_clock_invalid"),
            ("outcome", "timeout-killed", "external_deadline_exit_unconfirmed"),
            ("outcome", "exit-unknown", "external_deadline_exit_unconfirmed"),
            ("exit_code", 124, "external_deadline_exit_unconfirmed"),
        )
        for key, value, reason in changes:
            with self.subTest(key=key, value=value):
                bind({**baseline, key: value})
                check(run(), reason)
        for key in ("start_ns", "end_ns", "deadline_ns"):
            with self.subTest(missing=key):
                bind({k: v for k, v in baseline.items() if k != key})
                check(run(), "external_deadline_clock_invalid")
        bind(baseline)
        check(run())
        self.assertEqual(
            {path: original.sha(Path(path).read_bytes()) for path in captured}, captured
        )
        self.assertTrue(all((f.k / ("arm-%02d" % row["index"]) / "done-receipt.json").is_file()
                            for row in f.field["schedule"]))


if __name__ == "__main__":
    unittest.main()
