"""PR31 offline ADV-12 bridge. Only trusted synthetic C++ is executed."""
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
import zlib
from copy import deepcopy
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
MAIN_INPUTS = {
    "aotg/quality.py": "482e042ee7ca5612d7b9279e9def668758926f74",
    "tests/fixtures/benchmark/catalog.json": "323d66218056ae5a79b94e6f019a4f26b05a0054",
    "aotg/artifacts.py": PINS["aotg/artifacts.py"],
}


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
    "The archived assessment reader requires POSIX directory descriptors",
)
class ArchiveQualityBridgeTests(unittest.TestCase):
    def test_independent_cpp_reports_and_rejections(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "Existing Linux g++ required; no download")
        with tempfile.TemporaryDirectory(prefix="aotg-adv12-bridge-") as tmp:
            scratch = Path(tmp)
            staged = scratch / "candidate"
            # Copy only a finite, explicitly pinned inventory; never alter the archive.
            for relative, pin in PINS.items():
                raw = (ARCHIVE / relative).read_bytes()
                self.assertEqual(git_blob(raw), pin, relative)
                target = staged / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            for relative, pin in MAIN_INPUTS.items():
                raw = (ROOT / relative).read_bytes()
                self.assertEqual(git_blob(raw), pin, relative)
                (staged / relative).write_bytes(raw)

            old_modules = dict(sys.modules)
            try:
                spec = importlib.util.spec_from_file_location(
                    "_aotg_adv12_bridge_fixture", staged / "tests/test_field_assessment_assemble.py"
                )
                fixture = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(fixture)
                a = fixture.a
                evidence = scratch / "synthetic-evidence"
                evidence.mkdir()
                f = fixture.Fixture(evidence)
                self.assertEqual(len(f.field["schedule"]), 32)
                reports = []
                phases = set()

                def bind_report(index, report, *, update_outer=True):
                    arm = f.authority["arms"][str(index)]
                    arm["quality"] = f.trusted(f"arm-{index}/quality.json", report)
                    if update_outer:
                        isolated = json.loads(Path(arm["isolation"]["path"]).read_text())
                        isolated["stdout"] = base64.b64encode(zlib.compress(a.canonical(report))).decode()
                        arm["isolation"] = f.trusted(f"arm-{index}/isolation.json", isolated)

                for row in f.field["schedule"]:
                    index = row["index"]
                    arm = f.authority["arms"][str(index)]
                    source = Path(arm["replay"]["staged_files"][0]["path"])
                    receipt = json.loads(Path(arm["source_review"]["path"]).read_text())
                    # This is a checked-in reference solution from the synthetic fixture,
                    # not model code. All authority/isolation receipts are test-only.
                    self.assertEqual(source.read_bytes(), f.source)
                    report = f.api.quality.grade_source(
                        fixture.CASE, source, compiler=Path(compiler).resolve(),
                        compiler_kind="g++", execution_authorized=True,
                        isolation_evidence=arm["isolation_reference"],
                        catalog_path=Path(f.catalog_d["path"]), source_review=receipt,
                    )
                    self.assertEqual(report["status"], "pass", report)
                    self.assertTrue(report["quality_accepted"])
                    self.assertEqual(report["grading"]["observed"], 15)
                    self.assertEqual(report["toolchain"]["overflow_detection"]["mode"], "ubsan")
                    phase = report["overflow_preflight"]["attempts"]["ubsan"]["compile"]
                    phases.add(phase["seconds"])
                    identity = {k: v for k, v in report["toolchain"].items() if k != "version_probe"}
                    if not reports:
                        f.authority["toolchains"][fixture.CASE] = deepcopy(identity)
                    self.assertEqual(identity, f.authority["toolchains"][fixture.CASE])
                    reports.append(report)
                    bind_report(index, report)

                self.assertGreater(len(phases), 1, "Distinct native probe timings required")
                result = f.run()
                self.assertEqual(result["global_errors"], [])
                self.assertTrue(all(not row["missing_or_conflicting"] for row in result["ledger"]),
                                result["ledger"])
                self.assertEqual(result["decision"]["status"], "adopt")
                self.assertEqual(len(result["run"]["trials"]), 32)
                self.assertFalse(result["goal_complete"])

                # Keep independent authority fixed. Rebind the raw report and its
                # synthetic outer stdout together so the identity gate itself is tested.
                arm = f.authority["arms"]["0"]
                authority = a.Authority(a.Reader(), f.authority, f.t, [f.k, f.e])
                expected = {"driver": f.driver, "source_name": "intervals.cpp",
                            "modules": f.identity["aotg_modules"]}

                def gate():
                    return a.quality_gate(
                        f.api, authority, arm, a.sha(f.source), fixture.CASE,
                        f.field["verifier_sha256"], f.catalog_d["sha256"], f.catalog, expected,
                    )

                self.assertTrue(gate()[0])
                for key in ("compiler_sha256", "compiler_flags", "mode", "overflow_probe_sha256"):
                    with self.subTest(identity_key=key):
                        changed = deepcopy(reports[0])
                        tc = changed["toolchain"]
                        if key == "compiler_sha256":
                            tc[key] = "0" * 64
                        elif key == "compiler_flags":
                            tc[key] = tc[key] + ["-DUNEXPECTED"]
                        elif key == "mode":
                            tc["overflow_detection"][key] = "signed-overflow-trap"
                        else:
                            tc["overflow_detection"][key] = "0" * 64
                        bind_report(0, changed)
                        with self.assertRaisesRegex(a.EvidenceError, "native_toolchain_drift"):
                            gate()
                changed = deepcopy(reports[0])
                changed["grader_sha256"] = a.sha((ARCHIVE / "aotg/quality.py").read_bytes())
                bind_report(0, changed)
                with self.assertRaisesRegex(a.EvidenceError, "native_grade_binding_mismatch"):
                    gate()
                bind_report(0, reports[0])
                changed = deepcopy(reports[0])
                changed["overflow_preflight"]["attempts"]["ubsan"]["compile"]["seconds"] += 1
                bind_report(0, changed, update_outer=False)
                with self.assertRaisesRegex(a.EvidenceError, "outer_stdout_quality_mismatch"):
                    gate()
                bind_report(0, reports[0])
                self.assertTrue(gate()[0])
            finally:
                # The archive loader uses its own module namespace. Restore only
                # modules it added/replaced so other test suites cannot see it.
                for name in list(sys.modules):
                    if name.startswith("_aotg_private_assessment"):
                        if name in old_modules:
                            sys.modules[name] = old_modules[name]
                        else:
                            del sys.modules[name]


if __name__ == "__main__":
    unittest.main()
