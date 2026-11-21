"""Known synthetic programs exercise the independent native grader."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import aotg.quality as quality_module
from aotg.artifacts import ArtifactError
from aotg.quality import (
    CASES,
    CATALOG,
    _catalog_case,
    _environment,
    _harness,
    _review_gate,
    grade_observations,
    grade_source,
)

GOOD_CPP = """bool overlaps(int a, int b, int c, int d) {
    return a < b && c < d && a < d && c < b;
}
"""
GOOD_CSHARP = """using System;
using System.Collections.Generic;
public sealed class BatchRegistry {
    private readonly HashSet<string> ids = new HashSet<string>(StringComparer.Ordinal);
    public bool TryRegister(IEnumerable<string> batch) {
        var additions = new HashSet<string>(StringComparer.Ordinal);
        foreach (string id in batch)
            if (ids.Contains(id) || !additions.Add(id)) return false;
        ids.UnionWith(additions);
        return true;
    }
    public bool Contains(string id) => ids.Contains(id);
}
"""


def synthetic_review(source, verdict="accepted"):
    """Unit-test receipt only; never evidence of a real independent review."""
    return {"artifact": "aotg-source-review", "version": 1,
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "grader_sha256": hashlib.sha256(Path(quality_module.__file__).read_bytes()).hexdigest(),
            "catalog_sha256": hashlib.sha256(CATALOG.read_bytes()).hexdigest(),
            "independent": True, "reviewer": "synthetic-test-reviewer",
            "verdict": verdict, "evidence_reference": "unit-test-only-not-real-review"}


def existing_dotnet():
    """Discover only already-installed SDK/reference/runtime triples for tests."""
    command = shutil.which("dotnet")
    executable = Path(command).resolve() if command else Path.home() / ".dotnet/dotnet"
    if not executable.is_file():
        return None
    root = executable.parent
    compilers = sorted((root / "sdk").glob("*/Roslyn/bincore/csc.dll"))
    refs = sorted((root / "packs/Microsoft.NETCore.App.Ref").glob("*/ref/net*"))
    if not compilers:
        return None
    for ref in reversed(refs):
        version = ref.parents[1].name
        if (root / "shared/Microsoft.NETCore.App" / version).is_dir():
            return {"compiler": executable, "compiler_kind": "dotnet-csc",
                    "csc_dll": compilers[-1], "reference_dir": ref,
                    "dotnet_runtime_version": version}
    return None


DOTNET = existing_dotnet()


class ObservationTests(unittest.TestCase):
    def test_requires_exact_order_boolean_and_count(self):
        self.assertEqual(grade_observations("AOTG:0:true\nAOTG:1:false\n", [True, False])["status"], "pass")
        for output in ("AOTG:0:1", "AOTG:1:true", "AOTG:0:True", "log\nAOTG:0:true"):
            self.assertEqual(grade_observations(output, [True])["status"], "invalid-observations")
        self.assertEqual(grade_observations("", [True])["status"], "missing-observations")
        self.assertEqual(grade_observations("AOTG:0:true\nAOTG:1:true", [True])["status"], "invalid-observations")
        self.assertEqual(grade_observations("AOTG:0:false", [True])["mismatches"], [0])

    def test_trusted_catalog_builds_both_harnesses(self):
        for case_id, extension, count in ((CASES[0], ".cpp", 15), (CASES[1], ".cs", 16)):
            harness, expected, suffix = _harness(_catalog_case(case_id, CATALOG))
            self.assertEqual(suffix, extension)
            self.assertEqual(len(expected), count)
            self.assertEqual(harness.count("AOTG:"), count)
            self.assertTrue(all(type(value) is bool for value in expected))

    def test_cpp_catalog_matches_task_spec_and_boundary_cases(self):
        prompt = (CATALOG.parent / "cpp-interval-task.txt").read_text(encoding="utf-8")
        self.assertIn("half-open", prompt)
        self.assertIn("empty or reversed", prompt)
        self.assertIn("all int values", prompt)
        assertions = _catalog_case(CASES[0], CATALOG)["assertions"]
        self.assertEqual(len(assertions), 15)
        vectors = [item["arguments"] for item in assertions]
        for values in (
            [-2147483648, 0, -2147483648, 0],
            [-2147483648, 2147483647, -2147483648, 2147483647],
            [-2147483648, 2147483647, 0, 1],
            [0, 1, -2147483648, 2147483647],
            [-2147483648, -2147483647, 2147483646, 2147483647],
            [2147483646, 2147483647, -2147483648, -2147483647],
        ):
            self.assertIn(values, vectors)
        for item in assertions:
            a, b, c, d = item["arguments"]
            self.assertIs(item["result"], a < b and c < d and a < d and c < b)

    def test_invalid_catalog_never_generates_code(self):
        with self.assertRaises(ArtifactError):
            _harness({"id": CASES[0], "assertions": [{"arguments": [0, 1, 2, True], "result": False}]})
        with self.assertRaises(ArtifactError):
            _harness({"id": CASES[1], "assertion_sequences": [{"operations": [{"contains": 42, "result": True}]}]})

    def test_execution_requires_opt_in_and_external_evidence(self):
        with self.assertRaises(ArtifactError):
            grade_source(CASES[0], "unused", compiler="unused", compiler_kind="g++")
        with self.assertRaises(ArtifactError):
            grade_source(CASES[0], "unused", compiler="unused", compiler_kind="g++", execution_authorized=True)

    def test_nonfinite_or_unbounded_deadlines_rejected_before_launch(self):
        for deadline in (float("nan"), float("inf"), -1, 0, 61, True):
            with self.assertRaises(ArtifactError):
                grade_source(CASES[0], "unused", compiler="unused", compiler_kind="g++",
                             execution_authorized=True, isolation_evidence="test",
                             timeout_seconds=deadline)

    def test_process_environment_does_not_inherit_credentials_or_injection(self):
        with patch.dict(os.environ, {"API_KEY": "private", "LD_PRELOAD": "/private/library", "HOME": "/private/home"}):
            environment = _environment(Path("/scratch"), [Path("/trusted/compiler")])
        for key in ("API_KEY", "LD_PRELOAD", "HOME"):
            self.assertNotIn(key, environment)
        self.assertEqual(environment["DOTNET_CLI_TELEMETRY_OPTOUT"], "1")

    def test_review_binding_covers_source_grader_catalog_and_independence(self):
        receipt = synthetic_review(GOOD_CPP)
        bindings = {key: receipt[key] for key in ("source_sha256", "grader_sha256", "catalog_sha256")}
        self.assertEqual(_review_gate(receipt, bindings)["status"], "accepted")
        for key in bindings:
            changed = dict(receipt, **{key: "0" * 64})
            self.assertEqual(_review_gate(changed, bindings)["status"], "hash-mismatch")
        self.assertEqual(_review_gate(dict(receipt, independent=False), bindings)["status"], "not-independent")
        self.assertEqual(_review_gate(dict(receipt, verdict="rejected"), bindings)["status"], "rejected")
        with self.assertRaises(ArtifactError):
            _review_gate({"verdict": "accepted"}, bindings)

    def test_csharp_compile_contract_and_independent_grading(self):
        """Exercise csc argv on every OS; this is a mocked compile, not native proof."""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            compiler = directory / "csc.exe"
            compiler.write_bytes(b"fake compiler identity")
            source = directory / "submission.cs"
            source.write_text("public sealed class BatchRegistry {}", encoding="utf-8")
            _, expected, _ = _harness(_catalog_case(CASES[1], CATALOG))

            def run(argv, work, timeout, phase, tool_directories=(), *, dotnet=False):
                self.assertFalse(dotnet)
                if phase == "compile":
                    self.assertIn("/main:AotgTrustedHarness", argv)
                    self.assertIn("/target:exe", argv)
                    self.assertNotEqual(source.parent, work)
                    (work / "candidate.exe").write_bytes(b"fake program")
                stdout = "\n".join(f"AOTG:{i}:{str(v).lower()}" for i, v in enumerate(expected)) if phase == "run" else "compiler version"
                return {"status": "ok", "exit_code": 0, "seconds": 0.001,
                        "stdout": stdout, "stderr": "", "output_truncated": False}

            with patch("aotg.quality._run", side_effect=run):
                report = grade_source(CASES[1], source, compiler=compiler, compiler_kind="csc",
                                      execution_authorized=True, isolation_evidence="mock-only")
            self.assertEqual(report["status"], "source-review-required")
            self.assertEqual(report["behavioral_status"], "pass")
            self.assertFalse(report["quality_accepted"])
            self.assertFalse(report["isolation"]["verified_by_this_grader"])
            self.assertEqual(report["grading"]["observed"], 16)


class TemporaryCleanupTests(unittest.TestCase):
    def test_transient_windows_sharing_violation_cleans_up_without_hiding_body_error(self):
        temporary = tempfile.TemporaryDirectory()
        directory = Path(temporary.name)
        original_cleanup = temporary.cleanup
        sharing_error = PermissionError("file is still shared")
        sharing_error.winerror = 32
        attempts = 0

        def cleanup():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise sharing_error
            original_cleanup()

        try:
            with (patch("aotg.quality.tempfile.TemporaryDirectory", return_value=temporary),
                  patch.object(temporary, "cleanup", side_effect=cleanup),
                  patch("aotg.quality.sys.platform", "win32"),
                  patch("aotg.quality.time.monotonic", side_effect=[100, 100.1, 100.11]),
                  patch("aotg.quality.time.sleep") as sleep):
                with self.assertRaisesRegex(RuntimeError, "original evaluation failure"):
                    with quality_module._evaluation_directory() as work:
                        self.assertEqual(work, directory)
                        (work / "compiler.s").write_text("temporary assembly", encoding="utf-8")
                        raise RuntimeError("original evaluation failure")
            self.assertEqual(attempts, 2)
            sleep.assert_called_once_with(0.01)
            self.assertFalse(directory.exists())
        finally:
            original_cleanup()

    def test_persistent_windows_sharing_violation_propagates_at_deadline(self):
        temporary = tempfile.TemporaryDirectory()
        directory = Path(temporary.name)
        original_cleanup = temporary.cleanup
        sharing_error = PermissionError("file remains shared")
        sharing_error.winerror = 32
        try:
            with (patch("aotg.quality.tempfile.TemporaryDirectory", return_value=temporary),
                  patch.object(temporary, "cleanup", side_effect=sharing_error) as cleanup,
                  patch("aotg.quality.sys.platform", "win32"),
                  patch("aotg.quality.time.monotonic", side_effect=[100, 100.25, 100.26, 101.0]),
                  patch("aotg.quality.time.sleep") as sleep):
                with self.assertRaises(PermissionError) as raised:
                    with quality_module._evaluation_directory() as work:
                        (work / "compiler.s").write_text("still locked", encoding="utf-8")
            self.assertIs(raised.exception, sharing_error)
            self.assertEqual(cleanup.call_count, 2)
            sleep.assert_called_once_with(0.01)
            self.assertTrue(directory.exists())
        finally:
            original_cleanup()

    def test_unrelated_cleanup_errors_propagate_without_retry(self):
        denied = PermissionError("access denied")
        denied.winerror = 5
        non_windows = PermissionError("sharing error on a different OS")
        non_windows.winerror = 32
        for platform, error in (("win32", denied), ("linux", PermissionError("permission denied")),
                                ("win32", OSError("I/O failure")), ("linux", non_windows)):
            with self.subTest(platform=platform, error=error):
                temporary = tempfile.TemporaryDirectory()
                original_cleanup = temporary.cleanup
                try:
                    with (patch("aotg.quality.tempfile.TemporaryDirectory", return_value=temporary),
                          patch.object(temporary, "cleanup", side_effect=error) as cleanup,
                          patch("aotg.quality.sys.platform", platform),
                          patch("aotg.quality.time.sleep") as sleep):
                        with self.assertRaises(type(error)) as raised:
                            with quality_module._evaluation_directory():
                                pass
                    self.assertIs(raised.exception, error)
                    cleanup.assert_called_once_with()
                    sleep.assert_not_called()
                finally:
                    original_cleanup()


@unittest.skipUnless(shutil.which("g++"), "Existing g++ is required; no download")
class NativeCppTests(unittest.TestCase):
    def evaluate(self, source, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "submission.cpp"
            path.write_bytes(source.encode("utf-8"))
            return grade_source(CASES[0], path, compiler=Path(shutil.which("g++")).resolve(),
                                compiler_kind="g++", execution_authorized=True,
                                isolation_evidence="Trusted synthetic test only; no model code",
                                **kwargs)

    def test_correct_program_passes_with_provenance(self):
        report = self.evaluate(GOOD_CPP, source_review=synthetic_review(GOOD_CPP))
        self.assertEqual(report["status"], "pass", report)
        self.assertTrue(report["quality_accepted"])
        self.assertEqual(report["grading"]["observed"], 15)
        self.assertEqual(len(report["source_sha256"]), 64)
        self.assertEqual(len(report["executable_sha256"]), 64)
        self.assertIn("g++", report["toolchain"]["version_probe"]["stdout"])
        detector = report["toolchain"]["overflow_detection"]
        self.assertTrue(detector["active"])
        self.assertIn(detector["mode"], ("ubsan", "signed-overflow-trap"))
        flags = (quality_module.CXX_GRADING_FLAGS if detector["mode"] == "ubsan"
                 else quality_module.CXX_TRAP_FLAGS)
        self.assertEqual(report["toolchain"]["compiler_flags"], list(flags))
        self.assertNotIn(tempfile.gettempdir() + os.sep + "aotg-quality-", json.dumps(report))

    def test_overflow_preflight_timing_does_not_change_toolchain_identity(self):
        # Independent field assessment compares a stable toolchain identity,
        # not wall-clock timings from separate compile/runtime probes.
        toolchains = []
        for _ in range(2):
            report = self.evaluate(GOOD_CPP, source_review=synthetic_review(GOOD_CPP))
            self.assertEqual(report["status"], "pass")
            attempts = report["overflow_preflight"]["attempts"]
            self.assertIn("seconds", attempts["ubsan"]["compile"])
            toolchain = {key: value for key, value in report["toolchain"].items()
                         if key != "version_probe"}
            self.assertNotIn('"seconds"', json.dumps(toolchain))
            self.assertNotIn('"stdout"', json.dumps(toolchain))
            self.assertNotIn('"stderr"', json.dumps(toolchain))
            for stages in toolchain["overflow_detection"]["attempts"].values():
                for phase in stages.values():
                    if phase is not None:
                        self.assertEqual(set(phase), {"status", "exit_code"})
            toolchains.append(toolchain)
        self.assertEqual(toolchains[0], toolchains[1])

    def test_correct_but_unreviewed_source_is_not_quality_accepted(self):
        report = self.evaluate(GOOD_CPP)
        self.assertEqual(report["behavioral_status"], "pass")
        self.assertEqual(report["status"], "source-review-required")
        self.assertFalse(report["quality_accepted"])

    def test_spoofed_stdout_never_accepts_unaudited_or_rejected_source(self):
        # Intentional attack: no trusted harness execution, wrong function,
        # but expected protocol printed from a static constructor before main.
        _, expected, _ = _harness(_catalog_case(CASES[0], CATALOG))
        stdout = "".join(f"AOTG:{i}:{str(v).lower()}\n" for i, v in enumerate(expected))
        source = ('#include <cstdio>\n#include <cstdlib>\nstruct Forged { Forged() {'
                  f'std::fputs({json.dumps(stdout)}, stdout); std::fflush(stdout); std::_Exit(0);'
                  '} } forged;\nbool overlaps(int,int,int,int) { return false; }\n')
        for review, status in ((None, "source-review-required"),
                               (synthetic_review(source, "rejected"), "source-review-rejected")):
            report = self.evaluate(source, source_review=review)
            self.assertEqual(report["behavioral_status"], "pass")
            self.assertEqual(report["grading"]["observed"], 15)
            self.assertEqual(report["status"], status)
            self.assertFalse(report["quality_accepted"])

    def test_signed_overflow_implementations_fail_independent_grading(self):
        # Each would incorrectly pass at -O2 without UBSan. Review receipts in
        # this test are synthetic; they are never real independent acceptance.
        candidates = (
            "#include <algorithm>\n"
            "bool overlaps(int a,int b,int c,int d) {"
            " return std::min(b,d)-std::max(a,c)>0; }",
            "#include <algorithm>\n"
            "bool overlaps(int a,int b,int c,int d) {"
            " return b-a>0 && d-c>0 && std::min(b,d)-std::max(a,c)>0; }",
            "bool overlaps(int a,int b,int c,int d) {"
            " return b-a>0 && d-c>0 && a<d && c<b; }",
            "#include <algorithm>\n"
            "bool overlaps(int a,int b,int c,int d) {"
            " return a<d && c<b && b-a>0 && d-c>0; }",
        )
        for source in candidates:
            with self.subTest(source=source):
                report = self.evaluate(source, source_review=synthetic_review(source))
                self.assertEqual(report["behavioral_status"], "runtime-error")
                self.assertEqual(report["status"], "runtime-error")
                self.assertFalse(report["quality_accepted"])
                detector = report["toolchain"]["overflow_detection"]
                self.assertTrue(detector["active"])
                self.assertIsNone(report["grading"])
                self.assertNotEqual(report["execution"]["exit_code"], 0)
                if detector["mode"] == "ubsan":
                    self.assertIn("signed integer overflow", report["execution"]["stderr"])

    def test_unavailable_overflow_detection_fails_closed_before_candidate_compile(self):
        real_run = quality_module._run

        def fake_disabled(argv, directory, timeout_seconds, phase, tool_directories=(), *, dotnet=False):
            if phase in ("ubsan-run", "trap-run"):
                return {"status": "ok", "exit_code": 0, "seconds": 0.001,
                        "stdout": "", "stderr": "", "output_truncated": False}
            return real_run(argv, directory, timeout_seconds, phase, tool_directories, dotnet=dotnet)

        with patch("aotg.quality._run", side_effect=fake_disabled):
            report = self.evaluate(GOOD_CPP, source_review=synthetic_review(GOOD_CPP))
        self.assertEqual(report["behavioral_status"], "overflow-detector-unavailable")
        self.assertEqual(report["status"], "overflow-detector-unavailable")
        self.assertIsNone(report["compile"])
        self.assertIsNone(report["execution"])
        self.assertFalse(report["toolchain"]["overflow_detection"]["active"])
        self.assertFalse(report["quality_accepted"])

    def test_trap_fallback_rejects_ignored_optimized_subtraction(self):
        # Reproduce independent P1: addition traps, optimized subtraction does not.
        # A synthetic review cannot override the missing detector.
        real_run = quality_module._run

        def ignored_subtraction(argv, directory, timeout_seconds, phase,
                                tool_directories=(), *, dotnet=False):
            if phase in ("ubsan-run", "trap-subtract-run", "trap-run"):
                return {"status": "ok", "exit_code": 1 if phase == "trap-run" else 0,
                        "seconds": 0.001, "stdout": "", "stderr": "",
                        "output_truncated": False}
            return real_run(argv, directory, timeout_seconds, phase,
                            tool_directories, dotnet=dotnet)

        with patch("aotg.quality._run", side_effect=ignored_subtraction):
            report = self.evaluate(GOOD_CPP, source_review=synthetic_review(GOOD_CPP))
        self.assertEqual(report["status"], "overflow-detector-unavailable")
        self.assertEqual(report["behavioral_status"], "overflow-detector-unavailable")
        self.assertIsNone(report["compile"])
        self.assertIsNone(report["execution"])
        self.assertFalse(report["quality_accepted"])
        preflight = report["overflow_preflight"]["attempts"]["signed-overflow-trap"]
        self.assertEqual(preflight["execution"]["exit_code"], 1)
        self.assertEqual(preflight["subtract_execution"]["exit_code"], 0)
        self.assertEqual(preflight["control_execution"]["exit_code"], 0)
        detector = report["toolchain"]["overflow_detection"]
        self.assertFalse(detector["active"])
        self.assertEqual(
            detector["subtraction_probe_sha256"],
            hashlib.sha256(quality_module.CXX_TRAP_SUBTRACTION_PROBE.encode("utf-8")).hexdigest())
        for phase in detector["attempts"]["signed-overflow-trap"].values():
            if phase is not None:
                self.assertEqual(set(phase), {"status", "exit_code"})

    def test_trap_fallback_only_passes_when_both_native_probes_abort(self):
        # On systems without UBSan, use actual compiler/run for the trap probes.
        # If optimized subtraction does not trap, fail closed rather than skip.
        real_run = quality_module._run

        def no_ubsan(argv, directory, timeout_seconds, phase,
                     tool_directories=(), *, dotnet=False):
            if phase == "ubsan-run":
                return {"status": "ok", "exit_code": 0, "seconds": 0.001,
                        "stdout": "", "stderr": "", "output_truncated": False}
            return real_run(argv, directory, timeout_seconds, phase,
                            tool_directories, dotnet=dotnet)

        with patch("aotg.quality._run", side_effect=no_ubsan):
            report = self.evaluate(GOOD_CPP, source_review=synthetic_review(GOOD_CPP))
        trap = report["overflow_preflight"]["attempts"]["signed-overflow-trap"]
        self.assertEqual(trap["subtract_compile"]["exit_code"], 0, trap)
        detector = report["toolchain"]["overflow_detection"]
        both_detected = (
            trap["execution"] is not None and trap["execution"]["status"] == "ok"
            and trap["execution"]["exit_code"] != 0
            and trap["subtract_execution"] is not None
            and trap["subtract_execution"]["status"] == "ok"
            and trap["subtract_execution"]["exit_code"] != 0
            and trap["control_execution"] is not None
            and trap["control_execution"]["status"] == "ok"
            and trap["control_execution"]["exit_code"] == 0
        )
        if both_detected:
            self.assertEqual(detector["mode"], "signed-overflow-trap")
            self.assertEqual(report["status"], "pass")
        else:
            self.assertEqual(report["status"], "overflow-detector-unavailable")
            self.assertIsNone(report["compile"])
        self.assertEqual(detector["active"], both_detected)

    def test_public_cli_rejects_overflow_without_source_review(self):
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, source, status in (
                ("reference", GOOD_CPP, "pass"),
                ("overflow", "#include <algorithm>\n"
                 "bool overlaps(int a,int b,int c,int d) {"
                 " return std::min(b,d)-std::max(a,c)>0; }", "runtime-error"),
            ):
                with self.subTest(name=name):
                    source_path = directory / (name + ".cpp")
                    report_path = directory / (name + ".json")
                    source_path.write_text(source, encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, "-m", "aotg.quality", "--case", CASES[0],
                         "--source", str(source_path),
                         "--compiler", str(Path(shutil.which("g++")).resolve()),
                         "--compiler-kind", "g++", "--allow-execute",
                         "--isolation-evidence", "synthetic-public-cli-regression",
                         "--output", str(report_path)],
                        cwd=Path(__file__).resolve().parents[1], capture_output=True,
                        text=True, timeout=60, check=False,
                    )
                    self.assertEqual(result.returncode, 1, result.stderr)
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    self.assertEqual(report["behavioral_status"], status)
                    self.assertTrue(report["toolchain"]["overflow_detection"]["active"])
                    self.assertFalse(report["quality_accepted"])

    def test_original_buggy_fixture_is_rejected(self):
        source = (CATALOG.parent / "intervals.cpp").read_text(encoding="utf-8")
        report = self.evaluate(source)
        self.assertEqual(report["status"], "assertion-mismatch")
        self.assertIn(0, report["grading"]["mismatches"])

    def test_compile_error_is_not_quality_pass(self):
        report = self.evaluate("this is not C++;")
        self.assertEqual(report["status"], "compile-error")
        self.assertIsNone(report["execution"])
        self.assertIsNone(report["grading"])

    def test_missing_output_is_rejected(self):
        report = self.evaluate("#include <cstdlib>\nbool overlaps(int,int,int,int) { std::_Exit(0); }")
        self.assertEqual(report["status"], "missing-observations")

    def test_timeout_is_recorded(self):
        report = self.evaluate("bool overlaps(int,int,int,int) { volatile int i=0; while (true) { i=i+1; } }", timeout_seconds=0.05)
        self.assertEqual(report["status"], "run-timeout")
        self.assertIsNone(report["grading"])

    def test_runtime_error_is_recorded(self):
        report = self.evaluate("#include <cstdlib>\nbool overlaps(int,int,int,int) { std::exit(9); }")
        self.assertEqual(report["status"], "runtime-error")
        self.assertEqual(report["execution"]["exit_code"], 9)

    def test_excess_output_is_bounded_and_rejected(self):
        report = self.evaluate('#include <cstdio>\nbool overlaps(int,int,int,int) { for (int i=0; i<20000; ++i) std::puts("extra output"); return true; }')
        self.assertEqual(report["status"], "run-output-limit")
        self.assertTrue(report["execution"]["output_truncated"])
        self.assertLessEqual(len(report["execution"]["stdout"]), 64 * 1024)

    def test_modified_trusted_harness_is_rejected(self):
        # This trusted negative fixture touches only its own evaluator temp directory.
        source = '#include <fstream>\nbool overlaps(int a,int b,int c,int d) { std::ofstream f("trusted_harness.cpp"); f << "changed"; return a<b && c<d && a<d && c<b; }'
        report = self.evaluate(source)
        self.assertEqual(report["status"], "harness-tampering")
        self.assertIsNone(report["grading"])


@unittest.skipUnless(DOTNET, "Existing .NET SDK, reference pack and runtime required; no download")
class NativeCSharpTests(unittest.TestCase):
    def evaluate(self, source, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "submission.cs"
            path.write_bytes(source.encode("utf-8"))
            return grade_source(CASES[1], path, **DOTNET, execution_authorized=True,
                                isolation_evidence="Trusted synthetic test only; no model code", **kwargs)

    def test_correct_csharp_passes_without_restore(self):
        report = self.evaluate(GOOD_CSHARP, source_review=synthetic_review(GOOD_CSHARP))
        self.assertEqual(report["status"], "pass", report["compile"])
        self.assertTrue(report["quality_accepted"])
        self.assertEqual(report["grading"]["observed"], 16)
        self.assertEqual(report["toolchain"]["dotnet_inputs"]["runtime_version"], DOTNET["dotnet_runtime_version"])
        self.assertIn("System.Runtime.dll", report["toolchain"]["dotnet_inputs"]["references"]["files"])

    def test_original_buggy_csharp_is_rejected(self):
        report = self.evaluate((CATALOG.parent / "BatchRegistry.cs").read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "assertion-mismatch", report["compile"])
        self.assertTrue(report["grading"]["mismatches"])


if __name__ == "__main__":
    unittest.main()
