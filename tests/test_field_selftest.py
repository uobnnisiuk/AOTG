"""Public toy tests only; no benchmark catalog or hidden grading vectors."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aotg.artifacts import ArtifactError
from aotg.field_sandbox import run_isolated
from aotg.field_selftest import AS_BYTES, FILE_BYTES, GC_BYTES, run_public_selftest


def acknowledged_result():
    phase = {"status": "ok", "exit_code": 0, "seconds": 0.01,
             "stdout": "PUBLIC PASS\n", "stderr": "", "output_truncated": False}
    return {"status": "ok", "exit_code": 0, "isolation_verified": True,
            "readonly_workspace": True, "dotnet_gc_heap_limit_bytes": GC_BYTES,
            "limits": {"memory_bytes": AS_BYTES, "file_bytes": FILE_BYTES}, "seconds": 0.02,
            "stdout": json.dumps({"status": "pass", "compile": phase, "execution": phase}), "stderr": ""}


@unittest.skipUnless(sys.platform == "linux" and Path("/usr/bin/g++").is_file(), "Existing Linux g++ required")
class SelftestValidationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source, self.public = self.root / "intervals.cpp", self.root / "PublicTests.cpp"
        self.source.write_text("int public_value(){return 42;}\n", encoding="utf-8")
        self.public.write_text('#include "intervals.cpp"\nint main(){return public_value()==42?0:1;}\n', encoding="utf-8")

    def test_explicit_authorization_and_source_file_boundaries(self):
        with self.assertRaisesRegex(ArtifactError, "Explicit"):
            run_public_selftest(self.source, self.public, compiler="/usr/bin/g++")
        alias = self.root / "alias.cpp"
        alias.symlink_to(self.source)
        with self.assertRaisesRegex(ArtifactError, "symlinks"):
            run_public_selftest(alias, self.public, compiler="/usr/bin/g++", execution_authorized=True)
        alias.unlink()
        os.link(self.source, alias)
        with self.assertRaisesRegex(ArtifactError, "hardlinked"):
            run_public_selftest(alias, self.public, compiler="/usr/bin/g++", execution_authorized=True)

    def test_only_explicit_public_files_and_driver_are_exposed_readonly(self):
        hidden = self.root / "not-public.json"
        hidden.write_text("not an input", encoding="utf-8")

        def fake(argv, work, **kwargs):
            self.assertEqual(set(path.name for path in work.iterdir()),
                             {"intervals.cpp", "PublicTests.cpp", "_aotg_driver.py", "_aotg_selftest.json"})
            self.assertTrue(kwargs["readonly_workspace"])
            self.assertTrue(kwargs["execution_authorized"])
            self.assertEqual(kwargs["memory_limit_bytes"], AS_BYTES)
            self.assertEqual(kwargs["file_limit_bytes"], FILE_BYTES)
            config = json.loads((work / "_aotg_selftest.json").read_text())
            self.assertEqual(config["output"], "/tmp/public-test")
            self.assertEqual(config["compile_argv"].count("/work/intervals.cpp"), 0)
            self.assertFalse(config["dotnet"])
            return acknowledged_result()

        with patch("aotg.field_selftest.run_isolated", side_effect=fake):
            result = run_public_selftest(self.source, self.public, compiler="/usr/bin/g++", execution_authorized=True)
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["quality_accepted"])
        self.assertFalse(result["independent"])

    def test_missing_isolation_ro_or_caps_fails_closed(self):
        for field, value in (("isolation_verified", False), ("readonly_workspace", False),
                             ("dotnet_gc_heap_limit_bytes", None), ("limits", {})):
            with self.subTest(field=field):
                receipt = acknowledged_result()
                receipt[field] = value
                with patch("aotg.field_selftest.run_isolated", return_value=receipt):
                    result = run_public_selftest(self.source, self.public, compiler="/usr/bin/g++", execution_authorized=True)
                self.assertEqual(result["status"], "isolation-unverified")
                self.assertFalse(result["quality_accepted"])

    def test_driver_cannot_promote_independent_quality_or_forge_completion(self):
        for change in ("quality-flag", "bool-exit", "missing-execution", "truncated"):
            with self.subTest(change=change):
                receipt = acknowledged_result()
                outcome = json.loads(receipt["stdout"])
                if change == "quality-flag":
                    outcome["quality_accepted"] = True
                elif change == "bool-exit":
                    outcome["compile"]["exit_code"] = False
                elif change == "missing-execution":
                    outcome["execution"] = None
                else:
                    outcome["execution"]["output_truncated"] = True
                receipt["stdout"] = json.dumps(outcome)
                with patch("aotg.field_selftest.run_isolated", return_value=receipt):
                    result = run_public_selftest(self.source, self.public, compiler="/usr/bin/g++", execution_authorized=True)
                self.assertEqual(result["status"], "invalid-driver-output")
                self.assertFalse(result["quality_accepted"])

    def test_outer_timeout_overrides_early_success_output(self):
        receipt = acknowledged_result()
        receipt["status"] = "timeout"
        with patch("aotg.field_selftest.run_isolated", return_value=receipt):
            result = run_public_selftest(self.source, self.public, compiler="/usr/bin/g++", execution_authorized=True)
        self.assertEqual(result["status"], "isolation-timeout")


@unittest.skipUnless(sys.platform == "linux" and Path("/usr/bin/g++").is_file(), "Existing Linux native toolchain required")
class NativePublicSelftestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            try:
                probe = run_isolated(["/usr/bin/true"], directory, execution_authorized=True, readonly_workspace=True)
            except (OSError, ArtifactError) as error:
                raise unittest.SkipTest("Existing namespace containment unavailable") from error
        if not probe["isolation_verified"]:
            raise unittest.SkipTest("Host forbids required namespace containment")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def cpp(self, source_text, test_text, **kwargs):
        source, public = self.root / "intervals.cpp", self.root / "PublicTests.cpp"
        source.write_text(source_text, encoding="utf-8")
        public.write_text(test_text, encoding="utf-8")
        before = source.read_bytes(), public.read_bytes()
        result = run_public_selftest(source, public, compiler="/usr/bin/g++", execution_authorized=True, **kwargs)
        self.assertEqual((source.read_bytes(), public.read_bytes()), before)
        self.assertFalse(result["quality_accepted"])
        return result

    def test_cpp_public_pass_failure_and_compile_error(self):
        public = '#include "intervals.cpp"\n#include <iostream>\nint main(){if(public_value()!=42)return 1;std::cout<<"PUBLIC PASS\\n";}\n'
        passed = self.cpp("int public_value(){return 42;}\n", public)
        self.assertEqual(passed["status"], "pass", passed)
        self.assertEqual(passed["stdout"], "PUBLIC PASS\n")
        self.assertEqual(self.cpp("int public_value(){return 41;}\n", public)["status"], "test-failed")
        self.assertEqual(self.cpp("#error public compile failure\nint public_value(){return 42;}\n", public)["status"], "compile-error")

    def test_cpp_source_and_test_are_readonly_and_sigxfsz_is_default(self):
        public = ('#include "intervals.cpp"\n#include <cstdio>\n#include <csignal>\n'
                  'int main(){if(std::fopen("/work/intervals.cpp","w"))return 1;'
                  'if(std::fopen("/work/PublicTests.cpp","w"))return 2;'
                  'if(std::signal(SIGXFSZ,SIG_IGN)!=SIG_DFL)return 3;return public_value()==42?0:4;}\n')
        result = self.cpp("int public_value(){return 42;}\n", public)
        self.assertEqual(result["status"], "pass", result)

    def test_cpp_timeout_and_output_limit(self):
        timeout = self.cpp("int public_value(){return 42;}\n",
                           '#include "intervals.cpp"\nint main(){for(;;){}}\n', timeout_seconds=0.2)
        self.assertEqual(timeout["status"], "run-timeout", timeout)
        flood = self.cpp("int public_value(){return 42;}\n",
                         '#include "intervals.cpp"\n#include <iostream>\nint main(){for(int i=0;i<100000;i++)std::cout<<"x";}\n')
        self.assertEqual(flood["status"], "run-output-limit", flood)
        self.assertLessEqual(len(flood["stdout"]) + len(flood["stderr"]), 8192)

    def test_existing_dotnet_public_compile_and_run_without_restore(self):
        root = Path.home() / ".dotnet"
        dotnet = root / "dotnet"
        roslyn = root / "sdk/8.0.424/Roslyn/bincore/csc.dll"
        references = root / "packs/Microsoft.NETCore.App.Ref/8.0.30/ref/net8.0"
        if not dotnet.is_file() or not roslyn.is_file() or not references.is_dir():
            self.skipTest("Pinned existing .NET 8 toolchain unavailable; no download attempted")
        source, public = self.root / "BatchRegistry.cs", self.root / "PublicTests.cs"
        source.write_text("public static class BatchRegistry { public static int Value(){return 42;} }\n", encoding="utf-8")
        public.write_text('using System;public static class PublicTests {public static int Main(){if(BatchRegistry.Value()!=42)return 1;Console.WriteLine("PUBLIC CSHARP PASS");return 0;}}\n', encoding="utf-8")
        arguments = {"compiler": dotnet, "compiler_kind": "dotnet-csc", "csc_dll": roslyn,
                     "reference_dir": references, "runtime_version": "8.0.30", "execution_authorized": True}
        passed = run_public_selftest(source, public, **arguments)
        self.assertEqual(passed["status"], "pass", passed)
        self.assertFalse(passed["quality_accepted"])
        self.assertEqual(passed["stdout"], "PUBLIC CSHARP PASS\n")
        self.assertEqual(passed["limits"]["file_bytes"], FILE_BYTES)
        source.write_text("public static class BatchRegistry { public static int Value(){return 0;} }\n", encoding="utf-8")
        failed = run_public_selftest(source, public, **arguments)
        self.assertEqual(failed["status"], "test-failed", failed)


if __name__ == "__main__":
    unittest.main()
