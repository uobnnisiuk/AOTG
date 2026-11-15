"""Real namespace checks when the host supports unprivileged Linux isolation."""

import json
import os
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

from aotg.artifacts import ArtifactError
from aotg.field_sandbox import MAX_OUTPUT_BYTES, run_isolated


class SandboxValidationTests(unittest.TestCase):
    def test_explicit_opt_in_required(self):
        with self.assertRaisesRegex(ArtifactError, "explicit"):
            run_isolated(["/usr/bin/true"], "/tmp")

    @unittest.skipUnless(sys.platform == "linux", "Linux path validation")
    def test_invalid_workspace_and_commands_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "work"
            workspace.mkdir()
            for argv in (["true"], ["/usr/bin/../bin/true"], ["/outside/tool"], ["/usr/bin/true", "bad\0arg"]):
                with self.subTest(argv=argv), self.assertRaises(ArtifactError):
                    run_isolated(argv, workspace, execution_authorized=True)
            (workspace / "escape").symlink_to(root)
            with self.assertRaisesRegex(ArtifactError, "symlink"):
                run_isolated(["/usr/bin/true"], workspace, execution_authorized=True)
            (workspace / "escape").unlink()
            original = root / "host-original"
            original.write_text("host", encoding="utf-8")
            os.link(original, workspace / "hardlink")
            with self.assertRaisesRegex(ArtifactError, "hard-linked"):
                run_isolated(["/usr/bin/true"], workspace, execution_authorized=True)

    @unittest.skipUnless(sys.platform == "linux", "Linux path validation")
    def test_unsafe_bindings_and_limits_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            for bindings in ({"/etc": "/usr"}, {"/tools/../home": "/usr"}, {"/tools/home": str(Path.home())}):
                with self.subTest(bindings=bindings), self.assertRaises(ArtifactError):
                    run_isolated(["/usr/bin/true"], temporary, readonly_bindings=bindings,
                                 execution_authorized=True)
            with self.assertRaises(ArtifactError):
                run_isolated(["/usr/bin/true"], temporary, timeout_seconds=float("inf"),
                             execution_authorized=True)


@unittest.skipUnless(sys.platform == "linux", "Linux namespaces only")
class RealSandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            try:
                result = run_isolated(["/usr/bin/true"], directory, execution_authorized=True)
            except (ArtifactError, OSError) as error:
                raise unittest.SkipTest(f"Existing namespace tools unavailable: {type(error).__name__}") from error
        if not result["isolation_verified"]:
            raise unittest.SkipTest("Host forbids required namespace/mount/capability setup")
        if result["status"] != "ok":
            raise AssertionError(result)

    def test_compile_and_run_with_gpp(self):
        if not Path("/usr/bin/g++").is_file():
            self.skipTest("Existing g++ unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "example.cpp").write_text('#include <iostream>\nint main(){std::cout << 42 << "\\n";}\n', encoding="utf-8")
            build = run_isolated(["/usr/bin/g++", "-std=c++17", "/work/example.cpp", "-o", "/work/example"],
                                 root, execution_authorized=True)
            self.assertEqual(build["status"], "ok", build)
            result = run_isolated(["/work/example"], root, execution_authorized=True)
            self.assertEqual(result["status"], "ok", result)
            self.assertEqual(result["stdout"], "42\n")
            self.assertTrue(result["isolation_verified"])

    def test_ipc_namespace_is_separate(self):
        parent_ipc = os.readlink("/proc/self/ns/ipc")
        with tempfile.TemporaryDirectory() as directory:
            result = run_isolated(["/usr/bin/python3", "-c",
                                   "import os; print(os.readlink('/proc/self/ns/ipc'))"],
                                  directory, execution_authorized=True)
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(result["isolation_verified"])
        self.assertNotEqual(result["stdout"].strip(), parent_ipc)

    def test_readonly_workspace_cannot_be_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixed").write_text("original")
            code = "from pathlib import Path; Path('/work/fixed').write_text('changed')"
            result = run_isolated(["/usr/bin/python3", "-c", code], root,
                                  execution_authorized=True, readonly_workspace=True)
            self.assertEqual(result["status"], "nonzero-exit", result)
            self.assertTrue(result["isolation_verified"])
            self.assertEqual((root / "fixed").read_text(), "original")

    def test_existing_dotnet_compiles_with_bounded_readonly_workspace(self):
        from test_quality import GOOD_CSHARP, existing_dotnet

        compiler = existing_dotnet()
        if compiler is None:
            self.skipTest("Existing .NET SDK/reference/runtime unavailable")
        tool_root = Path(compiler["compiler"]).parent.resolve()
        repo = Path(__file__).resolve().parents[1]
        mapped = {key: str(Path("/tools/dotnet") / Path(value).relative_to(tool_root))
                  for key, value in compiler.items() if key in ("compiler", "csc_dll", "reference_dir")}
        mapped.update(compiler_kind="dotnet-csc", dotnet_runtime_version=compiler["dotnet_runtime_version"],
                      execution_authorized=True, isolation_evidence="actual-test-namespace")
        code = ("import sys,json;sys.path.insert(0,'/tools/repo');"
                "from aotg.quality import grade_source;"
                "r=grade_source('csharp-atomic-batch','/work/Submission.cs',**json.loads(sys.argv[1]));"
                "print(json.dumps({k:r[k] for k in ('status','behavioral_status','quality_accepted')}))")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Submission.cs").write_text(GOOD_CSHARP, encoding="utf-8")
            result = run_isolated(["/usr/bin/python3", "-c", code, json.dumps(mapped)], root,
                                  readonly_bindings={"/tools/dotnet": tool_root, "/tools/repo": repo},
                                  execution_authorized=True, readonly_workspace=True,
                                  memory_limit_bytes=8 * 1024**3, timeout_seconds=30)
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(result["isolation_verified"])
        measured = json.loads(result["stdout"])
        self.assertEqual(measured["behavioral_status"], "pass")
        self.assertFalse(measured["quality_accepted"])

    def test_host_home_network_and_environment_are_absent(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
            root = Path(directory)
            workspace = root / "work"
            workspace.mkdir()
            marker = root / "host-only-marker"
            marker.write_text("not exposed", encoding="utf-8")
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            source = (
                "import json,os,pathlib,socket\n"
                "s=socket.socket();s.settimeout(.2)\n"
                f"connected=s.connect_ex(('127.0.0.1',{port}))==0\n"
                f"print(json.dumps({{'host_visible':pathlib.Path({str(marker)!r}).exists(),"
                f"'home_visible':pathlib.Path({str(Path.home())!r}).exists(),"
                "'connected':connected,'env':os.getenv('AOTG_TEST_PRIVATE'),"
                "'devices':sorted(os.listdir('/dev')),'pid':os.getpid(),"
                "'home':os.environ['HOME']}))\n"
            )
            original = os.environ.get("AOTG_TEST_PRIVATE")
            os.environ["AOTG_TEST_PRIVATE"] = "must-not-propagate"
            try:
                result = run_isolated(["/usr/bin/python3", "-c", source], workspace,
                                      execution_authorized=True)
            finally:
                if original is None:
                    os.environ.pop("AOTG_TEST_PRIVATE")
                else:
                    os.environ["AOTG_TEST_PRIVATE"] = original
            self.assertEqual(result["status"], "ok", result)
            measured = json.loads(result["stdout"])
            self.assertFalse(measured["host_visible"])
            self.assertFalse(measured["home_visible"])
            self.assertFalse(measured["connected"])
            self.assertIsNone(measured["env"])
            self.assertEqual(measured["devices"], ["null", "random", "urandom", "zero"])
            self.assertEqual(measured["pid"], 1)
            self.assertEqual(measured["home"], "/home/sandbox")

    def test_system_and_explicit_tool_are_readonly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "work"
            workspace.mkdir()
            tool = root / "audited-tool.txt"
            tool.write_text("fixed", encoding="utf-8")
            source = (
                "import pathlib\n"
                "assert pathlib.Path('/tools/reference').read_text()=='fixed'\n"
                "for name in ['/tools/reference','/usr/aotg-forbidden-test','/aotg-forbidden-test']:\n"
                " try: pathlib.Path(name).write_text('changed');raise AssertionError('writable')\n"
                " except OSError: pass\n"
                "pathlib.Path('/tmp/fresh').write_text('ok')\n"
                "pathlib.Path('/home/sandbox/fresh').write_text('ok')\n"
                "print('isolated')\n"
            )
            result = run_isolated(["/usr/bin/python3", "-c", source], workspace,
                                  readonly_bindings={"/tools/reference": tool}, execution_authorized=True)
            self.assertEqual(result["status"], "ok", result)
            self.assertEqual(tool.read_text(encoding="utf-8"), "fixed")
            fresh = run_isolated(["/usr/bin/python3", "-c", "import pathlib;assert not pathlib.Path('/tmp/fresh').exists()"],
                                 workspace, execution_authorized=True)
            self.assertEqual(fresh["status"], "ok", fresh)

    def test_timeout_kills_detached_namespace_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = "import pathlib,time;pathlib.Path('/work/started').touch();time.sleep(1.2);pathlib.Path('/work/escaped').touch()"
            source = f"import subprocess,time;subprocess.Popen(['/usr/bin/python3','-c',{child!r}],start_new_session=True);time.sleep(10)"
            result = run_isolated(["/usr/bin/python3", "-c", source], root,
                                  timeout_seconds=0.6, execution_authorized=True)
            self.assertEqual(result["status"], "timeout", result)
            self.assertTrue(result["isolation_verified"])
            self.assertTrue((root / "started").exists())
            time.sleep(1.3)
            self.assertFalse((root / "escaped").exists())

    def test_file_and_output_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_isolated(["/usr/bin/python3", "-c", "with open('/work/large','wb') as stream: stream.write(b'x'*4096);stream.flush()"],
                                  directory, file_limit_bytes=1024, execution_authorized=True)
            self.assertNotEqual(result["status"], "ok")
            self.assertLessEqual((Path(directory) / "large").stat().st_size, 1024)
            flooded = run_isolated(["/usr/bin/python3", "-c", "import sys;sys.stdout.write('x'*1048576)"],
                                   directory, execution_authorized=True)
            self.assertEqual(flooded["status"], "output-limit")
            self.assertLessEqual(len(flooded["stdout"]) + len(flooded["stderr"]), MAX_OUTPUT_BYTES)


if __name__ == "__main__":
    unittest.main()
