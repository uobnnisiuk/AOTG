"""Fake clients plus real nested public compilers; no OpenCode or model runs."""

import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aotg.artifacts import ArtifactError
from aotg.field_client import (
    _namespace_tools,
    _supervise,
    client_command,
    run_opencode,
    summarize_events,
    validate_profile,
)
from aotg.field_sandbox import run_isolated


def sha(data):
    return hashlib.sha256(data).hexdigest()


def profile(endpoint="http://127.0.0.1:19180/v1"):
    return {"$schema": "https://opencode.ai/config.json", "provider": {"evo": {
        "npm": "@ai-sdk/openai-compatible", "options": {"baseURL": endpoint, "apiKey": "{file:/owner/existing-key}"},
        "models": {"fixture-model": {"name": "fixture-model", "tool_call": True,
                                      "limit": {"context": 8192, "output": 1024}}}}}}


def client_namespace_probe():
    """Probe the exact production wrapper, without an OpenCode/model process.

    Hosted CI may deny unprivileged namespaces even when util-linux is present.
    Only that known host limitation skips positive native tests. An unexpected
    acknowledgment or child failure remains a test failure, not a silent skip.
    """
    if os.name != "posix" or not Path("/proc/self/ns/pid").exists():
        return False, "Linux PID namespaces are unavailable on this host"
    supplied = {"unshare": "/usr/bin/unshare", "setpriv": "/usr/bin/setpriv", "python": sys.executable}
    if any(not Path(path).is_file() or not os.access(path, os.X_OK) for path in supplied.values()):
        return False, "Existing client namespace tools are unavailable"
    tools, _ = _namespace_tools(supplied)
    with tempfile.TemporaryDirectory(prefix="aotg-client-namespace-probe-") as temporary:
        root = Path(temporary)
        stderr = root / "probe.stderr"
        try:
            result = _supervise(
                [tools["python"], "-I", "-S", "-c", "print('aotg-client-namespace-probe')"],
                root, {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": str(root)},
                5, 4096, None, root / "probe.stdout", stderr, tools)
        except ArtifactError:
            diagnostic = stderr.read_text(encoding="utf-8", errors="replace") if stderr.exists() else ""
            if re.search(r"(?:unshare|setpriv):[^\n]*(?:operation not permitted|permission denied)",
                         diagnostic, flags=re.IGNORECASE):
                return False, "Host policy denies the required client namespace/capability setup"
            raise
        if (result["stop_reason"] != "exited" or result["exit_code"] != 0
                or result["stdout"] != b"aotg-client-namespace-probe\n"):
            raise AssertionError("Client namespace probe child failed after setup: " + repr(result))
    return True, None


class ConfigurationTests(unittest.TestCase):
    def test_profile_rejects_nonlocal_or_hidden_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "profile.json"
            configurations = []
            for key, value in (("plugin", ["some-plugin"]), ("mcp", {"server": {}}),
                               ("agent", {"other": {}}), ("instructions", ["private.md"]),
                               ("enabled_providers", ["evo", "cloud"]), ("autoupdate", True)):
                item = profile()
                item[key] = value
                configurations.append(item)
            item = profile()
            item["provider"]["evo"]["options"]["apiKey"] = "literal-value-must-not-be-copied"
            configurations.append(item)
            item = profile()
            item["provider"]["evo"]["npm"] = "downloaded-provider"
            configurations.append(item)
            for item in configurations:
                target.write_text(json.dumps(item), encoding="utf-8")
                with self.assertRaises(ArtifactError):
                    validate_profile(target, "http://127.0.0.1:19180/v1", "fixture-model")
            target.write_text(json.dumps(profile()), encoding="utf-8")
            for endpoint in ("http://example.com:19180/v1", "http://localhost:19180/v1", "http://127.0.0.1:19180/v1?url=x"):
                with self.assertRaises(ArtifactError):
                    validate_profile(target, endpoint, "fixture-model")

    def test_summary_requires_final_and_verification_after_last_edit(self):
        events = [
            {"type": "tool_use", "part": {"tool": "bash", "state": {"status": "completed", "input": {"command": "./verify.sh"}, "metadata": {"exit": 0}}}},
            {"type": "tool_use", "part": {"tool": "edit", "state": {"status": "completed", "input": {"filePath": "Source.cpp"}}}},
            {"type": "step_finish", "part": {"messageID": "m", "reason": "stop"}},
        ]
        raw = b"".join(json.dumps(event).encode() + b"\n" for event in events)
        summary = summarize_events(raw, Path("/work"), "Source.cpp", {"Source.cpp", "verify.sh"})
        self.assertFalse(summary["selftest_pass_reported"])
        self.assertFalse(summary["final_response_present"])
        self.assertIsNone(summary["tokens"])

    def test_tool_policy_and_malformed_evidence_are_reported(self):
        event = {"type": "tool_use", "part": {"tool": "bash", "state": {
            "status": "completed", "input": {"command": "./verify.sh; echo unsafe"}, "metadata": {"exit": 0}}}}
        raw = json.dumps(event).encode() + b"\nnot json\n"
        summary = summarize_events(raw, Path("/work"), "Source.cpp", {"Source.cpp", "verify.sh"})
        self.assertEqual(summary["tool_policy_violations"], ["unexpected-bash-command"])
        self.assertEqual(summary["invalid_event_lines"], 1)
        self.assertFalse(summary["selftest_pass_reported"])

    @unittest.skipUnless(sys.platform == "linux", "Client namespace capability classification is Linux-specific")
    def test_namespace_probe_skips_host_denial_but_not_protocol_regression(self):
        def denied(command, cwd, env, seconds, output_limit, max_steps, stdout, stderr, tools):
            stderr.write_text("unshare: unshare failed: Operation not permitted\n", encoding="utf-8")
            raise ArtifactError("Invalid PID namespace startup acknowledgment")

        with patch(__name__ + "._supervise", side_effect=denied):
            available, reason = client_namespace_probe()
        self.assertFalse(available)
        self.assertIn("Host policy", reason)

        def broken_protocol(command, cwd, env, seconds, output_limit, max_steps, stdout, stderr, tools):
            stderr.write_text("unexpected child protocol failure\n", encoding="utf-8")
            raise ArtifactError("Invalid PID namespace startup acknowledgment")

        with patch(__name__ + "._supervise", side_effect=broken_protocol), self.assertRaisesRegex(ArtifactError, "acknowledgment"):
            client_namespace_probe()


@unittest.skipUnless(os.name == "posix", "First-machine process supervision runs in WSL/POSIX")
class FakeClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.namespace_available, cls.namespace_unavailable_reason = client_namespace_probe()

    def require_namespace(self):
        if not self.namespace_available:
            self.skipTest(self.namespace_unavailable_reason)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.owner_profile = self.root / "owner-profile.json"
        self.owner_profile.write_text(json.dumps(profile()), encoding="utf-8")
        self.executable = self.root / "fake-client"
        self.workload = {"id": "synthetic-cpp", "public_files": []}
        for name, data, field in (("Source.cpp", b"initial source\n", "source"),
                                  ("verify.sh", b"#!/bin/sh\nexit 0\n", "public"),
                                  ("PublicTests.cpp", b"public examples only\n", "public"),
                                  ("prompt.txt", b"Repair Source.cpp. Run ./verify.sh and provide a final response.", "prompt")):
            path = self.root / name
            path.write_bytes(data)
            entry = {"path": str(path), "sha256": sha(data)}
            if field != "prompt":
                entry["name"] = name
            if field == "public":
                self.workload["public_files"].append(entry)
            else:
                self.workload[field] = entry

    def tearDown(self):
        self.temporary.cleanup()

    def script(self, body):
        preface = f"#!{sys.executable}\nimport json, os, sys, time, subprocess\nfrom pathlib import Path\nif '--version' in sys.argv:\n    print('1.1.53')\n    raise SystemExit(0)\n"
        self.executable.write_text(preface + body, encoding="utf-8")
        self.executable.chmod(0o700)

    def arguments(self, **overrides):
        return {"executable": self.executable, "profile": self.owner_profile,
                "command": client_command(self.executable, "fixture-model"),
                "workload": self.workload, "endpoint": "http://127.0.0.1:19180/v1", "model": "fixture-model",
                "output_dir": self.root / "result", "tool_path": ["/usr/bin", "/bin"],
                "max_seconds": 5, "max_steps": 4, "max_output_bytes": 65536,
                "namespace_tools": {"unshare": "/usr/bin/unshare", "setpriv": "/usr/bin/setpriv", "python": sys.executable},
                "execution_authorized": True, **overrides}

    def complete_body(self):
        return """
overlay = json.loads(os.environ['OPENCODE_CONFIG_CONTENT'])
assert overlay['permission']['bash'] == {'*': 'deny', './verify.sh': 'allow'}
assert overlay['permission']['external_directory'] == 'deny'
assert overlay['permission']['edit'] == {'*': 'deny', str((Path.cwd() / 'Source.cpp').relative_to('/')): 'allow'}
assert overlay['enabled_providers'] == ['evo']
assert overlay['agent']['aotg-field']['steps'] == 4
assert overlay['agent']['title'] == {'disable': True}
guidance = overlay['agent']['aotg-field']['prompt']
for name in ('Source.cpp', 'PublicTests.cpp', 'verify.sh'):
    assert str(Path.cwd() / name) in guidance
assert 'structured tool interface' in guidance
assert 'only allowed bash command is exactly ./verify.sh' in guidance
assert sys.argv[-1] == 'Repair Source.cpp. Run ./verify.sh and provide a final response.'
assert os.environ['OPENCODE_DISABLE_MODELS_FETCH'] == 'true'
assert 'API_KEY' not in os.environ and 'LD_PRELOAD' not in os.environ
assert Path(os.environ['HOME']).is_dir()
pkg = Path(os.environ['XDG_CONFIG_HOME']) / 'opencode/package.json'
assert json.loads(pkg.read_text())['dependencies'] == {'@opencode-ai/plugin': '1.1.53'}
assert Path(os.environ['OPENCODE_CONFIG']).name == 'owner-profile.json'
assert not list(Path(os.environ['OPENCODE_TEST_MANAGED_CONFIG_DIR']).iterdir())
Path('Source.cpp').write_text('modified source\\n')
events = [
 {'type':'step_start','part':{'messageID':'m'}},
 {'type':'tool_use','part':{'tool':'edit','state':{'status':'completed','input':{'filePath':str(Path.cwd() / 'Source.cpp')}}}},
 {'type':'tool_use','part':{'tool':'bash','state':{'status':'completed','input':{'command':'./verify.sh'},'metadata':{'exit':0}}}},
 {'type':'text','part':{'messageID':'m','text':'Implemented and ran the public selftest.'}},
 {'type':'step_finish','part':{'messageID':'m','reason':'stop','tokens':{'input':120,'output':30,'reasoning':0,'cache':{'read':10,'write':0}}}}
]
for event in events: print(json.dumps(event), flush=True)
"""

    def test_complete_synthetic_client_keeps_quality_independent(self):
        self.require_namespace()
        self.script(self.complete_body())
        original_profile = self.owner_profile.read_bytes()
        with patch.dict(os.environ, {"API_KEY": "should-not-propagate"}):
            result = run_opencode(**self.arguments())
        self.assertEqual(result["status"], "completed-awaiting-independent-quality", result)
        self.assertFalse(result["quality_accepted"])
        self.assertFalse(result["isolation"]["network_sandbox_verified"])
        self.assertTrue(result["isolation"]["pid_namespace_verified"])
        self.assertEqual(result["isolation"]["cleanup_scope"], "dedicated-pid-namespace")
        self.assertTrue(result["source_changed"])
        self.assertTrue(result["public_selftests_unchanged"])
        self.assertEqual(result["tokens"]["input"], 120)
        self.assertEqual(self.owner_profile.read_bytes(), original_profile)
        self.assertTrue((self.root / "result/private/events.jsonl").is_file())
        self.assertNotIn("literal-value", (self.root / "result/result.json").read_text())

    def test_public_selftest_tampering_invalidates_completion(self):
        self.require_namespace()
        self.script(self.complete_body() + "Path('verify.sh').chmod(0o600)\nPath('verify.sh').write_text('changed')\n")
        result = run_opencode(**self.arguments())
        self.assertEqual(result["status"], "protected-input-changed")
        self.assertFalse(result["public_selftests_unchanged"])

    def test_timeout_cleans_detached_descendants(self):
        self.require_namespace()
        self.script("subprocess.Popen([sys.executable,'-c',\"import time;from pathlib import Path;time.sleep(.6);Path('detached-survived').touch()\"], start_new_session=True)\ntime.sleep(30)\n")
        result = run_opencode(**self.arguments(max_seconds=0.15))
        self.assertEqual(result["status"], "wall-time")
        time.sleep(0.7)
        self.assertFalse((self.root / "result/work/detached-survived").exists())

    def test_normal_parent_exit_also_cleans_children(self):
        self.require_namespace()
        self.script("subprocess.Popen([sys.executable,'-c',\"import time;from pathlib import Path;time.sleep(.6);Path('detached-survived').touch()\"], start_new_session=True)\n")
        result = run_opencode(**self.arguments())
        self.assertEqual(result["status"], "incomplete")
        time.sleep(0.7)
        self.assertFalse((self.root / "result/work/detached-survived").exists())

    def test_git_ancestor_and_ambiguous_paths_rejected_before_client_execution(self):
        self.script("Path('client-ran').touch()\n")
        marker = self.root / ".git"
        # OpenCode treats each kind as a project marker, including worktrees.
        for kind in ("directory", "file", "broken-symlink"):
            with self.subTest(kind=kind):
                if kind == "directory":
                    marker.mkdir()
                elif kind == "file":
                    marker.write_text("gitdir: nonexistent\n", encoding="utf-8")
                else:
                    marker.symlink_to(self.root / "missing-git-directory")
                try:
                    with self.assertRaisesRegex(ArtifactError, "outside every Git project"):
                        run_opencode(**self.arguments())
                    self.assertFalse((self.root / "result").exists())
                finally:
                    if kind == "directory":
                        marker.rmdir()
                    else:
                        marker.unlink()
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for output in (alias / "result", self.root / "result*", self.root / "result?"):
            with self.subTest(output=output), self.assertRaises(ArtifactError):
                run_opencode(**self.arguments(output_dir=output))
        self.assertFalse((self.root / "result").exists())

    def test_missing_namespace_fails_without_client_execution(self):
        self.script("Path('client-ran').touch()\n")
        # This rejection test still runs when the real namespace probe is denied.
        args = self.arguments(namespace_tools={"unshare": "/bin/false", "setpriv": "/bin/false", "python": sys.executable})
        with self.assertRaisesRegex(ArtifactError, "namespace"):
            run_opencode(**args)
        self.assertFalse((self.root / "result/work/client-ran").exists())

    def test_output_and_step_limits(self):
        self.require_namespace()
        self.script("print('x' * 100000, flush=True)\ntime.sleep(30)\n")
        result = run_opencode(**self.arguments(max_output_bytes=4096))
        self.assertEqual(result["status"], "output-limit")
        self.assertTrue(result["output_truncated"])
        events = (self.root / "result/private/events.jsonl").read_bytes()
        self.assertLessEqual(len(events), 4096)
        self.assertEqual(result["private_events_sha256"], sha(events))
        self.script("for i in range(10): print(json.dumps({'type':'step_start','part':{'messageID':str(i)}}), flush=True)\ntime.sleep(30)\n")
        result = run_opencode(**self.arguments(output_dir=self.root / "step-result"))
        self.assertEqual(result["status"], "step-limit")

    def test_authorization_command_hash_and_output_guards(self):
        self.script(self.complete_body())
        with self.assertRaises(ArtifactError):
            run_opencode(**self.arguments(execution_authorized=False))
        with self.assertRaises(ArtifactError):
            run_opencode(**self.arguments(command=[str(self.executable), "run", "--command", "anything"]))
        with self.assertRaises(ArtifactError):
            run_opencode(**self.arguments(max_seconds=float("nan")))
        (self.root / "Source.cpp").write_text("changed before start")
        with self.assertRaises(ArtifactError):
            run_opencode(**self.arguments())
        self.assertFalse((self.root / "result").exists())


@unittest.skipUnless(sys.platform == "linux", "Nested native public selftests require Linux")
class NestedNativePublicSelftestTests(unittest.TestCase):
    """Exercise verify.sh through the real client wrapper and inner sandbox.

    A direct inner-sandbox host probe distinguishes missing host facilities from
    a regression composing two supported isolation layers. Once both facilities
    work independently, a nested uid_map failure must fail these tests.
    """

    @classmethod
    def setUpClass(cls):
        available, reason = client_namespace_probe()
        if not available:
            raise unittest.SkipTest(reason)
        with tempfile.TemporaryDirectory(prefix="aotg-direct-selftest-probe-") as temporary:
            probe = run_isolated(["/usr/bin/true"], temporary, execution_authorized=True,
                                 readonly_workspace=True)
        if not probe["isolation_verified"]:
            raise unittest.SkipTest("Host forbids the direct native selftest sandbox")

    def run_nested(self, source_text, public_text, source_name, public_name, toolchain):
        with tempfile.TemporaryDirectory(prefix="aotg-nested-public-selftest-") as temporary:
            root = Path(temporary)
            source, public = root / source_name, root / public_name
            source.write_text(source_text, encoding="utf-8")
            public.write_text(public_text, encoding="utf-8")
            before = source.read_bytes(), public.read_bytes()
            repository = str(Path(__file__).resolve().parents[1])
            driver = root / "run_public.py"
            driver.write_text(
                "import json, os, sys\nfrom pathlib import Path\n"
                + "sys.path.insert(0, " + repr(repository) + ")\n"
                + "from aotg.field_selftest import run_public_selftest\n"
                + "status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)\n"
                + "caps = {key: int(status[key].strip(), 16) for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')}\n"
                + "assert all(value == 0 for value in caps.values()) and status['NoNewPrivs'].strip() == '1'\n"
                + "result = run_public_selftest(" + repr(str(source)) + ", " + repr(str(public))
                + ", execution_authorized=True, **" + repr(toolchain) + ")\n"
                + "print(json.dumps({'outer_uid': os.getuid(), 'outer_caps': caps, 'selftest': result}))\n"
                + "raise SystemExit(0 if result['status'] == 'pass' else 1)\n", encoding="utf-8")
            verify = root / "verify.sh"
            verify.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable)
                              + " -I -S -B " + shlex.quote(str(driver)) + "\n", encoding="utf-8")
            verify.chmod(0o500)
            tools, _ = _namespace_tools({"unshare": "/usr/bin/unshare", "setpriv": "/usr/bin/setpriv",
                                         "python": sys.executable})
            observed = _supervise(["./verify.sh"], root,
                                  {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(root), "TMPDIR": str(root)},
                                  90, 65536, None, root / "stdout", root / "stderr", tools)
            self.assertEqual(observed["stop_reason"], "exited", observed)
            self.assertIn(observed["exit_code"], (0, 1), observed)
            self.assertEqual(observed["namespace"]["uid"], os.getuid())
            self.assertEqual(observed["namespace"]["gid"], os.getgid())
            self.assertTrue(observed["namespace"]["capabilities_dropped"])
            self.assertTrue(observed["namespace"]["no_new_privs"])
            self.assertEqual((source.read_bytes(), public.read_bytes()), before)
            payload = json.loads(observed["stdout"])
            self.assertEqual(payload["outer_uid"], os.getuid())
            self.assertEqual(set(payload["outer_caps"].values()), {0})
            report = payload["selftest"]
            self.assertTrue(report["isolation"]["isolation_verified"], report)
            self.assertTrue(report["isolation"]["readonly_workspace"], report)
            self.assertFalse(report["quality_accepted"])
            self.assertEqual(report["compile"]["exit_code"], 0, report)
            return observed["exit_code"], report

    @unittest.skipUnless(Path("/usr/bin/g++").is_file(), "Existing g++ unavailable; no download attempted")
    def test_cpp_starter_rejected_and_correct_source_passes_inside_client_namespace(self):
        public = '#include "candidate.cpp"\nint main(){return public_value()==42?0:1;}\n'
        for value, expected in ((41, "test-failed"), (42, "pass")):
            with self.subTest(value=value):
                code, report = self.run_nested("int public_value(){return " + str(value) + ";}\n", public,
                                              "candidate.cpp", "PublicTests.cpp", {"compiler": "/usr/bin/g++"})
                self.assertEqual(report["status"], expected, report)
                self.assertEqual(code, 0 if expected == "pass" else 1)

    def test_csharp_starter_rejected_and_correct_source_passes_inside_client_namespace(self):
        dotnet = Path.home() / ".dotnet"
        compiler, csc = dotnet / "dotnet", dotnet / "sdk/8.0.424/Roslyn/bincore/csc.dll"
        references = dotnet / "packs/Microsoft.NETCore.App.Ref/8.0.30/ref/net8.0"
        if not compiler.is_file() or not csc.is_file() or not references.is_dir():
            self.skipTest("Pinned existing .NET8 toolchain unavailable; no download attempted")
        toolchain = {"compiler": str(compiler), "compiler_kind": "dotnet-csc", "csc_dll": str(csc),
                     "reference_dir": str(references), "runtime_version": "8.0.30"}
        public = "public static class PublicTests {public static int Main(){return Candidate.Value()==42?0:1;}}\n"
        for value, expected in ((41, "test-failed"), (42, "pass")):
            with self.subTest(value=value):
                source = "public static class Candidate {public static int Value(){return " + str(value) + ";}}\n"
                code, report = self.run_nested(source, public, "Candidate.cs", "PublicTests.cs", toolchain)
                self.assertEqual(report["status"], expected, report)
                self.assertEqual(code, 0 if expected == "pass" else 1)


if __name__ == "__main__":
    unittest.main()
