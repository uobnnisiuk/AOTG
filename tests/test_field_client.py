"""Synthetic fake clients only: these tests do not run OpenCode or a model."""

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aotg.artifacts import ArtifactError
from aotg.field_client import client_command, run_opencode, summarize_events, validate_profile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def profile(endpoint="http://127.0.0.1:19180/v1"):
    return {"$schema": "https://opencode.ai/config.json", "provider": {"evo": {
        "npm": "@ai-sdk/openai-compatible", "options": {"baseURL": endpoint, "apiKey": "{file:/owner/existing-key}"},
        "models": {"fixture-model": {"name": "fixture-model", "tool_call": True,
                                      "limit": {"context": 8192, "output": 1024}}}}}}


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


@unittest.skipUnless(os.name == "posix", "First-machine process supervision runs in WSL/POSIX")
class FakeClientTests(unittest.TestCase):
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
assert overlay['enabled_providers'] == ['evo']
assert overlay['agent']['aotg-field']['steps'] == 4
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
        self.script(self.complete_body() + "Path('verify.sh').chmod(0o600)\nPath('verify.sh').write_text('changed')\n")
        result = run_opencode(**self.arguments())
        self.assertEqual(result["status"], "protected-input-changed")
        self.assertFalse(result["public_selftests_unchanged"])

    def test_timeout_cleans_detached_descendants(self):
        self.script("subprocess.Popen([sys.executable,'-c',\"import time;from pathlib import Path;time.sleep(.6);Path('detached-survived').touch()\"], start_new_session=True)\ntime.sleep(30)\n")
        result = run_opencode(**self.arguments(max_seconds=0.15))
        self.assertEqual(result["status"], "wall-time")
        time.sleep(0.7)
        self.assertFalse((self.root / "result/work/detached-survived").exists())

    def test_normal_parent_exit_also_cleans_children(self):
        self.script("subprocess.Popen([sys.executable,'-c',\"import time;from pathlib import Path;time.sleep(.6);Path('detached-survived').touch()\"], start_new_session=True)\n")
        result = run_opencode(**self.arguments())
        self.assertEqual(result["status"], "incomplete")
        time.sleep(0.7)
        self.assertFalse((self.root / "result/work/detached-survived").exists())

    def test_missing_namespace_fails_without_client_execution(self):
        self.script("Path('client-ran').touch()\n")
        args = self.arguments(namespace_tools={"unshare": "/bin/false", "setpriv": "/usr/bin/setpriv", "python": sys.executable})
        with self.assertRaisesRegex(ArtifactError, "namespace"):
            run_opencode(**args)
        self.assertFalse((self.root / "result/work/client-ran").exists())

    def test_output_and_step_limits(self):
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


if __name__ == "__main__":
    unittest.main()
