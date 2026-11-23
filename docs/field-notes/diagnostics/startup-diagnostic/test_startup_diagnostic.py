"""Offline startup diagnostic tests. All host/process/GPU actions are replaced.

Synthetic fixtures exercise real validation, execute control flow and result I/O
inside TemporaryDirectory only. They are not host startup or performance evidence.
"""
import argparse
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

W = None
BASELINE = None

def plan_for(root):
    protected = root / "inputs"
    run_id = "startup-synthetic"
    desc = lambda name: {"path": str(protected / name), "sha256": "0" * 64}
    plan = {
        "artifact": "aotg-evo-startup-diagnostic-plan", "version": 1,
        "run_id": run_id, "worker_sha256": "0" * 64,
        "maintenance_unit": "aotg-synthetic.service", "task_root": str(root / run_id),
        "control_root": str(protected / "control"),
        "source_roots": [str(protected / "control/serve")],
        "source_files": [desc("control/serve/server.py")], "dependency_packages": [],
        "api_key_file": str(protected / "key"), "path_dirs": [str(protected / "bin")],
        "library_dirs": [str(protected / "lib")], "readonly_roots": [str(protected)],
        "gpu": {"bdf": "0000:01:00.0", "hip_index": 0, "arch": "gfx1151",
                "vendor": "0x1002", "device": "0x1586"},
        "strata_dirs": {k: str(protected / k) for k in ("install", "data", "components")},
        "max_seconds": 240, "kernel_since": "2026-11-16 00:00:00 UTC",
        "required_alarm_keys": ["synthetic-alarm"],
    }
    for name in ("worker_python", "python", "engine", "telemetry", "hip_probe",
                 "journalctl", "active_config", "expert_profile"):
        plan[name] = desc(name)
    plan["native_argv"] = ["--serve", "--prefill", W.TOKEN, "--expert-profile", W.EXPERT]
    for key, value in (("--max-context", "131072"), ("--kv", "int8"), ("--draft", "dflash2"),
                       ("--spec", "8"), ("--draft-conf", "0.35"), ("--draft-fallback", "none")):
        plan["native_argv"] += [key, value]
    for key in ("--pack", "--native", "--ple-gguf", "--draft-model", "--mtp-draft-vocab"):
        plan["native_argv"] += [key, str(protected / ("model-" + key[2:]))]
    plan["profiles"] = [{"id": "baseline512", "prefill": 512,
                         "profile_sha256": W.profile_identity(plan, 512)}]
    return plan

class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_for(Path("/synthetic-root"))

    def rejected(self, changed):
        with self.assertRaises((W.StopTrial, TypeError)):
            W.validate_plan(changed)

    def test_valid_exact_single_baseline(self):
        self.assertIs(W.validate_plan(self.plan), self.plan)

    def test_legacy_artifact_schedule_and_field_plan_rejected(self):
        for key, value in (("artifact", "aotg-evo-worker-plan"), ("schedule", []),
                           ("field_plan", {"path": "/old/plan", "sha256": "0" * 64})):
            p = copy.deepcopy(self.plan); p[key] = value
            with self.subTest(key=key): self.rejected(p)

    def test_only_one_512_profile(self):
        for profiles in ([], self.plan["profiles"] * 2,
                         [{**self.plan["profiles"][0], "prefill": 256}],
                         [{**self.plan["profiles"][0], "prefill": 1024}],
                         [{**self.plan["profiles"][0], "prefill": True}],
                         [{**self.plan["profiles"][0], "prefill": 512.0}],
                         [{**self.plan["profiles"][0], "extra": "forbidden"}]):
            p = copy.deepcopy(self.plan); p["profiles"] = profiles
            with self.subTest(profiles=profiles): self.rejected(p)

    def test_fixed_240_limit_not_bool_or_float(self):
        for value in (60, 239, 241, 2040, True, 240.0, "240"):
            p = copy.deepcopy(self.plan); p["max_seconds"] = value
            with self.subTest(value=value): self.rejected(p)

    def test_profile_digest_binds_active_config_and_native_argv(self):
        for mutate in (
            lambda p: p["profiles"][0].update(profile_sha256="1" * 64),
            lambda p: p["active_config"].update(sha256="2" * 64),
            lambda p: p["native_argv"].extend(["--synthetic-extra", "changed"]),
        ):
            p = copy.deepcopy(self.plan); mutate(p); self.rejected(p)

    def test_critical_native_options_fail_closed(self):
        for key, value in (("--draft", "none"), ("--spec", "16"), ("--draft-conf", ".5"),
                           ("--kv", "fp16"), ("--max-context", "4096")):
            p = copy.deepcopy(self.plan); p["native_argv"][p["native_argv"].index(key)+1] = value
            p["profiles"][0]["profile_sha256"] = W.profile_identity(p, 512)
            with self.subTest(key=key): self.rejected(p)

    def test_protected_root_cannot_overlap_task(self):
        p = copy.deepcopy(self.plan); p["readonly_roots"] = ["/synthetic-root"]
        self.rejected(p)

    def test_guard_ownership_preflight_and_import_helpers_ast_unchanged(self):
        original = ast.parse(BASELINE.read_text())
        current = ast.parse(Path(W.__file__).read_text())
        before = {n.name: ast.dump(n, include_attributes=False) for n in original.body
                  if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        after = {n.name: ast.dump(n, include_attributes=False) for n in current.body
                 if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        self.assertEqual(set(before), set(after))
        allowed = {"validate_plan", "verify_inputs", "input_permissions", "execute", "main"}
        self.assertLessEqual({k for k in before if before[k] != after[k]}, allowed)
        for name in ("Monitor", "OwnedProcesses", "current_unit", "preflight", "resource_check",
                     "read_pswpout", "verify_hip", "verify_engine", "require_clean_cgroup",
                     "BoundedCommand", "bootstrap", "copied_config"):
            self.assertEqual(before[name], after[name], name)

class Scenario:
    def __init__(self, root, failure=None):
        self.plan = plan_for(root)
        self.root, self.failure, self.now = root, failure, 0.0
        self.calls = {"popen": 0, "cleanup": 0, "barrier": 0, "close": 0,
                      "kernel": 0, "hip": 0, "ticks": 0}
        inputs = root / "inputs"; inputs.mkdir()
        for name, data in (("telemetry", b'ERROR_PATTERN = "SYNTHETIC-NO-MATCH"\n'),
                           ("expert_profile", b"synthetic profile"), ("key", b"synthetic-key")):
            path = inputs / name; path.write_bytes(data); path.chmod(0o600)
            if name in self.plan:
                self.plan[name]["sha256"] = hashlib.sha256(data).hexdigest()
        self.base = {"model_name": "synthetic-model", "exe": self.plan["engine"]["path"],
                     "cwd": self.plan["control_root"], "backend": "hip", "drafting": "dflash2",
                     "user_args": ["--prefill", "512", "--max-context", "131072"],
                     "args": ["--expert-profile", self.plan["expert_profile"]["path"]],
                     "args_written": ["--expert-profile", self.plan["expert_profile"]["path"]]}
        self.plan["profiles"][0]["profile_sha256"] = W.profile_identity(self.plan, 512)
        self.proc = None
        self.mon = None

    @property
    def task(self): return Path(self.plan["task_root"])
    @property
    def arm(self): return self.task / "arm-000"
    def sleep(self, seconds): self.now += seconds
    def preflight(self, plan):
        W.validate_plan(plan)
        if self.failure == "preflight": raise W.StopTrial("synthetic preflight failure")
        return copy.deepcopy(self.base)
    def hip(self, plan, monitor):
        self.calls["hip"] += 1
        if self.failure == "insufficient-budget": self.now += 100
    def engine(self, plan, owned, profile, arm):
        if self.failure == "readiness-timeout": return None
        if self.failure == "native-replaced" and (arm / "startup-ready.json").exists(): return 8124
        return 8123
    def kernel(self, plan, pattern):
        self.calls["kernel"] += 1
        return {"status": "errors" if self.failure in ("kernel", "all-finalizers") else "clear",
                "since": plan["kernel_since"], "errors": [], "synthetic": True}
    def barrier(self, group, baseline):
        self.calls["barrier"] += 1
        if self.failure in ("barrier", "ownership-constructor", "all-finalizers"):
            raise W.StopTrial("synthetic unresolved cgroup")
    def popen(self, argv, **kwargs):
        self.calls["popen"] += 1
        if self.failure == "launch": raise OSError("synthetic launch failure")
        assert "--offline" in argv and "--parallel" in argv and argv[argv.index("--parallel")+1] == "1"
        assert argv[argv.index("--port")+1] == "19480"
        assert kwargs["start_new_session"] and kwargs["cwd"] == self.arm
        scenario = self
        class Process:
            pid = 7123
            def poll(self):
                if scenario.failure == "exit-load": return 7
                if scenario.failure == "exit-idle" and (scenario.arm / "startup-ready.json").exists(): return 9
                return None
        self.proc = Process()
        if self.failure != "readiness-timeout":
            ready = {"pid": self.proc.pid, "bound_host": "127.0.0.1", "bound_port": 19480,
                     "model_state": "ready", "api_state": "ready", "model_id": self.base["model_name"]}
            if self.failure == "bad-ready": ready["bound_port"] = 19481
            (self.arm / "server-ready.json").write_text(json.dumps(ready))
        return self.proc
    def owned(self, process, group):
        if self.failure == "ownership-constructor":
            raise W.StopTrial("synthetic ownership constructor failure")
        scenario = self
        class Owned:
            def cleanup(self):
                scenario.calls["cleanup"] += 1
                if scenario.failure in ("cleanup", "all-finalizers"): raise W.StopTrial("synthetic cleanup failure")
        return Owned()
    def monitor(self, plan, telemetry, stream, deadline, observation_stream):
        scenario = self
        class FakeMonitor:
            pause_since = None
            def tick(self, owned, native, force=False):
                scenario.calls["ticks"] += 1
                scenario.now += .25
                W.require(scenario.now < deadline, "Total worker time limit")
                if scenario.failure == "guard-prelaunch" and owned is None:
                    raise W.StopTrial("synthetic guard failure")
                if scenario.failure == "guard-load" and owned is not None:
                    raise W.StopTrial("synthetic guard failure")
                if scenario.failure == "guard-idle" and (scenario.arm / "startup-ready.json").exists():
                    raise W.StopTrial("synthetic guard failure")
            def finish_scan(self): pass
            def close(self):
                scenario.calls["close"] += 1
                if (scenario.failure in ("monitor-close", "all-finalizers")
                        or (scenario.failure == "outer-monitor-close" and scenario.calls["close"] == 2)):
                    raise TimeoutError("synthetic journal close timeout")
        self.mon = FakeMonitor()
        return self.mon
    def run(self):
        original_sha = W.sha_file
        def sha(path):
            if str(path).startswith("/proc/"):
                return "1" * 64 if self.failure == "engine-hash" else self.plan["engine"]["sha256"]
            return original_sha(path)
        fake_subprocess = types.SimpleNamespace(Popen=self.popen, DEVNULL=-3, STDOUT=-2)
        with contextlib.ExitStack() as stack:
            for name, value in {
                "current_unit": lambda p: "synthetic-cgroup", "preflight": self.preflight,
                "verify_file": lambda d: None, "verify_hip": self.hip, "verify_engine": self.engine,
                "Monitor": self.monitor, "OwnedProcesses": self.owned,
                "cgroup_identities": lambda group: {"synthetic-baseline"},
                "require_clean_cgroup": self.barrier, "final_kernel_scan": self.kernel,
                "sha_file": sha, "subprocess": fake_subprocess,
                "time": types.SimpleNamespace(monotonic=lambda: self.now, sleep=self.sleep),
                "bootstrap": lambda *a: "# synthetic never executed",
            }.items(): stack.enter_context(patch.object(W, name, value))
            stack.enter_context(patch.dict(os.environ, {"EVO_GPU_BDF": "synthetic-original"}))
            old_umask = os.umask(0o077); os.umask(old_umask)
            try:
                W.execute(self.plan, "a" * 64)
            finally:
                self.environment_restored = os.environ.get("EVO_GPU_BDF") == "synthetic-original"
                os.umask(old_umask)

class FlowTests(unittest.TestCase):
    def scenario(self, failure=None):
        temporary = tempfile.TemporaryDirectory(prefix="aotg-startup-review-")
        self.addCleanup(temporary.cleanup)
        return Scenario(Path(temporary.name), failure)

    def assert_finalized(self, s):
        self.assertTrue(s.environment_restored)
        summary = json.loads((s.task / "summary.json").read_text())
        self.assertIn("finished_at", summary)
        self.assertIn("wall_seconds", summary)
        self.assertFalse(summary["quality_accepted"])
        self.assertFalse(summary["comparison_complete"])
        self.assertFalse(summary["inference_invoked"])
        self.assertEqual(summary["benchmark_trials"], 0)
        self.assertFalse((s.task / "ready.json").exists())
        self.assertFalse(any(s.task.glob("done-*.json")))
        return summary

    def test_one_start_ready_ten_seconds_idle_cleanup_without_handshake(self):
        s = self.scenario(); s.run()
        summary = self.assert_finalized(s)
        self.assertEqual(summary["status"], "startup-observed-no-inference")
        self.assertEqual(len(summary["arms"]), 1)
        result = json.loads((s.arm / "result.json").read_text())
        self.assertEqual(result["purpose"], "baseline-startup-only")
        self.assertEqual(result["prefill"], 512)
        self.assertGreaterEqual(result["idle_observation_seconds"], 10)
        self.assertLess(result["idle_observation_seconds"], 10.6)
        self.assertTrue(result["startup_ready_observed"])
        self.assertEqual(s.calls["popen"], 1)
        self.assertEqual(s.calls["cleanup"], 1)
        self.assertEqual(s.calls["barrier"], 1)
        self.assertEqual(s.calls["kernel"], 1)
        self.assertNotIn("workload_wait_seconds", result)
        self.assertNotIn("k8_evidence_sha256", result)
        ready = json.loads((s.arm / "startup-ready.json").read_text())
        self.assertEqual(ready["artifact"], "aotg-startup-ready-observation")
        self.assertNotIn("endpoint", ready)

    def test_guard_readiness_exit_identity_failures_stop_and_cleanup(self):
        for mode in ("guard-load", "guard-idle", "readiness-timeout", "exit-load",
                     "exit-idle", "native-replaced", "bad-ready", "engine-hash"):
            with self.subTest(mode=mode):
                s = self.scenario(mode)
                with self.assertRaises(W.StopTrial): s.run()
                summary = self.assert_finalized(s)
                self.assertEqual(summary["status"], "stopped")
                self.assertEqual(s.calls["popen"], 1)
                self.assertEqual(s.calls["cleanup"], 1)
                self.assertEqual(s.calls["barrier"], 1)
                self.assertEqual(s.calls["kernel"], 1)
                if mode == "readiness-timeout":
                    self.assertGreaterEqual(s.now, 120)
                    self.assertLess(s.now, 121)
                    self.assertIn("120 seconds", summary["stop_reason"])

    def test_before_spawn_failures_never_launch_or_claim_success(self):
        for mode in ("guard-prelaunch", "insufficient-budget", "launch"):
            with self.subTest(mode=mode):
                s = self.scenario(mode)
                with self.assertRaises((W.StopTrial, OSError)): s.run()
                summary = self.assert_finalized(s)
                self.assertEqual(summary["status"], "stopped")
                self.assertEqual(s.calls["popen"], 1 if mode == "launch" else 0)
                self.assertEqual(s.calls["cleanup"], 0)
                self.assertEqual(s.calls["kernel"], 1)

    def test_ownership_constructor_failure_cannot_claim_clean_exit(self):
        s = self.scenario("ownership-constructor")
        with self.assertRaises(W.StopTrial): s.run()
        summary = self.assert_finalized(s)
        self.assertEqual(summary["status"], "stopped")
        self.assertEqual(summary["arms"][0]["status"], "cleanup-failed")
        self.assertEqual(s.calls["barrier"], 1)

    def test_cleanup_and_cgroup_failures_are_finalized_and_fail_closed(self):
        for mode in ("cleanup", "barrier"):
            with self.subTest(mode=mode):
                s = self.scenario(mode)
                with self.assertRaises(W.StopTrial): s.run()
                summary = self.assert_finalized(s)
                self.assertEqual(summary["status"], "stopped")
                self.assertEqual(summary["arms"][0]["status"], "cleanup-failed")
                self.assertEqual(s.calls["cleanup"], 1)
                self.assertEqual(s.calls["barrier"], 1)
                self.assertEqual(s.calls["kernel"], 1)

    def test_journal_close_failure_still_attempts_owned_cleanup_and_finalization(self):
        s = self.scenario("monitor-close")
        with self.assertRaises((W.StopTrial, TimeoutError)): s.run()
        self.assertEqual(s.calls["cleanup"], 1, "Journal close failure must not skip owned cleanup")
        self.assertEqual(s.calls["barrier"], 1)
        summary = self.assert_finalized(s)
        self.assertEqual(summary["status"], "stopped")
        self.assertEqual(s.calls["kernel"], 1)

    def test_all_cleanup_failures_still_reach_every_finalizer(self):
        s = self.scenario("all-finalizers")
        with self.assertRaises(W.StopTrial): s.run()
        summary = self.assert_finalized(s)
        self.assertEqual(summary["status"], "stopped")
        self.assertEqual(s.calls["cleanup"], 1)
        self.assertEqual(s.calls["barrier"], 1)
        self.assertEqual(s.calls["kernel"], 1)
        self.assertGreaterEqual(s.calls["close"], 2)
        self.assertIn("monitor_close_error_type", summary)
        self.assertIn("final_kernel_scan_error", summary)
        self.assertEqual({x["action"] for x in summary["arms"][0]["cleanup_failures"]},
                         {"journal-close", "owned-process-cleanup", "cgroup-verification"})

    def test_outer_only_close_failure_still_finalizes_and_fails(self):
        s = self.scenario("outer-monitor-close")
        with self.assertRaises(W.StopTrial): s.run()
        summary = self.assert_finalized(s)
        self.assertEqual(summary["status"], "stopped")
        self.assertEqual(s.calls["cleanup"], 1)
        self.assertEqual(s.calls["barrier"], 1)
        self.assertEqual(s.calls["kernel"], 1)
        self.assertIn("monitor_close_error_type", summary)

    def test_real_monitor_deadline_fails_before_resource_acquisition(self):
        monitor = W.Monitor.__new__(W.Monitor)
        monitor.deadline = 240
        telemetry = Mock()
        monitor.telemetry = telemetry
        with patch.object(W, "time", types.SimpleNamespace(monotonic=lambda: 240)):
            with self.assertRaisesRegex(W.StopTrial, "Total worker time limit"):
                monitor.tick(None, None)
        telemetry.sample.assert_not_called()

    def test_final_kernel_errors_prevent_success(self):
        s = self.scenario("kernel")
        with self.assertRaises(W.StopTrial): s.run()
        summary = self.assert_finalized(s)
        self.assertEqual(summary["status"], "stopped")
        self.assertIn("final_kernel_scan_error", summary)
        self.assertEqual(s.calls["cleanup"], 1)

    def test_preflight_failure_has_no_runtime_or_output(self):
        s = self.scenario("preflight")
        with self.assertRaises(W.StopTrial): s.run()
        self.assertEqual(s.calls["popen"], 0)
        self.assertFalse(s.task.exists())
        self.assertTrue(s.environment_restored)

    def test_execute_requires_actual_unit_before_preflight(self):
        with patch.object(W, "current_unit", side_effect=W.StopTrial("wrong unit")), \
             patch.object(W, "preflight") as preflight:
            with self.assertRaises(W.StopTrial): W.execute({}, "a" * 64)
            preflight.assert_not_called()

    def test_default_cli_preflight_never_execute(self):
        p = plan_for(Path("/synthetic-root"))
        with patch.object(W.sys, "argv", ["worker", "--plan", "/synthetic-plan"]), \
             patch.object(W, "read_json", return_value=p), \
             patch.object(W, "preflight", return_value={}) as preflight, \
             patch.object(W, "input_permissions", return_value=[]), \
             patch.object(W, "sha_file", return_value="a"*64), \
             patch.object(W, "execute") as execute, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(W.main(), 0)
            preflight.assert_called_once_with(p)
            execute.assert_not_called()
            self.assertEqual(json.loads(out.getvalue())["status"], "preflight-passed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    args, rest = parser.parse_known_args()
    BASELINE = args.baseline
    spec = importlib.util.spec_from_file_location("reviewed_startup_worker", args.worker)
    W = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(W)
    unittest.main(argv=[__file__, *rest])
