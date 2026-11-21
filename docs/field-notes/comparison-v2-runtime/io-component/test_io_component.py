"""Synthetic I/O v2 tests. No SSH, live counters, services, or long sleeps."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, filename):
    module = types.ModuleType(name)
    module.__file__ = str(HERE / filename)
    exec(compile((HERE / filename).read_bytes(), module.__file__, "exec"), module.__dict__)
    return module


L = load("io_lifecycle_v2_test", "supplemental-io-lifecycle-v2.py")
S = load("io_sampler_v2_test", "supplemental-io-sampler-v2.py")


class Clock:
    def __init__(self):
        self.now = 0.0
    def monotonic(self):
        return self.now
    def monotonic_ns(self):
        return int(self.now * 1e9)
    def sleep(self, seconds):
        self.now += max(.0001, seconds)


class NoThread:
    def __init__(self, **kwargs): pass
    def start(self): pass
    def join(self, **kwargs): pass
    def is_alive(self): return False


class Fixture:
    def __init__(self, root):
        self.root = root
        self.out = root / "capture"
        self.out.mkdir()
        self.plan_path = root / "plan.json"
        transport = {}
        for name, basename in (("wrapper", "windows-io-job.ps1"), ("helper", "WindowsIoJobV2.cs"),
                               ("ssh", "ssh.exe"), ("powershell", "powershell.exe")):
            p = root / basename
            p.write_bytes((HERE / basename).read_bytes() if (HERE / basename).exists() else b"synthetic-only")
            transport[name] = {"path": str(p), "sha256": L.sha(p), "windows_path": self.win(p)}
        sampler = root / "sampler.py"
        sampler.write_bytes((HERE / "supplemental-io-sampler-v2.py").read_bytes())
        self.plan = {"artifact": "aotg-supplemental-io-capture-plan", "version": 2,
            "status": "PROPOSED_UNAPPROVED_NOT_EXECUTED", "nonce": "0123456789abcdef",
            "run_id": "evo-comparison-0123456789abcdef", "authorization_sha256": "a" * 64,
            "client_plan_sha256": "b" * 64, "worker_plan_sha256": "c" * 64,
            "output_root": str(self.out), "windows_output_root": self.win(self.out),
            "sampler": {"path": str(sampler), "sha256": L.sha(sampler)}, "transport": transport,
            "limits": copy.deepcopy(L.LIMITS), "coverage_gate_max_gap_seconds": 2.5,
            "remote_file_created": False, "coverage_claimed": False,
            "ssh_argv": ["-T", "-o", "BatchMode=yes", "-o", "ForwardAgent=no", "-o",
                         "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "fixture.invalid"],
            "windows_job_plan": self.win(self.out) + "\\ssh-plan.json"}
        self.client = {"artifact": "aotg-k8-field-plan", "version": 2, "run_id": self.plan["run_id"],
                       "maintenance_nonce": self.plan["nonce"], "worker_plan_sha256": self.plan["worker_plan_sha256"],
                       "max_seconds": 5400, "cleanup_reserve_seconds": 60,
                       "ssh": [transport["ssh"]["path"]] + self.plan["ssh_argv"],
                       "windows_transport": {"ssh": transport["ssh"], "powershell": transport["powershell"]}}
        self.client_path = root / "client.json"
        self.client_path.write_text(json.dumps(self.client))
        self.plan["client_plan"] = {"path": str(self.client_path), "sha256": L.sha(self.client_path)}
        self.plan["client_plan_sha256"] = L.digest(self.client)
        self.plan["capture_binding_sha256"] = L.capture_binding(self.plan)
        self.job = {"artifact": "aotg-windows-io-job", "version": 2,
            "wrapper_sha256": transport["wrapper"]["sha256"],
            "helper": {"path": transport["helper"]["windows_path"], "sha256": transport["helper"]["sha256"]},
            "executable": {"path": transport["ssh"]["windows_path"], "sha256": transport["ssh"]["sha256"]},
            "cwd": self.win(self.out), "wall_seconds": L.JOB_SECONDS,
            "cancel_path": self.win(self.out) + "\\cancel", "result_path": self.win(self.out) + "\\job-result.json",
            "argv": self.plan["ssh_argv"] + ["/usr/bin/python3.14", "-I", "-S", "-B", "-", "--sample",
                    "--seconds", str(L.SAMPLER_SECONDS), "--run-id", self.plan["run_id"],
                    "--capture-binding-sha256", self.plan["capture_binding_sha256"]]}
        self.write()

    def win(self, path):
        return "C:\\fixture\\" + str(Path(path).relative_to(self.root)).replace("/", "\\")

    def write(self):
        jp = self.out / "ssh-plan.json"
        jp.write_text(json.dumps(self.job))
        self.plan["job_plan"] = {"path": str(jp), "sha256": L.sha(jp)}
        self.plan_path.write_text(json.dumps(self.plan))
        self.plan_sha = L.sha(self.plan_path)

    def capture(self):
        with patch.object(L, "windows_path", self.win):
            return L.Capture(self.plan_path, self.plan_sha)

    def rows(self, foreign=False):
        assoc = {"run_id": self.plan["run_id"],
                 "capture_binding_sha256": "0" * 64 if foreign else self.plan["capture_binding_sha256"]}
        meta = {**S.plan(L.SAMPLER_SECONDS), **assoc, "sample_requested": True}
        first = {**assoc, "artifact": "aotg-supplemental-io-sample", "version": 1,
                 "index": 0, "observed_baseline": True, "monotonic_read_start_ns": 1,
                 "monotonic_read_end_ns": 2, "utc_read_start": "2026-11-16T00:00:00+00:00",
                 "utc_read_end": "2026-11-16T00:00:00.000001+00:00"}
        final = {**assoc, "artifact": "aotg-supplemental-io-final", "version": 1,
                 "complete_to_configured_deadline": True, "reason": "deadline"}
        return [meta, first, final]

    def receipt(self, *, clean=True, timeout=False, cancelled=False):
        return {"artifact": "aotg-windows-io-job-result", "version": 2,
            "plan_sha256": self.plan["job_plan"]["sha256"],
            "wrapper_sha256": self.plan["transport"]["wrapper"]["sha256"],
            "helper_sha256": self.plan["transport"]["helper"]["sha256"],
            "result": {"ProcessId": 9876, "ExecutableSha256": self.plan["transport"]["ssh"]["sha256"],
                       "ExitCode": 0, "TimedOut": timeout, "Cancelled": cancelled,
                       "JobEmpty": clean, "CleanupScope": "windows-job-object", "Seconds": 1.0}}

    def spawn(self, capture, *, records=True, foreign=False, timeout=False, clean=True):
        fixture = self
        class Process:
            pid = 4567
            returncode = None
            waits = []
            def poll(self): return self.returncode
            def wait(self, timeout=None):
                self.waits.append(timeout)
                if timeout is not None and timeout > L.CLEANUP_SECONDS and timeout_mode:
                    raise L.subprocess.TimeoutExpired("synthetic", timeout)
                self.returncode = 124 if (fixture.out / "cancel").exists() else 0
                receipt = fixture.receipt(clean=clean, timeout=timeout_mode,
                                          cancelled=(fixture.out / "cancel").exists())
                (fixture.out / "job-result.json").write_text(json.dumps(receipt))
                return self.returncode
        timeout_mode = timeout
        proc = Process()
        def popen(command, **kwargs):
            assert command[0] == fixture.plan["transport"]["powershell"]["path"]
            assert kwargs["close_fds"] is True
            if records:
                kwargs["stdout"].write(b"".join((json.dumps(r) + "\n").encode() for r in fixture.rows(foreign)))
                kwargs["stdout"].flush()
            return proc
        return proc, popen


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(Path(self.tmp.name))

    def test_preview_is_read_only_and_unapproved(self):
        before = {p.name for p in self.f.out.iterdir()}
        with patch.object(L.subprocess, "Popen", side_effect=AssertionError("No subprocess")):
            c = self.f.capture()
            result = c.preview()
        self.assertEqual(result["status"], "UNAPPROVED")
        self.assertFalse(result["execute"])
        self.assertEqual(before, {p.name for p in self.f.out.iterdir()})

    def test_legacy_or_budget_or_binding_rejected(self):
        original = copy.deepcopy(self.f.plan)
        for mutate in (lambda p: p.update(version=1),
                       lambda p: p["limits"].update(sampler_seconds=2080),
                       lambda p: p.update(capture_binding_sha256="0" * 64),
                       lambda p: p.update(extra="unknown")):
            self.f.plan = copy.deepcopy(original)
            mutate(self.f.plan)
            self.f.write()
            with self.assertRaises(RuntimeError): self.f.capture()

    def test_source_drift_rejected(self):
        Path(self.f.plan["sampler"]["path"]).write_text("changed")
        with self.assertRaises(RuntimeError): self.f.capture()

    def test_legacy_job_rejected(self):
        self.f.job.update(artifact="aotg-windows-ssh-job", version=1, wall_seconds=2100)
        self.f.write()
        with self.assertRaises(RuntimeError): self.f.capture()

    def test_ssh_invocation_drift_rejected(self):
        self.f.job["argv"][-1] = "d" * 64
        self.f.write()
        with self.assertRaises(RuntimeError): self.f.capture()

    def test_route_change_even_with_rebound_job_is_rejected(self):
        self.f.plan["ssh_argv"][-1] = "different.invalid"
        self.f.job["argv"][len(self.f.plan["ssh_argv"])-1] = "different.invalid"
        self.f.write()
        with self.assertRaisesRegex(RuntimeError, "SSH argv differs"):
            self.f.capture()

    def test_client_raw_and_canonical_identity_both_required(self):
        self.f.client_path.write_text(json.dumps(self.f.client, indent=2))
        with self.assertRaises(RuntimeError): self.f.capture()
        self.f.plan["client_plan"]["sha256"] = L.sha(self.f.client_path)
        self.f.plan["client_plan_sha256"] = "0" * 64
        self.f.plan["capture_binding_sha256"] = L.capture_binding(self.f.plan)
        self.f.write()
        with self.assertRaisesRegex(RuntimeError, "canonical v2 client"):
            self.f.capture()

    def test_unused_root_required(self):
        (self.f.out / "unexpected").touch()
        with self.assertRaises(RuntimeError): self.f.capture()

    def test_explicit_authorization_required(self):
        c = self.f.capture()
        with patch.object(L.subprocess, "Popen", side_effect=AssertionError("No subprocess")):
            with self.assertRaises(RuntimeError): c.start(deadline=999999999)

    def run_capture(self, **options):
        c = self.f.capture()
        proc, popen = self.f.spawn(c, **options)
        clock = Clock()
        with patch.object(L, "time", clock), patch.object(L.subprocess, "Popen", popen), \
             patch.object(L.threading, "Thread", NoThread):
            first = c.start(execution_authorized=True, deadline=5)
            self.assertEqual(first["index"], 0)
            result = c.finish()
        return c, proc, result

    def test_associated_first_sample_and_verified_receipt(self):
        c, proc, r = self.run_capture()
        self.assertTrue(r["owned_windows_job_cleanup_verified"])
        self.assertTrue(r["capture_finished_to_deadline"])
        self.assertFalse(r["remote_process_exit_verified"])
        self.assertFalse(r["coverage_evaluated"])
        self.assertFalse(r["rates_computed"])
        self.assertEqual(r["files"]["job-result.json"], L.sha(self.f.out / "job-result.json"))
        self.assertEqual(r["capture_binding_sha256"], self.f.plan["capture_binding_sha256"])
        with self.assertRaises(RuntimeError): c.finish()

    def test_pinned_snapshot_streamed_when_path_changes_after_repin(self):
        c = self.f.capture()
        expected = c.source_bytes
        original_repin = c._repin
        def race():
            original_repin()
            Path(self.f.plan["sampler"]["path"]).write_text("changed after repin; never execute")
        proc, fake_popen = self.f.spawn(c)
        def inspect_popen(command, **kwargs):
            actual = kwargs["stdin"].read()
            self.assertEqual(actual, expected)
            self.assertEqual(hashlib.sha256(actual).hexdigest(), self.f.plan["sampler"]["sha256"])
            kwargs["stdin"].seek(0)
            return fake_popen(command, **kwargs)
        with patch.object(c, "_repin", race), patch.object(L, "time", Clock()), \
             patch.object(L.subprocess, "Popen", inspect_popen), patch.object(L.threading, "Thread", NoThread):
            c.start(execution_authorized=True, deadline=5)
            result = c.finish()
        self.assertTrue(result["owned_windows_job_cleanup_verified"])

    def test_timeout_cancels_and_does_not_claim_deadline_complete(self):
        c, proc, r = self.run_capture(timeout=True)
        self.assertTrue((self.f.out / "cancel").exists())
        self.assertTrue(r["owned_windows_job_cleanup_verified"])
        self.assertFalse(r["capture_finished_to_deadline"])
        self.assertIn("natural-job-deadline-unverified", r["errors"])
        self.assertLessEqual(proc.waits[-1], 10)

    def test_cancel_after_already_exited_job_cannot_claim_complete(self):
        c = self.f.capture()
        proc, popen = self.f.spawn(c)
        with patch.object(L, "time", Clock()), patch.object(L.subprocess, "Popen", popen), \
             patch.object(L.threading, "Thread", NoThread):
            c.start(execution_authorized=True, deadline=5)
            proc.wait(timeout=1)  # Synthetic successful process already ended.
            r = c.finish(cancel=True)
        self.assertTrue(r["owned_windows_job_cleanup_verified"])
        self.assertTrue(r["cancel_requested"])
        self.assertEqual(r["wrapper_returncode"], 0)
        self.assertFalse(r["capture_finished_to_deadline"])

    def test_output_inventory_failure_invalidates_completion(self):
        c = self.f.capture()
        proc, popen = self.f.spawn(c)
        original_sha = L.sha
        def fail_output(path, **kwargs):
            if Path(path).name == "launch.json":
                raise RuntimeError("synthetic changed output during inventory")
            return original_sha(path, **kwargs)
        with patch.object(L, "time", Clock()), patch.object(L.subprocess, "Popen", popen), \
             patch.object(L.threading, "Thread", NoThread):
            c.start(execution_authorized=True, deadline=5)
            with patch.object(L, "sha", side_effect=fail_output):
                r = c.finish()
        self.assertTrue(r["owned_windows_job_cleanup_verified"])
        self.assertIn("output-hash-failed-launch.json", r["errors"])
        self.assertFalse(r["capture_finished_to_deadline"])

    def test_job_not_empty_rejected(self):
        _, _, r = self.run_capture(clean=False)
        self.assertFalse(r["owned_windows_job_cleanup_verified"])
        self.assertFalse(r["capture_finished_to_deadline"])

    def test_missing_first_sample_cancels_within_five_fake_seconds(self):
        c = self.f.capture()
        proc, popen = self.f.spawn(c, records=False)
        clock = Clock()
        with patch.object(L, "time", clock), patch.object(L.subprocess, "Popen", popen), \
             patch.object(L.threading, "Thread", NoThread):
            with self.assertRaises(TimeoutError): c.start(execution_authorized=True, deadline=5)
        self.assertLess(clock.now, 5.01)
        self.assertTrue(c.finished)
        self.assertTrue((self.f.out / "cancel").exists())

    def test_foreign_first_sample_is_not_published(self):
        c = self.f.capture()
        proc, popen = self.f.spawn(c, foreign=True)
        with patch.object(L, "time", Clock()), patch.object(L.subprocess, "Popen", popen), \
             patch.object(L.threading, "Thread", NoThread):
            with self.assertRaises(RuntimeError): c.start(execution_authorized=True, deadline=5)
        self.assertFalse((self.f.out / "first-sample.json").exists())
        self.assertTrue((self.f.out / "cancel").exists())

    def test_output_monitor_requests_only_owned_cancel(self):
        c = self.f.capture()
        for name in ("samples.jsonl", "stderr.log"): (self.f.out / name).touch()
        with (self.f.out / "stderr.log").open("wb") as out: out.truncate(262145)
        c.process = types.SimpleNamespace(poll=lambda: None)
        c.monitor_stop = types.SimpleNamespace(wait=lambda _: False)
        c._monitor_output()
        self.assertEqual((self.f.out / "cancel").read_bytes(), b"")
        self.assertTrue(c.monitor_errors)


class SamplerTests(unittest.TestCase):
    def test_duration_cap_and_exact_budget_math(self):
        self.assertEqual(S.duration("6255"), 6255)
        for value in ("6256", "0", "1.5", True, "-1"):
            with self.assertRaises(S.argparse.ArgumentTypeError): S.duration(value)
        self.assertEqual(sum(L.LIMITS[k] for k in (
            "prearm_ready_seconds", "work_seconds", "worker_wait_grace_seconds",
            "recovery_seconds", "recovery_request_grace_seconds", "result_collection_seconds",
            "local_cleanup_seconds")), L.SAMPLER_SECONDS)
        self.assertEqual(L.JOB_SECONDS-L.SAMPLER_SECONDS, 20)

    def test_parser_and_counter_reset_are_explicit(self):
        block = S.parse_block(" ".join(map(str, range(17))))
        self.assertEqual(block["read_sectors_512b"], 2)
        with self.assertRaises(ValueError): S.parse_block("1 2")
        a = {"block": {"read_sectors_512b": 4}, "io_pressure": {}, "cpu": {"ticks": {"iowait": 2}}}
        b = {"block": {"read_sectors_512b": 3}, "io_pressure": {}, "cpu": {"ticks": {"iowait": 1}}}
        decreases = S.decreases(a, b)
        self.assertEqual(len(decreases), 2)
        self.assertEqual(decreases[1]["cause"], "iowait_can_decrease_without_reset")

    def sample(self, bad=False):
        clock, rows = Clock(), []
        calls = [0]
        def read(path):
            if path == S.BLOCK:
                calls[0] += 1
                if bad and calls[0] > 1: raise ValueError("synthetic missing block data")
                return " ".join(["0"] * 17)
            if path == S.PRESSURE: return "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0"
            return "cpu " + " ".join(["0"] * 10) + "\nbtime 1\n"
        with patch.object(S, "time", clock), patch.object(S, "read_kernel_text", read), \
             patch.object(S, "device_identity", return_value={"device": "synthetic"}), \
             patch.object(S, "emit", side_effect=lambda row, *a, **kw: rows.append(copy.deepcopy(row))), \
             patch.object(S.signal, "signal", return_value=None), \
             patch.object(S.os, "get_blocking", return_value=True), patch.object(S.os, "set_blocking"), \
             patch.object(S.os, "sysconf", return_value=100):
            result = S.sample(2, "evo-test-0123456789abcdef", "a" * 64)
        return result, rows, clock.now

    def test_finite_simulated_sampling_preserves_association(self):
        code, rows, elapsed = self.sample()
        self.assertEqual(code, 0)
        self.assertLessEqual(elapsed, 2)
        self.assertEqual([r["index"] for r in rows if r["artifact"].endswith("-sample")], [0, 1])
        self.assertTrue(rows[-1]["complete_to_configured_deadline"])
        self.assertTrue(all(r["capture_binding_sha256"] == "a" * 64 for r in rows))

    def test_missing_counter_does_not_claim_complete(self):
        code, rows, _ = self.sample(bad=True)
        self.assertEqual(code, 2)
        self.assertFalse(rows[-1]["complete_to_configured_deadline"])

    def test_output_bound_fails_before_write(self):
        with patch.object(S.os, "write", side_effect=AssertionError("No write")):
            with self.assertRaises(ValueError): S.emit({"x": "y" * 9000}, 9999)
            with self.assertRaises(ValueError): S.emit({"x": 1}, 9999, output_state=[S.MAX_OUTPUT_BYTES])

    def test_wrapper_and_native_job_delta_is_only_version_cap_class(self):
        baseline = json.loads((HERE / "baseline-inputs.json").read_text())
        self.assertEqual(baseline["WindowsStdioJob.cs"], "96a7c34338ff7001282223589bad8dbe736bd15005db98a40d83ccb85c25a69a")
        native = (HERE / "WindowsIoJobV2.cs").read_text()
        restored = native.replace("AotgWindowsIoJobV2", "AotgWindowsStdioJob").replace(
            "timeoutMilliseconds > 6275000", "timeoutMilliseconds > 2100000")
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), baseline["WindowsStdioJob.cs"])
        wrapper = (HERE / "windows-io-job.ps1").read_text()
        restored = wrapper.replace("aotg-windows-io-job", "aotg-windows-ssh-job").replace(
            "$frozen.version -ne 2", "$frozen.version -ne 1").replace("version=2;", "version=1;").replace(
            "$frozen.wall_seconds -isnot [int] -or $frozen.wall_seconds -ne 6275",
            "$frozen.wall_seconds -lt 1 -or $frozen.wall_seconds -gt 2100").replace(
            "AotgWindowsIoJobV2", "AotgWindowsStdioJob")
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), baseline["windows-ssh-job.ps1"])


if __name__ == "__main__":
    unittest.main()
