"""Synthetic adapter fixtures only: NO models, native execution, SSH or service calls.

All successful reports below are explicitly manufactured test data, never actual
assessment evidence. Temporary files are removed after each test.
"""
import base64
import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
import zlib
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("assemble", REPO / "tools/assemble_field_evidence.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
CASE = "cpp-half-open-interval"


class Fixture:
    def __init__(self, root):
        self.root = root
        self.k, self.e, self.t = (root / name for name in ("k8", "evo", "trusted"))
        for path in (self.k, self.e, self.t):
            path.mkdir()
        self.epoch = datetime(2026, 11, 15, 12, tzinfo=timezone.utc)
        self.catalog = json.loads((REPO / "tests/fixtures/benchmark/catalog.json").read_text())
        self.catalog_d = self.write("catalog.json", self.catalog)
        modules = {"aotg/" + name + ".py": a.sha((REPO / "aotg" / (name + ".py")).read_bytes())
                   for name in ("__init__", "artifacts", "field_evidence", "field_client", "quality", "field_sandbox", "field_selftest", "field_proxy")}
        self.guide = (REPO / "tests/fixtures/assessment/native-driver.md").read_bytes()
        self.driver = re.findall(r"```python\n(.*?)\n```", self.guide.decode().replace("\r\n", "\n"), re.S)[0] + "\n"
        self.base_config = {"user_args": ["--prefill", "512"], "args": ["--expert-profile", "/fixture/profile"],
                            "args_written": ["--expert-profile", "/fixture/profile"]}
        base_d = self.write("base-config.json", self.base_config)
        self.identity = {"aotg_modules": modules, "engine": {"sha256": a.sha(b"SYNTHETIC engine")},
                         "active_config_sha256": base_d["sha256"],
                         "measurement_transport": {"k8_runner_sha256": a.sha(b"SYNTHETIC runner")},
                         "worker_sha256": a.sha(b"SYNTHETIC worker"), "opencode": {"sha256": a.sha(b"SYNTHETIC client")},
                         "profile_sha256": a.sha(b"SYNTHETIC provider")}
        self.api = a.load_libraries(a.Reader(), REPO, self.identity)
        self.public = {"PublicTests.cpp": b"SYNTHETIC public test", "verify.sh": b"SYNTHETIC verify"}
        self.source = b"bool overlaps(int a,int b,int c,int d){return a<b && c<d && a<d && c<b;}\n"
        workload = {"id": CASE, "source": {"name": "intervals.cpp", "path": "/fixture/input/intervals.cpp", "sha256": a.sha(b"starter")},
                    "prompt": {"path": "/fixture/input/prompt.txt", "sha256": a.sha(b"public contract")},
                    "public_files": [{"name": n, "path": "/fixture/input/" + n, "sha256": a.sha(v)} for n, v in self.public.items()]}
        self.profiles = [{"id": n, "profile_sha256": a.sha(n.encode()), "prefill": p}
                         for n, p in (("baseline", 512), ("prefill256", 256), ("prefill1024", 1024))]
        self.field = self.api.evidence.freeze_plan(metric_gates={}, identity_sha256=a.digest(self.identity), verifier_sha256=modules["aotg/quality.py"],
                   candidates=[{k: p[k] for k in ("id", "profile_sha256")} for p in self.profiles],
                   workloads=[{"id": CASE, "input_sha256": a.digest(workload), "tests_sha256": self.catalog_d["sha256"],
                               "cache_cohort": "fresh-engine-fixed-short-primer"}],
                   limits={"trial_seconds": 180, "total_seconds": 2040, "max_temperature_c": 80,
                           "min_mem_available_bytes": 48 * 1024**3, "max_swapout_bytes": 0})
        self.failure_index = next(row["index"] for row in self.field["schedule"] if row["candidate_id"] == "prefill1024")
        self.field_d = self.write("field.json", self.field)
        self.worker = {"run_id": "synthetic-fixture-only", "task_root": "/fixture/evo/work", "schedule": self.field["schedule"], "field_plan": self.field_d,
                       "profiles": self.profiles, "engine": self.identity["engine"],
                       "active_config": {"sha256": self.identity["active_config_sha256"]},
                       "gpu": {"bdf": "fixture-gpu"}, "required_alarm_keys": ["nvme-alarm"],
                       "telemetry": {"sha256": a.sha(b"SYNTHETIC telemetry")}, "kernel_since": "2026-11-15 12:00:00 UTC"}
        self.worker_d = self.write("worker.json", self.worker)
        transport = {n: {"windows_path": "C:\\fixture\\" + n, "sha256": a.sha(n.encode())} for n in ("ssh", "helper", "wrapper")}
        transport.update(linux_root="/fixture/jobs", windows_root="C:\\fixture\\jobs")
        self.client = {"run_id": self.worker["run_id"], "schedule": self.field["schedule"], "worker_plan_sha256": self.worker_d["sha256"],
                       "runner_sha256": self.identity["measurement_transport"]["k8_runner_sha256"], "workloads": {CASE: workload},
                       "proxy_capture_version": 2, "output_root": str(self.k), "task_seconds": 130, "max_steps": 8, "max_requests": 9,
                       "namespace_tools": {"python": "/usr/bin/python3.12"},
                       "windows_transport": transport, "ssh": ["/fixture/ssh", "-T", "fixture-host"]}
        self.client_d = self.write("client.json", self.client)
        self.authority = {"artifact": "aotg-independent-assessment-authority", "version": 1,
                          "run_id": self.worker["run_id"], "field_plan_sha256": a.digest(self.field),
                          "client_plan_sha256": a.digest(self.client), "worker_plan_sha256": self.worker_d["sha256"],
                          "reviewer": "synthetic-fixture-reviewer", "arms": {}, "toolchains": {}, "complete_job_inventory": True,
                          "worker_source_sha256": self.identity["worker_sha256"], "client_source_sha256": self.client["runner_sha256"],
                          "execution_record": self.trusted("execution.txt", b"SYNTHETIC fixture; no run occurred"), "jobs": []}
        self.spec = {"artifact": "aotg-field-assessment-inputs", "version": 2, "source_root": str(REPO),
                     "field_plan": self.field_d, "client_plan": self.client_d, "worker_plan": self.worker_d,
                     "identity": self.write("identity.json", self.identity), "catalog": self.catalog_d,
                     "baseline_config": base_d,
                     "client_runner": self.write("runner.py", b"SYNTHETIC runner"),
                     "assessment_guide": self.write("guide.md", self.guide),
                     "assessment_policy": self.write("policy.json", {"artifact": "aotg-supplemental-assessment-policy", "version": 1,
                         "field_plan_sha256": a.digest(self.field), "resource_max_gap_seconds": 2.0,
                         "io_max_gap_seconds": 2.5, "window": "evo_ready_through_finished_conservative"}),
                     "k8_root": str(self.k), "evo_root": str(self.e), "trusted_root": str(self.t)}
        self.kr, self.er = [], []
        for row in self.field["schedule"]:
            self.arm(row)
        self.end = len(self.field["schedule"]) * 2 + 4
        self.esummary = {"artifact": "aotg-evo-worker-result", "version": 1, "run_id": self.worker["run_id"],
                         "plan_sha256": self.worker_d["sha256"], "status": a.COMPLETE, "arms": self.er,
                         "started_at": self.utc(0), "finished_at": self.utc(self.end), "wall_seconds": self.end}
        self.ksummary = {"artifact": "aotg-k8-field-run", "version": 1, "plan_sha256": a.digest(self.client),
                         "status": a.COMPLETE, "arms": self.kr, "cleanup_errors": [], "total_deadline_exceeded": False}
        self.refresh_summaries()
        self.samples = [self.sample(i / 5) for i in range(self.end * 5 + 1)]
        self.write_samples()
        kernel = {"status": "clear", "errors": [], "since": self.worker["kernel_since"], "scanned_at": self.utc(self.end - 1),
                  "output_sha256": a.sha(b"synthetic kernel clear")}
        self.put(self.e / "kernel-final.json", kernel)
        self.authority["kernel_review"] = {"record": self.trusted("kernel-review.txt", b"SYNTHETIC kernel check"),
                    "scan_sha256": a.sha((self.e / "kernel-final.json").read_bytes()), "worker_sha256": self.identity["worker_sha256"],
                    "telemetry_sha256": self.worker["telemetry"]["sha256"], "coverage_accepted": True}
        job = {"artifact": "aotg-windows-ssh-job", "version": 1, "wrapper_sha256": transport["wrapper"]["sha256"],
               "helper": {"path": transport["helper"]["windows_path"], "sha256": transport["helper"]["sha256"]},
               "executable": {"path": transport["ssh"]["windows_path"], "sha256": transport["ssh"]["sha256"]},
               "argv": [*self.client["ssh"][1:], "python3 -B -"], "wall_seconds": 10}
        job_d = self.trusted("0" * 24 + ".plan.json", job)
        receipt = {"artifact": "aotg-windows-ssh-job-result", "version": 1, "plan_sha256": job_d["sha256"],
                   "helper_sha256": transport["helper"]["sha256"], "wrapper_sha256": transport["wrapper"]["sha256"],
                   "result": {"JobEmpty": True, "ExecutableSha256": transport["ssh"]["sha256"], "TimedOut": False,
                              "ExitCode": 0, "Cancelled": False}}
        self.authority["jobs"] = [{"plan": job_d, "receipt": self.trusted("0" * 24 + ".result.json", receipt)}]
        relay = {**job, "argv": [*self.client["ssh"][1:-1], "-W", "127.0.0.1:19480", self.client["ssh"][-1]]}
        relay_d = self.trusted("1" * 24 + ".plan.json", relay)
        self.authority["jobs"].append({"plan": relay_d,
                     "receipt": self.trusted("1" * 24 + ".result.json", {**receipt, "plan_sha256": relay_d["sha256"]})})
        before = {"artifact": "aotg-owned-job-snapshot", "version": 1, "phase": "before-launch",
                  "run_id": self.client["run_id"], "client_plan_sha256": a.digest(self.client),
                  "jobs_root": transport["linux_root"], "observed_utc": self.utc(-1), "files": []}
        after = {**before, "phase": "after-exit", "observed_utc": self.utc(self.end + 2),
                 "files": [{"name": Path(d["path"]).name, "sha256": d["sha256"]} for j in self.authority["jobs"] for d in j.values()]}
        launch = {"artifact": "aotg-field-client-launch", "version": 1, "run_id": self.client["run_id"],
                  "client_plan_sha256": a.digest(self.client), "pid": 123, "pid_start_ticks": "12345", "observed_utc": self.utc(0),
                  "runner_sha256": self.client["runner_sha256"], "argv": ["/usr/bin/python3.12", "-I", "-B", self.spec["client_runner"]["path"],
                          "--plan", self.client_d["path"], "--execute-approved-plan-sha256", a.digest(self.client)]}
        completion = {"artifact": "aotg-field-client-exit", "version": 1, "run_id": self.client["run_id"],
                  "client_plan_sha256": a.digest(self.client), "pid": 123, "pid_start_ticks": "12345", "observed_utc": self.utc(self.end + 1),
                  "exit_code": 0, "summary_sha256": self.authority["client_summary_sha256"]}
        self.authority["job_inventory"] = {"before": self.trusted("jobs-before.json", before), "after": self.trusted("jobs-after.json", after),
               "launch": self.trusted("launch.json", launch), "completion": self.trusted("exit.json", completion)}
        self.authority["capture_association_record"] = self.trusted("capture.txt", b"SYNTHETIC capture association; no run occurred")
        self.refresh_capture()

    def utc(self, seconds):
        return (self.epoch + timedelta(seconds=seconds)).isoformat()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, bytes) else a.canonical(value) + b"\n"
        path.write_bytes(raw)
        return {"path": str(path), "sha256": a.sha(raw)}

    def write(self, name, value):
        return self.put(self.root / name, value)

    def trusted(self, name, value):
        return self.put(self.t / name, value)

    def refresh_summaries(self):
        self.authority["worker_summary_sha256"] = self.put(self.e / "summary.json", self.esummary)["sha256"]
        self.authority["client_summary_sha256"] = self.put(self.k / "summary.json", self.ksummary)["sha256"]

    def write_samples(self):
        self.put(self.e / "resources.jsonl", b"".join(a.canonical(row) + b"\n" for row in self.samples))

    def refresh_capture(self):
        self.authority["captured_files"] = [{"path": str(p), "sha256": a.sha(p.read_bytes())}
            for root in (self.k, self.e) for p in sorted(root.rglob("*")) if p.is_file()]

    def sample(self, elapsed):
        return {"utc": self.utc(elapsed), "elapsed_seconds": elapsed, "selected_gpu_bdf": "fixture-gpu",
                "temperatures_c": {"amdgpu:edge": 50, "nvme:Composite": 40, "nvme:Sensor 2": 45},
                "per_gpu_temperatures_c": {"fixture-gpu": {"edge": 50}}, "host_mem_available_bytes": 64 * 1024**3,
                "pswpout": 100, "alarms": {"nvme-alarm": 0}, "gpu": {"mem_info_vram_total": 64 * 1024**3,
                   "mem_info_vram_used": 48 * 1024**3, "mem_info_gtt_used": 1024},
                "swap_bytes": {"SwapTotal": 1024**3, "SwapFree": 1024**3}, "disk_free_bytes": 200 * 1024**3,
                "thermal_paused": False}

    def arm(self, row):
        i = row["index"]
        ka, ea = self.k / ("arm-%02d" % i), self.e / ("arm-%03d" % i)
        profile = next(p for p in self.profiles if p["id"] == row["candidate_id"])
        ready = {"artifact": "aotg-field-ready", "version": 1, "run_id": self.worker["run_id"],
                 "plan_sha256": self.worker_d["sha256"], **row, "profile_sha256": profile["profile_sha256"],
                 "prefill": profile["prefill"], "ready_at": self.utc(i * 2 + .2)}
        self.put(ka / "ready.json", ready)
        self.put(ea / "ready.json", ready)
        source_sha = a.sha(self.source)
        source_d = self.trusted(f"arm-{i}/source.cpp", self.source)
        review = {"artifact": "aotg-source-review", "version": 1, "source_sha256": source_sha,
                  "grader_sha256": self.field["verifier_sha256"], "catalog_sha256": self.catalog_d["sha256"],
                  "independent": True, "reviewer": self.authority["reviewer"], "verdict": "accepted", "evidence_reference": "fixture-only"}
        review_d = self.trusted(f"arm-{i}/source-review.json", review)
        phase = {"status": "ok", "exit_code": 0, "seconds": .01, "stdout": "", "stderr": "", "output_truncated": False}
        isolated = {"artifact": "aotg-offline-isolation", "version": 1, "status": "ok", "exit_code": 0,
                    "isolation_verified": True, "readonly_workspace": True, "output_truncated": False,
                    "dotnet_gc_heap_limit_bytes": 512 * a.MIB, "network": "new-offline-namespace",
                    "limits": {"cpu_seconds": 60, "file_bytes": 64 * a.MIB, "descriptors": 128,
                               "processes": 128, "memory_bytes": 8 * 1024**3}}
        toolchain = {"compiler_kind": "g++", "compiler_sha256": a.sha(b"synthetic compiler"), "runtime_sha256": None,
                     "runtime_arguments": [], "dotnet_inputs": None, "os_shared_libraries_pinned": False}
        self.authority["toolchains"][CASE] = toolchain
        harness, expected, _ = self.api.quality._harness(next(c for c in self.catalog["cases"] if c["id"] == CASE))
        stdout = "".join(f"AOTG:{j}:{str(value).lower()}\n" for j, value in enumerate(expected))
        quality = {"artifact": "aotg-independent-quality", "version": 2, "case_id": CASE,
                   **{k: review[k] for k in ("source_sha256", "grader_sha256", "catalog_sha256")},
                   "harness_sha256": a.sha(harness.encode()), "status": "pass", "behavioral_status": "pass", "quality_accepted": True,
                   "source_review": {"status": "accepted", "receipt": review, "receipt_sha256": a.digest(review)},
                   "toolchain": toolchain, "compile": phase, "execution": {**phase, "stdout": stdout},
                   "grading": self.api.quality.grade_observations(stdout, expected), "isolation": {"evidence_reference": "fixture-isolation"}}
        argv = ["/usr/bin/python3", "-I", "-S", "-B", "-c", self.driver, CASE, "intervals.cpp", "fixture-isolation"]
        isolated.update(command_sha256=a.digest(argv), stdout=base64.b64encode(zlib.compress(a.canonical(quality))).decode())
        public_iso = {**isolated, "limits": {**isolated["limits"], "cpu_seconds": 52}}
        public = {"artifact": "aotg-public-selftest", "version": 1, "status": "pass", "independent": False, "quality_accepted": False,
                  "source_sha256": source_sha, "public_test_sha256": a.sha(self.public["PublicTests.cpp"]),
                  "driver_sha256": self.api.public_driver_sha256, "compile": phase, "execution": phase, "isolation": public_iso}
        output = a.canonical(public).decode()
        events = [{"type": "tool_use", "part": {"tool": "write", "state": {"status": "completed", "input": {"filePath": "intervals.cpp"}}}},
                  {"type": "tool_use", "part": {"tool": "bash", "state": {"status": "completed", "input": {"command": "./verify.sh"},
                    "metadata": {"exit": 0}, "output": output}}},
                  {"type": "text", "part": {"text": "Synthetic final response", "messageID": "fixture"}},
                  {"type": "step_finish", "part": {"reason": "stop", "messageID": "fixture"}}]
        raw_events = b"".join(a.canonical(e) + b"\n" for e in events)
        summary = self.api.client.summarize_events(raw_events, ka / "coding/work", "intervals.cpp", ["intervals.cpp", *self.public])
        coding = {"artifact": "aotg-opencode-work", "version": 1, "workload_id": CASE, "status": a.COMPLETE,
                  "source_sha256_after": source_sha, "source_sha256_before": a.sha(b"starter"), "source_name": "intervals.cpp",
                  "client_sha256": self.identity["opencode"]["sha256"], "profile_sha256": self.identity["profile_sha256"],
                  "prompt_sha256": a.sha(b"public contract"), "public_selftests_unchanged": True,
                  "public_selftest_sha256": {n: a.sha(v) for n, v in self.public.items()}, "private_events_sha256": a.sha(raw_events),
                  "exit_code": 0, "output_truncated": False, "limits": {"seconds": 130, "steps": 8},
                  "seconds": 1 if row["candidate_id"] == "baseline" else .8,
                  "isolation": {"pid_namespace_verified": True, "cleanup_scope": "dedicated-pid-namespace",
                    "namespace": {"protocol": "aotg-pid-namespace-v1", "pid": 1, "no_new_privs": True, "capabilities_dropped": True}}, **summary}
        self.put(ka / "coding/result.json", coding)
        self.put(ka / "coding/private/events.jsonl", raw_events)
        self.put(ka / "coding/private/stderr.log", b"")
        self.put(ka / "coding/work/intervals.cpp", self.source)
        for n, v in self.public.items():
            self.put(ka / "coding/work" / n, v)
        short = {"status": "completed", "content": "42"}
        self.put(ka / "short-answer.json", short)
        requests = [{"kind": "aotg-proxy-request-v1", "index": 0, "status": "completed", "sse_done": True,
                     "fixed_sampling": {"temperature": 0, "top_p": 1, "top_k": 20, "min_p": 0, "seed": 4242,
                          "presence_penalty": 0, "frequency_penalty": 0, "repeat_penalty": 1, "cache_prompt": False, "max_tokens": 1024},
                     "request_sha256": a.sha(b"synthetic request"), "response_sha256": a.sha(b"synthetic response"), "ttft_seconds": .1}]
        requests[0]["event_sequence"] = 1
        requests = [{"kind": "aotg-proxy-capture-v2", "phase": "opened", "event_sequence": 0,
                     "request_limit": self.client["max_requests"], "rejection_record_limit": 128}, *requests,
                    {"kind": "aotg-proxy-capture-v2", "phase": "closed", "event_sequence": 2,
                     "status": "complete", "active_handlers": 0, "record_error": False,
                     "request_records": 1, "rejected_total": 0, "rejections_by_reason": {}, "rejection_events_dropped": 0}]
        self.put(ka / "requests.jsonl", b"".join(a.canonical(r) + b"\n" for r in requests))
        kr = {**row, "status": a.COMPLETE, "client_result_sha256": a.digest(coding), "short_result_sha256": a.digest(short),
              "seconds": coding["seconds"], "requests_complete": True, "requests": requests, "cleanup_errors": []}
        self.kr.append(kr)
        self.put(ka / "result.json", kr)
        self.put(ka / "done-receipt.json", {"written": True})
        self.put(self.e / ("done-%d.json" % i), {**row, "run_id": self.worker["run_id"], "plan_sha256": self.worker_d["sha256"],
                 "evidence_sha256": a.digest(kr), "status": "completed"})
        config = deepcopy(self.base_config)
        config["user_args"][1] = str(profile["prefill"])
        for name in ("args", "args_written"):
            config[name][1] = f"/fixture/evo/work/arm-{i:03d}/expert-profile.bin"
        config.update(log=f"/fixture/evo/work/arm-{i:03d}/logs/engine-private.log", host="127.0.0.1", port=19480, parallel=1, open_browser=False)
        config_d = self.put(ea / "config.json", config)
        self.put(ea / "server-ready.json", {"pid": i + 100, "model_state": "ready", "api_state": "ready", "bound_host": "127.0.0.1", "bound_port": 19480})
        er = {**row, "status": a.COMPLETE, "profile_sha256": profile["profile_sha256"], "prefill": profile["prefill"],
              "native_exe_sha256": self.worker["engine"]["sha256"], "native_pid": i + 200, "server_pid": i + 100,
              "config_sha256": config_d["sha256"], "k8_evidence_sha256": a.digest(kr), "started_at": self.utc(i * 2), "finished_at": self.utc(i * 2 + 1.8)}
        self.er.append(er)
        self.put(ea / "result.json", er)
        self.authority["arms"][str(i)] = {"source_review": review_d,
            "review_record": self.trusted(f"arm-{i}/review.txt", b"SYNTHETIC review; not an actual assessment"), "review_reference": "fixture-only",
            "quality": self.trusted(f"arm-{i}/quality.json", quality), "isolation": self.trusted(f"arm-{i}/isolation.json", isolated),
            "isolation_reference": "fixture-isolation", "replay": {"argv": argv, "source_sha256": source_sha,
                "sandbox_source": self.trusted(f"arm-{i}/field_sandbox.py", (REPO / "aotg/field_sandbox.py").read_bytes()),
                "grader_sha256": self.field["verifier_sha256"], "catalog_sha256": self.catalog_d["sha256"], "source_review_sha256": review_d["sha256"],
                "staged_files": [source_d, review_d, self.trusted(f"arm-{i}/quality.py", (REPO / "aotg/quality.py").read_bytes()),
                                 self.trusted(f"arm-{i}/__init__.py", (REPO / "aotg/__init__.py").read_bytes()),
                                 self.trusted(f"arm-{i}/artifacts.py", (REPO / "aotg/artifacts.py").read_bytes()),
                                 self.trusted(f"arm-{i}/catalog.json", Path(self.catalog_d["path"]).read_bytes())],
                "execution_record": self.trusted(f"arm-{i}/replay.txt", b"SYNTHETIC native replay record")},
            "public_selftest": {"event_index": 1, "json_path": ["part", "state", "output"], "output_sha256": a.sha(output.encode()),
                                "module_sha256": self.identity["aotg_modules"]["aotg/field_selftest.py"],
                                "driver_sha256": public["driver_sha256"]}}

    def rebind_arm(self, index, coding=None, requests=None):
        ka, ea = self.k / ("arm-%02d" % index), self.e / ("arm-%03d" % index)
        kr, er = self.kr[index], self.er[index]
        if coding is not None:
            self.put(ka / "coding/result.json", coding)
            kr.update(client_result_sha256=a.digest(coding), seconds=coding["seconds"], status=coding["status"])
        if requests is not None:
            self.put(ka / "requests.jsonl", b"".join(a.canonical(r) + b"\n" for r in requests))
            kr["requests"] = requests
        self.put(ka / "result.json", kr)
        er["k8_evidence_sha256"] = a.digest(kr)
        self.put(ea / "result.json", er)
        done_path = self.e / ("done-%d.json" % index)
        done = json.loads(done_path.read_text())
        done["evidence_sha256"] = a.digest(kr)
        self.put(done_path, done)
        self.refresh_summaries()
        completion = json.loads(Path(self.authority["job_inventory"]["completion"]["path"]).read_text())
        completion["summary_sha256"] = self.authority["client_summary_sha256"]
        self.authority["job_inventory"]["completion"] = self.trusted("exit.json", completion)
        self.refresh_capture()

    def run(self, authority=True):
        return a.assemble(self.spec, a.Reader(), self.authority if authority else None)


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
    "Offline evidence path validation requires Linux/WSL POSIX directory descriptors",
)
class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aotg-synthetic-assessment-")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name))

    def startup_failure(self):
        f = self.f
        # Exact producer shape: config and stopped result exist; no ready file,
        # native identity, client invocation, source, resources or kernel scan.
        index = 0
        er = f.er[index]
        for key in ("native_exe_sha256", "native_pid", "server_pid", "k8_evidence_sha256"):
            er.pop(key)
        er.update(status="stopped", stop_reason="Strata server exited during load")
        f.esummary.update(status="stopped", stop_reason=er["stop_reason"], arms=[er])
        for root in (f.k, f.e):
            for path in root.rglob("*"):
                if path.is_file():
                    path.unlink()
        profile = f.profiles[0]
        config = a.expected_arm_config(f.base_config, f.worker, f.field["schedule"][index], profile)
        config_d = f.put(f.e / "arm-000/config.json", config)
        er["config_sha256"] = config_d["sha256"]
        f.put(f.e / "arm-000/result.json", er)
        f.authority["worker_summary_sha256"] = f.put(f.e / "summary.json", f.esummary)["sha256"]
        f.refresh_capture()
        return er

    def test_startup_failure_without_source_or_client_is_counted_without_a_trial(self):
        self.startup_failure()
        result = self.f.run()
        self.assertEqual(result["run"]["trials"], [])
        self.assertEqual(result["decision"]["status"], "incomplete")
        self.assertEqual(result["observation_counts"]["verified_runtime_failure"], 1)
        observation = result["observation_decision"]
        self.assertEqual(observation["scheduled_arms"], len(self.f.field["schedule"]))
        self.assertEqual(observation["verified_failure_arms"], 1)
        self.assertEqual(observation["failures"][0]["worker_recorded_reason"], "Strata server exited during load")
        self.assertEqual(observation["failures"][0]["reasons"], ["worker_stopped"])
        self.assertFalse(observation["failures"][0]["normalized"])
        self.assertIsNone(observation["selected_candidate_id"])
        self.assertEqual(observation["comparison_sha256"], a.digest(result["decision"]))
        self.assertNotIn("source_sha256", result["ledger"][0])
        self.assertEqual(self.f.run(authority=False)["observation_counts"]["verified_runtime_failure"], 0)

    def test_startup_failure_duplicate_profile_config_and_hash_conflicts_are_not_verified(self):
        er = self.startup_failure()
        for mode in ("duplicate", "profile", "config", "tamper"):
            with self.subTest(mode=mode):
                original_er, original_summary = deepcopy(er), deepcopy(self.f.esummary)
                if mode == "duplicate":
                    self.f.esummary["arms"].append(deepcopy(er))
                elif mode == "profile":
                    er["profile_sha256"] = "0" * 64
                elif mode == "config":
                    er["config_sha256"] = "0" * 64
                self.f.put(self.f.e / "arm-000/result.json", er)
                self.f.authority["worker_summary_sha256"] = self.f.put(self.f.e / "summary.json", self.f.esummary)["sha256"]
                self.f.refresh_capture()
                if mode == "tamper":
                    self.f.put(self.f.e / "arm-000/result.json", {**er, "stop_reason": "changed after capture"})
                result = self.f.run()
                self.assertEqual(result["observation_counts"]["verified_runtime_failure"], 0)
                self.assertEqual(result["decision"]["status"], "incomplete")
                er.clear()
                er.update(original_er)
                self.f.esummary.clear()
                self.f.esummary.update(original_summary)
                self.f.esummary["arms"] = [er]

    def test_pre_sampling_failed_request_is_known_even_without_source(self):
        index = self.f.failure_index
        requests = deepcopy(self.f.kr[index]["requests"])
        request = requests[1]
        request.pop("fixed_sampling")
        request.update(status="failed", sse_done=False, request_sha256=None, response_sha256=a.sha(b""),
                       response_bytes=0, wall_seconds=.01, error="JSONDecodeError")
        self.f.rebind_arm(index, requests=requests)
        source = self.f.k / ("arm-%02d/coding/work/intervals.cpp" % index)
        source.unlink()
        self.f.refresh_capture()
        result = self.f.run()
        entry = result["ledger"][index]
        self.assertEqual(entry["observation_class"], "verified_runtime_failure")
        self.assertFalse(entry["normalized"])
        self.assertIn("request_failed_before_fixed_sampling", entry["runtime_failures"])
        self.assertEqual(result["observation_decision"]["verified_failure_arms"], 1)
        self.assertEqual(result["decision"]["status"], "incomplete")
        request["status"] = "completed"
        self.f.rebind_arm(index, requests=requests)
        result = self.f.run()
        self.assertEqual(result["observation_counts"]["verified_runtime_failure"], 0)
        self.assertEqual(result["decision"]["status"], "incomplete")

    def test_complete_synthetic_join_uses_real_wall_only(self):
        result = self.f.run()
        self.assertEqual(result["global_errors"], [])
        self.assertTrue(all(not row["missing_or_conflicting"] for row in result["ledger"]), result["ledger"])
        self.assertEqual(result["decision"]["status"], "adopt")
        self.assertEqual(len(result["run"]["trials"]), len(self.f.field["schedule"]))
        self.assertEqual(set(result["run"]["trials"][0]["metrics"]), {"wall_seconds"})
        self.assertFalse(result["goal_complete"])

    def test_missing_source_keeps_ledger_without_dummy_hash(self):
        (self.f.k / "arm-00/coding/work/intervals.cpp").unlink()
        result = self.f.run()
        self.assertFalse(result["ledger"][0]["normalized"])
        self.assertNotIn(0, [row["index"] for row in result["run"]["trials"]])
        self.assertEqual(result["decision"]["status"], "incomplete")

    def test_missing_external_authority_never_accepts_self_asserted_grade(self):
        result = self.f.run(False)
        self.assertEqual(result["decision"]["status"], "incomplete")
        self.assertTrue(all(row["quality"] is None for row in result["run"]["trials"]))

    def test_profile_swap_and_source_drift_are_not_normalized(self):
        self.f.put(self.f.k / "arm-00/ready.json", self.f.e.joinpath("arm-001/ready.json").read_bytes())
        self.f.put(self.f.k / "arm-01/coding/work/intervals.cpp", b"bool overlaps(int,int,int,int){return false;}")
        result = self.f.run()
        self.assertFalse(result["ledger"][0]["normalized"])
        self.assertFalse(result["ledger"][1]["normalized"])

    def test_swap_missing_resource_and_gap_fail_closed(self):
        for mode in ("swap", "missing", "gap"):
            with self.subTest(mode=mode):
                original = deepcopy(self.f.samples)
                if mode == "swap":
                    self.f.samples[5]["pswpout"] += 1
                if mode == "missing":
                    del self.f.samples[5]["host_mem_available_bytes"]
                if mode == "gap":
                    self.f.samples = [row for row in self.f.samples if row["elapsed_seconds"] == 0 or row["elapsed_seconds"] >= 3]
                self.f.write_samples()
                self.f.refresh_capture()
                result = self.f.run()
                self.assertEqual(result["decision"]["status"], "incomplete")
                self.f.samples = original
                self.f.write_samples()
                self.f.refresh_capture()

    def test_review_rejection_even_forged_behavior_pass_never_accepted(self):
        row = self.f.authority["arms"]["0"]
        receipt = json.loads(Path(row["source_review"]["path"]).read_text())
        receipt["verdict"] = "rejected"
        row["source_review"] = self.f.trusted("arm-0/source-review.json", receipt)
        result = self.f.run()
        trial = result["run"]["trials"][0]
        self.assertFalse(trial["quality"]["checks"]["correctness"])
        self.assertNotEqual(trial["status"], "passed")

    def test_spoofed_quality_file_not_matching_outer_stdout_rejected(self):
        row = self.f.authority["arms"]["0"]
        quality = json.loads(Path(row["quality"]["path"]).read_text())
        quality["source_sha256"] = a.sha(b"different source")
        row["quality"] = self.f.trusted("arm-0/quality.json", quality)
        result = self.f.run()
        self.assertIn("outer_stdout_quality_mismatch", str(result["ledger"][0]))
        self.assertNotEqual(result["run"]["trials"][0]["status"], "passed")

    def test_missing_job_receipt_and_frozen_hash_drift(self):
        Path(self.f.authority["jobs"][0]["receipt"]["path"]).unlink()
        self.assertEqual(self.f.run()["decision"]["status"], "incomplete")
        Path(self.f.spec["field_plan"]["path"]).write_bytes(b"{}")
        with self.assertRaisesRegex(a.EvidenceError, "pinned_input_hash_mismatch"):
            self.f.run()

    def test_static_constructor_spoof_requires_actual_accepted_source_review(self):
        bad = b'#include <cstdlib>\nstruct X{X(){std::_Exit(0);}} x; bool overlaps(int,int,int,int){return false;}\n'
        assessment = deepcopy(self.f.authority["arms"]["0"])
        receipt = json.loads(Path(assessment["source_review"]["path"]).read_text())
        receipt.update(source_sha256=a.sha(bad), verdict="rejected")
        assessment["source_review"] = self.f.trusted("spoof-source-review.json", receipt)
        authority = a.Authority(a.Reader(), self.f.authority, self.f.t, (self.f.k, self.f.e))
        accepted, observed_receipt, _ = a.quality_gate(self.f.api, authority, assessment, a.sha(bad), CASE,
                           self.f.field["verifier_sha256"], self.f.catalog_d["sha256"], self.f.catalog,
                           {"driver": self.f.driver, "source_name": "intervals.cpp", "modules": self.f.identity["aotg_modules"]})
        self.assertFalse(accepted)
        self.assertEqual(observed_receipt["verdict"], "rejected")

    def test_native_output_trailing_data_and_symlink_inputs_rejected(self):
        encoded = base64.b64encode(zlib.compress(b'{}') + b'extra').decode()
        with self.assertRaisesRegex(a.EvidenceError, "native_decoded_output_invalid"):
            a.decode_quality(encoded)
        target = self.f.root / "linked-source"
        target.symlink_to(self.f.k / "arm-00/coding/work/intervals.cpp")
        with self.assertRaises(OSError):
            a.Reader().raw(target)

    def test_cli_new_exclusive_output_and_original_evidence_protected(self):
        spec = self.f.write("inputs.json", self.f.spec)
        authority = self.f.trusted("authority.json", self.f.authority)
        output = self.f.root / "assessment.json"
        argv = ["assemble", "--inputs", spec["path"], "--inputs-sha256", spec["sha256"],
                "--authority", authority["path"], "--authority-sha256", authority["sha256"], "--output", str(output)]
        with patch.object(a.sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(a.main(), 0)
            with self.assertRaises(FileExistsError):
                a.main()
        before = output.read_bytes()
        with patch.object(a.sys, "argv", [*argv[:-1], str(self.f.k / "new.json")]), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(a.EvidenceError, "output_must_not_modify_original_evidence"):
                a.main()
        self.assertEqual(output.read_bytes(), before)

    def test_unbound_resources_and_ready_timestamps_rejected(self):
        self.f.samples[5]["host_mem_available_bytes"] += 1
        self.f.write_samples()  # Deliberately do not amend independently pinned inventory.
        result = self.f.run()
        self.assertIn("raw_capture_not_bound_to_independent_inventory", str(result["global_errors"]))
        self.assertNotEqual(result["decision"]["status"], "adopt")

    def test_elapsed_gap_and_trusted_root_ancestor_refused(self):
        samples = [self.f.sample(t) for t in (0, 1, 2)]
        for i, row in enumerate(samples):
            row["elapsed_seconds"] = i * 30
        _, coverage = a.resource_window(samples, a.utc(self.f.utc(.1)), a.utc(self.f.utc(1.9)), self.f.worker)
        self.assertEqual(coverage["max_monotonic_gap_seconds"], 30)
        self.assertEqual(coverage["max_gap_seconds"], 30)
        with self.assertRaisesRegex(a.EvidenceError, "authority_must_be_outside_generated_roots"):
            a.Authority(a.Reader(), {}, self.f.root, (self.f.k, self.f.e))

    def test_public_native_driver_is_bound_to_frozen_module(self):
        assessment = deepcopy(self.f.authority["arms"]["0"])
        events = [json.loads(line) for line in (self.f.k / "arm-00/coding/private/events.jsonl").read_bytes().splitlines()]
        report = json.loads(events[1]["part"]["state"]["output"])
        report["driver_sha256"] = a.sha(b"unrelated public driver")
        output = a.canonical(report).decode()
        events[1]["part"]["state"]["output"] = output
        assessment["public_selftest"].update(output_sha256=a.sha(output.encode()), driver_sha256=report["driver_sha256"])
        with self.assertRaisesRegex(a.EvidenceError, "public_selftest_report_mismatch"):
            a.public_selftest(events, assessment, a.sha(self.f.source), self.f.client["workloads"][CASE],
                self.f.identity["aotg_modules"]["aotg/field_selftest.py"], self.f.api.public_driver_sha256)


    def test_hash_bound_client_failure_is_observed_not_missing(self):
        i = self.f.failure_index
        ka = self.f.k / ("arm-%02d" % self.f.failure_index)
        events = [json.loads(line) for line in (ka / "coding/private/events.jsonl").read_bytes().splitlines()]
        events = [e for e in events if e["type"] != "text"]
        raw = b"".join(a.canonical(e) + b"\n" for e in events)
        self.f.put(ka / "coding/private/events.jsonl", raw)
        coding = json.loads((ka / "coding/result.json").read_text())
        coding.update(self.f.api.client.summarize_events(raw, ka / "coding/work", "intervals.cpp", ["intervals.cpp", *self.f.public]))
        coding.update(private_events_sha256=a.sha(raw), status="incomplete")
        self.f.rebind_arm(i, coding=coding)
        result = self.f.run()
        self.assertEqual(result["decision"]["status"], "incomplete")
        entry = result["ledger"][i]
        self.assertTrue(entry["normalized"], entry)
        self.assertEqual(entry["observation_class"], "verified_runtime_failure")
        self.assertIn("client_event_contract_failed", entry["runtime_failures"])
        trial = next(t for t in result["run"]["trials"] if t["index"] == i)
        self.assertEqual(trial["reason"], "client_event_contract_failed")
        self.assertEqual(result["decision"]["comparisons"][1]["trial_reasons"][str(i)], "client_event_contract_failed")
        self.assertNotEqual(trial["status"], "passed")
        self.assertNotIn("trial_missing", str(result["decision"]["comparisons"][1]["trial_errors"][str(i)]))
        self.assertEqual(result["observation_counts"]["verified_runtime_failure"], 1)

    def test_resource_stop_is_normalized_and_blocks_other_candidate_adoption(self):
        for mode in ("swap", "nvme", "gpu"):
            with self.subTest(mode=mode):
                original = deepcopy(self.f.samples)
                for sample in self.f.samples[self.f.failure_index * 10:(self.f.failure_index + 1) * 10 + 1]:
                    if mode == "swap":
                        sample["pswpout"] += 1
                    if mode == "nvme":
                        sample["temperatures_c"]["nvme:Composite"] = 80
                    if mode == "gpu":
                        sample["temperatures_c"]["amdgpu:edge"] = 95
                self.f.write_samples()
                self.f.refresh_capture()
                result = self.f.run()
                entry = result["ledger"][self.f.failure_index]
                self.assertTrue(entry["normalized"], entry)
                self.assertEqual(entry["observation_class"], "verified_runtime_failure")
                self.assertEqual(result["decision"]["status"], "incomplete")
                self.assertIsNone(result["decision"]["selected_candidate_id"])
                self.assertTrue(result["decision"]["global_resource_stop"])
                self.assertIn(self.f.failure_index, result["decision"]["resource_stop_trial_indices"])
                if mode == "swap":
                    self.assertIn("swapout_change_or_reset", entry["runtime_failures"])
                    trial = next(t for t in result["run"]["trials"] if t["index"] == self.f.failure_index)
                    self.assertIsNone(trial["resources"]["swapout_delta_bytes"])
                self.f.samples = original
                self.f.write_samples()
                self.f.refresh_capture()

    def test_refusal_is_bound_failure_and_missing_or_tampered_capture_is_unknown(self):
        original = deepcopy(self.f.kr[self.f.failure_index]["requests"])
        rows = deepcopy(original)
        rows.insert(2, {"kind": "aotg-proxy-rejection-v2", "status": "rejected", "http_status": 409,
                        "reason": "concurrent_request_rejected", "method": "POST", "event_sequence": 2})
        rows[-1].update(event_sequence=3, rejected_total=1, rejections_by_reason={"concurrent_request_rejected": 1})
        self.f.rebind_arm(self.f.failure_index, requests=rows)
        result = self.f.run()
        entry = result["ledger"][self.f.failure_index]
        self.assertTrue(entry["normalized"], entry)
        self.assertIn("proxy_requests_rejected", entry["runtime_failures"])
        self.assertEqual(result["decision"]["status"], "incomplete")
        for malformed in (rows[:-1], [rows[0], rows[1], {**rows[-1], "event_sequence": 2}],
                          [{**r, "event_sequence": 999} if n == 1 else r for n, r in enumerate(rows)]):
            self.f.rebind_arm(self.f.failure_index, requests=malformed)
            result = self.f.run()
            self.assertFalse(result["ledger"][self.f.failure_index]["normalized"])
            self.assertEqual(result["ledger"][self.f.failure_index]["observation_class"], "missing_or_conflicting")
            self.assertEqual(result["decision"]["status"], "incomplete")
        self.f.rebind_arm(self.f.failure_index, requests=original)

    def test_legacy_spec_and_request_only_records_cannot_silently_pass(self):
        self.f.spec["version"] = 1
        with self.assertRaisesRegex(a.EvidenceError, "assembly_v2_required"):
            self.f.run()
        self.f.spec["version"] = 2
        records = [r for r in self.f.kr[self.f.failure_index]["requests"] if r["kind"] == "aotg-proxy-request-v1"]
        self.f.rebind_arm(self.f.failure_index, requests=records)
        result = self.f.run()
        self.assertEqual(result["decision"]["status"], "incomplete")
        self.assertFalse(result["ledger"][self.f.failure_index]["normalized"])

    def test_unbound_failure_is_not_promoted_to_verified_failure(self):
        rows = deepcopy(self.f.kr[self.f.failure_index]["requests"])
        rows.insert(2, {"kind": "aotg-proxy-rejection-v2", "status": "rejected", "http_status": 429,
                        "reason": "request_limit_rejected", "method": "POST", "event_sequence": 2})
        rows[-1].update(event_sequence=3, rejected_total=1, rejections_by_reason={"request_limit_rejected": 1})
        self.f.rebind_arm(self.f.failure_index, requests=rows)
        result = self.f.run(False)
        self.assertFalse(result["ledger"][self.f.failure_index]["normalized"])
        self.assertNotEqual(result["ledger"][self.f.failure_index]["observation_class"], "verified_runtime_failure")
        self.assertEqual(result["decision"]["status"], "incomplete")



    def test_bound_timeout_is_normalized_but_invalid_measurement_is_missing(self):
        ka = self.f.k / ("arm-%02d" % self.f.failure_index)
        original = json.loads((ka / "coding/result.json").read_text())
        timed = {**original, "status": "timed_out", "seconds": 131, "exit_code": None}
        self.f.esummary["wall_seconds"] = 200
        self.f.rebind_arm(self.f.failure_index, coding=timed)
        result = self.f.run()
        trial = next(t for t in result["run"]["trials"] if t["index"] == self.f.failure_index)
        self.assertEqual(trial["status"], "timed_out")
        self.assertEqual(trial["reason"], "client_bounds_failed")
        self.assertEqual(result["decision"]["status"], "incomplete")
        self.f.rebind_arm(self.f.failure_index, coding={**original, "seconds": None})
        result = self.f.run()
        self.assertFalse(result["ledger"][self.f.failure_index]["normalized"])
        self.assertEqual(result["ledger"][self.f.failure_index]["observation_class"], "missing_or_conflicting")
        self.assertEqual(result["decision"]["status"], "incomplete")

    def test_new_capture_requires_explicit_frozen_plan_and_exact_proxy_source(self):
        del self.f.client["proxy_capture_version"]
        self.f.spec["client_plan"] = self.f.write("client.json", self.f.client)
        with self.assertRaisesRegex(a.EvidenceError, "frozen_proxy_capture_v2_not_requested"):
            self.f.run()

    def test_boolean_sequence_and_invented_zero_rejections_are_rejected(self):
        rows = deepcopy(self.f.kr[self.f.failure_index]["requests"])
        rows[0]["event_sequence"] = False
        with self.assertRaisesRegex(a.EvidenceError, "request_capture_sequence_invalid"):
            a.request_capture(rows, self.f.client["max_requests"])
        rows = deepcopy(self.f.kr[self.f.failure_index]["requests"])
        rows[-1]["rejections_by_reason"] = {"concurrent_request_rejected": 1}
        with self.assertRaisesRegex(a.EvidenceError, "proxy_rejection_counts_mismatch"):
            a.request_capture(rows, self.f.client["max_requests"])



    def test_refusal_only_capture_is_failure_not_an_empty_success(self):
        original = self.f.kr[self.f.failure_index]["requests"]
        records = [deepcopy(original[0]),
                   {"kind": "aotg-proxy-rejection-v2", "status": "rejected", "http_status": 401,
                    "reason": "authorization_rejected", "method": "POST", "event_sequence": 1},
                   {**original[-1], "event_sequence": 2, "request_records": 0, "rejected_total": 1,
                    "rejections_by_reason": {"authorization_rejected": 1}}]
        self.f.rebind_arm(self.f.failure_index, requests=records)
        result = self.f.run()
        entry = result["ledger"][self.f.failure_index]
        self.assertTrue(entry["normalized"], entry)
        self.assertEqual(entry["observation_class"], "verified_runtime_failure")
        self.assertIn("no_inference_requests_observed", entry["runtime_failures"])
        self.assertEqual(result["decision"]["status"], "incomplete")

if __name__ == "__main__":
    unittest.main()
