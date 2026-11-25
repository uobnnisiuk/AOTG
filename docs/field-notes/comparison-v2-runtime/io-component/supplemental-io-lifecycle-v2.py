"""Proposed single-capture I/O v2 lifecycle; CLI is local preview only.

Execution is an API operation requiring explicit authorization from a separately
reviewed controller. It sends pinned sampler bytes over existing SSH stdin.
Windows JobEmpty proves local Windows child cleanup, not remote process exit.
No default discovery, inference, service control, or remote file writes.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import threading
import tempfile

SAMPLER_SECONDS = 6255
JOB_SECONDS = 6275
FIRST_SAMPLE_SECONDS = 5
CLEANUP_SECONDS = 10
MAX_RECORDS = SAMPLER_SECONDS + 2
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
LIMITS = {"prearm_ready_seconds": 120, "work_seconds": 5400,
          "worker_wait_grace_seconds": 45, "recovery_seconds": 600,
          "recovery_request_grace_seconds": 15, "result_collection_seconds": 15,
          "local_cleanup_seconds": 60, "sampler_seconds": SAMPLER_SECONDS,
          "job_seconds": JOB_SECONDS, "job_cleanup_reserve_seconds": 20,
          "first_sample_seconds": FIRST_SAMPLE_SECONDS, "cleanup_seconds": CLEANUP_SECONDS,
          "maximum_records": MAX_RECORDS, "maximum_output_bytes": MAX_OUTPUT_BYTES}
PLAN_FIELDS = {"artifact", "version", "status", "run_id", "nonce", "authorization_sha256",
               "client_plan_sha256", "worker_plan_sha256", "output_root", "windows_output_root",
               "sampler", "transport", "job_plan", "windows_job_plan", "ssh_argv",
               "capture_binding_sha256", "limits", "client_plan", "coverage_gate_max_gap_seconds",
               "remote_file_created", "coverage_claimed"}
JOB_FIELDS = {"artifact", "version", "wrapper_sha256", "helper", "executable", "argv",
              "cwd", "wall_seconds", "cancel_path", "result_path"}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def raw(path, maximum=64 * 1024 * 1024, *, allowed_links=(1,)):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and not path.is_symlink(),
            "Canonical non-symlink local path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink in allowed_links
                and info.st_uid in (0, os.getuid()) and info.st_size <= maximum,
                "Owned bounded regular input required")
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, "Input grew beyond bound")
    return data


def sha(path, *, allowed_links=(1,)):
    return hashlib.sha256(raw(path, allowed_links=allowed_links)).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def pinned(item, *, allowed_links=(1,)):
    require(isinstance(item, dict) and set(item) in ({"path", "sha256"}, {"path", "sha256", "windows_path"}),
            "Exact file descriptor required")
    require(re.fullmatch("[0-9a-f]{64}", item["sha256"]) is not None, "Invalid pinned SHA")
    path = Path(item["path"])
    require(sha(path, allowed_links=allowed_links) == item["sha256"], "Pinned local bytes changed")
    return path


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def windows_path(path):
    text = str(path)
    require(text.startswith("/mnt/c/"), "Explicit C drive capture/transport paths required")
    return "C:" + text[len("/mnt/c"):].replace("/", "\\")


def capture_binding(plan):
    return digest({"artifact": "aotg-supplemental-io-invocation", "version": 2,
                   "run_id": plan["run_id"], "nonce": plan["nonce"],
                   "authorization_sha256": plan["authorization_sha256"],
                   "client_plan_sha256": plan["client_plan_sha256"],
                   "worker_plan_sha256": plan["worker_plan_sha256"],
                   "sampler_sha256": plan["sampler"]["sha256"], "limits": plan["limits"]})


class Capture:
    def __init__(self, plan_path, expected_sha256):
        self.plan_path = pinned({"path": str(plan_path), "sha256": expected_sha256})
        self.plan_sha256 = expected_sha256
        plan = self.plan = json.loads(raw(self.plan_path, 1024 * 1024))
        require(isinstance(plan, dict) and set(plan) == PLAN_FIELDS, "Unexpected I/O plan fields")
        require(plan["artifact"] == "aotg-supplemental-io-capture-plan"
                and type(plan["version"]) is int and plan["version"] == 2
                and plan["status"] == "PROPOSED_UNAPPROVED_NOT_EXECUTED", "Unexpected I/O plan")
        require(plan["limits"] == LIMITS and all(type(plan["limits"][k]) is int for k in LIMITS),
                "Unreviewed capture limits")
        require(plan["remote_file_created"] is False and plan["coverage_claimed"] is False
                and type(plan["coverage_gate_max_gap_seconds"]) is float
                and plan["coverage_gate_max_gap_seconds"] == 2.5, "Unreviewed coverage policy")
        require(isinstance(plan["nonce"], str) and re.fullmatch("[0-9a-f]{16}", plan["nonce"])
                and isinstance(plan["run_id"], str)
                and re.fullmatch("[a-z0-9][a-z0-9-]{1,95}", plan["run_id"])
                and plan["run_id"].endswith("-" + plan["nonce"]), "Invalid run association")
        for key in ("authorization_sha256", "client_plan_sha256", "worker_plan_sha256", "capture_binding_sha256"):
            require(isinstance(plan[key], str) and re.fullmatch("[0-9a-f]{64}", plan[key]), "Invalid association hash")
        require(capture_binding(plan) == plan["capture_binding_sha256"], "Capture invocation binding mismatch")
        self.client_path = pinned(plan["client_plan"])
        self.client = json.loads(raw(self.client_path, 16 * 1024 * 1024))
        client = self.client
        require(client.get("artifact") == "aotg-k8-field-plan" and type(client.get("version")) is int
                and client["version"] == 2 and digest(client) == plan["client_plan_sha256"],
                "Exact canonical v2 client plan required")
        require(client.get("run_id") == plan["run_id"] and client.get("maintenance_nonce") == plan["nonce"]
                and client.get("worker_plan_sha256") == plan["worker_plan_sha256"]
                and client.get("max_seconds") == 5400 and client.get("cleanup_reserve_seconds") == 60,
                "Client run/budget association mismatch")
        self.source = pinned(plan["sampler"])
        self.source_bytes = raw(self.source, 1024 * 1024)
        require(hashlib.sha256(self.source_bytes).hexdigest() == plan["sampler"]["sha256"],
                "Sampler snapshot changed during verification")
        self.job_path = pinned(plan["job_plan"])
        self.job = json.loads(raw(self.job_path, 1024 * 1024))
        require(isinstance(plan["transport"], dict)
                and set(plan["transport"]) == {"wrapper", "helper", "ssh", "powershell"},
                "Exact transport inventory required")
        for name, item in plan["transport"].items():
            pinned(item, allowed_links=(1, 2) if name in ("ssh", "powershell") else (1,))
            require(item["windows_path"] == windows_path(item["path"]), "Transport path mapping mismatch")
        self.root = Path(plan["output_root"])
        require(self.root.is_dir() and self.root.resolve() == self.root
                and self.root.stat().st_uid == os.getuid(), "Existing canonical owned I/O root required")
        require({p.name for p in self.root.iterdir()} == {"ssh-plan.json"}, "Capture root is not unused")
        job = self.job
        require(isinstance(job, dict) and set(job) == JOB_FIELDS
                and job["artifact"] == "aotg-windows-io-job" and type(job["version"]) is int
                and job["version"] == 2 and type(job["wall_seconds"]) is int
                and job["wall_seconds"] == JOB_SECONDS, "Unexpected Windows I/O job")
        transport = plan["transport"]
        require(job["wrapper_sha256"] == transport["wrapper"]["sha256"]
                and job["helper"] == {"path": transport["helper"]["windows_path"], "sha256": transport["helper"]["sha256"]}
                and job["executable"] == {"path": transport["ssh"]["windows_path"], "sha256": transport["ssh"]["sha256"]},
                "Transport binding mismatch")
        winroot = plan["windows_output_root"]
        require(winroot == windows_path(self.root) and self.job_path == self.root / "ssh-plan.json"
                and plan["windows_job_plan"] == winroot + "\\ssh-plan.json"
                and job["cwd"] == winroot and job["cancel_path"] == winroot + "\\cancel"
                and job["result_path"] == winroot + "\\job-result.json", "Job output binding mismatch")
        require(client["windows_transport"]["ssh"] == transport["ssh"]
                and client["windows_transport"]["powershell"] == transport["powershell"]
                and client["ssh"][0] == transport["ssh"]["path"],
                "I/O executable differs from frozen client route")
        argv = plan["ssh_argv"]
        require(argv == client["ssh"][1:], "I/O SSH argv differs from frozen client route")
        require(isinstance(argv, list) and 1 <= len(argv) <= 110
                and all(isinstance(a, str) and 0 < len(a) <= 2048 and "\0" not in a for a in argv)
                and "-T" in argv and all(x in argv for x in
                    ("BatchMode=yes", "ForwardAgent=no", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes")),
                "Explicit bounded SSH policy required")
        require(job["argv"] == argv + ["/usr/bin/python3.14", "-I", "-S", "-B", "-", "--sample",
                "--seconds", str(SAMPLER_SECONDS), "--run-id", plan["run_id"],
                "--capture-binding-sha256", plan["capture_binding_sha256"]], "Unexpected sampler invocation")
        self.process = None
        self.streams = []
        self.started = None
        self.first = None
        self.finished = False
        self.monitor_stop = threading.Event()
        self.monitor_thread = None
        self.monitor_errors = []
        self.outputs = {name: self.root / name for name in
            ("samples.jsonl", "stderr.log", "launch.json", "first-sample.json", "lifecycle-result.json",
             "cancel", "job-result.json")}

    def preview(self):
        return {"artifact": "aotg-supplemental-io-preview", "version": 2,
                "execute": False, "status": "UNAPPROVED", "plan_sha256": self.plan_sha256,
                "run_id": self.plan["run_id"], "capture_binding_sha256": self.plan["capture_binding_sha256"],
                "limits": LIMITS, "remote_written": False, "coverage_evaluated": False}

    def _repin(self):
        pinned({"path": str(self.plan_path), "sha256": self.plan_sha256})
        pinned(self.plan["sampler"])
        pinned(self.plan["client_plan"])
        pinned(self.plan["job_plan"])
        for name, item in self.plan["transport"].items():
            pinned(item, allowed_links=(1, 2) if name in ("ssh", "powershell") else (1,))

    def _cancel(self):
        try:
            with self.outputs["cancel"].open("xb") as stream:
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            require(raw(self.outputs["cancel"], 0) == b"", "Unexpected cancellation marker")

    def _monitor_output(self):
        while not self.monitor_stop.wait(.2):
            try:
                for name, maximum in (("samples.jsonl", MAX_OUTPUT_BYTES), ("stderr.log", 262144)):
                    require(self.outputs[name].stat().st_size <= maximum, "Output budget exceeded")
                if self.process.poll() is not None:
                    return
            except Exception as error:
                self.monitor_errors.append("output-monitor-" + type(error).__name__)
                try:
                    self._cancel()
                except Exception as cancel_error:
                    self.monitor_errors.append("output-monitor-cancel-" + type(cancel_error).__name__)
                return

    def start(self, *, execution_authorized=False, deadline):
        require(execution_authorized is True, "Explicit authenticated execution required")
        require(isinstance(deadline, (float, int)) and math.isfinite(deadline)
                and self.process is None and self.started is None and time.monotonic() < deadline,
                "Capture start unavailable")
        self._repin()
        require({p.name for p in self.root.iterdir()} == {"ssh-plan.json"}, "Capture already consumed")
        transport = self.plan["transport"]
        command = [transport["powershell"]["path"], "-NoLogo", "-NoProfile", "-NonInteractive",
                   "-File", transport["wrapper"]["windows_path"], "-Plan", self.plan["windows_job_plan"]]
        self.started = time.monotonic()
        # Open sequentially so a later failure leaves earlier streams owned for finally/finish.
        try:
            # Anonymous private snapshot: stream exactly the verified bytes even if
            # the source path is replaced after _repin. No remote reread by path.
            frozen_stdin = tempfile.TemporaryFile(mode="w+b")
            self.streams.append(frozen_stdin)
            frozen_stdin.write(self.source_bytes)
            frozen_stdin.flush()
            frozen_stdin.seek(0)
            for path in (self.outputs["samples.jsonl"], self.outputs["stderr.log"]):
                self.streams.append(path.open("xb"))
            require(time.monotonic() < deadline, "Handshake expired before I/O process launch")
            self.process = subprocess.Popen(command, stdin=self.streams[0], stdout=self.streams[1],
                                            stderr=self.streams[2], close_fds=True)
            save(self.outputs["launch.json"], {"artifact": "aotg-supplemental-io-launch", "version": 2,
                 "run_id": self.plan["run_id"], "authorization_sha256": self.plan["authorization_sha256"],
                 "client_plan_sha256": self.plan["client_plan_sha256"],
                 "client_plan_raw_sha256": self.plan["client_plan"]["sha256"],
                 "worker_plan_sha256": self.plan["worker_plan_sha256"], "plan_sha256": self.plan_sha256,
                 "capture_binding_sha256": self.plan["capture_binding_sha256"],
                 "job_plan_sha256": self.plan["job_plan"]["sha256"], "sampler_sha256": self.plan["sampler"]["sha256"],
                 "wrapper_pid": self.process.pid, "utc": utc(), "local_monotonic": self.started,
                 "remote_file_created": False, "command_sha256": digest(command)})
            self.monitor_thread = threading.Thread(target=self._monitor_output, daemon=True)
            self.monitor_thread.start()
            cutoff = min(deadline, self.started + FIRST_SAMPLE_SECONDS)
            while time.monotonic() < cutoff:
                require(self.process.poll() is None, "I/O job exited before first sample")
                require(self.outputs["stderr.log"].stat().st_size <= 262144, "I/O stderr exceeded bound")
                with self.outputs["samples.jsonl"].open("rb") as stream:
                    first_bytes = stream.read(65537)
                require(len(first_bytes) <= 65536, "First sample exceeded bound")
                lines = first_bytes.split(b"\n")
                if len(lines) >= 3:
                    meta, first = (json.loads(line) for line in lines[:2])
                    for row in (meta, first):
                        require(row["run_id"] == self.plan["run_id"]
                                and row["capture_binding_sha256"] == self.plan["capture_binding_sha256"],
                                "Foreign first sample association")
                    require(meta["artifact"] == "aotg-supplemental-io-plan" and meta["version"] == 1
                            and meta["sample_requested"] is True and meta["wall_budget_seconds"] == SAMPLER_SECONDS
                            and meta["maximum_output_bytes"] == MAX_OUTPUT_BYTES
                            and meta["maximum_records"] == MAX_RECORDS, "Unexpected sampler acknowledgement")
                    require(first["artifact"] == "aotg-supplemental-io-sample" and first["version"] == 1
                            and type(first["index"]) is int and first["index"] == 0
                            and first["observed_baseline"] is True
                            and first["monotonic_read_start_ns"] <= first["monotonic_read_end_ns"],
                            "Missing observed first sample")
                    require(datetime.fromisoformat(first["utc_read_start"]) <= datetime.fromisoformat(first["utc_read_end"])
                            and time.monotonic() < cutoff, "Invalid/late first sample bracket")
                    self.first = first
                    save(self.outputs["first-sample.json"], {"artifact": "aotg-supplemental-io-first-observed",
                         "version": 2, "plan_sha256": self.plan_sha256,
                         "capture_binding_sha256": self.plan["capture_binding_sha256"],
                         "observed_utc": utc(), "metadata": meta, "sample": first})
                    return first
                time.sleep(min(.05, max(0, cutoff - time.monotonic())))
            raise TimeoutError("First sample not observed in handshake budget")
        except BaseException as failure:
            # Caller still receives the original failure. Owned job is cancelled;
            # no retry, unrelated PID signaling, or fabricated completion.
            try:
                self.finish(cancel=True)
            except Exception as cleanup_error:
                failure.add_note("I/O cleanup result unavailable: " + type(cleanup_error).__name__)
            raise

    def finish(self, *, cancel=False):
        require(not self.finished, "Capture cleanup already recorded")
        self.finished = True
        errors, receipt, final, samples, clean = [], None, None, [], False
        try:
            if self.process is not None:
                if not cancel:
                    try:
                        self.process.wait(timeout=max(0, self.started + JOB_SECONDS + 5 - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        cancel = True
                        errors.append("natural-job-deadline-unverified")
                if cancel and self.process.poll() is None:
                    self._cancel()
                try:
                    self.process.wait(timeout=CLEANUP_SECONDS)
                except subprocess.TimeoutExpired:
                    errors.append("owned-job-cancellation-unverified")
                if self.outputs["job-result.json"].is_file():
                    receipt = json.loads(raw(self.outputs["job-result.json"], 65536))
                    result = receipt.get("result", {})
                    clean = (self.process.poll() is not None
                        and receipt.get("artifact") == "aotg-windows-io-job-result" and receipt.get("version") == 2
                        and receipt.get("plan_sha256") == self.plan["job_plan"]["sha256"]
                        and receipt.get("wrapper_sha256") == self.plan["transport"]["wrapper"]["sha256"]
                        and receipt.get("helper_sha256") == self.plan["transport"]["helper"]["sha256"]
                        and result.get("ExecutableSha256") == self.plan["transport"]["ssh"]["sha256"]
                        and result.get("ProcessId", 0) > 0
                        and result.get("CleanupScope") == "windows-job-object" and result.get("JobEmpty") is True)
                if not clean:
                    errors.append("owned-job-cleanup-receipt-unverified")
        except Exception as error:
            errors.append(type(error).__name__)
        finally:
            self.monitor_stop.set()
            if self.monitor_thread is not None:
                self.monitor_thread.join(timeout=1)
                if self.monitor_thread.is_alive():
                    errors.append("output-monitor-not-reaped")
            errors.extend(self.monitor_errors)
            for stream in self.streams:
                try:
                    stream.close()
                except OSError:
                    errors.append("local-stream-close-failed")
            try:
                if self.outputs["samples.jsonl"].is_file():
                    data = raw(self.outputs["samples.jsonl"], MAX_OUTPUT_BYTES)
                    require(data.endswith(b"\n"), "Partial I/O record")
                    rows = [json.loads(line) for line in data.splitlines()]
                    require(2 <= len(rows) <= MAX_RECORDS, "I/O record count outside bound")
                    require(all(row.get("run_id") == self.plan["run_id"]
                                and row.get("capture_binding_sha256") == self.plan["capture_binding_sha256"]
                                for row in rows), "Foreign sample association")
                    samples = [r for r in rows if r.get("artifact") == "aotg-supplemental-io-sample"]
                    finals = [r for r in rows if r.get("artifact") == "aotg-supplemental-io-final"]
                    final = finals[0] if len(finals) == 1 else None
            except Exception as error:
                errors.append("capture-readback-" + type(error).__name__)
            result = {"artifact": "aotg-supplemental-io-lifecycle-result", "version": 2,
                "plan_sha256": self.plan_sha256, "run_id": self.plan["run_id"], "utc": utc(),
                "authorization_sha256": self.plan["authorization_sha256"],
                "client_plan_sha256": self.plan["client_plan_sha256"],
                "client_plan_raw_sha256": self.plan["client_plan"]["sha256"], "worker_plan_sha256": self.plan["worker_plan_sha256"],
                "capture_binding_sha256": self.plan["capture_binding_sha256"],
                "sampler_sha256": self.plan["sampler"]["sha256"], "job_plan_sha256": self.plan["job_plan"]["sha256"],
                "limits": LIMITS, "owned_windows_job_cleanup_verified": clean,
                "remote_process_exit_verified": False, "cancel_requested": cancel,
                "wrapper_pid": self.process.pid if self.process is not None else None,
                "wrapper_returncode": self.process.poll() if self.process is not None else None,
                "job_receipt": receipt, "errors": errors, "first_sample_observed": self.first is not None,
                "sample_count": len(samples), "first_utc": samples[0]["utc_read_start"] if samples else None,
                "last_utc": samples[-1]["utc_read_end"] if samples else None, "sampler_final": final,
                # Finalized only after the complete output inventory below.
                "capture_finished_to_deadline": False,
                "coverage_evaluated": False, "coverage_complete": None, "rates_computed": False,
                "files": {}}
            for name, path in self.outputs.items():
                if name != "lifecycle-result.json" and path.exists():
                    try:
                        result["files"][name] = sha(path)
                    except (OSError, RuntimeError):
                        errors.append("output-hash-failed-" + name)
            result["capture_finished_to_deadline"] = bool(
                not cancel and not errors and clean and receipt
                and result["wrapper_returncode"] == 0
                and receipt["result"].get("ExitCode") == 0
                and not receipt["result"].get("TimedOut") and not receipt["result"].get("Cancelled")
                and final and final.get("complete_to_configured_deadline") is True)
            save(self.outputs["lifecycle-result.json"], result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(Capture(Path(args.plan), args.plan_sha256).preview(), sort_keys=True))


if __name__ == "__main__":
    main()
