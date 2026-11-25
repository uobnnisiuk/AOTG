"""Offline association checks for the reviewed, bounded I/O v2 producer.

The caller supplies an independently trusted inventory, expected run identities,
and a reader.raw(path, maximum) that safely returns bounded immutable bytes.
Descriptors locate collected copies, not necessarily the original live paths.
No source is imported/executed, no paths are discovered, and no process is probed.
This is evidence consistency under that external trust boundary, not a signature
or proof of remote process exit. Coverage, rates, quality and adoption are separate.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import PurePosixPath
import re

MIB = 1024 * 1024
MAX_OUTPUT = 32 * MIB
MAX_RECORDS = 6257
LIMITS = {"prearm_ready_seconds": 120, "work_seconds": 5400,
          "worker_wait_grace_seconds": 45, "recovery_seconds": 600,
          "recovery_request_grace_seconds": 15, "result_collection_seconds": 15,
          "local_cleanup_seconds": 60, "sampler_seconds": 6255, "job_seconds": 6275,
          "job_cleanup_reserve_seconds": 20, "first_sample_seconds": 5,
          "cleanup_seconds": 10, "maximum_records": MAX_RECORDS,
          "maximum_output_bytes": MAX_OUTPUT}
SOURCE_HASHES = {
    "lifecycle_source": "fd578d1d277ead2a1f15dfb1eb05441a49d0e6db0ca59f8fe3a32d13a21cd927",
    "sampler_source": "7c2e9800e6470db78a026a71894087e1254ee3ec6e81c47a38ef8f52c9cbf53d",
    "wrapper_source": "cae9d9d4800b566219779df1d48a6e9c9bb2121cea3d249e48db9ca1b47159aa",
    "native_helper_source": "d7ec1ffbdfba21c41770288f618e4274395e989ceee59904009153a4c50bad3d",
}
EXPECTED_KEYS = {"run_id", "nonce", "authorization_sha256", "client_plan_sha256",
                 "client_plan_raw_sha256", "worker_plan_sha256", "plan_sha256"}
BASE_ROLES = set(SOURCE_HASHES) | {"plan", "client_plan", "worker_plan", "authorization", "job_plan"}
FILE_ROLES = {"launch": "launch.json", "first_sample": "first-sample.json",
              "samples": "samples.jsonl", "job_receipt": "job-result.json",
              "stderr": "stderr.log", "cancel": "cancel"}
OPTIONAL_ROLES = set(FILE_ROLES) | {"lifecycle_result"}
BLOCK_NAMES = ("reads_completed", "reads_merged", "read_sectors_512b", "read_time_ms",
               "writes_completed", "writes_merged", "write_sectors_512b", "write_time_ms",
               "in_flight", "io_time_ms", "weighted_io_time_ms", "discards_completed",
               "discards_merged", "discard_sectors_512b", "discard_time_ms",
               "flushes_completed", "flush_time_ms")
CPU_NAMES = {"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"}
METADATA_TEXT = {
    "counter_semantics": "Raw cumulative counters except block.in_flight gauge and PSI average percentages; no rates computed",
    "cpu_tick_unit": "SC_CLK_TCK; guest/guest_nice already included in user/nice; iowait may decrease",
    "correlation": "UTC at read start/end and monotonic_ns bracket sequential reads; not one atomic host snapshot",
    "coverage": "First sample is observed baseline. Inspect actual sample timestamps; missing final record means incomplete capture",
    "interpretation": "Host/device totals include unrelated activity. Decreases do not prove a reset. These counters alone do not prove saturation or bottleneck cause",
    "references": ["https://docs.kernel.org/block/stat.html", "https://docs.kernel.org/admin-guide/iostats.html",
                   "https://docs.kernel.org/accounting/psi.html", "https://docs.kernel.org/filesystems/proc.html"],
}


class IOCaptureError(ValueError):
    """Input inventory or association is inconsistent; never safe to accept."""


def need(condition, reason):
    if not condition:
        raise IOCaptureError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def hash_value(value):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid_sha256")
    return value


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def number(value, minimum=0):
    return type(value) in (int, float) and math.isfinite(value) and value >= minimum


def exact(value, keys, reason):
    need(isinstance(value, dict) and set(value) == set(keys), reason)


def utc(value):
    need(isinstance(value, str) and len(value) <= 40, "invalid_utc")
    try:
        result = datetime.fromisoformat(value)
    except ValueError as error:
        raise IOCaptureError("invalid_utc") from error
    need(result.tzinfo is not None and result.utcoffset() == timezone.utc.utcoffset(None), "non_utc_timestamp")
    return result


def parse(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(IOCaptureError("nonfinite_json")))
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, IOCaptureError):
            raise
        raise IOCaptureError("invalid_json") from error
    need(isinstance(value, dict), "json_object_required")
    return value


def artifact(value, name, version):
    need(value.get("artifact") == name and type(value.get("version")) is int
         and value["version"] == version, "artifact_version_mismatch")


def descriptor(value):
    exact(value, {"path", "sha256"}, "invalid_descriptor")
    need(isinstance(value["path"], str) and value["path"].startswith("/")
         and len(value["path"]) <= 4096 and "\0" not in value["path"], "invalid_descriptor_path")
    hash_value(value["sha256"])


def logical_path(value):
    need(isinstance(value, str) and value.startswith("/") and "\0" not in value
         and str(PurePosixPath(value)) == value and ".." not in PurePosixPath(value).parts,
         "invalid_logical_path")
    return value


def winpath(value):
    value = logical_path(value)
    need(value.startswith("/mnt/c/"), "non_c_drive_transport")
    return "C:" + value[len("/mnt/c"):].replace("/", "\\")


def context(raws, expected):
    exact(expected, EXPECTED_KEYS, "expected_identity_required")
    plan, client, worker, authorization, job = (parse(raws[key]) for key in
                                               ("plan", "client_plan", "worker_plan", "authorization", "job_plan"))
    for key in EXPECTED_KEYS - {"run_id", "nonce"}:
        hash_value(expected[key])
    need(sha(raws["plan"]) == expected["plan_sha256"]
         and sha(raws["client_plan"]) == expected["client_plan_raw_sha256"]
         and sha(raws["worker_plan"]) == expected["worker_plan_sha256"]
         and canonical(client) == expected["client_plan_sha256"]
         and canonical(authorization) == expected["authorization_sha256"], "external_identity_mismatch")
    for role, digest in SOURCE_HASHES.items():
        need(sha(raws[role]) == digest, "unreviewed_producer_source")
    exact(plan, {"artifact", "version", "status", "run_id", "nonce", "authorization_sha256",
          "client_plan_sha256", "worker_plan_sha256", "output_root", "windows_output_root",
          "sampler", "transport", "job_plan", "windows_job_plan", "ssh_argv", "capture_binding_sha256",
          "limits", "client_plan", "coverage_gate_max_gap_seconds", "remote_file_created", "coverage_claimed"},
          "unexpected_plan_fields")
    artifact(plan, "aotg-supplemental-io-capture-plan", 2)
    need(plan["status"] == "PROPOSED_UNAPPROVED_NOT_EXECUTED", "plan_status_mismatch")
    need(plan["limits"] == LIMITS and all(type(plan["limits"][k]) is int for k in LIMITS), "limits_mismatch")
    need(plan["remote_file_created"] is False and plan["coverage_claimed"] is False
         and type(plan["coverage_gate_max_gap_seconds"]) is float
         and plan["coverage_gate_max_gap_seconds"] == 2.5, "unreviewed_coverage_policy")
    need(isinstance(plan["nonce"], str) and re.fullmatch(r"[0-9a-f]{16}", plan["nonce"])
         and isinstance(plan["run_id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,95}", plan["run_id"])
         and plan["run_id"].endswith("-" + plan["nonce"]), "invalid_run_identity")
    for key in ("run_id", "nonce", "authorization_sha256", "client_plan_sha256", "worker_plan_sha256"):
        need(plan[key] == expected[key], "plan_external_binding_mismatch")
    artifact(client, "aotg-k8-field-plan", 2)
    artifact(worker, "aotg-evo-worker-plan", 2)
    artifact(authorization, "aotg-owner-authorization", 1)
    need(worker.get("run_id") == plan["run_id"] and client.get("run_id") == plan["run_id"]
         and client.get("maintenance_nonce") == plan["nonce"]
         and client.get("worker_plan_sha256") == plan["worker_plan_sha256"]
         and type(client.get("max_seconds")) is int and client["max_seconds"] == 5400
         and type(client.get("cleanup_reserve_seconds")) is int and client["cleanup_reserve_seconds"] == 60
         and authorization.get("nonce") == plan["nonce"]
         and authorization.get("client_plan_sha256") == plan["client_plan_sha256"], "client_worker_authorization_mismatch")
    for name, role in (("client_plan", "client_plan"), ("job_plan", "job_plan"), ("sampler", "sampler_source")):
        descriptor(plan[name])
        logical_path(plan[name]["path"])
        need(plan[name]["sha256"] == sha(raws[role]), "plan_descriptor_hash_mismatch")
    transport = plan["transport"]
    exact(transport, {"wrapper", "helper", "ssh", "powershell"}, "transport_inventory_mismatch")
    for item in transport.values():
        exact(item, {"path", "sha256", "windows_path"}, "transport_descriptor_mismatch")
        hash_value(item["sha256"])
        need(item["windows_path"] == winpath(item["path"]), "transport_path_mapping_mismatch")
    need(transport["wrapper"]["sha256"] == SOURCE_HASHES["wrapper_source"]
         and transport["helper"]["sha256"] == SOURCE_HASHES["native_helper_source"], "transport_source_mismatch")
    need(isinstance(client.get("windows_transport"), dict)
         and all(client["windows_transport"].get(role) == transport[role] for role in ("ssh", "powershell")),
         "transport_differs_from_client")
    argv = plan["ssh_argv"]
    need(isinstance(argv, list) and 1 <= len(argv) <= 110
         and all(isinstance(a, str) and 0 < len(a) <= 2048 and "\0" not in a for a in argv)
         and "-T" in argv and all(x in argv for x in
             ("BatchMode=yes", "ForwardAgent=no", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes"))
         and client.get("ssh") == [transport["ssh"]["path"]] + argv, "ssh_route_differs_from_client")
    binding = canonical({"artifact": "aotg-supplemental-io-invocation", "version": 2,
        "run_id": plan["run_id"], "nonce": plan["nonce"], "authorization_sha256": plan["authorization_sha256"],
        "client_plan_sha256": plan["client_plan_sha256"], "worker_plan_sha256": plan["worker_plan_sha256"],
        "sampler_sha256": plan["sampler"]["sha256"], "limits": LIMITS})
    need(plan["capture_binding_sha256"] == binding, "capture_binding_mismatch")
    root = logical_path(plan["output_root"])
    winroot = winpath(root)
    need(plan["windows_output_root"] == winroot and plan["job_plan"]["path"] == root + "/ssh-plan.json"
         and plan["windows_job_plan"] == winroot + "\\ssh-plan.json", "job_output_mapping_mismatch")
    exact(job, {"artifact", "version", "wrapper_sha256", "helper", "executable", "argv", "cwd",
                "wall_seconds", "cancel_path", "result_path"}, "job_fields_mismatch")
    artifact(job, "aotg-windows-io-job", 2)
    need(job["wrapper_sha256"] == transport["wrapper"]["sha256"]
         and job["helper"] == {"path": transport["helper"]["windows_path"], "sha256": transport["helper"]["sha256"]}
         and job["executable"] == {"path": transport["ssh"]["windows_path"], "sha256": transport["ssh"]["sha256"]}
         and type(job["wall_seconds"]) is int and job["wall_seconds"] == 6275
         and job["cwd"] == winroot and job["cancel_path"] == winroot + "\\cancel"
         and job["result_path"] == winroot + "\\job-result.json"
         and job["argv"] == argv + ["/usr/bin/python3.14", "-I", "-S", "-B", "-", "--sample", "--seconds", "6255",
                                   "--run-id", plan["run_id"], "--capture-binding-sha256", binding], "job_invocation_mismatch")
    command = [transport["powershell"]["path"], "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
               transport["wrapper"]["windows_path"], "-Plan", plan["windows_job_plan"]]
    return plan, canonical(command)


def common_record(value, plan, raw_plan_sha):
    for key in ("run_id", "authorization_sha256", "client_plan_sha256", "worker_plan_sha256", "capture_binding_sha256"):
        need(value.get(key) == plan[key], "record_run_binding_mismatch")
    need(value.get("plan_sha256") == raw_plan_sha
         and value.get("client_plan_raw_sha256") == plan["client_plan"]["sha256"]
         and value.get("job_plan_sha256") == plan["job_plan"]["sha256"]
         and value.get("sampler_sha256") == plan["sampler"]["sha256"], "record_raw_binding_mismatch")


def read_launch(raw, plan, plan_sha, command_sha):
    value = parse(raw)
    exact(value, {"artifact", "version", "run_id", "authorization_sha256", "client_plan_sha256",
          "client_plan_raw_sha256", "worker_plan_sha256", "plan_sha256", "capture_binding_sha256",
          "job_plan_sha256", "sampler_sha256", "wrapper_pid", "utc", "local_monotonic",
          "remote_file_created", "command_sha256"}, "launch_fields_mismatch")
    artifact(value, "aotg-supplemental-io-launch", 2)
    common_record(value, plan, plan_sha)
    need(integer(value["wrapper_pid"], 1) and number(value["local_monotonic"])
         and value["remote_file_created"] is False and value["command_sha256"] == command_sha, "launch_identity_mismatch")
    utc(value["utc"])
    return value


def read_receipt(raw, plan):
    value = parse(raw)
    exact(value, {"artifact", "version", "plan_sha256", "helper_sha256", "wrapper_sha256", "result"}, "receipt_fields_mismatch")
    artifact(value, "aotg-windows-io-job-result", 2)
    need(value["plan_sha256"] == plan["job_plan"]["sha256"]
         and value["helper_sha256"] == plan["transport"]["helper"]["sha256"]
         and value["wrapper_sha256"] == plan["transport"]["wrapper"]["sha256"], "receipt_plan_binding_mismatch")
    row = value["result"]
    exact(row, {"ProcessId", "ExitCode", "TimedOut", "Cancelled", "JobEmpty", "Seconds",
                "ExecutableSha256", "CleanupScope"}, "job_result_fields_mismatch")
    need(integer(row["ProcessId"], 1) and integer(row["ExitCode"]) and row["ExitCode"] <= 2**32-1
         and all(type(row[k]) is bool for k in ("TimedOut", "Cancelled", "JobEmpty"))
         and number(row["Seconds"]) and row["ExecutableSha256"] == plan["transport"]["ssh"]["sha256"]
         and row["CleanupScope"] == "windows-job-object", "job_result_identity_mismatch")
    return value


def read_rows(raw, plan):
    need(raw.endswith(b"\n"), "partial_samples_tail")
    lines = raw.splitlines()
    need(2 <= len(lines) <= MAX_RECORDS and all(0 < len(line) + 1 <= 8192 for line in lines), "sample_record_bound")
    rows = [parse(line) for line in lines]
    for row in rows:
        need(row.get("run_id") == plan["run_id"]
             and row.get("capture_binding_sha256") == plan["capture_binding_sha256"], "foreign_sample_association")
    meta = rows[0]
    artifact(meta, "aotg-supplemental-io-plan", 1)
    exact(meta, {"artifact", "version", "sample_requested", "sources", "interval_seconds", "wall_budget_seconds",
          "maximum_seconds", "maximum_records", "maximum_output_bytes", "maximum_line_bytes", "final_record_reserve_seconds",
          "output", "sector_bytes", "counter_semantics", "cpu_tick_unit", "correlation", "coverage", "interpretation",
          "references", "run_id", "capture_binding_sha256", "utc", "monotonic_ns", "cpu_ticks_per_second"}, "metadata_fields_mismatch")
    need(meta["sample_requested"] is True and meta["sources"] == ["/sys/class/block/nvme0n1/stat", "/proc/pressure/io", "/proc/stat"]
         and meta["output"] == "stdout JSONL only" and all(meta[k] == v for k, v in METADATA_TEXT.items())
         and all(type(meta[k]) is int and meta[k] == v for k, v in {
             "interval_seconds": 1, "wall_budget_seconds": 6255, "maximum_seconds": 6255, "maximum_records": MAX_RECORDS,
             "maximum_output_bytes": MAX_OUTPUT, "maximum_line_bytes": 8192, "sector_bytes": 512}.items())
         and type(meta["final_record_reserve_seconds"]) is float and meta["final_record_reserve_seconds"] == .25
         and integer(meta["monotonic_ns"]) and integer(meta["cpu_ticks_per_second"], 1), "metadata_contract_mismatch")
    previous_mono, previous_utc = meta["monotonic_ns"], utc(meta["utc"])
    samples, final = [], None
    for index, row in enumerate(rows[1:]):
        if row.get("artifact") == "aotg-supplemental-io-final":
            need(index == len(rows) - 2 and final is None, "final_not_unique_last")
            final = row
            continue
        artifact(row, "aotg-supplemental-io-sample", 1)
        exact(row, {"artifact", "version", "run_id", "capture_binding_sha256", "index", "observed_baseline",
              "utc_read_start", "monotonic_read_start_ns", "block", "io_pressure", "cpu", "device_identity",
              "utc_read_end", "monotonic_read_end_ns", "counter_decreases", "counter_reset_or_decrease_detected"}, "sample_fields_mismatch")
        need(type(row["index"]) is int and row["index"] == len(samples)
             and row["observed_baseline"] is (len(samples) == 0), "sample_sequence_mismatch")
        start, end = row["monotonic_read_start_ns"], row["monotonic_read_end_ns"]
        need(integer(start) and integer(end) and previous_mono <= start <= end, "sample_monotonic_mismatch")
        first_utc, last_utc = utc(row["utc_read_start"]), utc(row["utc_read_end"])
        need(previous_utc <= first_utc <= last_utc, "sample_utc_mismatch")
        block = row["block"]
        need(isinstance(block, dict) and set(block) in [set(BLOCK_NAMES[:n]) for n in (11, 15, 17)]
             and all(integer(v) for v in block.values()), "invalid_block_counter_schema")
        exact(row["cpu"], {"ticks", "boot_time_unix_seconds"}, "invalid_cpu_schema")
        exact(row["cpu"]["ticks"], CPU_NAMES, "invalid_cpu_ticks")
        need(all(integer(v) for v in row["cpu"]["ticks"].values())
             and integer(row["cpu"]["boot_time_unix_seconds"]), "invalid_cpu_counter")
        exact(row["io_pressure"], {"some", "full"}, "invalid_pressure_scopes")
        for pressure in row["io_pressure"].values():
            exact(pressure, {"avg10", "avg60", "avg300", "total_us"}, "invalid_pressure_schema")
            need(integer(pressure["total_us"]) and all(number(pressure[k]) and pressure[k] <= 100
                 for k in ("avg10", "avg60", "avg300")), "invalid_pressure_counter")
        identity = row["device_identity"]
        exact(identity, {"resolved_stat_path", "stat_inode", "stat_device"}, "invalid_device_identity")
        logical_path(identity["resolved_stat_path"])
        need(integer(identity["stat_inode"], 1) and integer(identity["stat_device"]), "invalid_device_stat")
        need(isinstance(row["counter_decreases"], list) and len(row["counter_decreases"]) <= 29
             and type(row["counter_reset_or_decrease_detected"]) is bool
             and row["counter_reset_or_decrease_detected"] == bool(row["counter_decreases"]), "invalid_decrease_flag")
        if samples:
            need(identity == samples[0]["device_identity"]
                 and row["cpu"]["boot_time_unix_seconds"] == samples[0]["cpu"]["boot_time_unix_seconds"], "device_or_boot_changed")
        samples.append(row)
        previous_mono, previous_utc = end, last_utc
    need(samples, "no_observed_samples")
    if final is not None:
        artifact(final, "aotg-supplemental-io-final", 1)
        exact(final, {"artifact", "version", "run_id", "capture_binding_sha256", "reason", "signal", "error",
              "emitted_samples", "observations_with_counter_decreases", "utc", "monotonic_ns", "elapsed_seconds",
              "complete_to_configured_deadline"}, "final_fields_mismatch")
        need(type(final["emitted_samples"]) is int and final["emitted_samples"] == len(samples)
             and integer(final["observations_with_counter_decreases"])
             and integer(final["monotonic_ns"]) and final["monotonic_ns"] >= previous_mono
             and utc(final["utc"]) >= previous_utc and number(final["elapsed_seconds"])
             and type(final["complete_to_configured_deadline"]) is bool
             and (final["monotonic_ns"] - meta["monotonic_ns"]) / 1e9 <= final["elapsed_seconds"] + 1e-6,
             "final_counts_or_clock_mismatch")
        reason = final["reason"]
        need(reason in ("deadline", "signal", "observation_or_output_error"), "invalid_final_reason")
        need(final["complete_to_configured_deadline"] is (reason == "deadline"), "final_completion_contradiction")
        if reason == "deadline":
            need(final["observations_with_counter_decreases"] == sum(bool(r["counter_decreases"]) for r in samples),
                 "deadline_decrease_count_mismatch")
            need(final["signal"] is None and final["error"] is None
                 and 6254.75 <= final["elapsed_seconds"] < 6255, "deadline_terminal_mismatch")
        elif reason == "signal":
            need(integer(final["signal"], 1) and final["error"] is None, "signal_terminal_mismatch")
        else:
            need(final["signal"] is None and isinstance(final["error"], str)
                 and len(final["error"]) <= 512, "error_terminal_mismatch")
    return meta, samples, final


def read_first(raw, plan, plan_sha, meta, sample):
    value = parse(raw)
    exact(value, {"artifact", "version", "plan_sha256", "capture_binding_sha256", "observed_utc", "metadata", "sample"},
          "first_record_fields_mismatch")
    artifact(value, "aotg-supplemental-io-first-observed", 2)
    need(value["plan_sha256"] == plan_sha and value["capture_binding_sha256"] == plan["capture_binding_sha256"]
         and value["metadata"] == meta and value["sample"] == sample, "first_record_binding_mismatch")
    utc(value["observed_utc"])
    return value


def read_terminal(raw, plan, plan_sha, launch, receipt, raws, samples, final, first):
    value = parse(raw)
    exact(value, {"artifact", "version", "plan_sha256", "run_id", "utc", "authorization_sha256", "client_plan_sha256",
          "client_plan_raw_sha256", "worker_plan_sha256", "capture_binding_sha256", "sampler_sha256", "job_plan_sha256",
          "limits", "owned_windows_job_cleanup_verified", "remote_process_exit_verified", "cancel_requested", "wrapper_pid",
          "wrapper_returncode", "job_receipt", "errors", "first_sample_observed", "sample_count", "first_utc", "last_utc",
          "sampler_final", "capture_finished_to_deadline", "coverage_evaluated", "coverage_complete", "rates_computed", "files"},
          "terminal_fields_mismatch")
    artifact(value, "aotg-supplemental-io-lifecycle-result", 2)
    common_record(value, plan, plan_sha)
    need(utc(value["utc"]) >= utc(launch["utc"]) and value["limits"] == LIMITS
         and all(type(value["limits"][k]) is int for k in LIMITS), "terminal_clock_or_limits_mismatch")
    need(all(type(value[k]) is bool for k in ("owned_windows_job_cleanup_verified", "remote_process_exit_verified",
         "cancel_requested", "first_sample_observed", "capture_finished_to_deadline", "coverage_evaluated", "rates_computed"))
         and value["remote_process_exit_verified"] is False and value["coverage_evaluated"] is False
         and value["coverage_complete"] is None and value["rates_computed"] is False, "terminal_scope_mismatch")
    need(type(value["wrapper_pid"]) is int and value["wrapper_pid"] == launch["wrapper_pid"]
         and (value["wrapper_returncode"] is None or type(value["wrapper_returncode"]) is int)
         and value["job_receipt"] == receipt, "terminal_process_or_receipt_mismatch")
    need(isinstance(value["errors"], list) and len(value["errors"]) <= 64
         and all(isinstance(v, str) and len(v) <= 512 for v in value["errors"]), "terminal_errors_invalid")
    need(value["first_sample_observed"] is first and type(value["sample_count"]) is int
         and value["sample_count"] == len(samples) and value["first_utc"] == samples[0]["utc_read_start"]
         and value["last_utc"] == samples[-1]["utc_read_end"] and value["sampler_final"] == final, "terminal_sample_summary_mismatch")
    inventory = {name: sha(raws[role]) for role, name in FILE_ROLES.items() if role in raws}
    need(value["files"] == inventory, "terminal_file_inventory_mismatch")
    result = receipt["result"] if receipt is not None else None
    clean = result is not None and result["JobEmpty"] is True and value["wrapper_returncode"] is not None
    need(value["owned_windows_job_cleanup_verified"] is clean, "terminal_cleanup_contradiction")
    if result is not None and value["wrapper_returncode"] is not None:
        expected_return = 124 if result["TimedOut"] or result["Cancelled"] else result["ExitCode"]
        # The producer's successful/timeout paths use these codes; ambiguous wrapper
        # failures are incomplete, never reinterpreted as remote SSH exit status.
        need(value["wrapper_returncode"] == expected_return, "wrapper_returncode_mismatch")
    finished = bool(not value["cancel_requested"] and not value["errors"] and clean and result
                    and value["wrapper_returncode"] == 0 and result["ExitCode"] == 0
                    and not result["TimedOut"] and not result["Cancelled"] and final
                    and final["complete_to_configured_deadline"] is True)
    need(value["capture_finished_to_deadline"] is finished, "terminal_completion_contradiction")
    return value, clean, finished


def io_capture_diagnostics(reader, descriptors, expected):
    """Validate explicitly trusted copies; return association, never coverage/rates.

    Missing or invalid emitted/terminal evidence returns incomplete with fixed
    reason codes. Invalid external identities/source inputs raise IOCaptureError.
    No diagnostic output contains paths, commands, credentials or raw record text.
    """
    need(isinstance(descriptors, dict) and BASE_ROLES <= set(descriptors)
         and set(descriptors) <= BASE_ROLES | OPTIONAL_ROLES, "explicit_inventory_required")
    raws, hashes = {}, {}
    for role, item in descriptors.items():
        descriptor(item)
        maximum = MAX_OUTPUT if role == "samples" else 262144 if role == "stderr" else 0 if role == "cancel" else 16 * MIB
        raw = reader.raw(item["path"], maximum)
        need(type(raw) is bytes and len(raw) <= maximum and sha(raw) == item["sha256"], "input_bytes_or_hash_mismatch")
        raws[role], hashes[role] = raw, sha(raw)
    plan, command_sha = context(raws, expected)
    out = {"artifact": "aotg-io-capture-association", "version": 1, "status": "incomplete",
           "producer_association_verified": False, "job_association_verified": False,
           "owned_windows_job_cleanup_verified": False, "capture_finished_to_deadline": False,
           "remote_process_exit_verified": False, "external_identity_authentication_proved": False,
           "coverage_evaluated": False, "rates_computed": False, "quality_accepted": False,
           "adoption_evaluated": False, "sample_count": 0, "cancel_observed": "cancel" in raws,
           "reasons": [], "input_sha256": hashes}
    def attempt(role, operation):
        if role not in raws:
            out["reasons"].append("missing_" + role)
            return None
        try:
            return operation(raws[role])
        except (IOCaptureError, KeyError, TypeError, OverflowError):
            out["reasons"].append("invalid_" + role)
            return None
    launch = attempt("launch", lambda raw: read_launch(raw, plan, expected["plan_sha256"], command_sha))
    receipt = attempt("job_receipt", lambda raw: read_receipt(raw, plan))
    out["job_association_verified"] = receipt is not None
    parsed = attempt("samples", lambda raw: read_rows(raw, plan))
    if parsed is not None:
        meta, samples, final = parsed
        out["sample_count"] = len(samples)
        first = attempt("first_sample", lambda raw: read_first(raw, plan, expected["plan_sha256"], meta, samples[0]))
        out["producer_association_verified"] = launch is not None and first is not None
        if final is None:
            out["reasons"].append("missing_sampler_final")
        if launch is not None:
            checked = attempt("lifecycle_result", lambda raw: read_terminal(raw, plan, expected["plan_sha256"],
                launch, receipt, raws, samples, final, first is not None))
            if checked is not None:
                terminal, clean, finished = checked
                out["owned_windows_job_cleanup_verified"] = clean
                out["cancel_observed"] = out["cancel_observed"] or terminal["cancel_requested"] or bool(receipt and receipt["result"]["Cancelled"])
                if terminal["errors"]:
                    out["reasons"].append("lifecycle_reported_errors")
                if not clean:
                    out["reasons"].append("windows_cleanup_unverified")
                if not finished:
                    out["reasons"].append("configured_deadline_not_completed")
                if "stderr" not in raws:
                    out["reasons"].append("missing_stderr")
                if out["cancel_observed"]:
                    out["reasons"].append("cancellation_observed")
                if not out["reasons"] and out["producer_association_verified"] and out["job_association_verified"] and finished:
                    out["status"] = "associated_terminal_complete"
                    out["capture_finished_to_deadline"] = True
    if "lifecycle_result" not in raws and "missing_lifecycle_result" not in out["reasons"]:
        out["reasons"].append("missing_lifecycle_result")
    return out
