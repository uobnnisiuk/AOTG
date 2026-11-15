#!/usr/bin/env python3
"""Offline private evidence adapter. Never executes candidates or launches tools.

--inputs and optional --authority are independently supplied manifests, each
requiring an out-of-band raw SHA. Authority lives outside generated run roots.
It is an operator/reviewer attestation, NOT authenticated by this program.
Missing authority cannot yield accepted quality. Output is a new exclusive file.
No source-review receipt is created here. Fixtures are never real-run evidence.
"""
import argparse
import ast
import base64
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import types
import zlib

MIB = 1024**2
MAX_FILE = 64 * MIB
MAX_TOTAL = 256 * MIB
COMPLETE = "completed-awaiting-independent-quality"


class EvidenceError(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise EvidenceError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(canonical(value))


def hash_value(value):
    need(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value), "invalid_sha256")
    return value


def number(value, minimum=0):
    need(type(value) in (int, float) and math.isfinite(value) and value >= minimum, "invalid_number")
    return value


def utc(value):
    result = datetime.fromisoformat(value)
    need(result.tzinfo is not None, "timestamp_timezone_missing")
    return result.timestamp()


def no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=no_duplicate_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("nonfinite_json")))


def parent_fd(path):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts and path.name, "absolute_nontraversing_path_required")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


class Reader:
    def __init__(self):
        self.total = 0
        self.files = {}
        self.capture_roots = ()
        self.capture = None

    def raw(self, path, maximum=MAX_FILE):
        path = Path(path)
        directory = parent_fd(path)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
                 "unsafe_or_oversized_input")
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        need(len(raw) <= maximum and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "input_changed_during_read")
        self.total += len(raw)
        need(self.total <= MAX_TOTAL, "total_input_budget_exceeded")
        record = {"sha256": sha(raw), "bytes": len(raw)}
        if self.capture is not None and any(path.is_relative_to(root) for root in self.capture_roots):
            need(self.capture.get(str(path)) == record["sha256"], "raw_capture_not_bound_to_independent_inventory")
        need(str(path) not in self.files or self.files[str(path)] == record, "input_changed_between_reads")
        self.files[str(path)] = record
        return raw

    def pinned(self, descriptor, json_value=True):
        need(isinstance(descriptor, dict) and set(descriptor) == {"path", "sha256"}, "invalid_input_descriptor")
        raw = self.raw(descriptor["path"])
        need(sha(raw) == hash_value(descriptor["sha256"]), "pinned_input_hash_mismatch")
        return parse(raw) if json_value else raw

    def json(self, path):
        value = parse(self.raw(path))
        need(isinstance(value, dict), "expected_json_object")
        return value

    def jsonl(self, path):
        raw = self.raw(path)
        need(not raw or raw.endswith(b"\n"), "partial_jsonl_tail")
        lines = raw.splitlines()
        need(len(lines) <= 20000 and all(lines), "invalid_jsonl_record_count")
        values = [parse(line) for line in lines]
        need(all(isinstance(value, dict) for value in values), "expected_jsonl_objects")
        return values


def load_libraries(reader, source_root, identity):
    """Only the exact independently pinned repository bytes, never input code."""
    package = "_aotg_private_assessment"
    module_names = ("__init__", "artifacts", "field_evidence", "field_client", "quality")
    verified = {}
    for name in module_names:
        relative = "aotg/" + name + ".py"
        raw = reader.raw(Path(source_root) / relative, 2 * MIB)
        need(sha(raw) == identity["aotg_modules"][relative], "trusted_library_hash_mismatch")
        verified[name] = raw
    for name in module_names:
        full = package if name == "__init__" else package + "." + name
        module = types.ModuleType(full)
        module.__file__ = str(Path(source_root) / "aotg" / (name + ".py"))
        module.__package__ = package
        if name == "__init__":
            module.__path__ = []
        sys.modules[full] = module
        exec(compile(verified[name], module.__file__, "exec"), module.__dict__)
    raw = reader.raw(Path(source_root) / "aotg/field_selftest.py", 2 * MIB)
    need(sha(raw) == identity["aotg_modules"]["aotg/field_selftest.py"], "public_selftest_module_hash_mismatch")
    assignments = [node.value for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "_DRIVER" for target in node.targets)]
    need(len(assignments) == 1, "public_selftest_driver_ambiguous")
    driver = ast.literal_eval(assignments[0])
    need(isinstance(driver, str), "public_selftest_driver_not_literal")
    return types.SimpleNamespace(evidence=sys.modules[package + ".field_evidence"],
                                 client=sys.modules[package + ".field_client"],
                                 quality=sys.modules[package + ".quality"], public_driver_sha256=sha(driver.encode()))


def pointer(value, keys):
    need(isinstance(keys, list) and len(keys) <= 16 and all(isinstance(k, (str, int)) for k in keys), "invalid_json_pointer")
    for key in keys:
        value = value[key]
    return value


def success_phase(value):
    return (isinstance(value, dict) and value.get("status") == "ok" and type(value.get("exit_code")) is int
            and value["exit_code"] == 0 and value.get("output_truncated") is False)


def isolation_gate(value, *, full):
    need(value["status"] == "ok" and value["isolation_verified"] is True
         and value["readonly_workspace"] is True and value["dotnet_gc_heap_limit_bytes"] == 512 * MIB,
         "native_isolation_missing")
    limits = value["limits"]
    need(limits == {"cpu_seconds": 60 if full else 52, "file_bytes": 64 * MIB, "descriptors": 128,
                   "processes": 128, "memory_bytes": 8 * 1024**3}, "native_isolation_limits_changed")
    if full:
        need(value["artifact"] == "aotg-offline-isolation" and value["version"] == 1
             and type(value["exit_code"]) is int and value["exit_code"] == 0
             and value["output_truncated"] is False and value["network"] == "new-offline-namespace",
             "native_outer_result_failed")


def decode_quality(stdout):
    need(isinstance(stdout, str) and len(stdout) <= 65536, "native_encoded_output_limit")
    compressed = base64.b64decode(stdout.strip(), validate=True)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, 2 * MIB + 1)
    need(len(raw) <= 2 * MIB and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
         "native_decoded_output_invalid")
    return parse(raw)


class Authority:
    def __init__(self, reader, value, root, generated_roots):
        self.reader, self.value, self.root = reader, value, Path(root)
        need(self.root.is_absolute() and all(not self.root.is_relative_to(p) and not p.is_relative_to(self.root) for p in generated_roots),
             "authority_must_be_outside_generated_roots")

    def file(self, descriptor, json_value=True):
        need(Path(descriptor["path"]).is_relative_to(self.root), "assessment_file_outside_trusted_root")
        return self.reader.pinned(descriptor, json_value)

    def record(self, descriptor):
        raw = self.file(descriptor, False)
        need(raw.strip(), "empty_external_review_record")
        return descriptor


def quality_gate(api, authority, assessment, source_sha, case, verifier_sha, catalog_sha, catalog, expected_replay):
    """Independent input authority plus real outer record and exact native bytes."""
    need(authority is not None and assessment is not None, "independent_assessment_missing")
    receipt = authority.file(assessment["source_review"])
    authority.record(assessment["review_record"])
    expected = {"source_sha256": source_sha, "grader_sha256": verifier_sha, "catalog_sha256": catalog_sha}
    need(all(receipt.get(k) == v for k, v in expected.items()) and receipt.get("independent") is True
         and receipt.get("reviewer") == authority.value["reviewer"]
         and receipt.get("evidence_reference") == assessment["review_reference"], "external_source_review_binding_mismatch")
    # The trusted external receipt is retained even when rejected; unsafe source
    # need never have been executed merely to produce a failing native report.
    if receipt.get("verdict") == "rejected":
        return False, receipt, {"native_grading": "not_required_after_review_rejection"}
    need(receipt.get("verdict") == "accepted", "external_source_review_not_accepted")
    quality = authority.file(assessment["quality"])
    isolated = authority.file(assessment["isolation"])
    isolation_gate(isolated, full=True)
    need(decode_quality(isolated["stdout"]) == quality, "outer_stdout_quality_mismatch")
    replay = assessment["replay"]
    authority.record(replay["execution_record"])
    exact_argv = ["/usr/bin/python3", "-I", "-S", "-B", "-c", expected_replay["driver"],
                  case, expected_replay["source_name"], assessment["isolation_reference"]]
    need(replay["argv"] == exact_argv and digest(replay["argv"]) == isolated["command_sha256"], "native_replay_argv_mismatch")
    authority.file(replay["sandbox_source"], False)
    need(replay["sandbox_source"]["sha256"] == expected_replay["modules"]["aotg/field_sandbox.py"], "native_outer_sandbox_source_mismatch")
    need(replay["source_sha256"] == source_sha and replay["grader_sha256"] == verifier_sha
         and replay["catalog_sha256"] == catalog_sha
         and replay["source_review_sha256"] == assessment["source_review"]["sha256"], "native_staged_inputs_mismatch")
    for item in replay["staged_files"]:
        authority.file(item, False)
    need({replay["source_sha256"], replay["grader_sha256"], replay["catalog_sha256"], replay["source_review_sha256"],
          expected_replay["modules"]["aotg/__init__.py"], expected_replay["modules"]["aotg/artifacts.py"]}
         <= {item["sha256"] for item in replay["staged_files"]}, "native_stage_inventory_incomplete")
    need(quality["artifact"] == "aotg-independent-quality" and quality["version"] == 2 and quality["case_id"] == case
         and all(quality.get(k) == v for k, v in expected.items()), "native_grade_binding_mismatch")
    need(quality["isolation"]["evidence_reference"] == assessment["isolation_reference"], "native_isolation_reference_mismatch")
    gate = quality["source_review"]
    need(gate["status"] == "accepted" and gate["receipt"] == receipt and gate["receipt_sha256"] == digest(receipt),
         "native_embedded_review_mismatch")
    harness, observations, _ = api.quality._harness(next(item for item in catalog["cases"] if item["id"] == case))
    need(quality["harness_sha256"] == sha(harness.encode()), "native_harness_mismatch")
    toolchain = {k: v for k, v in quality["toolchain"].items() if k != "version_probe"}
    need(toolchain == authority.value["toolchains"][case], "native_toolchain_drift")
    behavior = (success_phase(quality["compile"]) and success_phase(quality["execution"])
                and api.quality.grade_observations(quality["execution"]["stdout"], observations) == quality["grading"]
                and quality["grading"]["status"] == "pass")
    accepted = behavior and quality["status"] == "pass" and quality["behavioral_status"] == "pass" and quality["quality_accepted"] is True
    return bool(accepted), receipt, {"native_report_sha256": assessment["quality"]["sha256"],
                                     "isolation_sha256": assessment["isolation"]["sha256"],
                                     "reviewer_identity_verified_by_assembler": False}


def resource_window(samples, start, end, worker):
    need(samples and start < end, "resource_window_missing")
    times = [utc(row["utc"]) for row in samples]
    need(all(a < b for a, b in zip(times, times[1:])), "resource_timestamps_nonmonotonic")
    elapsed = [number(row["elapsed_seconds"]) for row in samples]
    need(all(a < b for a, b in zip(elapsed, elapsed[1:])), "resource_monotonic_clock_regressed")
    left = [i for i, value in enumerate(times) if value <= start]
    right = [i for i, value in enumerate(times) if value >= end]
    need(left and right, "resource_window_not_bracketed")
    first, last = left[-1], right[0]
    selected = samples[first:last + 1]
    temperatures, memory, swap = [], [], []
    initial_gtt = number(samples[0]["gpu"]["mem_info_gtt_used"])
    for row in selected:
        need(row["selected_gpu_bdf"] == worker["gpu"]["bdf"], "resource_gpu_identity_changed")
        temperatures.append(number(row["temperatures_c"]["amdgpu:edge"]))
        need(row["per_gpu_temperatures_c"] and worker["gpu"]["bdf"] in row["per_gpu_temperatures_c"], "gpu_sensors_missing")
        temperatures.extend(number(value["edge"]) for value in row["per_gpu_temperatures_c"].values())
        memory.append(number(row["host_mem_available_bytes"]))
        swap.append(number(row["pswpout"]))
        need(number(row["temperatures_c"]["nvme:Composite"]) < 74.85
             and number(row["temperatures_c"]["nvme:Sensor 2"]) < 85, "nvme_temperature_failed")
        need(all(key in row["alarms"] for key in worker["required_alarm_keys"])
             and all(type(v) is int and v == 0 for v in row["alarms"].values()), "hardware_alarm_or_missing_sensor")
        gpu = row["gpu"]
        need(number(gpu["mem_info_vram_total"]) - number(gpu["mem_info_vram_used"]) >= 8 * 1024**3
             and number(gpu["mem_info_gtt_used"]) - initial_gtt <= 1024**3, "gpu_resource_limit")
        used = number(row["swap_bytes"]["SwapTotal"]) - number(row["swap_bytes"]["SwapFree"])
        need(0 <= used < 16 * MIB and number(row["disk_free_bytes"]) >= 150 * 1024**3, "swap_or_disk_limit")
    need(all(value == swap[0] for value in swap), "swapout_change_or_reset")
    utc_gap = max(b - a for a, b in zip(times[first:last + 1], times[first + 1:last + 1]))
    elapsed_gap = max(b - a for a, b in zip(elapsed[first:last + 1], elapsed[first + 1:last + 1]))
    coverage = {"scope": "bracketed_actual_samples", "first_index": first, "last_index": last,
                "first_utc": samples[first]["utc"], "last_utc": samples[last]["utc"],
                "arm_start_epoch": start, "arm_end_epoch": end, "samples": len(selected),
                "max_gap_seconds": max(utc_gap, elapsed_gap), "max_utc_gap_seconds": utc_gap,
                "max_monotonic_gap_seconds": elapsed_gap,
                "continuous_observation_claimed": False}
    return {"peak_temperature_c": max(temperatures), "min_mem_available_bytes": min(memory),
            "swapout_delta_bytes": 0, "gpu_errors": None, "io_errors": None}, coverage


def public_selftest(events, assessment, source_sha, workload, module_sha, driver_sha):
    record = assessment["public_selftest"]
    need(type(record["event_index"]) is int and record["event_index"] >= 0, "invalid_selftest_event_index")
    event = events[record["event_index"]]
    need(event["type"] == "tool_use" and event["part"]["tool"] == "bash"
         and event["part"]["state"]["input"]["command"] == "./verify.sh"
         and event["part"]["state"]["status"] == "completed"
         and type(event["part"]["state"]["metadata"]["exit"]) is int
         and event["part"]["state"]["metadata"]["exit"] == 0, "public_selftest_event_mismatch")
    output = pointer(event, record["json_path"])
    need(isinstance(output, str) and sha(output.encode()) == record["output_sha256"], "public_selftest_output_missing_or_changed")
    report = parse(output)
    tests = [f for f in workload["public_files"] if f["name"] != "verify.sh"]
    need(len(tests) == 1 and report["artifact"] == "aotg-public-selftest" and report["version"] == 1
         and report["status"] == "pass" and report["independent"] is False and report["quality_accepted"] is False
         and report["source_sha256"] == source_sha and report["public_test_sha256"] == tests[0]["sha256"]
         and report["driver_sha256"] == record["driver_sha256"] == driver_sha
         and record["module_sha256"] == module_sha, "public_selftest_report_mismatch")
    need(success_phase(report["compile"]) and success_phase(report["execution"]), "public_native_phases_failed")
    isolation_gate(report["isolation"], full=False)
    return record["event_index"]


def jobs_gate(reader, authority, client, spec):
    need(authority is not None, "external_run_assessment_missing")
    value = authority.value
    authority.record(value["execution_record"])
    need(value["complete_job_inventory"] is True and value["jobs"], "owned_job_inventory_missing")
    inventory = value["job_inventory"]
    before = authority.file(inventory["before"])
    after = authority.file(inventory["after"])
    launch = authority.file(inventory["launch"])
    completion = authority.file(inventory["completion"])
    snapshots = []
    for snapshot, phase in ((before, "before-launch"), (after, "after-exit")):
        need(snapshot["artifact"] == "aotg-owned-job-snapshot" and snapshot["version"] == 1
             and snapshot["phase"] == phase and snapshot["run_id"] == client["run_id"]
             and snapshot["client_plan_sha256"] == digest(client)
             and snapshot["jobs_root"] == client["windows_transport"]["linux_root"], "job_snapshot_scope_mismatch")
        files = {}
        for item in snapshot["files"]:
            need(isinstance(item["name"], str) and Path(item["name"]).name == item["name"]
                 and item["name"] not in files, "invalid_job_snapshot_name")
            files[item["name"]] = hash_value(item["sha256"])
        snapshots.append(files)
    old, current = snapshots
    need(all(current.get(name) == value for name, value in old.items()), "preexisting_job_file_changed")
    added = {name: value for name, value in current.items() if name not in old}
    need(added and all(re.fullmatch(r"[0-9a-f]{24}\.(?:plan\.json|result\.json|cancel)", name) for name in added),
         "unexpected_new_job_files")
    exact_command = [client["namespace_tools"]["python"], "-I", "-B", spec["client_runner"]["path"],
                     "--plan", spec["client_plan"]["path"], "--execute-approved-plan-sha256", digest(client)]
    need(launch["artifact"] == "aotg-field-client-launch" and completion["artifact"] == "aotg-field-client-exit"
         and launch["version"] == completion["version"] == 1 and launch["argv"] == exact_command
         and launch["runner_sha256"] == client["runner_sha256"], "client_launch_identity_missing")
    for item in (launch, completion):
        need(item["run_id"] == client["run_id"] and item["client_plan_sha256"] == digest(client)
             and type(item["pid"]) is int and item["pid"] > 0
             and isinstance(item["pid_start_ticks"], str) and item["pid_start_ticks"].isdigit(), "client_lifetime_identity_missing")
    need(completion["pid"] == launch["pid"] and completion["pid_start_ticks"] == launch["pid_start_ticks"]
         and completion["exit_code"] == 0 and completion["summary_sha256"] == value["client_summary_sha256"]
         and utc(before["observed_utc"]) <= utc(launch["observed_utc"]) <= utc(completion["observed_utc"]) <= utc(after["observed_utc"]),
         "client_lifetime_or_snapshot_order_mismatch")
    seen = set()
    covered_files, roles = set(), set()
    transport = client["windows_transport"]
    for item in value["jobs"]:
        job = authority.file(item["plan"])
        receipt = authority.file(item["receipt"])
        need(item["plan"]["sha256"] not in seen, "duplicate_job_receipt")
        seen.add(item["plan"]["sha256"])
        need(job["artifact"] == "aotg-windows-ssh-job" and job["version"] == 1
             and job["wrapper_sha256"] == transport["wrapper"]["sha256"]
             and job["helper"] == {"path": transport["helper"]["windows_path"], "sha256": transport["helper"]["sha256"]}
             and job["executable"] == {"path": transport["ssh"]["windows_path"], "sha256": transport["ssh"]["sha256"]}, "job_transport_mismatch")
        control = [*client["ssh"][1:], "python3 -B -"]
        relay = [*client["ssh"][1:-1], "-W", "127.0.0.1:19480", client["ssh"][-1]]
        need(job["argv"] in (control, relay), "job_route_mismatch")
        role = "control" if job["argv"] == control else "relay"
        roles.add(role)
        plan_name, result_name = Path(item["plan"]["path"]).name, Path(item["receipt"]["path"]).name
        need(plan_name.endswith(".plan.json") and result_name == plan_name.removesuffix(".plan.json") + ".result.json"
             and added.get(plan_name) == item["plan"]["sha256"] and added.get(result_name) == item["receipt"]["sha256"],
             "job_not_in_observed_new_file_delta")
        covered_files.update((plan_name, result_name))
        need(1 <= number(job["wall_seconds"]) <= 2100, "job_budget_mismatch")
        need(receipt["artifact"] == "aotg-windows-ssh-job-result" and receipt["version"] == 1
             and receipt["plan_sha256"] == item["plan"]["sha256"]
             and receipt["helper_sha256"] == transport["helper"]["sha256"]
             and receipt["wrapper_sha256"] == transport["wrapper"]["sha256"], "job_receipt_binding_mismatch")
        result = receipt["result"]
        need(result["JobEmpty"] is True and result["ExecutableSha256"] == transport["ssh"]["sha256"]
             and result["TimedOut"] is False, "owned_job_cleanup_failed")
        if role == "control":
            need(result["ExitCode"] == 0 and result["Cancelled"] is False, "control_job_failed")
        cancel = plan_name.removesuffix(".plan.json") + ".cancel"
        if cancel in added:
            need(added[cancel] == sha(b""), "unexpected_cancel_marker_contents")
            covered_files.add(cancel)
    need(covered_files == set(added) and roles == {"control", "relay"}, "global_job_inventory_incomplete")
    return True


def io_diagnostics(reader, descriptor, start, end, max_gap):
    """Report observed coverage only. No interpolation, rates or causal claims."""
    raw = reader.pinned(descriptor, False)
    complete_lines = raw.splitlines()
    rows = [parse(line) for line in complete_lines if line]
    need(len(rows) <= 4000, "supplemental_io_record_limit")
    samples = [row for row in rows if row.get("artifact") == "aotg-supplemental-io-sample"]
    finals = [row for row in rows if row.get("artifact") == "aotg-supplemental-io-final"]
    relevant = [row for row in samples if utc(row["utc_read_start"]) <= end and utc(row["utc_read_end"]) >= start]
    # Also retain bracketing observations, without inventing endpoint counters.
    earlier = [row for row in samples if utc(row["utc_read_end"]) <= start]
    later = [row for row in samples if utc(row["utc_read_start"]) >= end]
    selected = ([earlier[-1]] if earlier else []) + relevant + ([later[0]] if later else [])
    gaps = [(b["monotonic_read_start_ns"] - a["monotonic_read_start_ns"]) / 1e9 for a, b in zip(selected, selected[1:])]
    identity_stable = bool(selected) and all(row["device_identity"] == selected[0]["device_identity"]
                          and row["cpu"]["boot_time_unix_seconds"] == selected[0]["cpu"]["boot_time_unix_seconds"] for row in selected)
    complete = (bool(earlier and later and gaps) and all(0 < gap <= max_gap for gap in gaps)
                and identity_stable and len(finals) == 1 and raw.endswith(b"\n")
                and not any(row["counter_reset_or_decrease_detected"] for row in selected))
    return {"capture": descriptor, "sample_count": len(samples), "overlapping_samples": len(relevant),
            "start_bracket_observed": bool(earlier), "end_bracket_observed": bool(later),
            "first_utc": samples[0]["utc_read_start"] if samples else None,
            "last_utc": samples[-1]["utc_read_end"] if samples else None,
            "final_record_present": len(finals) == 1 and raw.endswith(b"\n"),
            "max_gap_seconds": max(gaps) if gaps else None, "coverage_complete": complete,
            "status": "coverage_only_unverified_producer", "producer_identity_verified": False, "owned_job_verified": False,
            "counter_decrease_rows": [row["index"] for row in samples if row["counter_reset_or_decrease_detected"]],
            "causal_bottleneck_claimed": False, "rates_computed": False}


def assemble(spec, reader, authority_value=None):
    need(spec["artifact"] == "aotg-field-assessment-inputs" and spec["version"] == 1, "wrong_assembly_spec")
    field = reader.pinned(spec["field_plan"])
    client = reader.pinned(spec["client_plan"])
    worker = reader.pinned(spec["worker_plan"])
    identity = reader.pinned(spec["identity"])
    catalog = reader.pinned(spec["catalog"])
    base_config = reader.pinned(spec["baseline_config"])
    reader.pinned(spec["client_runner"], False)
    need(spec["client_runner"]["sha256"] == client["runner_sha256"], "client_runner_source_mismatch")
    policy = reader.pinned(spec["assessment_policy"])
    need(policy == {"artifact": "aotg-supplemental-assessment-policy", "version": 1,
                    "field_plan_sha256": digest(field), "resource_max_gap_seconds": 2.0,
                    "io_max_gap_seconds": 2.5, "window": "evo_ready_through_finished_conservative"},
         "unreviewed_assessment_policy")
    guide = reader.pinned(spec["assessment_guide"], False).decode("utf-8").replace("\r\n", "\n")
    driver_blocks = re.findall(r"```python\n(.*?)\n```", guide, re.S)
    need(len(driver_blocks) == 1, "frozen_assessment_driver_missing_or_ambiguous")
    replay_driver = driver_blocks[0] + "\n"
    api = load_libraries(reader, spec["source_root"], identity)
    api.evidence.validate_field_plan(field)
    need(field["identity_sha256"] == digest(identity) and field["verifier_sha256"] == identity["aotg_modules"]["aotg/quality.py"],
         "frozen_identity_mismatch")
    need(client["worker_plan_sha256"] == spec["worker_plan"]["sha256"] and worker["field_plan"]["sha256"] == spec["field_plan"]["sha256"]
         and worker["schedule"] == client["schedule"] == field["schedule"] and client["run_id"] == worker["run_id"], "frozen_plan_join_mismatch")
    need(worker["engine"]["sha256"] == identity["engine"]["sha256"]
         and worker["active_config"]["sha256"] == identity["active_config_sha256"]
         and spec["baseline_config"]["sha256"] == identity["active_config_sha256"]
         and client["runner_sha256"] == identity["measurement_transport"]["k8_runner_sha256"], "runtime_identity_pin_mismatch")
    profiles = {row["id"]: row for row in worker["profiles"]}
    need(field["candidates"] == [{"id": row["id"], "profile_sha256": row["profile_sha256"]} for row in worker["profiles"]], "frozen_profile_mismatch")
    for workload in field["workloads"]:
        need(workload["input_sha256"] == digest(client["workloads"][workload["id"]])
             and workload["tests_sha256"] == spec["catalog"]["sha256"], "frozen_workload_mismatch")
    kroot, eroot = Path(spec["k8_root"]), Path(spec["evo_root"])
    need(kroot.is_absolute() and eroot.is_absolute() and kroot != eroot, "invalid_generated_roots")
    authority = None
    if authority_value is not None:
        authority = Authority(reader, authority_value, spec["trusted_root"], (kroot, eroot))
        need(authority_value["artifact"] == "aotg-independent-assessment-authority" and authority_value["version"] == 1
             and authority_value["run_id"] == worker["run_id"] and authority_value["field_plan_sha256"] == digest(field)
             and authority_value["client_plan_sha256"] == digest(client)
             and authority_value["worker_plan_sha256"] == spec["worker_plan"]["sha256"], "assessment_authority_run_mismatch")
        authority.record(authority_value["capture_association_record"])
        captures = authority_value["captured_files"]
        need(isinstance(captures, list) and len(captures) <= 4096, "capture_inventory_limit")
        mapping = {}
        for item in captures:
            path = Path(item["path"])
            need(any(path.is_relative_to(root) for root in (kroot, eroot)) and str(path) not in mapping,
                 "invalid_or_duplicate_capture_path")
            mapping[str(path)] = hash_value(item["sha256"])
        reader.capture_roots, reader.capture = (kroot, eroot), mapping
    ledger, trials, global_errors = [], [], []

    def optional(path, errors, mode="json"):
        try:
            return getattr(reader, mode)(path)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
            errors.append({"reason": str(error) if isinstance(error, EvidenceError) else type(error).__name__, "path": str(path)})
            return None

    esummary = optional(eroot / "summary.json", global_errors)
    ksummary = optional(kroot / "summary.json", global_errors)
    samples = optional(eroot / "resources.jsonl", global_errors, "jsonl")
    kernel = optional(eroot / "kernel-final.json", global_errors)
    global_ok = False
    try:
        need(esummary is not None and ksummary is not None and samples is not None and kernel is not None, "run_completion_evidence_missing")
        need(esummary["artifact"] == "aotg-evo-worker-result" and esummary["version"] == 1
             and esummary["run_id"] == worker["run_id"] and esummary["plan_sha256"] == spec["worker_plan"]["sha256"]
             and ksummary["artifact"] == "aotg-k8-field-run" and ksummary["version"] == 1
             and ksummary["plan_sha256"] == digest(client), "run_summary_binding_mismatch")
        need(esummary["status"] == ksummary["status"] == COMPLETE and ksummary["cleanup_errors"] == []
             and ksummary["total_deadline_exceeded"] is False and "final_kernel_scan_error" not in esummary, "run_completion_failed")
        need(authority is not None, "external_run_assessment_missing")
        need(authority_value["worker_summary_sha256"] == reader.files[str(eroot / "summary.json")]["sha256"]
             and authority_value["client_summary_sha256"] == reader.files[str(kroot / "summary.json")]["sha256"]
             and authority_value["worker_source_sha256"] == identity["worker_sha256"]
             and authority_value["client_source_sha256"] == client["runner_sha256"], "external_execution_binding_mismatch")
        jobs_gate(reader, authority, client, spec)
        authority.record(authority_value["kernel_review"]["record"])
        need(authority_value["kernel_review"]["scan_sha256"] == reader.files[str(eroot / "kernel-final.json")]["sha256"]
             and authority_value["kernel_review"]["worker_sha256"] == identity["worker_sha256"]
             and authority_value["kernel_review"]["telemetry_sha256"] == worker["telemetry"]["sha256"]
             and authority_value["kernel_review"]["coverage_accepted"] is True,
             "kernel_coverage_review_missing")
        need(kernel["status"] == "clear" and kernel["errors"] == [] and kernel["since"] == worker["kernel_since"]
             and utc(kernel["scanned_at"]) >= max(utc(row["finished_at"]) for row in esummary["arms"])
             and utc(kernel["scanned_at"]) <= utc(esummary["finished_at"]), "kernel_scan_missing_or_failed")
        hash_value(kernel["output_sha256"])
        global_ok = True
    except (ValueError, KeyError, TypeError, OSError) as error:
        global_errors.append({"reason": str(error) if isinstance(error, EvidenceError) else type(error).__name__})
    for row in field["schedule"]:
        index = row["index"]
        entry = {"index": index, "candidate_id": row["candidate_id"], "workload_id": row["workload_id"],
                 "missing_or_conflicting": [], "observed_terminal_status": {}, "normalized": False, "provenance": {}}
        ledger.append(entry)
        errors, provenance = entry["missing_or_conflicting"], entry["provenance"]
        ka, ea = kroot / ("arm-%02d" % index), eroot / ("arm-%03d" % index)
        paths = {"kresult": ka / "result.json", "kready": ka / "ready.json", "coding": ka / "coding/result.json",
                 "short": ka / "short-answer.json", "ack": ka / "done-receipt.json", "eresult": ea / "result.json",
                 "eready": ea / "ready.json", "done": eroot / ("done-%d.json" % index),
                 "server": ea / "server-ready.json", "config": ea / "config.json"}
        values = {name: optional(path, errors) for name, path in paths.items()}
        requests = optional(ka / "requests.jsonl", errors, "jsonl")
        raw_events = optional(ka / "coding/private/events.jsonl", errors, "raw")
        optional(ka / "coding/private/stderr.log", errors, "raw")
        workload = client["workloads"][row["workload_id"]]
        need(re.fullmatch(r"[A-Za-z0-9_.-]+", workload["source"]["name"]), "unsafe_source_name")
        raw_source = optional(ka / "coding/work" / workload["source"]["name"], errors, "raw")
        for which in ("kresult", "eresult", "coding"):
            if values[which] is not None:
                entry["observed_terminal_status"][which] = values[which].get("status")
        try:
            need(raw_source is not None, "source_artifact_missing_omit_unrepresentable_row")
            need(all(value is not None for value in values.values()) and requests is not None and raw_events is not None,
                 "arm_evidence_missing")
            kr, er, coding = values["kresult"], values["eresult"], values["coding"]
            for name in ("kresult", "eresult", "kready", "eready", "done"):
                need(all(values[name][key] == row[key] for key in ("index", "candidate_id", "workload_id")), "arm_schedule_swap_or_mismatch")
            profile = profiles[row["candidate_id"]]
            need(values["kready"] == values["eready"] and values["eready"]["run_id"] == worker["run_id"]
                 and values["eready"]["plan_sha256"] == spec["worker_plan"]["sha256"]
                 and values["eready"]["profile_sha256"] == er["profile_sha256"] == profile["profile_sha256"]
                 and values["eready"]["prefill"] == er["prefill"] == profile["prefill"], "observed_profile_or_identity_mismatch")
            need(er["native_exe_sha256"] == worker["engine"]["sha256"] and type(er["native_pid"]) is int
                 and er["server_pid"] == values["server"]["pid"] and values["server"]["model_state"] == "ready"
                 and values["server"]["api_state"] == "ready" and values["server"]["bound_host"] == "127.0.0.1"
                 and values["server"]["bound_port"] == 19480, "observed_engine_identity_missing")
            need(er["config_sha256"] == reader.files[str(paths["config"])]["sha256"], "actual_engine_config_hash_mismatch")
            expected_config = json.loads(json.dumps(base_config))
            remote_arm = Path(worker["task_root"]) / ("arm-%03d" % index)
            expected_config["user_args"][expected_config["user_args"].index("--prefill") + 1] = str(profile["prefill"])
            for key in ("args", "args_written"):
                expected_config[key][expected_config[key].index("--expert-profile") + 1] = str(remote_arm / "expert-profile.bin")
            expected_config.update(log=str(remote_arm / "logs/engine-private.log"), host="127.0.0.1", port=19480, parallel=1, open_browser=False)
            need(values["config"] == expected_config, "actual_engine_config_differs_from_frozen_candidate")
            need(kr in ksummary["arms"] and er in esummary["arms"], "summary_arm_mismatch")
            need(er["k8_evidence_sha256"] == digest(kr) == values["done"]["evidence_sha256"]
                 and values["done"]["run_id"] == worker["run_id"] and values["done"]["plan_sha256"] == spec["worker_plan"]["sha256"]
                 and values["ack"] == {"written": True}, "completion_private_hash_join_failed")
            need(kr["client_result_sha256"] == digest(coding) and kr["short_result_sha256"] == digest(values["short"]), "client_result_hash_join_failed")
            need(kr["requests_complete"] is True and kr["requests"] == requests and kr["cleanup_errors"] == [], "request_capture_or_cleanup_incomplete")
            source_sha = sha(raw_source)
            need(coding["artifact"] == "aotg-opencode-work" and coding["version"] == 1 and coding["workload_id"] == workload["id"]
                 and coding["source_sha256_after"] == source_sha and coding["source_sha256_before"] == workload["source"]["sha256"]
                 and coding["source_name"] == workload["source"]["name"], "final_source_binding_mismatch")
            need(coding["client_sha256"] == identity["opencode"]["sha256"] and coding["profile_sha256"] == identity["profile_sha256"]
                 and coding["prompt_sha256"] == workload["prompt"]["sha256"], "client_execution_inputs_mismatch")
            protected = {item["name"]: item["sha256"] for item in workload["public_files"]}
            need(coding["public_selftests_unchanged"] is True and coding["public_selftest_sha256"] == protected, "public_test_tampering")
            for name, expected in protected.items():
                need(re.fullmatch(r"[A-Za-z0-9_.-]+", name), "unsafe_public_name")
                need(sha(reader.raw(ka / "coding/work" / name, MIB)) == expected, "public_test_bytes_changed")
            need(coding["private_events_sha256"] == sha(raw_events), "event_evidence_hash_mismatch")
            summary = api.client.summarize_events(raw_events, Path(client["output_root"]) / ("arm-%02d/coding/work" % index),
                                                  coding["source_name"], [coding["source_name"], *protected])
            need(all(coding[key] == value for key, value in summary.items()), "client_event_summary_mismatch")
            need(summary["invalid_event_lines"] == summary["client_errors"] == 0 and summary["tool_policy_violations"] == []
                 and summary["final_response_present"] is True and summary["selftest_pass_reported"] is True
                 and summary["selftest_after_last_edit"] is True and summary["step_limit_summary"] is False,
                 "client_event_contract_failed")
            need(coding["exit_code"] == 0 and coding["output_truncated"] is False and coding["limits"]["seconds"] == client["task_seconds"]
                 and coding["limits"]["steps"] == client["max_steps"] and summary["steps"] <= client["max_steps"]
                 and 0 < number(coding["seconds"]) <= client["task_seconds"] and coding["seconds"] == kr["seconds"], "client_bounds_failed")
            namespace = coding["isolation"]["namespace"]
            need(coding["isolation"]["pid_namespace_verified"] is True and coding["isolation"]["cleanup_scope"] == "dedicated-pid-namespace"
                 and namespace["protocol"] == "aotg-pid-namespace-v1" and namespace["pid"] == 1
                 and namespace["no_new_privs"] is True and namespace["capabilities_dropped"] is True, "client_namespace_unverified")
            need(values["short"]["status"] == "completed" and values["short"]["content"].strip() == "42", "fixed_primer_failed")
            need(1 <= len(requests) <= client["max_requests"] and [r["index"] for r in requests] == list(range(len(requests))), "request_sequence_missing")
            for request in requests:
                need(request["kind"] == "aotg-proxy-request-v1" and request["status"] == "completed" and request["sse_done"] is True,
                     "request_failed_or_incomplete")
                need(request["fixed_sampling"] == {"temperature": 0, "top_p": 1, "top_k": 20, "min_p": 0,
                     "seed": 4242, "presence_penalty": 0, "frequency_penalty": 0, "repeat_penalty": 1,
                     "cache_prompt": False, "max_tokens": 1024}, "request_sampling_mismatch")
                hash_value(request["request_sha256"]); hash_value(request["response_sha256"])
            provenance["requests"] = requests
            provenance["metric_semantics"] = "Only client invocation wall time is a task metric; request TTFT/usage/timings remain separate"
            start, end = utc(values["eready"]["ready_at"]), utc(er["finished_at"])
            resources, coverage = resource_window(samples, start, end, worker)
            coverage["scope"] = "evo_ready_through_finished_task_and_cleanup_conservative"
            provenance["resource_coverage"] = coverage
            provenance["resource_coverage_sha256"] = digest(coverage)
            provenance["io_diagnostics"] = []
            for capture in spec.get("supplemental_io", []):
                try:
                    provenance["io_diagnostics"].append(io_diagnostics(reader, capture, start, end, policy["io_max_gap_seconds"]))
                except (OSError, ValueError, KeyError, TypeError) as error:
                    provenance["io_diagnostics"].append({"capture": capture, "incomplete": True, "reason": type(error).__name__})
            assessment = authority_value["arms"].get(str(index)) if authority_value is not None else None
            correctness = receipt = None
            compatibility = False
            try:
                correctness, receipt, extra = quality_gate(api, authority, assessment, source_sha, workload["id"],
                        field["verifier_sha256"], spec["catalog"]["sha256"], catalog,
                        {"driver": replay_driver, "source_name": workload["source"]["name"], "modules": identity["aotg_modules"]})
                provenance["quality"] = extra
                event_index = public_selftest([parse(line) for line in raw_events.splitlines()], assessment, source_sha, workload,
                                 identity["aotg_modules"]["aotg/field_selftest.py"], api.public_driver_sha256)
                need(event_index == max(t["event_index"] for t in summary["tool_calls"] if t["tool"] == "bash"), "public_report_not_last_selftest")
                compatibility = True
            except (OSError, ValueError, KeyError, TypeError, IndexError, StopIteration) as error:
                errors.append({"reason": str(error) if isinstance(error, EvidenceError) else type(error).__name__, "stage": "independent_quality"})
            stable = None
            if global_ok:
                try:
                    need(coverage["max_gap_seconds"] <= policy["resource_max_gap_seconds"], "resource_sampling_gap_exceeds_frozen_policy")
                    resources.update(gpu_errors=0, io_errors=0)
                    stable = True
                except (OSError, ValueError, KeyError, TypeError) as error:
                    errors.append({"reason": str(error) if isinstance(error, EvidenceError) else type(error).__name__, "stage": "resource_review"})
            complete = (er["status"] == kr["status"] == coding["status"] == COMPLETE and values["done"]["status"] == "completed")
            checks = {"correctness": correctness, "tool_compatibility": compatibility if assessment is not None else None,
                      "completed": complete, "stability": stable}
            frozen_workload = next(w for w in field["workloads"] if w["id"] == workload["id"])
            quality = api.evidence.quality_record(input_sha256=frozen_workload["input_sha256"], tests_sha256=frozen_workload["tests_sha256"],
                      verifier_sha256=field["verifier_sha256"], source_sha256=source_sha, independent=receipt is not None,
                      checks=checks, source_review=receipt) if receipt is not None else None
            passed = global_ok and not errors and all(v is True for v in checks.values())
            trial = {"index": index, "candidate_id": row["candidate_id"], "workload_id": row["workload_id"],
                     "identity_sha256": field["identity_sha256"], "profile_sha256": er["profile_sha256"], "source_sha256": source_sha,
                     "cache_cohort": frozen_workload["cache_cohort"], "status": "passed" if passed else "failed" if correctness is False else "stopped",
                     "reason": "verified_observations" if passed else "independent_quality_failed" if correctness is False else "assessment_incomplete",
                     "metrics": {"wall_seconds": coding["seconds"]}, "resources": resources, "quality": quality}
            trials.append(trial)
            entry["normalized"] = True
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            errors.append({"reason": str(error) if isinstance(error, EvidenceError) else type(error).__name__})
    run = decision = None
    try:
        need(esummary is not None and esummary.get("run_id") == worker["run_id"]
             and esummary.get("plan_sha256") == spec["worker_plan"]["sha256"], "observed_total_elapsed_missing")
        elapsed = number(esummary["wall_seconds"])
        run = {"artifact": "aotg-field-run", "version": 1, "plan": field, "plan_sha256": digest(field),
               "elapsed_seconds": elapsed, "trials": trials}
        decision = api.evidence.compare_field_run(run)
    except (ValueError, KeyError, TypeError) as error:
        global_errors.append({"reason": str(error) if isinstance(error, EvidenceError) else type(error).__name__, "stage": "comparison"})
    return {"artifact": "aotg-private-field-assessment", "version": 1, "run_id": worker["run_id"],
            "inputs_sha256": digest(spec), "authority_sha256": digest(authority_value) if authority_value is not None else None,
            "authority_identity_authenticated_by_program": False, "global_errors": global_errors, "ledger": ledger,
            "run": run, "decision": decision, "raw_files": reader.files,
            "measurement_generated": False, "deployment_verified": False, "goal_complete": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--authority")
    parser.add_argument("--authority-sha256")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    need(bool(args.authority) == bool(args.authority_sha256), "authority_requires_explicit_hash")
    reader = Reader()
    spec = reader.pinned({"path": args.inputs, "sha256": args.inputs_sha256})
    authority = reader.pinned({"path": args.authority, "sha256": args.authority_sha256}) if args.authority else None
    if args.authority:
        need(Path(args.authority).is_relative_to(Path(spec["trusted_root"])), "authority_index_outside_trusted_root")
    result = assemble(spec, reader, authority)
    destination = Path(args.output)
    need(str(destination) not in reader.files and not any(destination.is_relative_to(Path(spec[key])) for key in ("k8_root", "evo_root")),
         "output_must_not_modify_original_evidence")
    directory = parent_fd(destination)
    try:
        fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(result) + b"\n"); stream.flush(); os.fsync(stream.fileno())
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({"output_sha256": digest(result), "decision": result["decision"]["status"] if result["decision"] else "incomplete"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
