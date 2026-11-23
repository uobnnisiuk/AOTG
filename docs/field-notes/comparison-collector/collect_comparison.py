"""Private post-restoration evidence receiver; default execution is preview only.

The integrating controller must verify this source and collector_remote.py before
import, validate the approved run/transport context, and supply one bounded streaming
transport callback. This module never launches SSH, authenticates or controls a service.
"""
import base64
import hashlib
import math
import os
from pathlib import Path, PureWindowsPath
from datetime import datetime
import re
import stat
import time
import types

REMOTE_SOURCE_SHA256 = "22a8667bd5f935403e85ebbce6a6f8dbfaeddd00137e6241448df87d074ddf5d"


def load_protocol():
    """Load exact companion bytes, never a stale bytecode/cache or arbitrary import."""
    path = Path(__file__).absolute().with_name("collector_remote.py")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 128 * 1024:
                raise ValueError("Invalid pinned collector source")
            raw = stream.read(128 * 1024 + 1); after = os.fstat(stream.fileno())
            signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_nlink)
            if signature(before) != signature(after) or hashlib.sha256(raw).hexdigest() != REMOTE_SOURCE_SHA256:
                raise ValueError("Pinned collector source changed")
    finally:
        os.close(directory)
    module = types.ModuleType("_aotg_pinned_collector_protocol")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


protocol = load_protocol()

LIMITS = protocol.LIMITS
need = protocol.need
CollectionError = protocol.CollectionError
canon = protocol.canon
sha = protocol.sha
parse = protocol.parse


def exact(value, keys, reason):
    need(isinstance(value, dict) and set(value) == set(keys), reason)


def finite(value, minimum=0, maximum=90):
    return type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum


def hash_value(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def build_payload(request, source, source_sha256):
    protocol.validate(request)
    need(type(source) is bytes and len(source) <= 128 * 1024
         and source_sha256 == REMOTE_SOURCE_SHA256 and sha(source) == source_sha256, "remote_source_pin")
    # Source is fixed and reviewed, not generated from the workload. JSON is data.
    prefix = b"import json\nCONFIG=json.loads(" + repr(canon(request)).encode("ascii") + b")\n"
    payload = prefix + source
    need(len(payload) <= 256 * 1024, "payload_limit")
    return payload


def validate_seed(seed):
    """Only the already-approved transport projection; no endpoint discovery."""
    need(isinstance(seed, dict) and isinstance(seed.get("windows_transport"), dict), "transport_seed")
    t = seed["windows_transport"]
    for role in ("wrapper", "helper", "ssh"):
        need(isinstance(t.get(role), dict) and hash_value(t[role].get("sha256")), "transport_source_pin")
    for role in ("helper", "ssh"):
        value = t[role].get("windows_path")
        need(type(value) is str and PureWindowsPath(value).is_absolute() and ".." not in PureWindowsPath(value).parts
             and "\0" not in value, "transport_absolute_path")
    need(type(t.get("windows_root")) is str and PureWindowsPath(t["windows_root"]).is_absolute()
         and ".." not in PureWindowsPath(t["windows_root"]).parts, "transport_job_root")
    ssh = seed.get("ssh")
    need(isinstance(ssh, list) and 2 <= len(ssh) <= 123 and all(type(x) is str and 0 < len(x) <= 4096 and "\0" not in x for x in ssh)
         and ssh[0] == t["ssh"].get("path") and all(x in ssh for x in ("-T", "BatchMode=yes", "ForwardAgent=no")),
         "existing_noninteractive_ssh_route")


def validate_transport(seed, response, payload_sha, stdout_sha, stderr_sha):
    """Validate raw native Job evidence; JobEmpty is Windows containment only."""
    validate_seed(seed)
    exact(response, {"job_plan_bytes", "receipt_bytes", "wrapper_returncode", "stdout_sha256",
                     "stderr_sha256", "payload_sha256", "callback_error"}, "transport_response_fields")
    need(response["callback_error"] is None or (type(response["callback_error"]) is str
         and 0 < len(response["callback_error"]) <= 128), "callback_error_field")
    for key in ("job_plan_bytes", "receipt_bytes"):
        need(type(response[key]) is bytes and len(response[key]) <= 65536, "transport_metadata_limit")
    need(response["payload_sha256"] == payload_sha and response["stdout_sha256"] == stdout_sha
         and response["stderr_sha256"] == stderr_sha, "transport_stream_hash")
    job, receipt = parse(response["job_plan_bytes"]), parse(response["receipt_bytes"])
    t = seed["windows_transport"]
    ssh = seed["ssh"]
    need(isinstance(ssh, list) and len(ssh) >= 2 and all(type(x) is str and "\0" not in x for x in ssh),
         "existing_ssh_argv_required")
    exact(job, {"artifact", "version", "wrapper_sha256", "helper", "executable", "argv", "cwd",
                "wall_seconds", "cancel_path", "result_path"}, "job_fields")
    expected = {"artifact": "aotg-windows-ssh-job", "version": 1,
                "wrapper_sha256": t["wrapper"]["sha256"],
                "helper": {"path": t["helper"]["windows_path"], "sha256": t["helper"]["sha256"]},
                "executable": {"path": t["ssh"]["windows_path"], "sha256": t["ssh"]["sha256"]},
                "argv": ssh[1:] + ["/usr/bin/python3.14", "-I", "-S", "-B", "-"],
                "cwd": t["windows_root"], "wall_seconds": LIMITS["transport_seconds"]}
    need(all(type(job[k]) is type(v) and job[k] == v for k, v in expected.items()), "job_route_or_pin")
    root = PureWindowsPath(t["windows_root"])
    cancel, result = PureWindowsPath(job["cancel_path"]), PureWindowsPath(job["result_path"])
    need(root.is_absolute() and cancel.parent == result.parent == root
         and re.fullmatch(r"[a-f0-9]{24}\.cancel", cancel.name)
         and result.name == cancel.stem + ".result.json", "dedicated_job_files")
    exact(receipt, {"artifact", "version", "plan_sha256", "helper_sha256", "wrapper_sha256", "result"},
          "receipt_fields")
    need(receipt["artifact"] == "aotg-windows-ssh-job-result" and type(receipt["version"]) is int
         and receipt["version"] == 1 and receipt["plan_sha256"] == sha(response["job_plan_bytes"])
         and receipt["helper_sha256"] == t["helper"]["sha256"]
         and receipt["wrapper_sha256"] == t["wrapper"]["sha256"], "receipt_binding")
    r = receipt["result"]
    exact(r, {"ProcessId", "ExitCode", "TimedOut", "Cancelled", "JobEmpty", "Seconds",
              "ExecutableSha256", "CleanupScope"}, "native_result_fields")
    need(type(r["ProcessId"]) is int and r["ProcessId"] > 0 and type(r["ExitCode"]) is int
         and all(type(r[k]) is bool for k in ("TimedOut", "Cancelled", "JobEmpty"))
         and finite(r["Seconds"], maximum=LIMITS["local_seconds"])
         and r["ExecutableSha256"] == t["ssh"]["sha256"]
         and r["CleanupScope"] == "windows-job-object", "native_result_types_or_identity")
    need(type(response["wrapper_returncode"]) is int, "wrapper_returncode")
    return {"job_plan_sha256": sha(response["job_plan_bytes"]), "receipt_sha256": sha(response["receipt_bytes"]),
            "owned_windows_job_empty": r["JobEmpty"], "remote_process_exit_verified": False,
            "transport_completed": r["JobEmpty"] and not r["TimedOut"] and not r["Cancelled"]
            and r["ExitCode"] in (0, 2) and response["wrapper_returncode"] == r["ExitCode"]
            and response["callback_error"] is None, "callback_error": response["callback_error"],
            "remote_command_exit_code": r["ExitCode"]}


class Sink:
    """Callback gets only bounded writes, not the underlying descriptor."""
    def __init__(self, stream, limit, deadline, clock):
        self.stream, self.limit, self.deadline, self.clock = stream, limit, deadline, clock
        self.count, self.digest, self.failed = 0, hashlib.sha256(), False

    def write(self, data):
        try:
            need(type(data) is bytes and len(data) <= 1024 * 1024, "callback_chunk_limit")
            need(self.clock() < self.deadline, "local_collection_deadline")
            need(self.count + len(data) <= self.limit, "local_output_limit")
            written = self.stream.write(data)
            need(written == len(data), "local_short_write")
            self.count += written
            self.digest.update(data)
            return written
        except BaseException:
            self.failed = True
            raise

    def flush(self):
        self.stream.flush()


def create_output(path):
    p = Path(path)
    need(p.is_absolute() and str(p) == str(path) and ".." not in p.parts, "canonical_output_required")
    parent = protocol.open_directory(str(p.parent))
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "unsafe_output_parent")
        os.mkdir(p.name, 0o700, dir_fd=parent)
        fd = os.open(p.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.fsync(parent)
        return fd
    finally:
        os.close(parent)


def new_file(directory, name):
    need("/" not in name and name not in (".", ".."), "fixed_output_name")
    return os.fdopen(os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=directory), "w+b")


def persist(directory, name, value):
    with new_file(directory, name) as stream:
        stream.write(value); stream.flush(); os.fsync(stream.fileno())
    os.fsync(directory)


def validate_stat(value, request, cap, *, directory=False):
    exact(value, {"device", "inode", "bytes", "mtime_ns", "ctime_ns", "mode", "uid", "gid", "links"},
          "stat_fields")
    need(all(type(v) is int and v >= 0 for v in value.values()), "stat_types")
    need(value["uid"] == request["owner_uid"] and value["gid"] == request["owner_gid"]
         and not value["mode"] & 0o022 and value["inode"] > 0, "stat_owner_mode")
    need((stat.S_ISDIR(value["mode"]) if directory else stat.S_ISREG(value["mode"]) and value["links"] == 1)
         and (directory or value["bytes"] <= cap), "stat_file_type_or_limit")


def decode_wire(stream, request, directory, *, deadline, clock=time.monotonic):
    """One-pass, bounded receiver. Partial files stay explicitly .partial, never normalized."""
    planned = protocol.inventory(); request_sha = sha(canon(request))
    header = final = active = None; files = []; records = wire_bytes = total = 0
    wire_digest = hashlib.sha256()
    partial = None
    try:
        while True:
            need(clock() < deadline, "local_collection_deadline")
            raw = stream.readline(LIMITS["wire_line_bytes"] + 1)
            if not raw: break
            records += 1; wire_bytes += len(raw)
            wire_digest.update(raw)
            need(records <= LIMITS["wire_records"] and wire_bytes <= LIMITS["wire_bytes"]
                 and len(raw) <= LIMITS["wire_line_bytes"] and raw.endswith(b"\n"), "wire_limit_or_partial_tail")
            row = parse(raw); kind = row.get("artifact")
            need(type(row.get("version")) is int and row["version"] == 1 and final is None, "wire_version_or_after_final")
            if header is None:
                expected = {"artifact": "aotg-comparison-collection-open", "version": 1,
                            "request_sha256": request_sha, "run_id": request["run_id"], "nonce": request["nonce"],
                            "worker_plan_sha256": request["worker_plan_sha256"], "owner_result_sha256": request["owner_result_sha256"],
                            "planned_files": len(planned), "limits": LIMITS}
                exact(row, set(expected) | {"started_utc"}, "wire_header_fields")
                need(all(row[k] == v for k, v in expected.items()), "wire_header_binding")
                header = row; continue
            if kind == "aotg-comparison-file-open":
                exact(row, {"artifact", "version", "index", "label", "byte_cap", "record_cap"}, "file_open_fields")
                index = len(files)
                need(active is None and index < len(planned) and type(row["index"]) is int and row["index"] == index,
                     "file_order")
                label, cap, count_cap = planned[index]
                need((row["label"], row["byte_cap"], row["record_cap"]) == (label, cap, count_cap), "file_inventory_binding")
                active = {"index": index, "label": label, "bytes": 0, "records": 0, "tail": b"",
                          "digest": hashlib.sha256(), "cap": cap, "count_cap": count_cap}
                partial = new_file(directory, "%03d.partial" % index)
            elif kind == "aotg-comparison-file-chunk":
                exact(row, {"artifact", "version", "index", "offset", "bytes", "base64"}, "chunk_fields")
                need(active is not None and type(row["index"]) is int and row["index"] == active["index"]
                     and type(row["offset"]) is int and row["offset"] == active["bytes"]
                     and type(row["bytes"]) is int and 0 < row["bytes"] <= LIMITS["chunk_bytes"], "chunk_order")
                need(type(row["base64"]) is str, "chunk_base64_type")
                data = base64.b64decode(row["base64"], validate=True)
                need(len(data) == row["bytes"] and active["bytes"] + len(data) <= active["cap"]
                     and total + len(data) <= LIMITS["total_raw_bytes"], "chunk_byte_limit")
                if active["count_cap"] is not None:
                    pieces = (active["tail"] + data).split(b"\n")
                    need(max(map(len, pieces)) <= LIMITS["jsonl_line_bytes"], "jsonl_line_limit")
                    for line in pieces[:-1]: parse(line)
                    active["records"] += len(pieces) - 1; active["tail"] = pieces[-1]
                    need(active["records"] <= active["count_cap"], "jsonl_record_limit")
                partial.write(data); active["digest"].update(data); active["bytes"] += len(data); total += len(data)
            elif kind == "aotg-comparison-file-close":
                exact(row, {"artifact", "version", "index", "label", "status", "reason", "bytes", "read_bytes",
                            "sha256", "partial_sha256", "records", "stat_before", "stat_after"}, "file_close_fields")
                need(active is not None and type(row["index"]) is int and row["index"] == active["index"]
                     and row["label"] == active["label"] and type(row["bytes"]) is int and row["bytes"] == active["bytes"]
                     and type(row["read_bytes"]) is int and row["read_bytes"] >= row["bytes"]
                     and row["partial_sha256"] == active["digest"].hexdigest(), "file_close_binding")
                need(row["status"] in ("captured", "incomplete"), "file_close_status")
                if row["status"] == "captured":
                    need(row["reason"] is None and row["read_bytes"] == row["bytes"]
                         and row["sha256"] == row["partial_sha256"] and row["stat_before"] == row["stat_after"], "captured_file_consistency")
                    validate_stat(row["stat_before"], request, active["cap"])
                    need(row["bytes"] == row["stat_before"]["bytes"] and not active["tail"], "captured_file_size_or_tail")
                    need(row["records"] == (active["records"] if active["count_cap"] is not None else None), "captured_record_count")
                    if row["label"].endswith(".json"):
                        partial.flush(); partial.seek(0); obj_raw = partial.read(active["cap"] + 1)
                        parse(obj_raw)
                        if row["label"] == "work/owner-entry-result.json": protocol.owner_gate(obj_raw, request)
                        if row["label"] == "task/summary.json": protocol.summary_gate(obj_raw, request)
                else:
                    need(row["sha256"] is None and row["stat_after"] is None and type(row["reason"]) is str
                         and 0 < len(row["reason"]) <= 128, "incomplete_file_reason")
                partial.flush(); os.fsync(partial.fileno()); partial.close(); partial = None
                filename = "%03d.%s" % (active["index"], "raw" if row["status"] == "captured" else "partial")
                if row["status"] == "captured":
                    old = "%03d.partial" % active["index"]
                    os.link(old, filename, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                    os.unlink(old, dir_fd=directory)
                files.append(dict(row, local_file=filename)); active = None
            elif kind == "aotg-comparison-collection-final":
                need(active is None and row.get("request_sha256") == request_sha
                     and row.get("status") in ("complete", "incomplete"), "final_binding")
                need(type(row.get("attempted_files")) is int and row["attempted_files"] == len(files)
                     and type(row.get("complete_files")) is int
                     and row["complete_files"] == sum(f["status"] == "captured" for f in files)
                     and row.get("unattempted_indices") == list(range(len(files), len(planned)))
                     and type(row.get("raw_bytes")) is int and row["raw_bytes"] == total
                     and type(row.get("total_read_bytes")) is int
                     and sum(f["read_bytes"] for f in files) <= row["total_read_bytes"] <= LIMITS["total_raw_bytes"],
                     "final_counts")
                need(row.get("independent_restoration_verified") is False and row.get("remote_written") is False
                     and row.get("inference_invoked") is False and row.get("service_control_invoked") is False
                     and finite(row.get("seconds"), maximum=LIMITS["remote_seconds"])
                     and isinstance(row.get("errors"), list), "final_scope")
                need(row.get("started_utc") == header["started_utc"], "final_start_time_binding")
                start, end = datetime.fromisoformat(row["started_utc"]), datetime.fromisoformat(row["finished_utc"])
                need(start.tzinfo is not None and end.tzinfo is not None and end >= start, "final_utc_bracket")
                if row["status"] == "complete":
                    need(row.get("preconditions_verified") is True and row.get("protected_unchanged") is True
                         and row.get("owner_reported_restoration") is True and not row["errors"]
                         and len(files) == len(planned) and row["complete_files"] == len(planned), "false_complete")
                    protected = row.get("protected_before")
                    exact(protected, {"work", "task", "owner_result", "owner_result_sha256", "worker_summary", "worker_summary_sha256"},
                          "protected_fields")
                    need(row.get("protected_after") == protected, "protected_before_after")
                    for key in ("work", "task"): validate_stat(protected[key], request, 0, directory=True)
                    need({k: protected["work"][k] for k in ("device", "inode")} == request["work_identity"], "protected_root_identity")
                    need(protected["owner_result"] == files[0]["stat_before"] and protected["owner_result_sha256"] == files[0]["sha256"]
                         and protected["worker_summary"] == files[1]["stat_before"] and protected["worker_summary_sha256"] == files[1]["sha256"],
                         "protected_file_binding")
                    need(row["total_read_bytes"] == total + 2 * (files[0]["bytes"] + files[1]["bytes"]), "protected_reread_accounting")
                final = row
            else:
                need(False, "unknown_wire_record")
        need(header is not None and final is not None and active is None, "missing_terminal_record")
        return {"header": header, "final": final, "files": files, "wire_records": records,
                "wire_bytes": wire_bytes, "wire_sha256": wire_digest.hexdigest()}
    finally:
        if partial is not None: partial.close()


def run_collection(request, seed, owner_result_bytes, output_dir, transport, *, remote_source, remote_source_sha256,
                   clock=time.monotonic, deadline=None):
    """Explicit library-only operation. Caller supplies the reviewed context and transport.

    Callback MUST return/raise by the supplied absolute deadline, perform its own
    bounded owned cleanup even if a sink refuses output, and never retry. No arbitrary
    callback can be made preemptible here; integration must qualify that contract.
    """
    started = clock()
    deadline = started + LIMITS["local_seconds"] if deadline is None else deadline
    need(finite(deadline-started, minimum=0, maximum=LIMITS["local_seconds"]) and deadline > started, "bounded_shared_deadline")
    protocol.validate(request)
    need(type(owner_result_bytes) is bytes and len(owner_result_bytes) <= 262144, "owner_result_byte_limit")
    protocol.owner_gate(owner_result_bytes, request); validate_seed(seed)
    payload = build_payload(request, remote_source, remote_source_sha256)
    directory = create_output(output_dir)
    result = {"artifact": "aotg-comparison-collection-result", "version": 1, "status": "incomplete",
              "request_sha256": sha(canon(request)), "payload_sha256": sha(payload), "remote_source_sha256": remote_source_sha256,
              "owner_result_sha256": sha(owner_result_bytes), "transport_attempts": 0,
              "owner_reported_restoration": True, "independent_restoration_verified": False,
              "remote_process_exit_verified": False, "quality_accepted": False, "adoption_accepted": False,
              "new_authentication": False, "remote_written": False, "errors": []}
    try:
        persist(directory, "request.json", canon(request) + b"\n")
        persist(directory, "payload.py", payload)
        with new_file(directory, "stdout.jsonl") as stdout, new_file(directory, "stderr-private.txt") as stderr:
            out_sink = Sink(stdout, LIMITS["wire_bytes"], deadline, clock)
            err_sink = Sink(stderr, LIMITS["stderr_bytes"], deadline, clock)
            result["transport_attempts"] = 1
            response = transport(payload=payload, stdout=out_sink, stderr=err_sink,
                                 remote_seconds=LIMITS["remote_seconds"], wall_seconds=LIMITS["transport_seconds"],
                                 cleanup_seconds=LIMITS["cleanup_seconds"], deadline=deadline,
                                 stdout_limit=LIMITS["wire_bytes"], stderr_limit=LIMITS["stderr_bytes"])
            stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
            for key, name in (("job_plan_bytes", "job-plan.json"), ("receipt_bytes", "job-result.json")):
                if isinstance(response, dict) and type(response.get(key)) is bytes and len(response[key]) <= 65536:
                    persist(directory, name, response[key])
            need(clock() < deadline, "local_collection_deadline")
            need(not out_sink.failed and not err_sink.failed, "output_rejection_occurred")
            result["transport"] = validate_transport(seed, response, sha(payload), out_sink.digest.hexdigest(), err_sink.digest.hexdigest())
            stdout.seek(0)
            result["capture"] = decode_wire(stdout, request, directory, deadline=deadline, clock=clock)
            need(result["capture"]["wire_sha256"] == out_sink.digest.hexdigest(), "saved_wire_changed")
            need(result["transport"]["transport_completed"], "transport_or_cleanup_incomplete")
            need(result["transport"]["remote_command_exit_code"] == (0 if result["capture"]["final"]["status"] == "complete" else 2),
                 "exit_status_disagreement")
            need(result["capture"]["final"]["status"] == "complete", "remote_collection_incomplete")
            need(clock() < deadline, "local_collection_deadline")
            result["status"] = "complete"
    except Exception as error:
        result["errors"].append(str(error) if isinstance(error, CollectionError) else type(error).__name__)
    finally:
        result["seconds"] = clock() - started
        if clock() >= deadline:
            result["status"] = "incomplete"; result["errors"].append("local_collection_deadline")
        try:
            persist(directory, "collection-result.json", canon(result) + b"\n")
        finally:
            os.close(directory)
    return result


if __name__ == "__main__":
    print(canon({"artifact": "aotg-comparison-collector-preview", "version": 1,
                 "planned_files": len(protocol.inventory()), "limits": LIMITS,
                 "remote_actions": False, "integration_qualified": False}).decode("ascii"))
