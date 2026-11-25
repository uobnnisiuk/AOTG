#!/usr/bin/env python3
"""Private, finite EVO trial worker. No production control or restoration calls.

Default preflight is read-only and never starts a GPU runtime. Execution requires
the reviewed maintenance unit, read-only model/source mounts, and a frozen plan.
The supervising unit owns production restoration and final cgroup cleanup.
This script is not a sandbox or a substitute for that independently reviewed unit.
"""

import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
import types

GIB = 1024 ** 3
MIB = 1024 ** 2
SHA = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
PLAN_FIELDS = {
    "artifact", "version", "run_id", "worker_sha256", "maintenance_unit",
    "task_root", "worker_python", "python", "engine", "telemetry", "hip_probe", "journalctl",
    "control_root", "source_roots", "source_files", "dependency_packages", "active_config",
    "expert_profile", "api_key_file", "gpu", "strata_dirs", "path_dirs",
    "library_dirs", "readonly_roots", "native_argv", "profiles", "schedule",
    "field_plan", "field_validator_modules", "budget_policy_sha256", "max_seconds", "kernel_since", "required_alarm_keys",
}
BUDGET_POLICY_SHA256 = "96f81bfa1ea1c90e4988a0a25560156ea402493b9549ac7f17d408c53f3bf277"
FIELD_VALIDATOR_SHAS = {
    "artifacts": "4b3def66e8d3fe1a65326930adfdbba970c40c70e5ead99c9330cd85562f60bc",
    "field_evidence": "3965ae8ead3e8c11fa513ba84a83105e1f5811d8a51b65c046b75b0ed6a888ac",
}
MARKER_IDENTITY_FIELDS = ("run_id", "plan_sha256", "field_plan_sha256", "schedule_sha256",
                          "index", "candidate_id", "comparison_id", "workload_id", "block", "profile_sha256")
TOKEN = "{{prefill}}"
EXPERT = "{{expert_profile}}"


class StopTrial(RuntimeError):
    """Fail-closed stop, including unavailable evidence."""


def require(condition, message):
    if not condition:
        raise StopTrial(message)


def exact(value, fields, name):
    require(isinstance(value, dict) and set(value) == set(fields),
            "Invalid " + name + " fields")


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(MIB), b""):
            h.update(block)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha_value(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def profile_identity(plan, prefill):
    """Public-safe profile hash excludes per-arm private path substitutions."""
    return sha_value({"artifact": "aotg-evo-prefill-profile", "version": 1,
                      "active_config_sha256": plan["active_config"]["sha256"],
                      "prefill": prefill, "native_argv": plan["native_argv"]})


def absolute(value):
    require(isinstance(value, str) and value.startswith("/") and "\x00" not in value,
            "Require explicit absolute Linux path")
    p = Path(value)
    require(".." not in p.parts and str(p) == value, "Noncanonical path")
    return p


def secure_regular(path, *, max_bytes=None, allow_existing_writable=False):
    p = Path(path)
    info = p.lstat()
    require(stat.S_ISREG(info.st_mode) and not p.is_symlink(), "Require regular non-symlink file")
    require(info.st_uid in (0, os.getuid()), "Unexpected file owner")
    require(allow_existing_writable or not info.st_mode & 0o022, "File write permissions are unsafe")
    if max_bytes is not None:
        require(info.st_size <= max_bytes, "File exceeds bounded input size")
    return p


def read_json(path, max_bytes=4 * MIB, *, allow_existing_writable=False):
    return json.loads(secure_regular(path, max_bytes=max_bytes,
                                    allow_existing_writable=allow_existing_writable).read_text())


def descriptor(value):
    exact(value, ("path", "sha256"), "file descriptor")
    absolute(value["path"])
    require(isinstance(value["sha256"], str) and SHA.fullmatch(value["sha256"]), "Invalid SHA256")


def verify_file(value):
    descriptor(value)
    # Existing installation permissions are observed, never changed. Execute
    # separately requires these hash-pinned inputs to be mounted read-only.
    secure_regular(value["path"], allow_existing_writable=True)
    require(sha_file(value["path"]) == value["sha256"], "Frozen input hash mismatch: " + value["path"])


def option(args, key):
    require(args.count(key) == 1, "Missing or duplicate option: " + key)
    i = args.index(key)
    require(i + 1 < len(args), "Option has no value: " + key)
    return args[i + 1]


def validate_native(args, prefill, expert):
    require(isinstance(args, list) and all(isinstance(x, str) and "\x00" not in x for x in args),
            "Invalid native arguments")
    require(args.count("--serve") == 1, "Native server mode missing")
    for key, value in {
        "--prefill": str(prefill), "--expert-profile": expert,
        "--max-context": "131072", "--kv": "int8", "--draft": "dflash2",
        "--spec": "8", "--draft-conf": "0.35", "--draft-fallback": "none",
    }.items():
        require(option(args, key) == value, "Unexpected native option: " + key)
    for key in ("--pack", "--native", "--ple-gguf", "--draft-model", "--mtp-draft-vocab"):
        absolute(option(args, key))


def validate_dependencies(packages):
    require(isinstance(packages, list) and len(packages) <= 8, "Bound explicit dependency package count")
    names = set()
    for package in packages:
        exact(package, ("module", "root", "origin", "files", "distribution"), "dependency package")
        name = package["module"]
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name)
                and name not in names, "Invalid/duplicate dependency module")
        names.add(name)
        root, origin = absolute(package["root"]), absolute(package["origin"])
        require(root.name == name and origin.parent == root and origin.name == "__init__.py",
                "Only explicit ordinary dependency packages are supported")
        files = package["files"]
        require(isinstance(files, list) and 1 <= len(files) <= 2048, "Invalid dependency file inventory")
        paths = set()
        for row in files:
            descriptor(row)
            path = Path(row["path"])
            require(path.is_relative_to(root) and "__pycache__" not in path.parts and path.suffix != ".pyc"
                    and row["path"] not in paths, "Invalid dependency source/native file")
            paths.add(row["path"])
        require(str(origin) in paths, "Dependency origin not pinned")
        distribution = package["distribution"]
        exact(distribution, ("metadata", "record", "name", "version", "requires_dist"), "installed dependency distribution")
        for key in ("metadata", "record"):
            descriptor(distribution[key])
            path = Path(distribution[key]["path"])
            require(path.parent.parent == root.parent and path.parent.name.endswith(".dist-info"), "Distribution metadata outside existing install")
        require(Path(distribution["metadata"]["path"]).name == "METADATA"
                and Path(distribution["record"]["path"]).name == "RECORD"
                and Path(distribution["metadata"]["path"]).parent == Path(distribution["record"]["path"]).parent,
                "Mismatched distribution provenance")
        require(isinstance(distribution["name"], str) and distribution["name"]
                and isinstance(distribution["version"], str) and distribution["version"]
                and isinstance(distribution["requires_dist"], list)
                and all(isinstance(value, str) for value in distribution["requires_dist"]), "Invalid installed dependency metadata")


def verify_dependencies(packages):
    validate_dependencies(packages)
    for package in packages:
        root = Path(package["root"])
        require(root.is_dir() and not root.is_symlink(), "Dependency package root missing/symlinked")
        actual = set()
        for path in root.rglob("*"):
            require(not path.is_symlink(), "Dependency package symlink")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                actual.add(str(path))
        require(actual == {row["path"] for row in package["files"]}, "Dependency source/native inventory changed")
        for row in [*package["files"], package["distribution"]["metadata"], package["distribution"]["record"]]:
            verify_file(row)


def validate_plan(plan):
    exact(plan, PLAN_FIELDS, "worker plan")
    require(plan["artifact"] == "aotg-evo-worker-plan" and type(plan["version"]) is int and plan["version"] == 2, "Unsupported plan")
    require(isinstance(plan["run_id"], str) and ID.fullmatch(plan["run_id"]), "Invalid run ID")
    require(SHA.fullmatch(plan["worker_sha256"]), "Invalid worker hash")
    require(re.fullmatch(r"aotg-[a-z0-9-]+\.service", plan["maintenance_unit"]), "Invalid maintenance unit")
    require(type(plan["max_seconds"]) is int and plan["max_seconds"] == 5340
            and plan["budget_policy_sha256"] == BUDGET_POLICY_SHA256,
            "Require separately approved v2 budget policy; legacy windows are ineligible")
    exact(plan["field_validator_modules"], FIELD_VALIDATOR_SHAS, "field validator modules")
    for name, item in plan["field_validator_modules"].items():
        descriptor(item)
        require(item["sha256"] == FIELD_VALIDATOR_SHAS[name], "Reviewed field validator source differs")
    require(re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC", plan["kernel_since"]), "Invalid kernel since")
    for name in ("task_root", "control_root", "api_key_file"):
        absolute(plan[name])
    for name in ("worker_python", "python", "engine", "telemetry", "hip_probe", "journalctl", "active_config", "expert_profile", "field_plan"):
        descriptor(plan[name])
    for name in ("source_roots", "path_dirs", "library_dirs", "readonly_roots"):
        require(isinstance(plan[name], list) and plan[name] and len(plan[name]) == len(set(plan[name])), "Invalid " + name)
        for path in plan[name]:
            absolute(path)
    require(isinstance(plan["source_files"], list) and plan["source_files"], "Empty source inventory")
    for item in plan["source_files"]:
        descriptor(item)
        path = Path(item["path"])
        require(any(path.is_relative_to(root) for root in plan["source_roots"])
                or (path.parent == Path(plan["control_root"]) and path.suffix in (".py", ".so")),
                "Source outside code roots")
    require(len({x["path"] for x in plan["source_files"]}) == len(plan["source_files"]), "Duplicate source file")
    validate_dependencies(plan["dependency_packages"])
    exact(plan["gpu"], ("bdf", "hip_index", "arch", "vendor", "device"), "GPU")
    require(re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", plan["gpu"]["bdf"]), "Invalid GPU BDF")
    require(type(plan["gpu"]["hip_index"]) is int and 0 <= plan["gpu"]["hip_index"] <= 15, "Invalid HIP index")
    require(plan["gpu"]["arch"] == "gfx1151" and plan["gpu"]["vendor"] == "0x1002"
            and plan["gpu"]["device"] == "0x1586", "Not the reviewed 8060S identity")
    exact(plan["strata_dirs"], ("install", "data", "components"), "Strata directories")
    for path in plan["strata_dirs"].values():
        absolute(path)
    require(isinstance(plan["required_alarm_keys"], list) and plan["required_alarm_keys"]
            and all(isinstance(x, str) and x for x in plan["required_alarm_keys"]), "Alarm inventory required")
    require(isinstance(plan["profiles"], list) and len(plan["profiles"]) == 3, "Exactly three prefill profiles required")
    for profile in plan["profiles"]:
        exact(profile, ("id", "prefill", "profile_sha256"), "profile")
        require(ID.fullmatch(profile["id"]) and SHA.fullmatch(profile["profile_sha256"]), "Invalid profile identity")
        require(type(profile["prefill"]) is int and profile["prefill"] in (256, 512, 1024), "Invalid prefill")
    require({x["prefill"] for x in plan["profiles"]} == {256, 512, 1024}, "Profile set incomplete")
    require(len({x["id"] for x in plan["profiles"]}) == 3, "Duplicate profile ID")
    profiles = {x["id"]: x for x in plan["profiles"]}
    require(isinstance(plan["schedule"], list) and len(plan["schedule"]) == 64, "Require exact64 balanced comparison schedule")
    for index, row in enumerate(plan["schedule"]):
        exact(row, ("index", "candidate_id", "comparison_id", "workload_id", "block"), "schedule row")
        require(type(row["index"]) is int and row["index"] == index and row["candidate_id"] in profiles and row["comparison_id"] in profiles,
                "Invalid schedule identity")
        require(ID.fullmatch(row["workload_id"]) and type(row["block"]) is int and 0 <= row["block"] < 4,
                "Invalid workload or block")
    require(isinstance(plan["native_argv"], list) and plan["native_argv"].count(TOKEN) == 1
            and plan["native_argv"].count(EXPERT) == 1, "Require exact native argv template")
    validate_native(["512" if x == TOKEN else "/reviewed/expert" if x == EXPERT else x
                     for x in plan["native_argv"]], 512, "/reviewed/expert")
    for profile in plan["profiles"]:
        require(profile["profile_sha256"] == profile_identity(plan, profile["prefill"]),
                "Profile hash does not bind baseline, native template and prefill")
    task = Path(plan["task_root"])
    require(task.name == plan["run_id"] or (task.name == "work" and task.parent.name == plan["run_id"]),
            "Task root must be the run ID directory or its fresh work child")
    for root in plan["readonly_roots"]:
        require(not task.is_relative_to(root) and not Path(root).is_relative_to(task), "Task and protected roots overlap")
    protected = [*plan["source_roots"], *[x["path"] for x in plan["source_files"]]]
    protected.extend(plan[name]["path"] for name in
                     ("worker_python", "python", "engine", "telemetry", "hip_probe", "journalctl", "active_config", "expert_profile", "field_plan"))
    protected.extend(item["path"] for item in plan["field_validator_modules"].values())
    protected.extend(option(plan["native_argv"], key) for key in
                     ("--pack", "--native", "--ple-gguf", "--draft-model", "--mtp-draft-vocab"))
    for package in plan["dependency_packages"]:
        protected.extend((package["root"], package["distribution"]["metadata"]["path"], package["distribution"]["record"]["path"]))
    for path in protected:
        require(any(Path(path).is_relative_to(root) for root in plan["readonly_roots"]),
                "Protected source/model input is outside read-only roots")
    return plan


def validate_field_contract(plan, frozen):
    """Use exact reviewed v2 validator bytes; no import from writable sys.path."""
    sources = {}
    for name, expected in FIELD_VALIDATOR_SHAS.items():
        item = plan["field_validator_modules"][name]
        raw = secure_regular(item["path"], max_bytes=MIB, allow_existing_writable=True).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == item["sha256"] == expected,
                "Field validator source changed before import")
        sources[name] = raw
    prefix = "_aotg_comparison_v2_verified"
    names = [prefix, prefix + ".artifacts", prefix + ".field_evidence"]
    require(not any(name in sys.modules for name in names), "Private validator namespace already occupied")
    try:
        package = types.ModuleType(prefix)
        package.__path__ = []
        sys.modules[prefix] = package
        for name in ("artifacts", "field_evidence"):
            module = types.ModuleType(prefix + "." + name)
            module.__package__ = prefix
            module.__file__ = plan["field_validator_modules"][name]["path"]
            sys.modules[module.__name__] = module
            exec(compile(sources[name], module.__file__, "exec", dont_inherit=True), module.__dict__)
        module.validate_field_plan(frozen)
    except ValueError as error:
        raise StopTrial("Frozen v2 field plan invalid: " + str(error)) from error
    finally:
        for name in reversed(names):
            sys.modules.pop(name, None)
    require({w["id"] for w in frozen["workloads"]} == {"cpp-half-open-interval", "csharp-atomic-batch"},
            "Require the reviewed C++ and C# workload identities")
    require(len(frozen["workloads"]) == 2 and len(frozen["candidates"]) == 3
            and len(frozen["schedule"]) == 64, "Exactly two workloads and two alternatives required")
    require(all(type(r["index"]) is int and type(r["block"]) is int for r in frozen["schedule"]),
            "Schedule index/block must be integers, not booleans")
    require(frozen["schedule"] == plan["schedule"], "Worker schedule differs from full validated v2 plan")
    require(frozen["candidates"] == [{"id": p["id"], "profile_sha256": p["profile_sha256"]}
                                   for p in plan["profiles"]], "Profile hashes differ from evidence plan")
    require(frozen["verifier_sha256"] == "f8797a3a6ab7bad05995572e7bed306f372eb5cd8a356396bc8f0f4ac8f42e9c"
            and all(w["tests_sha256"] == "277abb01f995890be289b2c3d2e679f8a3283a12040b54218991fc005c19c268"
                    for w in frozen["workloads"]), "Require paired revised verifier/catalog identities")
    baseline = next(p for p in plan["profiles"] if p["id"] == frozen["baseline_id"])
    require(baseline["prefill"] == 512, "Baseline must remain the512 profile")
    require(frozen["limits"] == {"trial_seconds":180,"total_seconds":5340,
            "max_temperature_c":80,"min_mem_available_bytes":48*GIB,"max_swapout_bytes":0},
            "Field limits differ from fixed worker resource/time policy")
    return frozen


def verify_inputs(plan):
    validate_plan(plan)
    require(sha_file(__file__) == plan["worker_sha256"], "Worker changed after freeze")
    for name in ("worker_python", "python", "engine", "telemetry", "hip_probe", "journalctl", "active_config", "expert_profile", "field_plan"):
        verify_file(plan[name])
    for path in (plan["worker_python"]["path"], plan["python"]["path"], plan["engine"]["path"], plan["hip_probe"]["path"], plan["journalctl"]["path"]):
        require(os.access(path, os.X_OK), "Frozen executable is not executable")
    inventory = {x["path"] for x in plan["source_files"]}
    actual = set()
    control = Path(plan["control_root"])
    package_roots = {str(control / x) for x in ("serve", "strata_control", "tools")}
    package_roots.update(str(p) for p in control.iterdir() if p.is_dir() and (p / "__init__.py").exists())
    require(set(plan["source_roots"]) == package_roots, "Importable package root inventory changed")
    for path in control.iterdir():
        if path.is_file() and path.suffix in (".py", ".so"):
            require(not path.is_symlink(), "Top-level source symlink")
            actual.add(str(path))
    for root in plan["source_roots"]:
        root_path = absolute(root)
        require(root_path.is_dir() and not root_path.is_symlink(), "Invalid source root")
        for path in root_path.rglob("*"):
            require(not path.is_symlink(), "Symlink within frozen source tree")
            if path.is_file() and "__pycache__" not in path.parts:
                actual.add(str(path))
    require(actual == inventory, "Source inventory incomplete or changed")
    for item in plan["source_files"]:
        verify_file(item)
    verify_dependencies(plan["dependency_packages"])
    frozen = read_json(plan["field_plan"]["path"], allow_existing_writable=True)
    validate_field_contract(plan, frozen)
    base = read_json(plan["active_config"]["path"], allow_existing_writable=True)
    require(base.get("exe") == plan["engine"]["path"] and base.get("cwd") == plan["control_root"], "Engine/control identity mismatch")
    require(base.get("drafting") == "dflash2" and base.get("backend") == "hip", "Unexpected drafting/backend")
    require(option(base["user_args"], "--max-context") == "131072", "Base context changed")
    require(option(base["user_args"], "--prefill") == "512", "Base prefill changed")
    for key in ("before_load", "mcp_servers", "mcp", "images", "vision", "api_key"):
        require(not base.get(key), "Unexpected executable/network/secret config feature: " + key)
    for key in ("args", "args_written"):
        require(option(base[key], "--expert-profile") == plan["expert_profile"]["path"], "Expert profile identity mismatch")
    for path in plan["readonly_roots"] + plan["path_dirs"] + plan["library_dirs"] + list(plan["strata_dirs"].values()):
        require(absolute(path).is_dir(), "Required directory missing: " + path)
    secure_regular(plan["api_key_file"], max_bytes=4096)
    return base


def copied_config(base, prefill, arm):
    require(prefill in (256, 512, 1024), "Unsupported prefill")
    config = json.loads(json.dumps(base))
    config["user_args"][config["user_args"].index("--prefill") + 1] = str(prefill)
    expert = str(arm / "expert-profile.bin")
    for key in ("args", "args_written"):
        config[key][config[key].index("--expert-profile") + 1] = expert
    config.update(log=str(arm / "logs" / "engine-private.log"), host="127.0.0.1",
                  port=19480, parallel=1, open_browser=False)
    return config


def resource_check(sample, *, bdf, alarm_keys, disk_free, pswpout, initial_pswpout, initial_gtt):
    """Validate every required measurement; missing/NaN values never imply safety."""
    require(isinstance(sample, dict) and sample.get("selected_gpu_bdf") == bdf, "Telemetry GPU changed")

    def num(value):
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0, "Missing/invalid resource measurement")
        return value

    try:
        temps = sample["temperatures_c"]
        edge = num(temps["amdgpu:edge"])
        require(edge < 80, "GPU hard 80C limit")
        require(num(temps["nvme:Composite"]) < 74.85, "NVMe Composite limit")
        require(num(temps["nvme:Sensor 2"]) < 85, "NVMe Sensor 2 limit")
        all_gpus = sample["per_gpu_temperatures_c"]
        require(bdf in all_gpus and all_gpus, "Missing per-GPU sensors")
        for values in all_gpus.values():
            require(num(values["edge"]) < 80, "Other GPU hard 80C limit")
        alarms = sample["alarms"]
        require(all(key in alarms for key in alarm_keys), "Required alarm sensor missing")
        require(all(type(value) is int and value == 0 for value in alarms.values()), "Hardware alarm/invalid alarm value")
        require(num(sample["host_mem_available_bytes"]) >= 48 * GIB, "Host MemAvailable below 48 GiB")
        gpu = sample["gpu"]
        free = num(gpu["mem_info_vram_total"]) - num(gpu["mem_info_vram_used"])
        require(free >= 8 * GIB, "Free VRAM below 8 GiB")
        require(num(gpu["mem_info_gtt_used"]) - num(initial_gtt) <= GIB, "GTT grew by more than 1 GiB")
        swap = sample["swap_bytes"]
        used = num(swap["SwapTotal"]) - num(swap["SwapFree"])
        require(0 <= used < 16 * MIB, "Swap used reached 16 MiB")
        require(num(pswpout) == num(initial_pswpout), "New swapout or counter reset")
        require(num(disk_free) >= 150 * GIB, "Disk free below 150 GiB")
        return edge
    except (KeyError, TypeError) as exc:
        raise StopTrial("Required telemetry missing") from exc


def read_pswpout():
    rows = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
    require("pswpout" in rows, "pswpout unavailable")
    return int(rows["pswpout"])


def cgroup_of(pid):
    rows = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    found = [row[3:] for row in rows if row.startswith("0::/")]
    require(len(found) == 1, "Require unified cgroup")
    return found[0]


def current_unit(plan):
    require(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "Linux pidfd support required")
    group = cgroup_of("self")
    require(group == "/system.slice/" + plan["maintenance_unit"], "Execute only inside exact maintenance unit")
    require(re.fullmatch(r"[0-9a-f]{32}", os.environ.get("INVOCATION_ID", "")), "Missing systemd invocation identity")
    require(Path(sys.executable).resolve() == Path(plan["worker_python"]["path"]).resolve(), "Wrong worker Python interpreter")
    require(sys.version_info >= (3, 11), "Worker Python 3.11 or newer required")
    for root in plan["readonly_roots"]:
        require(os.statvfs(root).f_flag & os.ST_RDONLY, "Protected root is not mounted read-only: " + root)
    return group


def atomic_json(path, value):
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "x", encoding="utf-8") as stream:
        os.chmod(temp, 0o600)
        stream.write(canonical(value) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def child_identity(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    tail = raw[raw.rindex(")") + 2:].split()
    return {"pid": pid, "ppid": int(tail[1]), "start_ticks": int(tail[19]), "state": tail[0]}


def cgroup_identities(group):
    """Read only: unknown unit members are never treated as kill-authorized."""
    root = Path("/sys/fs/cgroup") / group.lstrip("/")
    found = set()
    for member_file in (root / "cgroup.procs", *root.glob("**/cgroup.procs")):
        for raw in member_file.read_text().splitlines():
            try:
                info = child_identity(int(raw))
                found.add((info["pid"], info["start_ticks"]))
            except FileNotFoundError:
                raise StopTrial("Cgroup membership changed during identity capture; cleanup is inconclusive")
    return found


def require_clean_cgroup(group, baseline):
    require(cgroup_identities(group) <= baseline,
            "Untracked/new process remains in maintenance cgroup; abort before next arm and require unit cleanup")


class OwnedProcesses:
    """Signals only pidfds acquired for verified descendants in our unit."""

    def __init__(self, process, cgroup):
        self.process = process
        self.cgroup = cgroup
        self.records = {}
        try:
            self.capture(process.pid, child_identity(process.pid))
        except BaseException:
            # Popen's direct child is our creation, unlike arbitrary scanned PIDs.
            # Wait/reap it; the enclosing cgroup barrier catches any fast orphan.
            if process.poll() is None:
                try:
                    fd = os.pidfd_open(process.pid)
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGCONT)
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    finally:
                        os.close(fd)
                except ProcessLookupError:
                    pass
            process.wait(timeout=3)
            raise

    def capture(self, pid, info):
        require(cgroup_of(pid) == self.cgroup, "Child escaped maintenance cgroup")
        fd = os.pidfd_open(pid)
        try:
            require(child_identity(pid)["start_ticks"] == info["start_ticks"], "PID changed during ownership capture")
        except BaseException:
            os.close(fd)
            raise
        self.records[pid] = {**info, "fd": fd}

    def refresh(self):
        for _ in range(5):
            added = False
            for path in Path("/proc").iterdir():
                if not path.name.isdigit() or int(path.name) in self.records:
                    continue
                try:
                    info = child_identity(int(path.name))
                    parent = self.records.get(info["ppid"])
                    if parent is None:
                        continue
                    # A retained fd alone does not make a reused numeric parent ours.
                    if child_identity(parent["pid"])["start_ticks"] != parent["start_ticks"]:
                        continue
                    self.capture(info["pid"], info)
                    added = True
                except (FileNotFoundError, ProcessLookupError):
                    continue
            if not added:
                break

    def send(self, sig, pids=None):
        for pid in list(self.records) if pids is None else pids:
            try:
                signal.pidfd_send_signal(self.records[pid]["fd"], sig)
            except ProcessLookupError:
                pass

    def alive(self):
        return [pid for pid, info in self.records.items() if not select.select([info["fd"]], [], [], 0)[0]]

    def cleanup(self):
        errors = []
        try:
            self.refresh()
        except (OSError, StopTrial) as exc:
            errors.append(type(exc).__name__)
        self.send(signal.SIGCONT)
        self.send(signal.SIGTERM)
        deadline = time.monotonic() + 10
        while self.alive() and time.monotonic() < deadline:
            self.process.poll()
            time.sleep(0.05)
        self.send(signal.SIGCONT)
        self.send(signal.SIGKILL)
        deadline = time.monotonic() + 3
        while self.alive() and time.monotonic() < deadline:
            self.process.poll()
            time.sleep(0.05)
        remaining = self.alive()
        for info in self.records.values():
            os.close(info["fd"])
        require(not remaining and not errors, "Owned cleanup incomplete; unit cgroup cleanup required")


class BoundedCommand:
    """Asynchronously drain bounded subprocess output without blocking telemetry."""

    def __init__(self, argv, env, timeout=5, output_limit=2 * MIB):
        self.p = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
        self.fd = os.pidfd_open(self.p.pid)
        os.set_blocking(self.p.stdout.fileno(), False)
        self.deadline = time.monotonic() + timeout
        self.limit = output_limit
        self.data = bytearray()
        self.closed = False

    def poll(self):
        try:
            while True:
                data = os.read(self.p.stdout.fileno(), 65536)
                if not data:
                    break
                self.data.extend(data)
                require(len(self.data) <= self.limit, "Bounded command output limit")
        except BlockingIOError:
            pass
        require(time.monotonic() < self.deadline, "Bounded command timeout")
        code = self.p.poll()
        if code is None:
            return None
        # Child may have written its final bytes after the first drain.
        while True:
            data = os.read(self.p.stdout.fileno(), 65536)
            if not data:
                break
            self.data.extend(data)
            require(len(self.data) <= self.limit, "Bounded command output limit")
        require(code == 0, "Bounded command failed")
        result = bytes(self.data).decode("utf-8", errors="strict")
        self.close()
        return result

    def close(self):
        if self.closed:
            return
        try:
            signal.pidfd_send_signal(self.fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.p.wait(timeout=2)
        self.p.stdout.close()
        os.close(self.fd)
        self.closed = True


def explicit_env(plan, arm=None, api_key=None, masked=True):
    env = {"PATH": ":".join(plan["path_dirs"]), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "LD_LIBRARY_PATH": ":".join(plan["library_dirs"]), "EVO_GPU_BDF": plan["gpu"]["bdf"],
           "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    if masked:
        env["HIP_VISIBLE_DEVICES"] = str(plan["gpu"]["hip_index"])
    if arm is not None:
        env.update({"HOME": str(arm / "home"), "TMPDIR": str(arm / "tmp"),
                    "XDG_CACHE_HOME": str(arm / "cache"), "XDG_CONFIG_HOME": str(arm / "home" / ".config"),
                    "STRATA_NO_PRESET": "1", "STRATA_NO_ACQUIRE": "1", "STRATA_START_RETRIES": "0",
                    "STRATA_SETTINGS_FILE": str(arm / "settings.json"),
                    "PYTHONPYCACHEPREFIX": str(arm / "pycache"), "STRATA_API_KEY": api_key})
        for name, value in plan["strata_dirs"].items():
            env["STRATA_" + name.upper() + "_DIR"] = value
        for name in ("runtime", "state", "profile", "preset"):
            env["STRATA_" + name.upper() + "_DIR"] = str(arm / name)
    return env


DEPENDENCY_BOOTSTRAP = '''
import importlib.machinery, hashlib
from pathlib import Path
class _AotgExplicitDependencyFinder:
    def find_spec(self, fullname, path=None, target=None):
        package = _aotg_dependencies.get(fullname.partition('.')[0])
        if package is None:
            return None
        search = [str(Path(package['root']).parent)] if path is None else path
        found = importlib.machinery.PathFinder.find_spec(fullname, search)
        if found is None:
            return None
        expected = package['files'].get(found.origin)
        if expected is None:
            raise ImportError('Unpinned dependency module: ' + fullname)
        with open(found.origin, 'rb') as stream:
            observed = hashlib.file_digest(stream, 'sha256').hexdigest()
        if observed != expected:
            raise ImportError('Frozen dependency changed: ' + fullname)
        return found
sys.meta_path.insert(0, _AotgExplicitDependencyFinder())
'''


def dependency_bootstrap(packages):
    validate_dependencies(packages)
    frozen = {package["module"]: {"root": package["root"], "files": {row["path"]: row["sha256"] for row in package["files"]}}
              for package in packages}
    source = "_aotg_dependencies = " + repr(frozen) + "\n" + DEPENDENCY_BOOTSTRAP
    require(len(source.encode()) <= 65536, "Dependency bootstrap exceeds bounded command size")
    return source


def bootstrap(control_root, packages):
    # -I -S strips ambient paths/site/.pth. The site-packages directory is never
    # inserted into sys.path: only individually frozen modules are exposed.
    return ("import sys,runpy\nassert sys.version_info[:2]==(3,12),'Strata requires pinned Python3.12'\n"
            + "sys.path[:0]=" + repr([control_root, str(Path(control_root) / "tools")]) + "\n"
            + dependency_bootstrap(packages)
            + "\nfrom strata_control import drafting\ndrafting._HARDWARE[:]=[('hip',['gfx1151'])]\n"
            + "runpy.run_module('serve.server',run_name='__main__')")


def verify_engine(plan, owned, profile, arm):
    owned.refresh()
    expected = [str(profile["prefill"]) if x == TOKEN else str(arm / "expert-profile.bin") if x == EXPERT else x
                for x in plan["native_argv"]]
    matches = []
    for pid in owned.alive():
        try:
            if os.readlink(f"/proc/{pid}/exe") != plan["engine"]["path"]:
                continue
            args = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
            require(args[0] == plan["engine"]["path"] and args[1:] == expected, "Native command differs from frozen trial")
            validate_native(args[1:], profile["prefill"], str(arm / "expert-profile.bin"))
            env = dict(item.split("=", 1) for item in Path(f"/proc/{pid}/environ").read_bytes().decode().rstrip("\0").split("\0"))
            require(env.get("HIP_VISIBLE_DEVICES") == str(plan["gpu"]["hip_index"]), "Native GPU visibility changed")
            require(not any(key in env for key in ("ROCR_VISIBLE_DEVICES", "CUDA_VISIBLE_DEVICES", "GPU_DEVICE_ORDINAL")), "Unexpected GPU mask")
            matches.append(pid)
        except FileNotFoundError:
            continue
    require(len(matches) <= 1, "Multiple native engines")
    return matches[0] if matches else None


def validate_done(done, ready):
    exact(done, ("artifact", "version", *MARKER_IDENTITY_FIELDS, "status", "evidence_sha256"), "done marker")
    require(done["artifact"] == "aotg-field-done" and type(done["version"]) is int and done["version"] == 1, "Invalid done marker")
    for key in MARKER_IDENTITY_FIELDS:
        require(type(done[key]) is type(ready[key]) and done[key] == ready[key], "Done marker identity mismatch")
    require(done["status"] in ("completed", "failed") and SHA.fullmatch(done["evidence_sha256"]), "Invalid completion evidence")
    require(done["status"] == "completed", "K8 task failed")


class Monitor:
    def __init__(self, plan, telemetry, stream, deadline, observation_stream):
        self.plan, self.telemetry, self.stream, self.deadline = plan, telemetry, stream, deadline
        self.observation_stream = observation_stream
        self.observation_sequence = 0
        self.started = time.monotonic()
        anchor_started = utc()
        self.pswpout = read_pswpout()
        first = telemetry.sample(self.started)
        self.gtt = first["gpu"]["mem_info_gtt_used"]
        self.anchor = {"utc_read_start": anchor_started, "utc_read_end": utc(),
                       "pswpout": self.pswpout, "initial_gtt_bytes": self.gtt}
        self.record_observation({"phase": "startup-anchor", "anchor": self.anchor,
                                 "guard_verdict": "not-evaluated"})
        self.last_sample = 0
        self.journal = None
        self.last_kernel = 0
        self.pause_since = None
        try:
            self.start_kernel()
            self.tick(None, None, force=True)
        except BaseException:
            self.close()
            raise

    def record_observation(self, record):
        """Flush separate evidence; observation never implies guard acceptance."""
        event = {"artifact": "aotg-resource-observation", "version": 1,
                 "run_id": self.plan["run_id"], **record}
        try:
            self.observation_stream.write(canonical(event) + "\n")
            self.observation_stream.flush()
        except Exception as exc:
            raise StopTrial("Resource observation evidence write failed") from exc

    def start_kernel(self):
        require(self.journal is None, "Kernel scan already running")
        self.journal = BoundedCommand([self.plan["journalctl"]["path"], "-k", "--since", self.plan["kernel_since"],
                                       "--no-pager", "--output=short-iso"], explicit_env(self.plan), timeout=5)

    def tick(self, owned, native_pid, force=False):
        now = time.monotonic()
        require(now < self.deadline, "Total worker time limit")
        if force or now - self.last_sample >= 0.19:
            sample = self.telemetry.sample(self.started, native_pid)
            sample["disk_free_bytes"] = shutil.disk_usage(self.plan["task_root"]).free
            sample["pswpout"] = read_pswpout()
            sequence = self.observation_sequence
            self.observation_sequence += 1
            observed = {"sequence": sequence, "observed_at_utc": utc(),
                        "sample_utc": sample.get("utc"), "anchor": self.anchor}
            self.record_observation({**observed, "phase": "observed", "sample": sample,
                                     "guard_verdict": "not-evaluated"})
            try:
                edge = resource_check(sample, bdf=self.plan["gpu"]["bdf"], alarm_keys=self.plan["required_alarm_keys"],
                                      disk_free=sample["disk_free_bytes"], pswpout=sample["pswpout"],
                                      initial_pswpout=self.pswpout, initial_gtt=self.gtt)
                if owned is not None:
                    owned.refresh()
                    if edge >= 70 and self.pause_since is None:
                        owned.send(signal.SIGSTOP)
                        self.pause_since = now
                    elif self.pause_since is not None and edge <= 60:
                        owned.send(signal.SIGCONT)
                        self.pause_since = None
                    if self.pause_since is not None:
                        # Include children discovered after the first pause signal.
                        owned.send(signal.SIGSTOP)
                        require(now - self.pause_since <= 30, "GPU thermal pacing exceeded 30 seconds")
                else:
                    require(edge < 70, "GPU not cool enough to start next arm")
            except Exception as exc:
                try:
                    self.record_observation({**observed, "phase": "guard-result", "guard_verdict": "rejected",
                                             "reason": str(exc), "error_type": type(exc).__name__})
                except Exception as evidence_error:
                    exc.add_note("Guard verdict evidence write failed: " + type(evidence_error).__name__)
                raise
            self.record_observation({**observed, "phase": "guard-result", "guard_verdict": "passed"})
            sample["thermal_paused"] = self.pause_since is not None
            self.stream.write(canonical(sample) + "\n")
            self.stream.flush()
            self.last_sample = now
        if self.journal is not None:
            text = self.journal.poll()
            if text is not None:
                self.journal = None
                require(not re.search(r"not seeing messages|No journal files|Failed to|Permission denied|Hint:", text, re.I),
                        "Kernel journal availability/permissions not verified")
                require(not re.search(self.telemetry.ERROR_PATTERN, text, re.I), "Kernel error since frozen baseline")
                self.last_kernel = now
        elif now - self.last_kernel >= 10:
            self.start_kernel()

    def finish_scan(self):
        if self.journal is None:
            self.start_kernel()
        while self.journal is not None:
            self.tick(None, None)
            time.sleep(0.02)

    def close(self):
        if self.journal is not None:
            self.journal.close()
            self.journal = None


def verify_hip(plan, monitor):
    for masked in (False, True):
        command = BoundedCommand([plan["hip_probe"]["path"], "list"], explicit_env(plan, masked=masked), timeout=20, output_limit=65536)
        try:
            text = None
            while text is None:
                monitor.tick(None, None)
                text = command.poll()
                time.sleep(0.02)
            rows = json.loads(text)
            require(isinstance(rows, list), "Invalid HIP inventory")
            found = [row for row in rows if row.get("bdf") == plan["gpu"]["bdf"]]
            require(len(found) == 1, "HIP BDF missing/duplicated")
            require(found[0].get("index") == (0 if masked else plan["gpu"]["hip_index"]), "HIP index mapping changed")
            require(found[0].get("arch", "").split(":")[0] == plan["gpu"]["arch"], "HIP architecture changed")
            require(not masked or len(rows) == 1, "HIP mask exposes other GPU")
        finally:
            command.close()


def final_kernel_scan(plan, pattern):
    """Run after owned cleanup, even when resource checks caused the stop."""
    command = BoundedCommand([plan["journalctl"]["path"], "-k", "--since", plan["kernel_since"],
                              "--no-pager", "--output=short-iso"], explicit_env(plan), timeout=5)
    try:
        output = None
        while output is None:
            output = command.poll()
            if output is None:
                time.sleep(0.02)
        require(not re.search(r"not seeing messages|No journal files|Failed to|Permission denied|Hint:", output, re.I),
                "Final kernel journal availability/permissions not verified")
        matches = [line for line in output.splitlines() if re.search(pattern, line, re.I)]
        return {"status": "errors" if matches else "clear", "since": plan["kernel_since"],
                "scanned_at": utc(), "output_sha256": hashlib.sha256(output.encode()).hexdigest(), "errors": matches}
    finally:
        command.close()


def preflight(plan):
    base = verify_inputs(plan)
    gpu = Path("/sys/bus/pci/devices") / plan["gpu"]["bdf"]
    for name in ("vendor", "device"):
        require((gpu / name).read_text().strip() == plan["gpu"][name], "PCI identity changed")
    require((gpu / "driver").resolve().name == "amdgpu", "Unexpected GPU driver")
    require(not Path(plan["task_root"]).exists(), "Task root already exists; do not reuse runs")
    parent = Path(plan["task_root"]).parent
    require(parent.is_dir() and parent.resolve() == parent, "Task parent missing or symlinked")
    require(shutil.disk_usage(parent).free >= 150 * GIB, "Disk free below 150 GiB")
    return base


def input_permissions(plan):
    existing = [plan[name]["path"] for name in
                ("worker_python", "python", "engine", "telemetry", "hip_probe", "journalctl", "active_config", "expert_profile", "field_plan")]
    existing.extend(row["path"] for row in plan["source_files"])
    for package in plan["dependency_packages"]:
        existing.extend(row["path"] for row in package["files"])
        existing.extend(package["distribution"][key]["path"] for key in ("metadata", "record"))
    return [{"path": path, "mode": oct(Path(path).stat().st_mode & 0o777)}
            for path in sorted(set(existing)) if Path(path).stat().st_mode & 0o022]


def execute(plan, plan_sha):
    group = current_unit(plan)
    base = preflight(plan)
    task = Path(plan["task_root"])
    os.umask(0o077)
    task.mkdir(mode=0o700)
    summary = {"artifact": "aotg-evo-worker-result", "version": 1, "run_id": plan["run_id"],
               "plan_sha256": plan_sha, "started_at": utc(), "status": "running", "arms": [],
               "production_restore_owned_by": plan["maintenance_unit"], "quality_accepted": False}
    atomic_json(task / "summary.json", summary)
    started = time.monotonic()
    deadline = started + plan["max_seconds"]
    monitor = None
    telemetry = None
    final_error = None
    old_bdf = os.environ.get("EVO_GPU_BDF")
    os.environ["EVO_GPU_BDF"] = plan["gpu"]["bdf"]
    try:
        # All frozen helper/source inputs were verified above, before this import.
        # Compile the verified source bytes directly: never trust stale .pyc.
        telemetry_source = secure_regular(plan["telemetry"]["path"], allow_existing_writable=True).read_bytes()
        require(hashlib.sha256(telemetry_source).hexdigest() == plan["telemetry"]["sha256"], "Telemetry changed before import")
        telemetry = types.ModuleType("aotg_frozen_gpu_telemetry")
        telemetry.__file__ = plan["telemetry"]["path"]
        exec(compile(telemetry_source, telemetry.__file__, "exec"), telemetry.__dict__)
        key = secure_regular(plan["api_key_file"], max_bytes=4096).read_text().strip()
        require(key and key.lower() != "none" and not any(x in key for x in "\r\n\x00,"), "Invalid existing API key")
        with open(task / "resources.jsonl", "x", encoding="utf-8") as resource_stream, \
                open(task / "resource-observations.jsonl", "x", encoding="utf-8") as observation_stream:
            monitor = Monitor(plan, telemetry, resource_stream, deadline, observation_stream)
            monitor.finish_scan()
            verify_hip(plan, monitor)
            profiles = {p["id"]: p for p in plan["profiles"]}
            for row in plan["schedule"]:
                require(time.monotonic() + 120 + 180 + 15 < deadline, "Insufficient remaining budget for another bounded arm")
                verify_file(plan["active_config"])
                verify_file(plan["expert_profile"])
                profile = profiles[row["candidate_id"]]
                arm = task / ("arm-" + str(row["index"]).zfill(3))
                arm.mkdir(mode=0o700)
                for name in ("home", "tmp", "cache", "runtime", "state", "profile", "preset", "logs", "pycache"):
                    (arm / name).mkdir(mode=0o700)
                shutil.copyfile(plan["expert_profile"]["path"], arm / "expert-profile.bin")
                config = copied_config(base, profile["prefill"], arm)
                atomic_json(arm / "config.json", config)
                atomic_json(arm / "settings.json", {})
                argv = [plan["python"]["path"], "-I", "-S", "-B", "-X", "pycache_prefix=" + str(arm / "pycache"),
                        "-c", bootstrap(plan["control_root"], plan["dependency_packages"]),
                        "--engine", "strata", "--config", str(arm / "config.json"), "--offline",
                        "--host", "127.0.0.1", "--port", "19480", "--parallel", "1",
                        "--ready-file", str(arm / "server-ready.json"), "--shutdown-timeout", "8"]
                result = {**row, "profile_sha256": profile["profile_sha256"], "prefill": profile["prefill"],
                          "started_at": utc(), "status": "running", "config_sha256": sha_file(arm / "config.json")}
                summary["arms"].append(result)
                owned = None
                baseline_members = None
                monitor.pause_since = None
                try:
                    monitor.tick(None, None, force=True)
                    baseline_members = cgroup_identities(group)
                    with open(arm / "logs" / "server-private.log", "xb") as log:
                        proc = subprocess.Popen(argv, cwd=arm, env=explicit_env(plan, arm, key),
                                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                                close_fds=True, start_new_session=True)
                        owned = OwnedProcesses(proc, group)
                        load_deadline = time.monotonic() + 120
                        native = None
                        while True:
                            require(proc.poll() is None, "Strata server exited during load")
                            require(time.monotonic() < load_deadline, "Server load exceeded 120 seconds")
                            native = verify_engine(plan, owned, profile, arm)
                            monitor.tick(owned, native)
                            require((arm / "logs" / "server-private.log").stat().st_size < 64 * MIB, "Server log limit")
                            ready_path = arm / "server-ready.json"
                            if native is not None and ready_path.exists():
                                server_ready = read_json(ready_path, 16384)
                                require(server_ready.get("pid") == proc.pid and server_ready.get("bound_host") == "127.0.0.1"
                                        and server_ready.get("bound_port") == 19480 and server_ready.get("model_state") == "ready"
                                        and server_ready.get("api_state") == "ready" and server_ready.get("model_id") == base["model_name"],
                                        "Unverified Strata readiness")
                                break
                            time.sleep(0.02)
                        result["load_seconds"] = time.monotonic() - (load_deadline - 120)
                        result["native_pid"] = native
                        result["server_pid"] = proc.pid
                        result["native_exe_sha256"] = sha_file(f"/proc/{native}/exe")
                        require(result["native_exe_sha256"] == plan["engine"]["sha256"], "Loaded engine hash changed")
                        done_deadline = time.monotonic() + 180
                        ready = {"artifact": "aotg-field-ready", "version": 1, "run_id": plan["run_id"],
                                 "plan_sha256": plan_sha, "field_plan_sha256": plan["field_plan"]["sha256"],
                                 "schedule_sha256": sha_value(plan["schedule"]), **row, "profile_sha256": profile["profile_sha256"],
                                 "prefill": profile["prefill"], "endpoint": "http://127.0.0.1:19480/v1",
                                 "ready_at": utc(), "deadline_epoch": time.time() + 180}
                        atomic_json(task / "ready.json", ready)
                        atomic_json(arm / "ready.json", ready)
                        done_path = task / ("done-" + str(row["index"]) + ".json")
                        while True:
                            require(proc.poll() is None, "Strata server exited during workload")
                            require(time.monotonic() < done_deadline, "K8 completion deadline exceeded")
                            require(verify_engine(plan, owned, profile, arm) == native, "Native engine replaced/exited")
                            monitor.tick(owned, native)
                            require((arm / "logs" / "server-private.log").stat().st_size < 64 * MIB, "Server log limit")
                            if done_path.exists():
                                done = read_json(done_path, 16384)
                                validate_done(done, ready)
                                result["k8_evidence_sha256"] = done["evidence_sha256"]
                                break
                            time.sleep(0.02)
                        result["workload_wait_seconds"] = time.monotonic() - (done_deadline - 180)
                        result["status"] = "completed-awaiting-independent-quality"
                except BaseException as exc:
                    result["status"] = "stopped"
                    result["stop_reason"] = str(exc) if isinstance(exc, StopTrial) else type(exc).__name__
                    raise
                finally:
                    primary_error = sys.exception()
                    cleanup_failures = []
                    try:
                        for action, function in (
                            ("journal-close", monitor.close),
                            ("owned-process-cleanup", owned.cleanup if owned is not None else None),
                            ("cgroup-verification", (lambda: require_clean_cgroup(group, baseline_members))
                             if baseline_members is not None else None),
                        ):
                            if function is not None:
                                try:
                                    function()
                                except BaseException as error:
                                    cleanup_failures.append({"action":action,"error_type":type(error).__name__})
                        if cleanup_failures:
                            result["status"] = "cleanup-failed"
                            result["cleanup_failures"] = cleanup_failures
                            if primary_error is None:
                                raise StopTrial("Comparison arm cleanup failed")
                    finally:
                        monitor.pause_since = None
                        result["finished_at"] = utc()
                        atomic_json(arm / "result.json", result)
                        atomic_json(task / "summary.json", summary)
                        if (task / "ready.json").exists():
                            (task / "ready.json").unlink()
                monitor.finish_scan()
            monitor.finish_scan()
            verify_file(plan["active_config"])
            verify_file(plan["expert_profile"])
            summary["status"] = "completed-awaiting-independent-quality"
    except BaseException as exc:
        summary["status"] = "stopped"
        summary["stop_reason"] = str(exc) if isinstance(exc, StopTrial) else type(exc).__name__
        raise
    finally:
        if monitor is not None:
            try:
                monitor.close()
            except BaseException as error:
                final_error = type(error).__name__
                summary["status"] = "stopped"
                summary["monitor_close_error_type"] = final_error
        if telemetry is not None:
            try:
                scan = final_kernel_scan(plan, telemetry.ERROR_PATTERN)
                atomic_json(task / "kernel-final.json", scan)
                require(scan["status"] == "clear", "Kernel errors at worker completion")
            except BaseException as exc:
                final_error = str(exc) if isinstance(exc, StopTrial) else type(exc).__name__
                summary["status"] = "stopped"
                summary["final_kernel_scan_error"] = final_error
        if old_bdf is None:
            os.environ.pop("EVO_GPU_BDF", None)
        else:
            os.environ["EVO_GPU_BDF"] = old_bdf
        summary["finished_at"] = utc()
        summary["wall_seconds"] = time.monotonic() - started
        atomic_json(task / "summary.json", summary)
    if final_error is not None:
        raise StopTrial("Final kernel verification failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        plan = read_json(args.plan, 16 * MIB)
        validate_plan(plan)
        if not args.execute:
            preflight(plan)
            print(canonical({"status": "preflight-passed", "gpu_runtime_invoked": False,
                             "execution_authorized": False, "plan_sha256": sha_file(args.plan),
                             "existing_group_world_writable_inputs": input_permissions(plan),
                             "execute_requires_all_frozen_inputs_readonly": True}))
            return 0
        def interrupted(signum, frame):
            raise StopTrial("Maintenance worker interrupted by signal " + str(signum))
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        execute(plan, sha_file(args.plan))
        print(canonical({"status": "completed-awaiting-independent-quality", "quality_accepted": False}))
        return 0
    except (StopTrial, OSError, ValueError, KeyError, TypeError) as exc:
        # Do not serialize arbitrary subprocess/environment values or API secrets.
        print(canonical({"status": "stopped", "reason": str(exc) if isinstance(exc, StopTrial) else type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
