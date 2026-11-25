"""Dry-run-first, explicitly approved Linux systemd maintenance coordination.

No service action happens on import or plan creation. Root execution is a
separate opt-in, bound to the exact private plan hash. The timer and copied
recovery program remain independent of the invoking shell. A restored systemd
unit is not evidence of inference quality, model health or complete rollback.
"""

import hashlib
import json
import math
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from .artifacts import ArtifactError, digest

ORIGINAL_UNIT = "evo-inference.service"
PYTHON = "/usr/bin/python3"
BUDGET_POLICY_SHA256 = "96f81bfa1ea1c90e4988a0a25560156ea402493b9549ac7f17d408c53f3bf277"
MAX_FILE_BYTES = 16 * 1024 * 1024
GLOBAL_LOCK = "/run/aotg-field-maintenance.lock"
GLOBAL_LEASE = "/run/aotg-field-maintenance-lease.json"

# This exact standalone source is copied into a root-only /run bundle. It has
# no AOTG/package/user imports, and never executes code from the worker tree.
RECOVERY_SOURCE = r'''"""Standalone root-owned AOTG recovery; stdlib only."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

GLOBAL_LOCK = "/run/aotg-field-maintenance.lock"
GLOBAL_LEASE = "/run/aotg-field-maintenance-lease.json"


def sha(value):
    return hashlib.sha256(json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def names(plan):
    nonce = plan["nonce"]
    if not isinstance(nonce, str) or not re.fullmatch("[0-9a-f]{16}", nonce) or plan["original_unit"] != "evo-inference.service":
        raise ValueError("Invalid recovery ownership scope")
    return {"worker": "aotg-" + nonce + "-worker.service", "service": "aotg-" + nonce + "-recovery.service", "timer": "aotg-" + nonce + "-recovery.timer"}


def active_original(state):
    return all(state.get(key) == value for key, value in {"LoadState": "loaded", "ActiveState": "active", "SubState": "exited", "Result": "success", "ExecMainStatus": "0"}.items())


def file_sha(path):
    path = Path(path)
    if not path.is_absolute() or any(part.is_symlink() for part in [path, *path.parents]):
        raise ValueError("Unsafe baseline path")
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.fstat(stream.fileno()).st_size > 16777216:
            raise ValueError("Invalid baseline file")
        return hashlib.file_digest(stream, "sha256").hexdigest()


def recover(plan, backend, deadline=None):
    """Caller holds exclusive root-bundle lock; backend is injectable for tests."""
    owned = names(plan)
    lease = backend.lease_state(plan)
    if lease == "absent" and backend.prior_restored(plan):
        return {"status": "unit-restored", "plan_sha256": sha(plan), "inference_verified": False, "rollback_demonstrated": False}
    if lease != "matching":
        raise RuntimeError("Global maintenance lease does not belong to this recovery")
    if deadline is None:
        deadline = backend.now() + plan["recovery_seconds"]
    backend.record("recovery_started")
    backend.save("recovery-started.json", {"plan_sha256": sha(plan)})
    try:
        state = backend.show(owned["worker"])
        if state.get("LoadState") != "not-found":
            backend.command(["/usr/bin/systemctl", "stop", owned["worker"]], timeout=min(60, max(1, deadline - backend.now())))
        while not backend.empty(owned["worker"]):
            if backend.now() >= deadline - 90:
                raise RuntimeError("Owned candidate cgroup did not empty; baseline not started")
            backend.sleep(0.2)
        backend.record("candidate_cgroup_empty")
        if not backend.baseline_matches(plan):
            raise RuntimeError("Baseline configuration drift; automatic start refused")
        backend.record("baseline_hashes_verified")
        if deadline - backend.now() <= 60:
            raise RuntimeError("Recovery reserve exhausted before baseline start")
        backend.command(["/usr/bin/systemctl", "start", plan["original_unit"]], timeout=deadline - backend.now() - 60)
        if not active_original(backend.show(plan["original_unit"])):
            raise RuntimeError("Original unit is not active(exited) with successful result")
        if not backend.empty(owned["worker"]) or not backend.baseline_matches(plan):
            raise RuntimeError("State changed during restoration verification")
        timer = backend.show(owned["timer"])
        if timer.get("LoadState") != "not-found":
            stopped = backend.command(["/usr/bin/systemctl", "stop", owned["timer"]], timeout=10, check=False)
            if stopped["returncode"]:
                backend.record("timer_stop_command_failed", returncode=stopped["returncode"])
            timer = backend.show(owned["timer"])
            if timer.get("LoadState") != "not-found" and timer.get("ActiveState") not in ("inactive", "failed"):
                raise RuntimeError("Owned recovery timer did not stop; lease retained")
        backend.command(["/usr/bin/systemctl", "reset-failed", owned["timer"], owned["worker"]], timeout=10, check=False)
        result = {"status": "unit-restored", "plan_sha256": sha(plan), "inference_verified": False,
                  "rollback_demonstrated": False}
        backend.save("restored.json", result)
        backend.record("unit_restore_verified")
        # This is the last lifecycle action. Once cleared, another approved
        # plan may acquire the lease; this recovery must not touch services.
        backend.release_lease(plan)
        return result
    except Exception as error:
        backend.save("failure-" + str(time.time_ns()) + ".json", {"status": "recovery-failed", "reason": str(error), "plan_sha256": sha(plan)})
        backend.record("recovery_failed", reason=str(error))
        raise


def enqueue_recovery(plan, backend):
    """ExecStopPost must exit before recovery can observe an empty cgroup."""
    if backend.lease_state(plan) != "matching":
        raise RuntimeError("Callback does not own the global maintenance lease")
    backend.command(["/usr/bin/systemctl", "--no-block", "start", names(plan)["service"]], timeout=10)


@contextmanager
def global_lock():
    descriptor = os.open(GLOBAL_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("Unsafe global maintenance lock")
        deadline = time.monotonic() + 15
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Global maintenance lock deadline exceeded")
                time.sleep(0.05)
        yield
    finally:
        os.close(descriptor)


def read_lease():
    try:
        descriptor = os.open(GLOBAL_LEASE, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096:
            raise RuntimeError("Unsafe global maintenance lease")
        return json.load(stream)


def expected_lease(plan):
    return {"artifact": "aotg-field-maintenance-lease", "version": 1, "nonce": plan["nonce"],
            "plan_sha256": sha(plan), "bundle": "/run/aotg-" + plan["nonce"]}


class Backend:
    def __init__(self, bundle, plan):
        self.bundle, self.plan = bundle, plan
    def now(self):
        return time.monotonic()
    def sleep(self, seconds):
        time.sleep(seconds)
    def record(self, event, **fields):
        with (self.bundle / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"time": time.time(), "event": event, **fields}) + "\n")
    def save(self, name, value):
        temporary = self.bundle / (".write-" + str(os.getpid()) + "-" + str(time.time_ns()))
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.bundle / name)
    def command(self, argv, timeout, check=True):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=timeout, check=False)
        if check and result.returncode:
            raise RuntimeError("systemctl operation failed: " + argv[1])
        return {"returncode": result.returncode, "stdout": result.stdout}
    def show(self, unit):
        permitted = {*names(self.plan).values(), self.plan["original_unit"]}
        if unit not in permitted:
            raise ValueError("Refuse unrelated unit")
        result = self.command(["/usr/bin/systemctl", "show", unit,
                               "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,ControlGroup,Triggers"], 10, check=False)
        return dict(line.split("=", 1) for line in result["stdout"].splitlines() if "=" in line)
    def empty(self, unit):
        if unit != names(self.plan)["worker"]:
            raise ValueError("Recovery may inspect only its owned candidate cgroup")
        state = self.show(unit)
        expected = "/system.slice/" + unit
        if state.get("ControlGroup", "") not in ("", expected):
            raise ValueError("Unexpected candidate cgroup")
        root = Path("/sys/fs/cgroup" + expected)
        if not root.exists():
            return state.get("ActiveState") in ("inactive", "failed", None) or state.get("LoadState") == "not-found"
        return not any(path.read_text().strip() for path in root.rglob("cgroup.procs"))
    def baseline_matches(self, plan):
        return all(file_sha(item["path"]) == item["sha256"] for item in [*plan["baseline_files"], plan["interpreter"]])
    def lease_state(self, plan):
        lease = read_lease()
        return "absent" if lease is None else "matching" if lease == expected_lease(plan) else "foreign"
    def prior_restored(self, plan):
        path = self.bundle / "restored.json"
        if not path.is_file():
            return False
        result = json.loads(path.read_text())
        return result.get("status") == "unit-restored" and result.get("plan_sha256") == sha(plan)
    def release_lease(self, plan):
        with global_lock():
            if self.lease_state(plan) != "matching":
                raise RuntimeError("Refuse to clear another maintenance lease")
            if not self.empty(names(plan)["worker"]) or not self.baseline_matches(plan) or not active_original(self.show(plan["original_unit"])):
                raise RuntimeError("State changed before global lease release")
            os.unlink(GLOBAL_LEASE)
            descriptor = os.open("/run", os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--cause", choices=("callback", "service"), required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("Recovery requires root")
    os.umask(0o077)
    plan_path = Path(args.plan)
    bundle = plan_path.parent
    if bundle.is_symlink() or bundle.stat().st_uid != 0 or stat.S_IMODE(bundle.stat().st_mode) != 0o700:
        raise RuntimeError("Root recovery bundle ownership mismatch")
    for path in (plan_path, bundle / "approval.json", Path(__file__)):
        if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            raise RuntimeError("Root recovery artifact is writable or replaced")
    plan = json.loads(plan_path.read_text())
    owned = names(plan)
    if bundle != Path("/run/aotg-" + plan["nonce"]) or plan["recovery_seconds"] != 600:
        raise RuntimeError("Unexpected recovery location or reserve")
    approval = json.loads((bundle / "approval.json").read_text())
    if approval != {"plan_sha256": sha(plan), "recovery_sha256": file_sha(__file__)} or approval["recovery_sha256"] != plan["recovery_sha256"]:
        raise RuntimeError("Root recovery approval/hash mismatch")
    # ExecStopPost is itself in the candidate cgroup. It must enqueue recovery
    # and exit, never lock/wait/stop that same unit synchronously.
    if args.cause == "callback":
        enqueue_recovery(plan, Backend(bundle, plan))
        return
    backend = Backend(bundle, plan)
    lock = os.open(bundle / "recovery.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + plan["recovery_seconds"]
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Recovery lock deadline exceeded")
                time.sleep(0.2)
        recover(plan, backend, deadline)
    finally:
        os.close(lock)


if __name__ == "__main__":
    main()
'''


def _require(condition, message):
    if not condition:
        raise ArtifactError(message)


def _file(path):
    path = Path(path)
    _require(path.is_absolute() and all(not item.is_symlink() for item in [path, *path.parents]),
             "Expected absolute path without symlinks")
    with path.open("rb") as stream:
        details = os.fstat(stream.fileno())
        _require(stat.S_ISREG(details.st_mode) and details.st_size <= MAX_FILE_BYTES, "Invalid or oversized maintenance input")
        data = stream.read(MAX_FILE_BYTES + 1)
    _require(len(data) <= MAX_FILE_BYTES, "Maintenance input grew beyond limit")
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}, data


def unit_names(plan):
    nonce = plan["nonce"]
    _require(isinstance(nonce, str) and re.fullmatch("[0-9a-f]{16}", nonce), "Invalid owned-unit nonce")
    return {"worker": f"aotg-{nonce}-worker.service", "service": f"aotg-{nonce}-recovery.service",
            "timer": f"aotg-{nonce}-recovery.timer"}


def freeze_maintenance_plan(*, nonce, uid, gid, worker_script, worker_plan, baseline_files,
                            work_dir, worker_args=("--plan", "@WORKER_PLAN@"), work_seconds=5400):
    script, _ = _file(worker_script)
    input_plan, _ = _file(worker_plan)
    interpreter, _ = _file(Path(PYTHON).resolve(strict=True))
    plan = {"artifact": "aotg-maintenance-plan", "version": 2, "nonce": nonce,
            "budget_policy_sha256": BUDGET_POLICY_SHA256,
            "original_unit": ORIGINAL_UNIT, "uid": uid, "gid": gid,
            "worker_script": script, "worker_plan": input_plan, "worker_args": list(worker_args),
            "interpreter": interpreter, "baseline_files": [_file(path)[0] for path in baseline_files],
            "coordinator_sha256": _file(Path(__file__).resolve())[0]["sha256"],
            "recovery_sha256": hashlib.sha256(RECOVERY_SOURCE.encode()).hexdigest(),
            "work_dir": str(Path(work_dir)), "work_seconds": work_seconds, "recovery_seconds": 600}
    validate_maintenance_plan(plan)
    return plan


def validate_maintenance_plan(plan, *, check_files=True):
    fields = {"artifact", "version", "nonce", "original_unit", "uid", "gid", "worker_script",
              "worker_plan", "worker_args", "interpreter", "baseline_files", "work_dir", "work_seconds", "recovery_seconds"}
    fields.update(("coordinator_sha256", "recovery_sha256", "budget_policy_sha256"))
    _require(isinstance(plan, dict) and set(plan) == fields and plan["artifact"] == "aotg-maintenance-plan"
             and type(plan["version"]) is int and plan["version"] == 2, "Invalid v2 maintenance plan")
    _require(plan["budget_policy_sha256"] == BUDGET_POLICY_SHA256, "Unreviewed comparison runtime budget policy")
    unit_names(plan)
    for key in ("coordinator_sha256", "recovery_sha256"):
        _require(isinstance(plan[key], str) and re.fullmatch("[0-9a-f]{64}", plan[key]), "Invalid approved control-code hash")
    _require(plan["original_unit"] == ORIGINAL_UNIT, "Refuse unrelated production unit")
    for key in ("uid", "gid"):
        _require(type(plan[key]) is int and 0 < plan[key] < 2**31, "Worker requires nonroot uid and gid")
    _require(type(plan["work_seconds"]) is int and plan["work_seconds"] == 5400
             and plan["recovery_seconds"] == 600 and type(plan["recovery_seconds"]) is int,
             "Require separately approved v2 5400-second work and600-second recovery policy")
    _require(isinstance(plan["worker_args"], list) and 1 <= len(plan["worker_args"]) <= 64
             and all(type(arg) is str and "\0" not in arg and len(arg) <= 4096 for arg in plan["worker_args"])
             and plan["worker_args"].count("@WORKER_PLAN@") == 1, "Invalid staged-worker argv")
    _require(isinstance(plan["baseline_files"], list) and plan["baseline_files"], "Baseline hashes are required")
    artifacts = [plan["worker_script"], plan["worker_plan"], plan["interpreter"], *plan["baseline_files"]]
    for item in artifacts:
        _require(isinstance(item, dict) and set(item) == {"path", "sha256"}
                 and isinstance(item["path"], str) and isinstance(item["sha256"], str)
                 and re.fullmatch("[0-9a-f]{64}", item["sha256"]), "Invalid artifact fingerprint")
        if check_files:
            _require(_file(item["path"])[0] == item, "Maintenance input hash drift")
    work = Path(plan["work_dir"])
    _require(work.is_absolute() and ".." not in work.parts and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(work)),
             "Work directory must be an absolute, unambiguous systemd path")
    if check_files:
        worker_input = json.loads(_file(plan["worker_plan"]["path"])[1])
        _require(worker_input.get("artifact") == "aotg-evo-worker-plan" and type(worker_input.get("version")) is int
                 and worker_input["version"] == 2
                 and worker_input.get("budget_policy_sha256") == BUDGET_POLICY_SHA256
                 and type(worker_input.get("max_seconds")) is int and worker_input["max_seconds"] == 5340
                 and worker_input.get("maintenance_unit") == unit_names(plan)["worker"]
                 and worker_input.get("task_root") == str(work / "work")
                 and worker_input.get("worker_sha256") == plan["worker_script"]["sha256"],
                 "Staged worker budget, identity or owned task binding differs")
        _require(plan["coordinator_sha256"] == _file(Path(__file__).resolve())[0]["sha256"]
                 and plan["recovery_sha256"] == hashlib.sha256(RECOVERY_SOURCE.encode()).hexdigest(),
                 "Maintenance control code changed after plan approval")
        _require(work.is_dir() and all(not item.is_symlink() for item in [work, *work.parents]), "Unsafe work directory")
        _require(work.stat().st_uid == plan["uid"] and stat.S_IMODE(work.stat().st_mode) == 0o700,
                 "Work directory must be private and owned by worker uid")
        _require(str(Path(PYTHON).resolve(strict=True)) == plan["interpreter"]["path"], "Fixed Python interpreter drift")
        for item in plan["baseline_files"]:
            _require(not Path(item["path"]).is_relative_to(work), "Baseline must be outside writable worker directory")
    return plan


def _original_active(state):
    return all(state.get(key) == value for key, value in {"LoadState": "loaded", "ActiveState": "active",
               "SubState": "exited", "Result": "success", "ExecMainStatus": "0"}.items())


@contextmanager
def _global_lock():
    import fcntl
    descriptor = os.open(GLOBAL_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                 "Unsafe global maintenance lock")
        deadline = time.monotonic() + 15
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                _require(time.monotonic() < deadline, "Global maintenance lock deadline exceeded")
                time.sleep(0.05)
        yield
    finally:
        os.close(descriptor)


def render_commands(plan, *, remaining_seconds=None):
    validate_maintenance_plan(plan, check_files=False)
    owned = unit_names(plan)
    bundle = f"/run/aotg-{plan['nonce']}"
    staged = f"/run/aotg-worker-{plan['nonce']}"
    recovery = [PYTHON, "-I", "-B", bundle + "/recover.py", "--plan", bundle + "/plan.json"]
    timer = ["/usr/bin/systemd-run", "--unit=" + owned["service"], f"--on-active={plan['work_seconds']}s",
             "--timer-property=AccuracySec=1s", "--property=Type=oneshot", "--property=TimeoutStartSec=600s",
             "--property=User=root", "--property=Group=root", "--", *recovery, "--cause", "service"]
    runtime = plan["work_seconds"] if remaining_seconds is None else remaining_seconds
    _require(type(runtime) is int and 1 <= runtime <= plan["work_seconds"], "Invalid remaining worker budget")
    callback = "+" + " ".join([*recovery, "--cause", "callback"])
    worker = ["/usr/bin/systemd-run", "--unit=" + owned["worker"], "--property=Type=exec",
              "--property=RemainAfterExit=yes",
              f"--property=User={plan['uid']}", f"--property=Group={plan['gid']}", "--property=KillMode=control-group",
              f"--property=RuntimeMaxSec={runtime}s", "--property=TimeoutStopSec=30s", "--property=SendSIGKILL=yes",
              "--property=PrivateTmp=yes", "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict",
              "--property=ProtectHome=read-only", "--property=ReadWritePaths=" + plan["work_dir"],
              "--property=UMask=0077", "--property=ExecStopPost=" + callback, "--", PYTHON, "-I", "-B",
              staged + "/worker.py", *[staged + "/worker-plan.json" if arg == "@WORKER_PLAN@" else arg for arg in plan["worker_args"]]]
    return {"arm_timer": timer, "stop_original": ["/usr/bin/systemctl", "stop", ORIGINAL_UNIT],
            "start_worker": worker, "request_recovery": ["/usr/bin/systemctl", "start", owned["service"]]}


class SystemdBackend:
    simulation = False

    def __init__(self):
        self.bundle = None

    def now(self):
        return time.monotonic()

    def lease_active(self):
        # Any stale, malformed or inaccessible lease refuses new work. Only a
        # matching root-owned recovery may clear it; never silently steal it.
        return os.path.lexists(GLOBAL_LEASE)

    def acquire_lease(self, plan):
        _require(self.bundle == Path("/run/aotg-" + plan["nonce"]), "Root bundle must be staged before lease acquisition")
        with _global_lock():
            _require(not self.lease_active(), "An active or stale global maintenance lease exists")
            _require(_original_active(self.show(ORIGINAL_UNIT)) and self.baseline_matches(plan),
                     "Original state changed before maintenance lease acquisition")
            value = {"artifact": "aotg-field-maintenance-lease", "version": 1, "nonce": plan["nonce"],
                     "plan_sha256": digest(plan), "bundle": str(self.bundle)}
            temporary = Path("/run/.aotg-field-lease-" + secrets.token_hex(8))
            try:
                with temporary.open("x", encoding="utf-8") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    os.fchown(stream.fileno(), 0, 0)
                    json.dump(value, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Global lock excludes other coordinators; hard-link publication
                # additionally refuses replacing any unexpectedly created lease.
                os.link(temporary, GLOBAL_LEASE)
            finally:
                temporary.unlink(missing_ok=True)

    def command(self, argv, timeout, check=True):
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, timeout=timeout, check=False)
        if check and completed.returncode:
            raise ArtifactError("Maintenance systemd command failed")
        return {"returncode": completed.returncode, "stdout": completed.stdout}

    def show(self, unit):
        result = self.command(["/usr/bin/systemctl", "show", unit,
                               "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,ControlGroup,Triggers"], 10, check=False)
        return dict(line.split("=", 1) for line in result["stdout"].splitlines() if "=" in line)

    def empty(self, unit):
        state = self.show(unit)
        expected = "/system.slice/" + unit
        _require(state.get("ControlGroup", "") in ("", expected), "Unexpected maintenance cgroup")
        root = Path("/sys/fs/cgroup" + expected)
        if not root.exists():
            return state.get("ActiveState") in ("inactive", "failed", None)
        return not any(path.read_text().strip() for path in root.rglob("cgroup.procs"))

    def baseline_matches(self, plan):
        return all(_file(item["path"])[0] == item for item in [*plan["baseline_files"], plan["interpreter"]])

    def restored_receipt(self, plan):
        if self.lease_active() or self.bundle is None or not (self.bundle / "restored.json").is_file():
            return False
        value = json.loads((self.bundle / "restored.json").read_text())
        return value.get("status") == "unit-restored" and value.get("plan_sha256") == digest(plan)

    @contextmanager
    def launch_guard(self, deadline):
        import fcntl
        _require(self.bundle is not None, "Root staging is required before launch")
        descriptor = os.open(self.bundle / "recovery.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            while True:
                _require(self.now() < deadline, "Work deadline expired before launch lock")
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.1)
            _require(not (self.bundle / "recovery-started.json").exists(), "Recovery already began; worker launch refused")
            yield
        finally:
            os.close(descriptor)

    def wait_worker(self, unit, deadline):
        while self.now() < deadline:
            state = self.show(unit)
            _require(state.get("LoadState") == "loaded", "Worker state disappeared before outcome collection")
            if state.get("ActiveState") in ("inactive", "failed") or state.get("SubState") == "exited":
                return 0 if state.get("Result") == "success" and state.get("ExecMainStatus") == "0" else 1
            time.sleep(0.2)
        raise ArtifactError("Worker did not finish within bounded deadline")


def preview_maintenance(plan, *, backend=None):
    """Read-only hash/unit validation and exact command rendering; no staging."""
    validate_maintenance_plan(plan)
    backend = backend or SystemdBackend()
    _require(not backend.lease_active(), "An active or stale global maintenance lease exists; explicit recovery is required")
    _require(_original_active(backend.show(ORIGINAL_UNIT)), "Original service is not active(exited)/success")
    for name in unit_names(plan).values():
        _require(backend.show(name).get("LoadState") == "not-found", "Owned transient name already exists; freeze a new plan")
    return {"artifact": "aotg-maintenance-preview", "version": 1, "dry_run": True,
            "plan_sha256": digest(plan), "commands": render_commands(plan),
            "production_changed": False, "rollback_demonstrated": False}


def _stage(plan):
    bundle = Path("/run/aotg-" + plan["nonce"])
    staged = Path("/run/aotg-worker-" + plan["nonce"])
    _require(not bundle.exists() and not staged.exists(), "Refuse reuse of staged maintenance bundle")
    bundle.mkdir(mode=0o700)
    os.chown(bundle, 0, 0)
    staged.mkdir(mode=0o750)
    os.chown(staged, 0, plan["gid"])
    os.chmod(staged, 0o750)
    outputs = [(bundle / "plan.json", json.dumps(plan, sort_keys=True).encode(), 0, 0o600),
               (bundle / "recover.py", RECOVERY_SOURCE.encode(), 0, 0o500),
               (bundle / "approval.json", json.dumps({"plan_sha256": digest(plan),
                "recovery_sha256": hashlib.sha256(RECOVERY_SOURCE.encode()).hexdigest()}).encode(), 0, 0o600)]
    for name, item in (("worker.py", plan["worker_script"]), ("worker-plan.json", plan["worker_plan"])):
        observed, data = _file(item["path"])
        _require(observed == item, "Worker changed while staging")
        outputs.append((staged / name, data, plan["gid"], 0o440))
    for path, content, gid, mode in outputs:
        with path.open("xb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    return bundle


def _run_sequence(plan, backend):
    """Testable coordinator; real caller must first approve, validate and stage."""
    commands, owned = render_commands(plan), unit_names(plan)
    deadline = backend.now() + plan["work_seconds"]
    worker_exit = None
    failures = []
    recovery_needed = False
    lease_acquired = False
    try:
        backend.acquire_lease(plan)
        lease_acquired = True
        # Treat even ambiguous timer creation failure as requiring recovery.
        recovery_needed = True
        backend.command(commands["arm_timer"], timeout=20)
        timer = backend.show(owned["timer"])
        _require(timer.get("LoadState") == "loaded" and timer.get("ActiveState") == "active"
                 and timer.get("Triggers") == owned["service"], "Recovery timer did not arm; original not stopped")
        # Registration and recovery share a short lock. Do not hold it while
        # waiting for the benchmark: the independent timer must remain able to
        # stop the worker if this supervisor disappears or the work expires.
        with backend.launch_guard(deadline):
            backend.command(commands["stop_original"], timeout=60)
            _require(backend.show(ORIGINAL_UNIT).get("ActiveState") == "inactive" and backend.empty(ORIGINAL_UNIT),
                     "Original unit did not stop and release its cgroup")
            remaining = math.floor(deadline - backend.now())
            _require(remaining >= 5340, "Insufficient remaining coordinator budget for frozen worker allotment")
            worker = render_commands(plan, remaining_seconds=remaining)["start_worker"]
            result = backend.command(worker, timeout=20, check=False)
            worker_exit = result["returncode"]
        if worker_exit == 0:
            worker_exit = backend.wait_worker(owned["worker"], deadline + 45)
    except Exception as error:
        failures.append(str(error))
    finally:
        if recovery_needed:
            try:
                backend.command(commands["request_recovery"], timeout=plan["recovery_seconds"] + 15)
            except Exception as error:
                failures.append("Recovery request failed: " + str(error))
    try:
        restored = (backend.restored_receipt(plan) and backend.empty(owned["worker"])
                    and backend.baseline_matches(plan) and _original_active(backend.show(ORIGINAL_UNIT)))
    except Exception as error:
        failures.append("Post-recovery verification failed: " + str(error))
        restored = False
    simulation = backend.simulation
    return {"artifact": "aotg-maintenance-result", "version": 1, "plan_sha256": digest(plan),
            "status": "lease-refused" if not lease_acquired else "recovery-failed" if not restored else "completed" if worker_exit == 0 and not failures else "worker-failed-restored",
            "worker_exit_code": worker_exit, "failures": failures, "simulation": simulation,
            "unit_restore_verified": restored and not simulation, "simulated_restore_passed": restored and simulation,
            "inference_verified": False, "rollback_demonstrated": False}


def execute_maintenance(plan, *, execute=False, approved_plan_sha256=None):
    """Default is read-only preview. Real execution requires root + exact approval.

    The operator must verify API idle and obtain the service-interruption approval
    before this call. A unit's active(exited) state does not prove API idleness.
    No persistent service registration, sudo rule, download or driver change is
    made. Both root bundles remain in /run for diagnosis until reboot/manual care.
    The global AOTG field lease survives supervisor death. Any existing lease,
    including a stale one, blocks a new plan until its matching recovery verifies
    restoration and clears it; this path never reuses UOB-58 reservation locks.
    """
    if not execute:
        return preview_maintenance(plan)
    _require(execute is True and sys.platform == "linux" and os.geteuid() == 0,
             "Approved maintenance execution requires Linux root")
    _require(approved_plan_sha256 == digest(plan), "Explicit approval must match the exact private plan SHA-256")
    preview_maintenance(plan)
    backend = SystemdBackend()
    backend.bundle = _stage(plan)
    result = _run_sequence(plan, backend)
    with (backend.bundle / "supervisor-result.json").open("x", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(result, stream, sort_keys=True, indent=2)
    return result
