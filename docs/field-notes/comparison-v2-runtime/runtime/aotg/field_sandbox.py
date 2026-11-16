"""Optional offline Linux namespace containment for compiler evaluation.

Requires existing util-linux tools and unprivileged user namespaces. No fallback
executes a command on the host. This reduces accidental access to home files and
network services; it is not a hardened adversarial sandbox, VM, seccomp policy or
cgroup memory limit. The kernel, /usr tree and explicitly supplied tool trees
remain trusted. Do not bind credentials or an unaudited tool/cache directory.
"""

import ctypes
import json
import math
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath

from .artifacts import ArtifactError, digest

MAX_OUTPUT_BYTES = 128 * 1024
_TOOLS = ("/usr/bin/unshare", "/usr/bin/mount", "/usr/bin/setpriv", "/usr/bin/python3")
_SYSTEM = ("/usr", "/bin", "/lib", "/lib64")
_NAMESPACES = ("user", "mnt", "pid", "net", "ipc")
_SECRETS = {".ssh", ".aws", ".azure", ".gnupg", ".codex", ".kube"}

# Executed after chroot and setpriv, before the caller's executable. A private
# pipe acknowledges actual namespace/capability checks, then is closed before
# the untrusted command can run. stdout cannot forge this readiness evidence.
_EXEC = r'''
import json, os, pathlib, resource, sys
config = json.loads(sys.argv[1])
status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)
assert all(int(status[key].strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"))
assert status["NoNewPrivs"].strip() == "1"
assert all(os.readlink("/proc/self/ns/" + key) != value for key, value in config["parent_namespaces"].items())
assert os.getpid() == 1
caps = config["caps"]
for limit, value in ((resource.RLIMIT_CPU, caps["cpu_seconds"]), (resource.RLIMIT_FSIZE, caps["file_bytes"]),
                     (resource.RLIMIT_NOFILE, caps["descriptors"]), (resource.RLIMIT_NPROC, caps["processes"]),
                     (resource.RLIMIT_CORE, 0)):
    resource.setrlimit(limit, (value, value))
if caps["memory_bytes"] is not None:
    resource.setrlimit(resource.RLIMIT_AS, (caps["memory_bytes"], caps["memory_bytes"]))
os.umask(0o077)
os.chdir("/work")
os.write(config["ready_fd"], b"namespace-capabilities-verified\n")
os.close(config["ready_fd"])
os.execve(config["argv"][0], config["argv"], config["environment"])
'''


def _require(condition, message):
    if not condition:
        raise ArtifactError(message)


def _bounded(value, name, minimum, maximum):
    _require(type(value) in (int, float) and math.isfinite(value)
             and minimum <= value <= maximum, f"Invalid {name}")


def _path_without_symlinks(value):
    path = Path(value)
    _require(path.is_absolute() and ".." not in path.parts, "Require an absolute, non-traversing path")
    _require(path.exists(), "Sandbox source path does not exist")
    _require(all(not item.is_symlink() for item in [path, *path.parents]),
             "Symlink in sandbox source path")
    return path.resolve(strict=True)


def _bindings(workspace, supplied):
    _require(isinstance(supplied, dict), "readonly_bindings must map sandbox destinations to host sources")
    result = {}
    for destination, source in supplied.items():
        _require(isinstance(destination, str), "Invalid binding destination")
        target = PurePosixPath(destination)
        _require(target.is_absolute() and str(target) == destination
                 and len(target.parts) == 3 and target.parts[1] == "tools"
                 and target.name not in (".", "..") and "\\" not in destination,
                 "Read-only bindings must target /tools/<name>")
        path = _path_without_symlinks(source)
        _require(path.is_file() or path.is_dir(), "Tool binding must be a regular file or directory")
        _require(path not in (Path.home().resolve(), workspace)
                 and len(path.parts) >= 3 and not (_SECRETS & set(path.parts)),
                 "Refuse home, workspace or credential directory binding")
        _require(path != Path("/home") and path != Path("/root")
                 and path.parts[1] not in ("proc", "sys", "dev", "etc"),
                 "Refuse broad or special filesystem binding")
        result[destination] = str(path)
    return result


def _validate_workspace(workspace):
    workspace = _path_without_symlinks(workspace)
    _require(workspace.is_dir() and workspace != Path.home().resolve()
             and len(workspace.parts) >= 3 and not (_SECRETS & set(workspace.parts)),
             "Use a dedicated task workspace, never a home or credential directory")
    # Do not expose host IPC sockets/device nodes, nor pre-existing symlink
    # escapes. New symlinks created inside the chroot cannot see the host root.
    count = 0
    for base, directories, files in os.walk(workspace, followlinks=False):
        for name in [*directories, *files]:
            count += 1
            _require(count <= 20000, "Task workspace exceeds 20,000 entries")
            path = Path(base) / name
            _require(not path.is_symlink() and (path.is_file() or path.is_dir()),
                     "Workspace contains a symlink or special file")
            _require(not path.is_file() or path.stat().st_nlink == 1,
                     "Workspace contains a hard-linked file; copy task inputs instead")
    return workspace


def _validate_argv(argv, workspace, bindings):
    _require(isinstance(argv, (list, tuple)) and 1 <= len(argv) <= 256
             and all(type(item) is str and "\0" not in item for item in argv)
             and sum(len(item) for item in argv) <= 65536, "Invalid executable argument vector")
    executable = PurePosixPath(argv[0])
    _require(executable.is_absolute() and ".." not in executable.parts
             and str(executable) == argv[0], "Executable must be an absolute sandbox path")
    if executable.is_relative_to("/work"):
        host = workspace / str(executable.relative_to("/work"))
    else:
        host = None
        for destination, source in bindings.items():
            if executable == PurePosixPath(destination):
                host = Path(source)
            elif executable.is_relative_to(destination):
                host = Path(source) / str(executable.relative_to(destination))
        if host is None and any(executable.is_relative_to(base) for base in _SYSTEM):
            host = Path(argv[0])
    _require(host is not None and host.is_file() and os.access(host, os.X_OK),
             "Executable is absent from exposed system/tool/workspace paths")


def _mount(argv):
    subprocess.run(["/usr/bin/mount", *argv], check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)


def _recursive_readonly(target):
    # WSL's /usr includes locked driver-library submounts: use rbind, then
    # recursively restrict *all* mounts, not merely the top-level bind.
    class MountAttributes(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in
                    ("attr_set", "attr_clr", "propagation", "userns_fd")]
    library = ctypes.CDLL(None, use_errno=True)
    operation = library.mount_setattr
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
                          ctypes.POINTER(MountAttributes), ctypes.c_size_t]
    operation.restype = ctypes.c_int
    attributes = MountAttributes(1 | 2 | 4, 0, 0, 0)  # RDONLY | NOSUID | NODEV
    if operation(-100, os.fsencode(target), 0x8000, ctypes.byref(attributes),
                 ctypes.sizeof(attributes)) != 0:  # AT_FDCWD, AT_RECURSIVE
        raise OSError(ctypes.get_errno(), "Cannot restrict recursive tool binding")


def _bind(root, destination, source, *, readonly, device=False):
    target = root / destination.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    if Path(source).is_dir():
        target.mkdir(exist_ok=True)
    else:
        target.touch(exist_ok=True)
    _mount(["--rbind" if readonly else "--bind", str(source), str(target)])
    if readonly:
        _recursive_readonly(target)
        return
    flags = "remount,bind,nosuid" + (",ro" if readonly else ",rw")
    if device:
        flags += ",noexec"
    else:
        flags += ",nodev"
    _mount(["-o", flags, str(target)])


def _child(config_path):
    # Only the trusted launcher enters this branch; candidate code is reached
    # only after every setup operation and the post-setpriv checks succeed.
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    root = Path(config["root"])
    _mount(["--make-rprivate", "/"])
    _mount(["--bind", str(root), str(root)])
    for system in _SYSTEM:
        if Path(system).exists():
            _bind(root, system, Path(system).resolve(), readonly=True)
    _bind(root, "/work", config["workspace"], readonly=config["readonly_workspace"])
    for destination, source in config["bindings"].items():
        _bind(root, destination, source, readonly=True)
    for device in ("null", "zero", "random", "urandom"):
        _bind(root, "/dev/" + device, "/dev/" + device, readonly=False, device=True)
    for destination, size in (("tmp", 128 * 1024 * 1024), ("home/sandbox", 16 * 1024 * 1024)):
        target = root / destination
        target.mkdir(parents=True, exist_ok=True)
        _mount(["-t", "tmpfs", "-o", f"nosuid,nodev,size={size},mode=700", "tmpfs", str(target)])
    proc = root / "proc"
    proc.mkdir()
    _mount(["-t", "proc", "-o", "ro,nosuid,nodev,noexec", "proc", str(proc)])
    _mount(["-o", "remount,bind,ro,nosuid,nodev", str(root)])
    os.chroot(root)
    os.chdir("/work")
    payload = {key: config[key] for key in ("argv", "caps", "parent_namespaces", "ready_fd", "environment")}
    command = ["/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all",
               "--ambient-caps=-all", "--no-new-privs", "/usr/bin/python3",
               "-I", "-B", "-c", _EXEC, json.dumps(payload)]
    os.execve(command[0], command, config["environment"])


def run_isolated(argv, workspace, *, readonly_bindings=None, timeout_seconds=30,
                 execution_authorized=False, memory_limit_bytes=512 * 1024 * 1024,
                 file_limit_bytes=64 * 1024 * 1024, process_limit=128,
                 readonly_workspace=False):
    """Execute in an offline disposable chroot; return bounded private output.

    ``argv`` uses sandbox paths (/work, /tools/<name>, /usr/bin, etc.). Bindings
    map /tools/<name> to existing audited host tool files/directories. The only
    persistent writable mount is ``workspace``. No credentials are inherited.
    RLIMIT_AS is per process, not an aggregate memory limit; .NET often needs
    ``memory_limit_bytes=None`` because of large virtual address reservations.
    CPU/process limits are also per-process/per-user limits, not cgroup quotas.
    """
    _require(execution_authorized is True, "Execution requires explicit execution_authorized=True")
    _require(sys.platform == "linux", "Namespace isolation is only available on Linux")
    _bounded(timeout_seconds, "timeout_seconds", 0.1, 180)
    _require(type(readonly_workspace) is bool, "readonly_workspace must be boolean")
    _bounded(file_limit_bytes, "file_limit_bytes", 1024, 512 * 1024 * 1024)
    _require(type(file_limit_bytes) is int, "file_limit_bytes must be an integer")
    _require(type(process_limit) is int and 8 <= process_limit <= 256, "Invalid process limit")
    if memory_limit_bytes is not None:
        _require(type(memory_limit_bytes) is int, "memory_limit_bytes must be an integer")
        _bounded(memory_limit_bytes, "memory_limit_bytes", 64 * 1024 * 1024, 16 * 1024**3)
    _require(all(Path(tool).is_file() and os.access(tool, os.X_OK) for tool in _TOOLS),
             "Required existing Linux isolation tools are unavailable")
    workspace = _validate_workspace(workspace)
    bindings = _bindings(workspace, readonly_bindings or {})
    _validate_argv(argv, workspace, bindings)
    caps = {"cpu_seconds": max(1, math.ceil(timeout_seconds)), "file_bytes": file_limit_bytes,
            "descriptors": 128, "processes": process_limit, "memory_bytes": memory_limit_bytes}
    result = {"artifact": "aotg-offline-isolation", "version": 1,
              "status": "isolation-unavailable", "exit_code": None,
              "isolation_verified": False, "seconds": 0.0, "stdout": "", "stderr": "",
              "output_truncated": False, "limits": caps, "network": "new-offline-namespace",
              "command_sha256": digest(list(argv)), "aggregate_memory_limit": False,
              "dotnet_gc_heap_limit_bytes": 512 * 1024 * 1024,
              "readonly_workspace": readonly_workspace}
    started = time.monotonic()
    # Mounts exist only in the child namespace, and cannot propagate back here.
    with tempfile.TemporaryDirectory(prefix="aotg-sandbox-") as temporary:
        container = Path(temporary).resolve()
        root = container / "root"
        root.mkdir(mode=0o700)
        ready_read, ready_write = os.pipe()
        config = {"root": str(root), "workspace": str(workspace), "bindings": bindings,
                  "readonly_workspace": readonly_workspace,
                  "argv": list(argv), "caps": caps, "ready_fd": ready_write,
                  "parent_namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in _NAMESPACES},
                  "environment": {"PATH": "/usr/bin:/bin", "HOME": "/home/sandbox",
                                  "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TMPDIR": "/tmp",
                                  "DOTNET_CLI_HOME": "/home/sandbox", "DOTNET_NOLOGO": "1",
                                  "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
                                  "DOTNET_GCHeapHardLimit": "0x20000000",
                                  "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": "/tmp/nuget"}}
        config_path = container / "setup.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        config_path.chmod(0o600)
        command = ["/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net", "--ipc",
                   "--pid", "--fork", "--kill-child=SIGKILL", "--propagation", "private",
                   "/usr/bin/python3", "-I", "-B", "-c",
                   "import sys; sys.path.insert(0, sys.argv.pop(1)); "
                   "from aotg.field_sandbox import _child; _child(sys.argv[1])",
                   str(Path(__file__).resolve().parents[1]), str(config_path)]
        process = None
        selector = selectors.DefaultSelector()
        output = {"stdout": bytearray(), "stderr": bytearray(), "ready": bytearray()}
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                                       close_fds=True, pass_fds=(ready_write,), start_new_session=True)
            os.close(ready_write)
            ready_write = None
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr"), (ready_read, "ready")):
                descriptor = stream if isinstance(stream, int) else stream.fileno()
                os.set_blocking(descriptor, False)
                selector.register(descriptor, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() - started >= timeout_seconds:
                    result["status"] = "timeout"
                    break
                for key, _ in selector.select(timeout=0.02):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fd)
                    else:
                        output[key.data].extend(data)
                if sum(len(value) for value in output.values()) > MAX_OUTPUT_BYTES:
                    result["status"] = "output-limit"
                    result["output_truncated"] = True
                    break
            if result["status"] not in ("timeout", "output-limit"):
                process.wait(timeout=max(0.1, timeout_seconds - (time.monotonic() - started)))
                result["status"] = "ok" if process.returncode == 0 else "nonzero-exit"
        except (OSError, subprocess.SubprocessError):
            result["status"] = "launch-error"
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    result["status"] = "cleanup-failed"
                result["exit_code"] = process.returncode
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            selector.close()
            os.close(ready_read)
            if ready_write is not None:
                os.close(ready_write)
        result["isolation_verified"] = bytes(output["ready"]) == b"namespace-capabilities-verified\n"
        if not result["isolation_verified"] and result["status"] in ("ok", "nonzero-exit"):
            result["status"] = "isolation-unavailable"
        remaining = MAX_OUTPUT_BYTES
        for name in ("stdout", "stderr"):
            data = bytes(output[name][:remaining])
            remaining -= len(data)
            result[name] = data.decode("utf-8", errors="replace")
            for source, replacement in ((str(container), "<sandbox>"), (str(workspace), "<workspace>"),
                                         (str(Path(__file__).resolve().parents[1]), "<tooling>"),
                                         *((source, "<readonly-tool>") for source in bindings.values())):
                result[name] = result[name].replace(source, replacement)
        _require(root.resolve().is_relative_to(container), "Refuse unsafe sandbox cleanup")
    result["seconds"] = time.monotonic() - started
    return result


if __name__ == "__main__":
    # Standalone execution is reserved for the namespace setup process.
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        try:
            _child(sys.argv[2])
        except Exception:
            print("AOTG namespace setup failed before candidate execution", file=sys.stderr)
            raise SystemExit(125)
    raise SystemExit("Use run_isolated() with explicit execution authorization")
