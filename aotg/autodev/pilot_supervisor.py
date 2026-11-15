"""Supervise one AOTG pilot from a trusted external copy of this file.

The owner must pin this copy to reviewed bytes and be the sole writer of
the installed checkout and its parents while the pilot is running.
"""

import argparse
import hashlib
import os
import re
import runpy
import secrets
import selectors
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from time import monotonic_ns
from typing import Literal

MAX_RUNTIME_SECONDS = 40 * 60
_SECOND = 1_000_000_000
_OUTPUT_LIMIT = 4096
_TREE_LIMIT = 64 * 1024**2
_COMMIT = re.compile(r"(?!0{40})[0-9a-f]{40}")
_INTEROP = re.compile(r"/run/WSL/[0-9]{1,12}_interop")
_PROGRAMS = ("/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/env", "/usr/bin/python3")
_ORIGIN = "https://github.com/uobnnisiuk/AOTG.git"
_GIT_CONFIG = {
    "core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
    "core.ignorecase", "core.precomposeunicode", "core.symlinks",
    "remote.origin.url", "remote.origin.fetch", "remote.origin.tagopt",
    "branch.main.remote", "branch.main.merge",
}
_GIT_REDIRECTS = (
    "commondir", "config.worktree", "objects/info/alternates", "objects/info/http-alternates",
    "info/grafts", "info/attributes", "info/sparse-checkout", "refs/replace", "shallow",
)
_UNSET_LOADER_ENV = (
    "LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT LD_LIBRARY_PATH LD_PRELOAD "
    "LD_PROFILE GLIBC_TUNABLES MALLOC_TRACE"
)


@dataclass(frozen=True, slots=True)
class SupervisorResult:
    """Local process supervision only. The pilot receipt is independently verified."""

    status: Literal["complete", "timeout", "unconfirmed", "blocked"]
    exit_code: int | None = None


def _trusted_system_program(path):
    executable = Path(path).resolve(strict=True)
    for parent in executable.parents:
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
            raise ValueError("System executable directory is not trusted")
    info = executable.stat()
    if (info.st_uid != 0 or info.st_mode & 0o022
            or not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o100):
        raise ValueError("System executable is not trusted")
    return str(executable)


def _safe_path(path):
    return path.is_absolute() and path.resolve(strict=True) == path and not any(
        character in str(path) for character in ("\x00", "\n", "\r", "$", "%")
    )


def _owner_directory(path, uid, *, private=False):
    if not _safe_path(path):
        raise ValueError("Expected a canonical deployment directory")
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or info.st_mode & (0o077 if private else 0o022)):
        raise ValueError("Deployment directory is not owner controlled")


def _trusted_supervisor(checkout):
    source = Path(__file__).absolute()
    uid = os.geteuid()
    if source.is_relative_to(checkout) or not _safe_path(source):
        raise ValueError("Use an independently pinned copy of the supervisor")
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, uid)
            or info.st_mode & 0o022 or info.st_nlink != 1):
        raise ValueError("The external supervisor file is not trusted")
    for directory in source.parents:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid)
                or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise ValueError("The external supervisor path is not owner controlled")
    return source


def _entries(root, uid, deadline, *, max_entries, skip_git=False):
    pending = [(root, Path())]
    count = 0
    while pending:
        directory, prefix = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if skip_git and prefix == Path() and entry.name == ".git":
                    continue
                count += 1
                if count > max_entries or monotonic_ns() >= deadline:
                    raise ValueError("The checkout exceeds its verification bound")
                relative = prefix / entry.name
                info = entry.stat(follow_symlinks=False)
                if info.st_uid != uid or info.st_mode & 0o022:
                    raise ValueError("The checkout has non-owner-controlled entries")
                if stat.S_ISDIR(info.st_mode):
                    pending.append((Path(entry.path), relative))
                elif not stat.S_ISREG(info.st_mode):
                    raise ValueError("The checkout has a link or irregular entry")
                yield relative, info


def _git_bytes(git, checkout, deadline, *arguments, limit=4096):
    argv = (
        git, "--no-pager", "--no-optional-locks", f"--git-dir={checkout / '.git'}",
        f"--work-tree={checkout}", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.allow=never", *arguments,
    )
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
    }
    code, payload = _read_command(argv, environment, deadline, limit=limit, stderr=subprocess.DEVNULL)
    if code != 0:
        raise ValueError("The pinned Git checkout could not be verified")
    return payload


def _tracked(git, checkout, deadline, sha):
    entries = _git_bytes(git, checkout, deadline, "ls-tree", "--full-tree", "-rz", sha, limit=2 * 1024**2)
    files = {}
    directories = set()
    for item in entries.split(b"\0")[:-1]:
        metadata, separator, name = item.partition(b"\t")
        mode, kind, oid = metadata.decode("ascii").split(" ")
        relative = Path(os.fsdecode(name))
        if (
            not separator or kind != "blob" or mode not in {"100644", "100755"}
            or not _COMMIT.fullmatch(oid) or relative.is_absolute() or str(relative) != os.fsdecode(name)
            or not relative.parts or any(part in {"..", ".git", "__pycache__"} for part in relative.parts)
            or relative.suffix in {".pyc", ".pyo"} or relative in files
        ):
            raise ValueError("The pinned tree contains an unsafe or ambiguous path")
        files[relative] = mode == "100755", oid
        directories.update(parent for parent in relative.parents if parent != Path())
    return files, directories


def _blob_id(path, info, deadline):
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {info.st_size}\0".encode("ascii"))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(info, opened):
            raise ValueError("The verified source file changed")
        remaining = info.st_size
        while remaining:
            if monotonic_ns() >= deadline:
                raise TimeoutError("Source verification exceeded its deadline")
            chunk = stream.read(min(64 * 1024, remaining))
            if not chunk:
                raise ValueError("The verified source size changed")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(stream.fileno())
        if after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns or stream.read(1):
            raise ValueError("The verified source file changed")
    return digest.hexdigest()


def _checkout_matches(checkout, sha, *, deadline_ns=None):
    """Check actual main bytes and metadata before any checkout code can import."""
    if (sys.platform != "linux" or not isinstance(checkout, Path) or checkout.name != "checkout"
            or type(sha) is not str or not _COMMIT.fullmatch(sha)):
        return False
    deadline = monotonic_ns() + 10 * _SECOND
    if deadline_ns is not None:
        deadline = min(deadline, deadline_ns)
    try:
        uid = os.geteuid()
        if uid == 0:
            return False
        _owner_directory(checkout.parent, uid, private=True)
        _owner_directory(checkout, uid)
        config = checkout.parent / "config"
        if os.path.lexists(config):
            _owner_directory(config, uid, private=True)
        metadata = checkout / ".git"
        _owner_directory(metadata, uid)
        if any(os.path.lexists(metadata / path) for path in _GIT_REDIRECTS):
            return False
        for _ in _entries(metadata, uid, deadline, max_entries=50_000):
            pass
        if any((metadata / name).stat().st_nlink != 1 for name in ("HEAD", "config")):
            return False

        git = _trusted_system_program("/usr/bin/git")
        keys = _git_bytes(git, checkout, deadline, "config", "--local", "--no-includes", "--name-only",
                          "-z", "--list").decode("ascii").split("\0")[:-1]
        if len(keys) != len(set(keys)) or not set(keys) <= _GIT_CONFIG:
            return False
        for command, value in (
            (("symbolic-ref", "--quiet", "HEAD"), b"refs/heads/main\n"),
            (("rev-parse", "--verify", "HEAD"), sha.encode("ascii") + b"\n"),
            (("config", "--local", "--no-includes", "--get", "remote.origin.url"), _ORIGIN.encode() + b"\n"),
        ):
            if _git_bytes(git, checkout, deadline, *command) != value:
                return False
        _git_bytes(git, checkout, deadline, "fsck", "--strict", "--full", "--no-reflogs",
                   "--no-dangling", sha)
        _git_bytes(git, checkout, deadline, "diff-index", "--cached", "--quiet", "--no-ext-diff",
                   "--no-textconv", "--ignore-submodules=all", sha, "--")
        files, directories = _tracked(git, checkout, deadline, sha)
        if Path("aotg/autodev/pilot_launch.py") not in files:
            return False
        size = 0
        for path, info in _entries(checkout, uid, deadline, max_entries=16_384, skip_git=True):
            if stat.S_ISDIR(info.st_mode):
                if path not in directories:
                    return False
                continue
            expected = files.pop(path, None)
            size += info.st_size
            if expected is None or size > _TREE_LIMIT or bool(info.st_mode & stat.S_IXUSR) != expected[0]:
                return False
            if _blob_id(checkout / path, info, deadline) != expected[1]:
                return False
        return not files
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        return False


def _deployment(workdir):
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("The supervisor requires a non-root WSL execution identity")
    # Keep POSIX-only account lookup out of module imports on CI's Windows hosts.
    import pwd

    uid = os.geteuid()
    _owner_directory(workdir.parent, uid, private=True)
    _owner_directory(workdir, uid)
    home = Path(pwd.getpwuid(uid).pw_dir)
    _owner_directory(home, uid)
    runtime = Path("/run/user") / str(uid)
    _owner_directory(runtime, uid, private=True)
    bus = (runtime / "bus").lstat()
    if not stat.S_ISSOCK(bus.st_mode) or bus.st_uid != uid:
        raise ValueError("The user bus is not independently addressable")
    programs = tuple(_trusted_system_program(path) for path in _PROGRAMS)
    return programs, home, runtime


def _wsl_interop():
    socket = os.environ.get("WSL_INTEROP", "")
    if not _INTEROP.fullmatch(socket):
        return None
    try:
        path = Path(socket)
        if _safe_path(path):
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode) and info.st_uid in (0, os.geteuid()):
                return socket
    except (OSError, RuntimeError, ValueError):
        pass
    return None


def _service_command(systemd_run, env, python, source, workdir, home, runtime, unit, *,
                     startup, service_runtime, stop, commit, child_deadline, probe, interop):
    interop_env = (f"WSL_INTEROP={interop}",) if interop is not None else ()
    command = (
        systemd_run, "--user", "--wait", "--collect", "--service-type=exec",
        f"--unit={unit}", f"--working-directory={workdir}",
        f"--property=TimeoutStartSec={startup}s", f"--property=RuntimeMaxSec={service_runtime}s",
        "--property=RuntimeRandomizedExtraSec=0", "--property=NotifyAccess=none",
        f"--property=TimeoutStopSec={stop}s", "--property=KillMode=control-group",
        "--property=KillSignal=SIGTERM", "--property=FinalKillSignal=SIGKILL",
        "--property=SendSIGKILL=yes", "--property=Restart=no", "--property=Delegate=no",
        "--property=StandardInput=null", "--property=StandardOutput=null",
        "--property=StandardError=null", f"--property=UnsetEnvironment={_UNSET_LOADER_ENV}",
        "--", env, "-i", "PATH=/usr/bin:/bin", "LANG=C.UTF-8", f"HOME={home}",
        f"XDG_RUNTIME_DIR={runtime}", f"AOTG_PILOT_UNIT={unit}", *interop_env,
        python, "-I", "-B", str(source), "--child", "--deadline-ns", str(child_deadline),
        str(workdir), commit,
    )
    return (*command, "--probe") if probe else command


def _seconds_left(deadline):
    return max(0, (deadline - monotonic_ns()) / _SECOND)


def _read_command(argv, environment, deadline, *, limit, stderr):
    if not _seconds_left(deadline):
        raise TimeoutError("The command deadline elapsed before startup")
    process = subprocess.Popen(
        argv, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=stderr, shell=False, close_fds=True,
    )
    try:
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = _seconds_left(deadline)
                if not remaining or not selector.select(remaining):
                    raise TimeoutError("The service observation reached its deadline")
                chunk = os.read(process.stdout.fileno(), min(64 * 1024, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit:
                    raise ValueError("Unexpected bounded status size")
        code = process.wait(timeout=_seconds_left(deadline))
        return code, bytes(output)
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=min(1, _seconds_left(deadline)))


def _observe(argv, environment, deadline):
    code, output = _read_command(argv, environment, deadline, limit=_OUTPUT_LIMIT, stderr=subprocess.STDOUT)
    return code, b"Finished with result: timeout" in output.splitlines()


def _stop(systemctl, unit, environment, deadline):
    """Only stop the fresh per-invocation unit. Its own timeout remains in force."""
    try:
        subprocess.run(
            (systemctl, "--user", "stop", "--", unit), env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            shell=False, timeout=_seconds_left(deadline), check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def supervise_pilot(workdir: Path, *, expected_commit: str, probe: bool = False,
                    timeout_seconds: int = MAX_RUNTIME_SECONDS) -> SupervisorResult:
    """Run the pinned checkout's launcher under an independent control-group deadline.

    Invoke only from the trusted deployment. The child verifies its checkout and
    live prerequisites before network operations. A service timeout cannot
    establish whether a request already delivered to a remote server took effect.
    """
    if (
        not isinstance(workdir, Path) or not workdir.is_absolute()
        or type(expected_commit) is not str or not _COMMIT.fullmatch(expected_commit)
        or type(probe) is not bool or type(timeout_seconds) is not int
        or not 8 <= timeout_seconds <= MAX_RUNTIME_SECONDS
    ):
        return SupervisorResult("blocked")
    deadline = monotonic_ns() + _SECOND * timeout_seconds
    try:
        (systemd_run, systemctl, env, python), home, runtime = _deployment(workdir)
        source = _trusted_supervisor(workdir)
    except (OSError, KeyError, RuntimeError, ValueError):
        return SupervisorResult("blocked")
    if not _checkout_matches(workdir, expected_commit, deadline_ns=deadline):
        return SupervisorResult("blocked")

    # Keep startup, final SIGKILL, and observer cleanup inside the overall cap.
    now = monotonic_ns()
    available = (deadline - now) // _SECOND
    startup = stop = min(5, timeout_seconds // 8)
    reserve = max(2, min(15, timeout_seconds // 8))
    service_runtime = available - startup - stop - reserve
    if service_runtime <= stop:
        return SupervisorResult("blocked")
    child_deadline = now + (service_runtime - stop) * _SECOND
    unit = f"aotg-pilot-{secrets.token_hex(8)}.service"
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0",
        "XDG_RUNTIME_DIR": str(runtime), "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }
    argv = _service_command(
        systemd_run, env, python, source, workdir, home, runtime, unit, startup=startup,
        service_runtime=service_runtime, stop=stop, commit=expected_commit,
        child_deadline=child_deadline, probe=probe, interop=_wsl_interop(),
    )
    try:
        code, expired = _observe(argv, environment, deadline - stop * _SECOND)
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
        _stop(systemctl, unit, environment, deadline)
        return SupervisorResult("unconfirmed")
    if code != 0 and expired:
        return SupervisorResult("timeout", code)
    if code == 0 and not expired:
        return SupervisorResult("complete", code)
    _stop(systemctl, unit, environment, deadline)
    return SupervisorResult("unconfirmed", code)


def _child(workdir, expected_commit, deadline_ns, *, probe):
    if (not isinstance(deadline_ns, int) or not 0 < deadline_ns - monotonic_ns() <= MAX_RUNTIME_SECONDS * _SECOND
            or Path.cwd() != workdir):
        return 1
    try:
        _trusted_supervisor(workdir)
    except (OSError, RuntimeError, ValueError):
        return 1
    if not _checkout_matches(workdir, expected_commit, deadline_ns=deadline_ns):
        return 1
    args = ["--expected-commit", expected_commit, "--deadline-ns", str(deadline_ns)]
    if probe:
        args.append("--probe")
    sys.argv = [sys.argv[0], *args]
    sys.path.insert(0, str(workdir))
    runpy.run_module("aotg.autodev.pilot_launch", run_name="__main__")
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--deadline-ns", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("expected_commit")
    args = parser.parse_args(argv)
    if args.child:
        if args.timeout_seconds is not None:
            return 1
        return _child(args.checkout, args.expected_commit, args.deadline_ns, probe=args.probe)
    if args.deadline_ns is not None:
        return 1
    result = supervise_pilot(
        args.checkout, expected_commit=args.expected_commit, probe=args.probe,
        timeout_seconds=MAX_RUNTIME_SECONDS if args.timeout_seconds is None else args.timeout_seconds,
    )
    print(result.status)
    return 0 if result.status == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
