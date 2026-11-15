"""Prepare a pinned private checkout and extract only bounded, in-scope changes."""

import os
import re
import signal
import stat
import subprocess
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path, PureWindowsPath
from tempfile import TemporaryDirectory

MAX_RUNTIME_SECONDS = 40 * 60
_MAX_FILES = 4096
_MAX_FILE_BYTES = 1024 * 1024
_MAX_TREE_BYTES = 32 * 1024 * 1024
_MAX_PATCH_BYTES = 1024 * 1024
_SAFE_PART = re.compile(r"[a-zA-Z0-9_.-]{1,120}")
_BLOCKED_NAMES = {".agents", ".codex", ".git", ".github", ".gitmodules", "agents.md"}


class WorkerError(RuntimeError):
    """A workspace or process failed the worker's verification."""


class CandidateRejected(WorkerError):
    """A completed candidate definitively failed an approved local check."""


@dataclass(frozen=True)
class PreparedCheckout:
    path: Path
    base_sha: str
    # Tuples keep immutable copies of the checkout's original file bytes and modes.
    baseline: tuple[tuple[str, bytes, bool], ...]


@dataclass(frozen=True)
class ChangeSet:
    paths: tuple[str, ...]
    patch: bytes


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    timed_out: bool


def _git_bytes(checkout: Path, *args: str, input_data: bytes | None = None) -> bytes:
    # Trusted local Git operations do not need account credentials or user filters.
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
           if key in os.environ}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), "-c", "core.fsmonitor=false",
             "-c", "core.autocrlf=false", *args],
            env=env, input=input_data, capture_output=True, timeout=15, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WorkerError("Git could not verify the isolated checkout") from exc
    return result.stdout


def _git(checkout: Path, *args: str) -> str:
    return _git_bytes(checkout, *args).decode("utf-8").strip()

def prepare_checkout(source: Path, checkout: Path, base_sha: str) -> PreparedCheckout:
    """Clone a dedicated clean main with no shared object store or push remote."""
    if not isinstance(base_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise WorkerError("Expected a complete base commit SHA")
    source = Path(source).resolve(strict=True)
    checkout = Path(checkout)
    if checkout.exists() or checkout.is_symlink():
        raise WorkerError("The candidate checkout already exists")
    checkout = checkout.resolve()
    if (not checkout.parent.is_dir() or checkout.is_relative_to(source)
            or source.is_relative_to(checkout)):
        raise WorkerError("The candidate requires a separate workspace")
    if (_git(source, "rev-parse", "--show-prefix")
            or _git(source, "symbolic-ref", "--short", "HEAD") != "main"
            or _git(source, "rev-parse", "HEAD") != base_sha
            or _git(source, "status", "--porcelain", "--untracked-files=all")):
        raise WorkerError("The source checkout is not the clean pinned main")
    tree = _git_bytes(source, "ls-tree", "-r", "-z", base_sha)
    for entry in tree.split(b"\0")[:-1]:
        header, _, path = entry.partition(b"\t")
        mode = header.split(b" ", 1)[0]
        if mode not in (b"100644", b"100755"):
            raise WorkerError("The source tree contains a symlink or submodule")
        _path_parts(path.decode("utf-8"))
    # Export only objects reachable from this commit. Copying the source object
    # store would also reveal unrelated branches and formerly deleted work.
    pack = _git_bytes(source, "pack-objects", "--stdout", "--revs",
                      input_data=f"{base_sha}\n".encode("ascii"))
    if len(pack) > _MAX_TREE_BYTES:
        raise WorkerError("The source pack exceeds the size limit")
    with TemporaryDirectory(prefix="aotg-git-template-") as template:
        checkout.mkdir(mode=0o700)
        _git(checkout, "init", f"--template={template}")
    _git_bytes(checkout, "index-pack", "--stdin", input_data=pack)
    _git(checkout, "-c", f"core.hooksPath={os.devnull}", "checkout", "--detach", base_sha)
    if _git(checkout, "rev-parse", "HEAD") != base_sha or _git(checkout, "remote"):
        raise WorkerError("The candidate checkout did not match the expected base")
    baseline = _scan(checkout)
    return PreparedCheckout(checkout, base_sha, tuple((key, *value) for key, value in baseline.items()))


def _path_parts(value: str) -> list[str]:
    if not isinstance(value, str) or len(value) > 240:
        raise WorkerError("Invalid repository-relative path")
    parts = value.split("/")
    if any(not _SAFE_PART.fullmatch(part) or part in (".", "..") or part.endswith(".")
           or PureWindowsPath(part).is_reserved()
           for part in parts):
        raise WorkerError("Invalid repository-relative path")
    return parts


def _contents(path: Path, info: os.stat_result) -> bytes:
    if info.st_nlink != 1 or info.st_size > _MAX_FILE_BYTES:
        raise WorkerError("A candidate file is linked or exceeds the size limit")
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_BINARY", 0))
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not os.path.samestat(info, before):
                raise WorkerError("The candidate tree changed while it was being read")
            data = stream.read(_MAX_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise WorkerError("Failed to read the candidate tree") from exc
    if (len(data) > _MAX_FILE_BYTES or len(data) != info.st_size
            or after.st_mtime_ns != info.st_mtime_ns or not os.path.samestat(info, after)):
        raise WorkerError("The candidate tree changed while it was being read")
    return data


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _scan(checkout: Path) -> dict[str, tuple[bytes, bool]]:
    files = {}
    total = 0
    count = 0
    names = set()
    try:
        if not stat.S_ISDIR(checkout.lstat().st_mode) or _is_link(checkout.lstat()):
            raise WorkerError("The checkout no longer points to a regular directory")
        pending = [(checkout, "")]
        while pending:
            directory, parent = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not parent and entry.name == ".git":
                        # This clone's metadata never contributes to the resulting patch.
                        metadata = Path(entry.path).lstat()
                        if _is_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
                            raise WorkerError("The candidate Git metadata is not a directory")
                        continue
                    count += 1
                    if count > _MAX_FILES:
                        raise WorkerError("The candidate tree contains too many entries")
                    relative = f"{parent}/{entry.name}" if parent else entry.name
                    _path_parts(relative)
                    if relative.casefold() in names:
                        raise WorkerError("The candidate tree contains ambiguous paths")
                    names.add(relative.casefold())
                    info = Path(entry.path).lstat()
                    if _is_link(info):
                        raise WorkerError("Symlinks are not allowed in the candidate tree")
                    if stat.S_ISDIR(info.st_mode):
                        pending.append((Path(entry.path), relative))
                    elif stat.S_ISREG(info.st_mode):
                        data = _contents(Path(entry.path), info)
                        total += len(data)
                        if total > _MAX_TREE_BYTES:
                            raise WorkerError("The candidate tree exceeds the size limit")
                        files[relative] = data, bool(info.st_mode & stat.S_IXUSR)
                    else:
                        raise WorkerError("Candidate paths must be regular files or directories")
    except OSError as exc:
        raise WorkerError("Failed to inspect the candidate tree") from exc
    return files


def _text_lines(data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise WorkerError("Only UTF-8 text changes are permitted") from exc
    if any(ord(char) < 32 and char not in "\n\t" for char in text):
        raise WorkerError("Only plain text with LF line endings is permitted")
    lines = text.split("\n")
    return [line + "\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def capture_changes(prepared: PreparedCheckout, allowed_paths: tuple[str, ...]) -> ChangeSet:
    """Build a text patch from approved file paths without consulting candidate Git state."""
    for path in allowed_paths:
        parts = _path_parts(path)
        if any(part.casefold() in _BLOCKED_NAMES for part in parts):
            raise WorkerError("The approved change list includes a protected path")
    baseline = {key: (data, executable) for key, data, executable in prepared.baseline}
    after = _scan(prepared.path)
    changed = tuple(sorted(name for name in baseline.keys() | after.keys()
                           if baseline.get(name) != after.get(name)))
    if not changed or set(changed) - set(allowed_paths):
        raise CandidateRejected("The candidate has no changes or exceeds the approved scope")
    sections = []
    for path in changed:
        before_data, before_executable = baseline.get(path, (b"", False))
        after_data, after_executable = after.get(path, (b"", False))
        if before_executable or after_executable:
            raise WorkerError("Executable file changes are outside the worker scope")
        if before_data == after_data:
            raise WorkerError("Empty file creation or deletion is outside the worker scope")
        sections.extend(unified_diff(
            _text_lines(before_data), _text_lines(after_data),
            fromfile=f"a/{path}" if path in baseline else "/dev/null",
            tofile=f"b/{path}" if path in after else "/dev/null",
        ))
    patch = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                    for line in sections).encode("utf-8")
    if len(patch) > _MAX_PATCH_BYTES:
        raise WorkerError("The candidate patch exceeds the size limit")
    return ChangeSet(changed, patch)


def codex_argv(executable: Path, checkout: Path) -> tuple[str, ...]:
    """Construct fixed flags after a trusted caller verifies the runtime and permissions."""
    executable = Path(executable)
    checkout = Path(checkout)
    if not executable.is_absolute() or not checkout.is_absolute():
        raise WorkerError("The worker requires a pinned executable and workspace")
    return (
        str(executable), "--ask-for-approval", "never", "exec", "--ignore-user-config",
        "--ephemeral", "--sandbox", "workspace-write", "--cd", str(checkout),
        "-c", "sandbox_workspace_write.network_access=false", "-",
    )


def _run_in_wsl(
    argv: tuple[str, ...], checkout: Path, *, input_text: str,
    env: dict[str, str], timeout_seconds: float = MAX_RUNTIME_SECONDS,
) -> RunResult:
    """Bound a trusted command's own process group and discard private output.

    A process group cannot guarantee containment of descendants that leave it.
    A live caller must provide a separate verified containment boundary.
    """
    if os.name != "posix" or not 0 < timeout_seconds <= MAX_RUNTIME_SECONDS:
        raise WorkerError("The process requires the bounded Linux execution boundary")
    payload = input_text.encode("utf-8")
    if not argv or not Path(argv[0]).is_absolute() or len(payload) > 64 * 1024:
        raise WorkerError("Invalid bounded worker input")
    try:
        process = subprocess.Popen(
            argv, cwd=checkout, env=env, shell=False, stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
    except OSError as exc:
        raise WorkerError("The worker process could not start") from exc
    timed_out = False
    try:
        process.communicate(input=payload, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired as exc:
            raise WorkerError("The worker process exceeded its cleanup bound") from exc
    return RunResult(process.returncode, timed_out)
