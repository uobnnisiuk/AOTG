"""Run the reviewed AOTG pilot under an explicit WSL execution boundary.

Codex permission profiles constrain agent commands, not service-client traffic.
Real generation requires independently verified deployment and owner approval.
The offline probe and candidate tests never invoke inference or use network.
"""

import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from .ledger import LedgerError, _validate_path
from .model_egress import run_model_client
from .worker import (
    MAX_RUNTIME_SECONDS,
    CandidateRejected,
    RunResult,
    WorkerError,
    _run_in_wsl,
)

_PROFILE = "aotg-pilot"
_PYTHON = "/usr/bin/python3"
_UNSHARE = "/usr/bin/unshare"
_SHA256 = re.compile(r"(?!0{64})[0-9a-f]{64}")
_MODEL = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
_MAX_CONTRACT_BYTES = 64 * 1024 - 65
_REJECTED_EXIT = 42
_VERIFIER = """\
import ctypes
import hashlib
import os
import subprocess
import sys

class RejectCandidate(Exception):
    pass

# Candidate subprocesses do not receive this process's input or nonce.
# Disallow same-UID inspection of this verifier's memory and descriptors.
libc = ctypes.CDLL(None, use_errno=True)
header = (ctypes.c_uint32 * 2)(0x20080522, 0)
capabilities = (ctypes.c_uint32 * 6)()
CAP_SYS_PTRACE = 1 << 19
if (libc.prctl(4, 0, 0, 0, 0) or libc.prctl(38, 1, 0, 0, 0)
        or libc.capget(header, capabilities) or (capabilities[0] | capabilities[1]) & CAP_SYS_PTRACE):
    raise SystemExit(2)

payload = sys.stdin.buffer.read(65537)
nonce, separator, script = payload.partition(b"\\n")
if (len(payload) > 65536 or not separator or len(nonce) != 64
        or any(byte not in b"0123456789abcdef" for byte in nonce)
        or hashlib.sha256(script).hexdigest() != sys.argv[3]):
    raise SystemExit(2)

verdict = b"pass"
exit_code = 0
if sys.argv[2] == "contract":
    try:
        exec(compile(script, "<independent AOTG contract>", "exec"), {"RejectCandidate": RejectCandidate})
    except RejectCandidate:
        verdict = b"reject"
        exit_code = 42
elif sys.argv[2] == "suite" and not script:
    completed = subprocess.run(
        [sys.executable, "-EBsS", "-m", "unittest", "discover", "-s", "tests"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # The suite imports candidate-authored code. Its failure alone does not
    # establish a rejection by the independent contract.
    if completed.returncode != 0:
        raise SystemExit(2)
else:
    raise SystemExit(2)

descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, "wb") as receipt:
    receipt.write(nonce + b" " + verdict + b"\\n")
raise SystemExit(exit_code)
"""
_PROBE = """\
import os
import sys
from pathlib import Path
from tempfile import TemporaryFile

probe = Path(sys.argv[1])
sentinel = Path(sys.argv[2])
if "CODEX_HOME" in os.environ:
    raise SystemExit(17)
try:
    sentinel.read_bytes()
except OSError:
    pass
else:
    raise SystemExit(13)
try:
    sentinel.write_bytes(b"modified")
except OSError:
    pass
else:
    raise SystemExit(14)
if sys.argv[3] == "write":
    probe.write_bytes(b"verified")
else:
    if probe.read_bytes() != b"verified":
        raise SystemExit(15)
    try:
        probe.write_bytes(b"modified")
    except OSError:
        pass
    else:
        raise SystemExit(16)
    with TemporaryFile(dir=sys.argv[4]) as scratch:
        scratch.write(b"verified")
"""


@dataclass(frozen=True, slots=True)
class ModelAuthorization:
    """Evidence supplied by the trusted launcher, never by a candidate or issue."""

    model: str
    prompt_sha256: str
    expires_at: datetime
    max_seconds: int
    owner_approved: bool = False
    dedicated_chatgpt_login_verified: bool = False
    service_egress_verified: bool = False
    managed_tools_verified_disabled: bool = False


@dataclass(frozen=True, slots=True)
class CodexDeployment:
    """Pinned native client under the expected, non-root AOTG account."""

    codex: Path
    codex_sha256: str
    uid: int
    model_authorization: ModelAuthorization | None = None
    codex_home: Path | None = None
    bwrap: Path | None = None
    bwrap_sha256: str | None = None


def _current_uid():
    if sys.platform != "linux":
        raise WorkerError("The isolated process requires the Linux deployment")
    return os.geteuid()


def _trusted_codex(deployment):
    path = deployment.codex
    if (not isinstance(path, Path) or not path.is_absolute()
            or not isinstance(deployment.codex_sha256, str)
            or not _SHA256.fullmatch(deployment.codex_sha256)
            or type(deployment.uid) is not int or deployment.uid <= 0
            or _current_uid() != deployment.uid):
        raise WorkerError("The Codex executable and AOTG identity must be pinned")
    try:
        if path.resolve(strict=True) != path:
            raise WorkerError("The native Codex executable must not be a link")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR
                or info.st_mode & 0o022 or info.st_uid not in (0, deployment.uid)
                or not 0 < info.st_size <= 512 * 1024**2
                or source.read(4) != b"\x7fELF"
            ):
                raise WorkerError("The pinned Codex executable is not a trusted native client")
            source.seek(0)
            if hashlib.file_digest(source, "sha256").hexdigest() != deployment.codex_sha256:
                raise WorkerError("The Codex executable digest changed")
    except OSError:
        raise WorkerError("The Codex executable could not be verified") from None
    return str(path)


def _trusted_bwrap(deployment, *, checkout):
    path = deployment.bwrap
    digest = deployment.bwrap_sha256
    auth_home = deployment.codex_home
    if (
        not isinstance(path, Path) or not path.is_absolute() or path.name != "bwrap"
        or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
        or not isinstance(checkout, Path) or not checkout.is_absolute()
        or not isinstance(auth_home, Path) or not auth_home.is_absolute()
        or auth_home.name != "codex" or auth_home.parent.name != "config"
        or type(deployment.uid) is not int or deployment.uid <= 0 or _current_uid() != deployment.uid
    ):
        raise WorkerError("An independently pinned bwrap executable is required")
    root = auth_home.parent.parent
    directory = path.parent
    if directory == root or not directory.is_relative_to(root):
        raise WorkerError("The pinned bwrap must be inside the dedicated deployment")
    if any(
        directory.is_relative_to(other) or other.is_relative_to(directory)
        for other in (checkout, auth_home)
    ):
        raise WorkerError("The pinned bwrap must be outside the checkout and Codex home")
    try:
        if path.resolve(strict=True) != path:
            raise WorkerError("The pinned bwrap path must be canonical")
        _validate_path(root, directory=True)
        _validate_path(directory, directory=True)
        directory_identity = directory.lstat()
        ancestors = tuple((ancestor, ancestor.lstat()) for ancestor in directory.parents)
        if any(
            not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, deployment.uid)
            or info.st_mode & 0o022
            for _, info in ancestors
        ):
            raise WorkerError("The pinned bwrap has untrusted directory ancestors")
        with os.scandir(directory) as entries:
            entry = next(entries, None)
            if entry is None or entry.name != "bwrap" or next(entries, None) is not None:
                raise WorkerError("The pinned bwrap directory must contain only that executable")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            initial = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(initial.st_mode) or stat.S_IMODE(initial.st_mode) not in (0o500, 0o700)
                or initial.st_uid != deployment.uid or initial.st_nlink != 1
                or not 4 <= initial.st_size <= 512 * 1024**2 or source.read(4) != b"\x7fELF"
            ):
                raise WorkerError("The pinned bwrap is not a private native executable")
            source.seek(0)
            if hashlib.file_digest(source, "sha256").hexdigest() != digest:
                raise WorkerError("The pinned bwrap executable digest changed")
            final = os.fstat(source.fileno())
            current_directory = directory.lstat()
            if (
                final.st_ctime_ns != initial.st_ctime_ns or final.st_size != initial.st_size
                or not os.path.samestat(final, path.lstat())
                or directory_identity.st_ctime_ns != current_directory.st_ctime_ns
                or not os.path.samestat(directory_identity, current_directory)
            ):
                raise WorkerError("The pinned bwrap changed during verification")
        for ancestor, initial in ancestors:
            current = ancestor.lstat()
            if (not os.path.samestat(initial, current)
                    or current.st_mode != initial.st_mode or current.st_uid != initial.st_uid):
                raise WorkerError("The pinned bwrap ancestor changed during verification")
    except (LedgerError, OSError):
        raise WorkerError("The pinned bwrap executable could not be verified") from None
    return path


def _trusted_codex_home(deployment, *, checkout=None):
    home = deployment.codex_home
    if (
        not isinstance(home, Path) or not home.is_absolute()
        or home.name != "codex" or home.parent.name != "config"
        or type(deployment.uid) is not int or deployment.uid <= 0 or _current_uid() != deployment.uid
        or (checkout is not None and (home.is_relative_to(checkout) or checkout.is_relative_to(home)))
    ):
        raise WorkerError("An independent AOTG Codex home is required")
    try:
        if home.resolve(strict=True) != home:
            raise WorkerError("The AOTG Codex home must be canonical")
        for directory in (home.parent.parent, home.parent, home):
            _validate_path(directory, directory=True)
        auth = home / "auth.json"
        _validate_path(auth, directory=False)
        if not 0 < auth.lstat().st_size <= 1024**2:
            raise WorkerError("The AOTG Codex login metadata is invalid")
    except (LedgerError, OSError):
        raise WorkerError("The AOTG Codex login cache is unavailable or not private") from None
    return home


def _workspace(checkout, uid):
    if not isinstance(checkout, Path) or not checkout.is_absolute():
        raise WorkerError("The candidate workspace must be an absolute path")
    try:
        info = checkout.lstat()
        if (
            checkout.resolve(strict=True) != checkout or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise WorkerError("The candidate workspace is not owner-private")
    except OSError:
        raise WorkerError("The candidate workspace could not be verified") from None
    return checkout, info.st_dev, info.st_ino


def _profile(native, checkout, *, writable, scratch, denied_homes=()):
    mode = "write" if writable else "read"
    temporary_mode = "write" if scratch else "deny"
    home_rules = "".join(f'{json.dumps(str(home))}="deny",' for home in denied_homes)
    return (
        f'permissions.{_PROFILE}={{extends=":workspace",filesystem={{'
        f'":root"="deny",":minimal"="read",":tmpdir"="{temporary_mode}",'
        f'":slash_tmp"="deny",{json.dumps(native)}="read",'
        f'{json.dumps(str(checkout))}="{mode}",{home_rules}'
        f'":workspace_roots"={{"."="{mode}"}}}},network={{enabled=false}}}}'
    )


def _offline_namespace():
    return (_UNSHARE, "--user", "--map-current-user", "--mount", "--pid", "--fork",
            "--kill-child", "--mount-proc", "--net", "--")


def _finite_timeout(seconds):
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= MAX_RUNTIME_SECONDS:
        raise WorkerError("The isolated command requires a bounded timeout")
    return seconds


def _verified_verdict(path, nonce, mode, exit_code):
    if exit_code == 0:
        verdict = b"pass"
    elif mode == "contract" and exit_code == _REJECTED_EXIT:
        verdict = b"reject"
    else:
        raise WorkerError("The isolated checker exit could not be verified")
    expected = nonce.encode("ascii") + b" " + verdict + b"\n"
    try:
        _validate_path(path, directory=False)
        initial = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as receipt:
            actual = os.fstat(receipt.fileno())
            if not os.path.samestat(initial, actual) or actual.st_size != len(expected):
                raise WorkerError("The isolated checker receipt changed")
            value = receipt.read(len(expected) + 1)
            final = os.fstat(receipt.fileno())
            _validate_path(path, directory=False)
            if (not os.path.samestat(final, path.lstat()) or final.st_mtime_ns != actual.st_mtime_ns
                    or final.st_size != actual.st_size):
                raise WorkerError("The isolated checker receipt changed")
    except (OSError, LedgerError):
        raise WorkerError("The isolated checker receipt could not be verified") from None
    if not secrets.compare_digest(value, expected):
        raise WorkerError("The isolated checker receipt did not match the exit")
    return verdict


def _approved(approval, prompt, timeout_seconds):
    if (
        type(approval) is not ModelAuthorization or type(approval.model) is not str
        or not _MODEL.fullmatch(approval.model) or not isinstance(approval.expires_at, datetime)
        or approval.expires_at.utcoffset() is None or type(approval.max_seconds) is not int
        or not timeout_seconds <= approval.max_seconds <= MAX_RUNTIME_SECONDS
        or any(condition is not True for condition in (
            approval.owner_approved, approval.dedicated_chatgpt_login_verified,
            approval.service_egress_verified, approval.managed_tools_verified_disabled,
        ))
    ):
        return False
    now = datetime.now(timezone.utc)
    if (approval.expires_at - now).total_seconds() < timeout_seconds:
        return False
    if not isinstance(prompt, str):
        return False
    payload = prompt.encode("utf-8")
    return 0 < len(payload) <= 64 * 1024 and hashlib.sha256(payload).hexdigest() == approval.prompt_sha256


class IsolatedProcess:
    """Preflight, launch, and verify without handing the candidate service credentials."""

    def __init__(self, deployment: CodexDeployment, *, runner=None):
        if type(deployment) is not CodexDeployment:
            raise WorkerError("An explicit Codex deployment is required")
        self.deployment = deployment
        self.runner = _run_in_wsl if runner is None else runner
        self._verified_workspace = None
        self._generated = False

    def _run(self, argv, checkout, text, timeout, *, codex_home, scratch=None, sandbox_bin=None):
        environment = {
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "CODEX_HOME": str(codex_home),
        }
        if scratch is not None:
            environment["TMPDIR"] = str(scratch)
        timeout = _finite_timeout(timeout)
        if sandbox_bin is not None:
            result = run_model_client(
                argv, checkout, input_text=text, env=environment, timeout_seconds=timeout,
                runner=self.runner, sandbox_bin=sandbox_bin,
            )
        else:
            result = self.runner(argv, checkout, input_text=text, env=environment, timeout_seconds=timeout)
        if type(result) is not RunResult or type(result.exit_code) is not int or type(result.timed_out) is not bool:
            raise WorkerError("The isolated process result could not be verified")
        if result.timed_out:
            raise TimeoutError("The isolated process reached its deadline")
        return result.exit_code

    def _run_sandbox(self, native, checkout, text, deadline, *command, writable=False,
                     scratch=None, denied_home=None, evidence=None):
        # Profile resolution may initialize authentication even for a sandbox-only command.
        with TemporaryDirectory(prefix="aotg-offline-codex-", dir=checkout.parent) as offline_home:
            denied = (offline_home,) if denied_home is None else (offline_home, denied_home)
            profile = _profile(
                native, checkout, writable=writable, scratch=scratch is not None, denied_homes=denied,
            )
            argv = (
                *_offline_namespace(), native, "sandbox", "-P", _PROFILE, "-C", str(checkout),
                "--include-managed-config", "-c", profile, "-c", 'cli_auth_credentials_store="file"',
                "--", "/usr/bin/env", "-u", "CODEX_HOME", "--", *command,
            )
            exit_code = self._run(argv, checkout, text, _remaining(deadline), scratch=scratch,
                                  codex_home=offline_home)
        if evidence is not None:
            if _verified_verdict(*evidence, exit_code) == b"reject":
                raise CandidateRejected("The candidate failed the independent contract")
        elif exit_code != 0:
            raise WorkerError("The isolated process did not complete successfully")

    def preflight(self, checkout: Path, *, timeout_seconds: float) -> None:
        self._verified_workspace = None
        deadline = monotonic() + _finite_timeout(timeout_seconds)
        native = _trusted_codex(self.deployment)
        identity = _workspace(checkout, self.deployment.uid)
        with (
            TemporaryDirectory(prefix="aotg-private-probe-", dir=checkout.parent) as denied,
            TemporaryDirectory(prefix=".aotg-probe-", dir=checkout) as allowed,
            TemporaryDirectory(prefix="aotg-pilot-check-", dir=checkout.parent) as scratch,
        ):
            synthetic_home = Path(denied)
            sentinel = synthetic_home / "auth.json"
            sentinel.write_bytes(b"private")
            proof = Path(allowed) / "observed"
            self._run_sandbox(
                native, checkout, _PROBE, deadline, _PYTHON, "-EBsS", "-I", "-",
                str(proof), str(sentinel), "write", writable=True, denied_home=synthetic_home,
            )
            if not proof.is_file() or proof.is_symlink() or proof.read_bytes() != b"verified":
                raise WorkerError("The permission probe could not write to the candidate workspace")
            self._run_sandbox(
                native, checkout, _PROBE, deadline, _PYTHON, "-EBsS", "-I", "-",
                str(proof), str(sentinel), "read", scratch, scratch=scratch, denied_home=synthetic_home,
            )
            if proof.read_bytes() != b"verified" or sentinel.read_bytes() != b"private":
                raise WorkerError("The permission probe did not verify filesystem isolation")
        if identity != _workspace(checkout, self.deployment.uid):
            raise WorkerError("The candidate workspace changed during preflight")
        self._verified_workspace = identity

    def _verified(self, checkout):
        native = _trusted_codex(self.deployment)
        if self._verified_workspace is None or _workspace(checkout, self.deployment.uid) != self._verified_workspace:
            raise WorkerError("Preflight is required for this exact candidate workspace")
        return native

    def generate(self, checkout: Path, prompt: str, *, timeout_seconds: float) -> None:
        timeout_seconds = _finite_timeout(timeout_seconds)
        deadline = monotonic() + timeout_seconds
        approval = self.deployment.model_authorization
        if self._generated or not _approved(approval, prompt, timeout_seconds):
            raise WorkerError("Explicit authorization for this bounded model attempt is required")
        native = self._verified(checkout)
        codex_home = _trusted_codex_home(self.deployment, checkout=checkout)
        sandbox_bin = _trusted_bwrap(self.deployment, checkout=checkout).parent
        profile = _profile(native, checkout, writable=True, scratch=False, denied_homes=(codex_home,))
        argv = (
            native, "--ask-for-approval", "never", "exec",
            "--ignore-user-config", "--ephemeral", "--cd", str(checkout), "--model", approval.model,
            "-c", f'default_permissions="{_PROFILE}"', "-c", profile,
            "-c", 'forced_login_method="chatgpt"', "-c", 'model_provider="openai"',
            "-c", 'cli_auth_credentials_store="file"', "-c", 'chatgpt_base_url="https://chatgpt.com/backend-api/"',
            "-c", 'web_search="disabled"', "-c", "mcp_servers={}", "-c", "features.apps=false",
            "-c", "features.plugins=false", "-c", "allow_login_shell=false",
            "-c", 'shell_environment_policy.inherit="none"', "-",
        )
        self._generated = True
        if self._run(
            argv, checkout, prompt, _remaining(deadline), codex_home=codex_home, sandbox_bin=sandbox_bin,
        ) != 0:
            raise WorkerError("The isolated process did not complete successfully")

    def verify(self, checkout: Path, *, timeout_seconds: float, contract: str | None = None) -> None:
        deadline = monotonic() + _finite_timeout(timeout_seconds)
        native = self._verified(checkout)
        if contract is not None and (not isinstance(contract, str)
                                    or not 0 < len(contract.encode("utf-8")) <= _MAX_CONTRACT_BYTES):
            raise WorkerError("Only a bounded independent contract script can be supplied")
        if contract is not None:
            self._verify_command(native, checkout, deadline, "contract", contract)
        self._verify_command(native, checkout, deadline, "suite", "")

    def _verify_command(self, native, checkout, deadline, mode, script):
        with TemporaryDirectory(prefix="aotg-pilot-check-", dir=checkout.parent) as scratch:
            receipt = Path(scratch) / "verdict"
            nonce = secrets.token_hex(32)
            source_hash = hashlib.sha256(script.encode("utf-8")).hexdigest()
            self._run_sandbox(
                native, checkout, nonce + "\n" + script, deadline,
                _PYTHON, "-I", "-S", "-B", "-c", _VERIFIER, str(receipt), mode, source_hash,
                scratch=scratch, denied_home=self.deployment.codex_home, evidence=(receipt, nonce, mode),
            )


def _remaining(deadline):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("The candidate verification deadline elapsed")
    return remaining
