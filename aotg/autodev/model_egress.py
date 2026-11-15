"""Limit the native Codex pilot client to a single TLS destination on K8."""

import ctypes
import json
import os
import select
import socket
import subprocess
import sys
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic

from . import chatgpt_signin as boundary
from .model_net_filter import apply_model_network_filter
from .worker import RunResult, WorkerError

_HOST = "chatgpt.com"
_AUTHORITY = b"chatgpt.com:443"
_HELLO_MAX = 32768
_HANDSHAKE_SECONDS = 5
_SOURCE = Path(__file__).resolve().parents[2]
_UNSHARE = (
    "/usr/bin/unshare", "--user", "--map-current-user", "--keep-caps", "--mount", "--net",
    "--pid", "--ipc", "--fork", "--kill-child", "--mount-proc", "--",
)
_BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from aotg.autodev.model_egress import _entry; _entry(*sys.argv[2:])"
)


class _InvalidHello(ValueError):
    pass


class _Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, count):
        end = self.offset + count
        if end > len(self.data):
            raise _InvalidHello
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def number(self, count):
        return int.from_bytes(self.take(count), "big")

    def vector(self, count):
        return self.take(self.number(count))

    def at_end(self):
        return self.offset == len(self.data)


def _matches_sni(message):
    try:
        hello = _Reader(message)
        if hello.number(1) != 1:
            return False
        contents = _Reader(hello.vector(3))
        if not hello.at_end():
            return False
        contents.take(34)  # Legacy version and random.
        contents.vector(1)  # Legacy session ID.
        contents.vector(2)  # Cipher suites.
        contents.vector(1)  # Legacy compression.
        extensions = _Reader(contents.vector(2))
        if not contents.at_end():
            return False
        seen = set()
        hostname = None
        while not extensions.at_end():
            extension = extensions.number(2)
            data = extensions.vector(2)
            # Encrypted ClientHello can hide a different effective server name.
            if extension in seen or extension in (0xFE0D, 0xFFCE):
                return False
            seen.add(extension)
            if extension == 0:
                field = _Reader(data)
                names = _Reader(field.vector(2))
                if not field.at_end() or names.number(1) != 0:
                    return False
                hostname = names.vector(2)
                if not names.at_end():
                    return False
        return hostname == _HOST.encode("ascii")
    except _InvalidHello:
        return False


def _read_exact(sock, count, deadline):
    chunks = bytearray()
    while len(chunks) < count:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise _InvalidHello
        chunks.extend(chunk)
    return bytes(chunks)


def _client_hello(sock):
    deadline = monotonic() + _HANDSHAKE_SECONDS
    records = bytearray()
    message = bytearray()
    while len(message) < 4 or len(message) < 4 + int.from_bytes(message[1:4], "big"):
        header = _read_exact(sock, 5, deadline)
        length = int.from_bytes(header[3:5], "big")
        if header[:2] != b"\x16\x03" or not 0 < length <= 16384 or len(records) + 5 + length > _HELLO_MAX:
            raise _InvalidHello
        record = _read_exact(sock, length, deadline)
        records.extend(header + record)
        message.extend(record)
    if not _matches_sni(message):
        raise _InvalidHello
    return bytes(records)


def _relay(first, second, stopped, deadline):
    first.settimeout(_HANDSHAKE_SECONDS)
    second.settimeout(_HANDSHAKE_SECONDS)
    peers = {first: second, second: first}
    while peers and not stopped.is_set():
        remaining = deadline - monotonic()
        if remaining <= 0:
            return
        ready, _, _ = select.select(tuple(peers), (), (), min(remaining, 0.2))
        for source in ready:
            target = peers[source]
            data = source.recv(65536)
            if data:
                target.sendall(data)
            else:
                del peers[source]
                target.shutdown(socket.SHUT_WR)


def _handle(client, stopped, established, deadline, *, dial=None):
    if dial is None:
        dial = partial(boundary._dial_auth, stopped, host=_HOST)
    try:
        if stopped.is_set() or not boundary._read_connect(client, authority=_AUTHORITY):
            stopped.set()
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        hello = _client_hello(client)
        if stopped.is_set():
            return
        with dial() as upstream:
            if stopped.is_set():
                return
            upstream.settimeout(_HANDSHAKE_SECONDS)
            upstream.sendall(hello)
            # An immediate reset or EOF before the server responds is a failed connection.
            response = _read_exact(upstream, 5, min(deadline, monotonic() + _HANDSHAKE_SECONDS))
            if response[:2] != b"\x16\x03":
                raise _InvalidHello
            client.sendall(response)
            established.set()
            _relay(client, upstream, stopped, deadline)
    except (OSError, ValueError):
        stopped.set()


def _bridge(client, path, stopped, deadline):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as host:
            host.settimeout(_HANDSHAKE_SECONDS)
            host.connect(path)
            _relay(client, host, stopped, deadline)
    except OSError:
        stopped.set()


def _no_dump():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise WorkerError("The model egress supervisor could not protect its descriptors")


def _namespace(receipt):
    uid = receipt["uid"]
    inside = boundary._namespace_identity()
    if (
        os.geteuid() != uid or uid <= 0
        or any(local == outer for local, outer in zip(inside, receipt["outside"], strict=True))
        or Path("/proc/self/uid_map").read_text().split() != [str(uid), str(uid), "1"]
    ):
        raise WorkerError("The model egress namespaces could not be verified")

    last_capability = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    boundary._mount("--make-rprivate", "/")
    for path in ("/mnt", "/run"):
        boundary._mount("-t", "tmpfs", "-o", "size=64k,nodev,nosuid,noexec,mode=0000", "tmpfs", path)
    if Path("/init").exists():
        boundary._mount("--bind", "/dev/null", "/init")
    boundary._bring_up_loopback()
    boundary._drop_capabilities(last_capability)
    _no_dump()

    deadline = receipt["deadline"]
    stopped = Event()
    handler = partial(_bridge, path=receipt["bridge"], stopped=stopped, deadline=deadline)
    with boundary._serve(boundary._LoopbackServer(("127.0.0.1", 0), handler, on_failure=stopped.set)) as server:
        proxy = "http://127.0.0.1:" + str(server.server_address[1])
        env = {
            **boundary._ENV, "CODEX_HOME": os.environ["CODEX_HOME"], "HTTPS_PROXY": proxy,
            "PATH": receipt["sandbox_bin"] + os.pathsep + boundary._ENV["PATH"],
        }
        command = (boundary._PYTHON, "-I", "-B", "-c", _BOOTSTRAP, str(_SOURCE), "client", *receipt["argv"])
        remaining = deadline - monotonic()
        if remaining <= 0:
            return 124
        process = subprocess.Popen(command, env=env, close_fds=True)
        try:
            while not stopped.is_set():
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return 124
                try:
                    result = process.wait(timeout=min(remaining, 0.1))
                except subprocess.TimeoutExpired:
                    continue
                if server.drained() and not stopped.is_set():
                    return 0 if result == 0 else 125
                break
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        return 125


def _entry(mode, *args):
    try:
        if mode == "client":
            apply_model_network_filter()
            os.execve(args[0], args, os.environ)
        if mode == "namespace":
            raise SystemExit(_namespace(json.loads(args[0])))
    except Exception:
        # No private paths, destinations or subprocess output enter public logs.
        pass
    raise SystemExit(125)


def run_model_client(argv, checkout, *, input_text, env, timeout_seconds, sandbox_bin, runner):
    """Run the pinned client with mandatory, destination-checked TLS egress."""

    if sys.platform != "linux" or not argv or not Path(argv[0]).is_absolute():
        raise WorkerError("The Linux model egress boundary is required")
    if not isinstance(sandbox_bin, Path) or not sandbox_bin.is_absolute() or os.pathsep in str(sandbox_bin):
        raise WorkerError("A dedicated, pinned model sandbox helper is required")
    deadline = monotonic() + timeout_seconds
    stopped, established = Event(), Event()
    try:
        with TemporaryDirectory(prefix=".eg-", dir=checkout.parent) as directory:
            bridge = str(Path(directory) / "proxy")
            if len(os.fsencode(bridge)) >= 108:
                raise WorkerError("The private model egress socket path is too long")
            receipt = json.dumps({
                "uid": os.geteuid(), "outside": boundary._namespace_identity(), "bridge": bridge,
                "argv": argv, "deadline": deadline, "sandbox_bin": str(sandbox_bin),
            })
            command = (
                *_UNSHARE, boundary._PYTHON, "-I", "-B", "-c", _BOOTSTRAP, str(_SOURCE),
                "namespace", receipt,
            )
            handler = partial(_handle, stopped=stopped, established=established, deadline=deadline)
            with boundary._serve(boundary._UnixServer(bridge, handler, on_failure=stopped.set)) as server:
                try:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise TimeoutError("The model egress deadline elapsed")
                    result = runner(
                        command, checkout, input_text=input_text,
                        env={**boundary._ENV, "CODEX_HOME": env["CODEX_HOME"]},
                        timeout_seconds=remaining, cancelled=stopped.is_set,
                    )
                    if not server.drained() or stopped.is_set() or type(result) is not RunResult:
                        raise WorkerError("The model client's restricted connection could not be verified")
                    if result.timed_out or result.exit_code == 124:
                        return RunResult(result.exit_code, True)
                    if not established.is_set() or result.exit_code != 0:
                        raise WorkerError("The model client's restricted connection could not be verified")
                    return result
                finally:
                    stopped.set()
    except (OSError, ValueError):
        raise WorkerError("The model egress boundary could not start or complete") from None
