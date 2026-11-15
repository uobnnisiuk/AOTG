"""Give native ChatGPT device sign-in a bounded, auth-only K8 network path."""

import argparse
import codecs
import ctypes
import hashlib
import ipaddress
import os
import re
import select
import socket
import socketserver
import stat
import struct
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Condition, Event, Thread
from time import monotonic

_HOST = "auth.openai.com"
_AUTHORITY = b"auth.openai.com:443"
_HEADER_MAX = 8192
_TIMEOUTS = {"probe": 20, "status": 20, "device-login": 300}
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
_NAMESPACES = ("user", "mnt", "net", "pid", "ipc")
_PROXY_PATH = Path("/bridge/login.sock")
_MOUNT = "/usr/bin/mount"
_PYTHON = "/usr/bin/python3"
_CHATGPT_STATUS = b"Logged in using ChatGPT\n"
_SIGNED_OUT_STATUS = b"Not logged in\n"


class SignInError(ValueError):
    """The dedicated login boundary failed a required check."""


class _SignInArguments(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "AOTG ChatGPT authentication arguments could not be verified\n")


def _read_connect(client, *, authority=_AUTHORITY):
    header = bytearray()
    deadline = monotonic() + 5
    while not header.endswith(b"\r\n\r\n"):
        remaining = deadline - monotonic()
        if remaining <= 0:
            return False
        client.settimeout(remaining)
        data = client.recv(1024)
        header.extend(data)
        if not data or len(header) > _HEADER_MAX:
            return False
    request, *headers = bytes(header[:-4]).split(b"\r\n")
    if request not in (b"CONNECT " + authority + b" HTTP/1.1",
                       b"CONNECT " + authority + b" HTTP/1.0"):
        return False
    names = set()
    for field in headers:
        name, sep, value = field.partition(b":")
        name = name.lower()
        if (
            not sep or not re.fullmatch(rb"[a-z0-9-]+", name) or name in names
            or any(byte < 32 or byte > 126 for byte in value)
            or name in (b"proxy-authorization", b"authorization", b"transfer-encoding", b"content-length")
            or (name == b"host" and value.strip() != authority)
        ):
            return False
        names.add(name)
    return True


def _dial_auth(denied=None, *, host=_HOST):
    if denied is not None and denied.is_set():
        raise SignInError("Authentication endpoint no longer allowed")
    addresses = socket.getaddrinfo(
        host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
    )
    deadline = monotonic() + 5
    for family, kind, proto, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            continue
        remaining = deadline - monotonic()
        if remaining <= 0 or (denied is not None and denied.is_set()):
            break
        connection = socket.socket(family, kind, proto)
        try:
            connection.settimeout(remaining)
            connection.connect(address)
            connection.settimeout(5)
            return connection
        except OSError:
            connection.close()
    raise SignInError("Authentication endpoint not reachable")


def _relay(first, second, denied=None):
    routes = {first: second, second: first}
    idle_until = monotonic() + 20
    while routes and (denied is None or not denied.is_set()):
        remaining = idle_until - monotonic()
        if remaining <= 0:
            return
        ready, _, _ = select.select(tuple(routes), (), (), min(remaining, 0.2))
        if ready:
            idle_until = monotonic() + 20
        for source in ready:
            target = routes[source]
            data = source.recv(65536)
            if data:
                target.sendall(data)
            else:
                if source is first and denied is not None:
                    return
                del routes[source]
                target.shutdown(socket.SHUT_WR)


class _BoundedServer(socketserver.ThreadingMixIn):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, address, handle, *, on_failure=None):
        self.handle_connection = handle
        self.on_failure = on_failure
        self.active = set()
        self.changed = Condition()
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        with self.changed:
            if len(self.active) >= self.request_queue_size:
                if self.on_failure is not None:
                    self.on_failure()
                self.shutdown_request(request)
                return
            self.active.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._finished(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._finished(request)

    def _finished(self, request):
        with self.changed:
            self.active.remove(request)
            self.changed.notify_all()

    def drained(self):
        with self.changed:
            return self.changed.wait_for(lambda: not self.active, timeout=6)

    def handle_error(self, request, client_address):
        # Connection contents and exceptions are never rendered.
        if self.on_failure is not None:
            self.on_failure()


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.server.handle_connection(self.request)


class _UnixServer(_BoundedServer, socketserver.UnixStreamServer if sys.platform == "linux" else socketserver.TCPServer):
    pass


class _LoopbackServer(_BoundedServer, socketserver.TCPServer):
    pass


@contextmanager
def _serve(server):
    with server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


def _host_connect(client, dial=_dial_auth, *, denied=None):
    try:
        accepted = (denied is None or not denied.is_set()) and _read_connect(client)
    except OSError:
        accepted = False
    if not accepted:
        if denied is not None:
            denied.set()
        client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
        return
    if denied is not None and denied.is_set():
        return
    with dial() as upstream:
        if denied is not None and denied.is_set():
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _relay(client, upstream, denied)


def _inside_connect(client):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bridge:
        bridge.settimeout(5)
        bridge.connect(str(_PROXY_PATH))
        _relay(client, bridge)


def _mount(*args):
    subprocess.run((_MOUNT, "-n", *map(str, args)), env=_ENV, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def _bind(source, target, *, directory=False, writable=False, device=False):
    if directory:
        target.mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch(exist_ok=False)
    _mount("--bind", source, target)
    flags = ["remount", "bind", "nosuid", "rw" if writable else "ro"]
    if not device:
        flags.append("nodev")
    _mount("-o", ",".join(flags), target)


def _bring_up_loopback():
    import fcntl

    if socket.if_nameindex() != [(1, "lo")]:
        raise SignInError("Network namespace did not contain only loopback")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        request = struct.pack("16sh22x", b"lo", 0)
        current = fcntl.ioctl(control, 0x8913, request)  # SIOCGIFFLAGS
        flags = struct.unpack_from("h", current, 16)[0]
        fcntl.ioctl(control, 0x8914, struct.pack("16sh22x", b"lo", flags | 1))  # SIOCSIFFLAGS / IFF_UP


def _drop_capabilities(last_capability):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise SignInError("Could not prevent new privileges")
    for capability in range(last_capability + 1):
        if libc.prctl(24, capability, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
            raise SignInError("Could not drop namespace capability")
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)  # Linux capability API version 3, current PID
    data = (ctypes.c_uint32 * 6)()
    if libc.capset(header, data) != 0:
        raise SignInError("Could not clear active namespace capabilities")


def _namespace_identity():
    return tuple(os.readlink("/proc/self/ns/" + kind) for kind in _NAMESPACES)


def _enter_private_root(root, staging, native, bridge, command, expected_uid, outside):
    mapped = Path("/proc/self/uid_map").read_text(encoding="ascii").split()
    if (
        os.geteuid() != 0 or expected_uid <= 0 or mapped != ["0", str(expected_uid), "1"]
        or len(outside) != len(_NAMESPACES)
        or any(current == host for current, host in zip(_namespace_identity(), outside, strict=True))
    ):
        raise SignInError("Private Linux namespaces were not confirmed")
    last_capability = int(Path("/proc/sys/kernel/cap_last_cap").read_text(encoding="ascii"))
    if not 0 <= last_capability <= 128:
        raise SignInError("Unexpected Linux capability bounds")
    if command in ("probe", "device-login"):
        _bring_up_loopback()
    elif socket.if_nameindex() != [(1, "lo")]:
        raise SignInError("Offline authentication status has an unexpected network")
    codecs.lookup("idna")
    _mount("--make-rprivate", "/")
    _mount("-t", "tmpfs", "-o", "mode=0755,nosuid,nodev,size=16m", "tmpfs", root)
    # The pinned Linux client is self-contained. Leave host binaries, home,
    # runtime sockets, and WSL interop outside this root.
    _bind("/dev/null", root / "dev/null", device=True)
    _bind("/dev/urandom", root / "dev/urandom", device=True)
    _bind("/etc/ssl/certs/ca-certificates.crt", root / "etc/ssl/certs/ca-certificates.crt")
    _bind(native, root / "native/codex")
    if command == "device-login":
        _bind(staging, root / "state", directory=True, writable=True)
    elif command == "status":
        _bind(Path(staging) / "auth.json", root / "state/auth.json")
    else:
        (root / "state").mkdir(mode=0o700)
    if bridge != "-":
        _bind(bridge, root / "bridge", directory=True)
    (root / "tmp").mkdir(mode=0o700)
    (root / "home").mkdir(mode=0o700)
    (root / "proc").mkdir()
    _mount("-t", "proc", "-o", "ro,nosuid,nodev,noexec", "proc", root / "proc")
    os.chroot(root)
    os.chdir("/")
    os.umask(0o077)
    _drop_capabilities(last_capability)


def _native_command(command, endpoint=None):
    env = dict(_ENV, HOME="/home", CODEX_HOME="/state", TMPDIR="/tmp", RUST_LOG="off")
    flags = ("/native/codex", "-c", 'cli_auth_credentials_store="file"',
             "-c", 'forced_login_method="chatgpt"', "-c", 'log_dir="/tmp"', "login")
    if command == "status":
        return (*flags, "status"), env
    env["HTTPS_PROXY"] = f"http://127.0.0.1:{endpoint}"
    return (*flags, "--device-auth"), env


def _native_status(expected, exit_code):
    commandline, env = _native_command("status")
    with subprocess.Popen(commandline, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as process:
        # Keep a bounded result in process memory and emit only our exit status.
        marker = process.stderr.read(len(expected) + 1)
        return marker == expected and process.wait() == exit_code


@contextmanager
def _block_browser_callback():
    # The pinned native client can fall back after a device endpoint 404.
    # Occupy both of its fixed callback ports only in this private namespace.
    with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as primary,
          socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fallback):
        primary.bind(("127.0.0.1", 1455))
        fallback.bind(("127.0.0.1", 1457))
        yield


def _inside(root, staging, native, digest, bridge, command, uid, namespaces):
    _enter_private_root(Path(root), staging, native, bridge, command, int(uid), namespaces.split(";"))
    with open("/native/codex", "rb") as executable:
        if hashlib.file_digest(executable, "sha256").hexdigest() != digest:
            raise SignInError("The native login binary changed")
    if command == "status":
        return 0 if _native_status(_CHATGPT_STATUS, 0) else 1
    with _serve(_LoopbackServer(("127.0.0.1", 0), _inside_connect)) as proxy:
        port = proxy.server_address[1]
        if command == "probe":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(4)
                connection.connect(("127.0.0.1", port))
                connection.sendall(b"CONNECT auth.openai.com:443 HTTP/1.1\r\n\r\n")
                with connection.makefile("rb") as reply:
                    received = reply.readline(64)
            if received != b"AOTG offline probe\n":
                return 1
            return 0 if _native_status(_SIGNED_OUT_STATUS, 1) else 1
        commandline, env = _native_command(command, port)
        # fd 1/2 are handed directly to the invoking user's terminal by the outside launcher.
        with _block_browser_callback():
            return subprocess.run(commandline, env=env, stdin=subprocess.DEVNULL, check=False).returncode


def _private_auth_file(path, uid):
    info = path.lstat()
    return (
        stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 1024 * 1024
    )


def _login_home_ready(auth_home, uid):
    # A launcher may have installed a private policy file already. Neither the
    # login nor its status process reads that file through the isolated root.
    return all(
        path.name == "config.toml" and _private_auth_file(path, uid)
        for path in auth_home.iterdir()
    )


def _auth_home_identity(auth_home, uid):
    from .isolated_process import _workspace

    if auth_home.name != "codex" or auth_home.parent.name != "config":
        raise SignInError("The dedicated login cache must be under the AOTG config directory")
    config = auth_home.parent
    root = config.parent
    identity = tuple(_workspace(directory, uid) for directory in (root, config, auth_home))
    for directory in root.parents:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid) or info.st_mode & 0o022:
            raise SignInError("The dedicated AOTG installation path is not protected")
    return identity


def _device_process(args, tty, denied):
    if denied.is_set():
        return 1
    with subprocess.Popen(args, env=_ENV, stdin=subprocess.DEVNULL, stdout=tty, stderr=tty) as process:
        deadline = monotonic() + _TIMEOUTS["device-login"]
        try:
            while not denied.is_set():
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
                try:
                    return process.wait(timeout=min(remaining, 0.2))
                except subprocess.TimeoutExpired:
                    continue
            return 1
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def _run_inside(command, native, digest, staging, tty, *, uid):
    with TemporaryDirectory(prefix="aotg-login-") as temporary:
        directory = Path(temporary)
        root = directory / "root"
        root.mkdir(mode=0o700)
        args = (
            "/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net", "--pid",
            "--ipc", "--uts", "--fork", "--kill-child", "--", _PYTHON, "-I", "-B",
            str(Path(__file__).resolve()), "--inside", str(root), str(staging), str(native), digest,
            "-" if command == "status" else str(directory), command, str(uid),
            ";".join(_namespace_identity()),
        )

        def launch():
            return subprocess.run(
                args, env=_ENV, stdin=subprocess.DEVNULL, stdout=tty, stderr=tty,
                timeout=_TIMEOUTS[command], check=False,
            ).returncode

        if command == "status":
            return launch()

        if command == "probe":
            def offline_probe(connection):
                if _read_connect(connection):
                    connection.sendall(b"AOTG offline probe\n")

            with _serve(_UnixServer(str(directory / "login.sock"), offline_probe)):
                return launch()
        denied = Event()
        server = _UnixServer(str(directory / "login.sock"),
                             lambda connection: _host_connect(
                                 connection, lambda: _dial_auth(denied), denied=denied,
                             ))
        with _serve(server):
            result = _device_process(args, tty, denied)
        return 1 if not server.drained() or denied.is_set() else result


def _outside(command, native, digest, auth_home):
    from .isolated_process import CodexDeployment, _trusted_codex

    if sys.platform != "linux" or os.geteuid() <= 0:
        raise SignInError("Sign-in requires the unprivileged AOTG Linux account")
    uid = os.geteuid()
    native = _trusted_codex(CodexDeployment(native, digest, uid))
    identity = _auth_home_identity(auth_home, uid)
    if command == "probe":
        return _run_inside(command, native, digest, auth_home, subprocess.DEVNULL, uid=uid)
    target = auth_home / "auth.json"
    if command == "status":
        if not _private_auth_file(target, uid):
            return 1
        return _run_inside(command, native, digest, auth_home, subprocess.DEVNULL, uid=uid)
    if (
        not _login_home_ready(auth_home, uid)
        or not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr))
    ):
        raise SignInError("A new dedicated credential directory and local terminal are required")
    if _run_inside("probe", native, digest, auth_home, subprocess.DEVNULL, uid=uid) != 0:
        raise SignInError("The dedicated login network could not be verified")
    with TemporaryDirectory(prefix="aotg-login-state-", dir=auth_home.parent) as temporary:
        staged = Path(temporary)
        with open("/dev/tty", "wb", buffering=0) as tty:
            result = _run_inside(command, native, digest, staged, tty, uid=uid)
        if (
            result or _auth_home_identity(auth_home, uid) != identity
            or not _private_auth_file(staged / target.name, uid)
        ):
            return 1
        if _run_inside("status", native, digest, staged, subprocess.DEVNULL, uid=uid) != 0:
            return 1
        # Atomic no-overwrite publication. The link in the private staging tree is
        # removed as the context closes, leaving the dedicated credential only.
        os.link(staged / target.name, target, follow_symlinks=False)
        return 0


def main(argv=None):
    parser = _SignInArguments(description=__doc__)
    parser.add_argument("command", choices=tuple(_TIMEOUTS))
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--auth-home", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = _outside(args.command, args.native, args.sha256, args.auth_home)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, LookupError, KeyboardInterrupt):
        result = 1
    print("AOTG ChatGPT authentication check " + ("passed" if result == 0 else "could not be verified"))
    return 0 if result == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) == 10 and sys.argv[1] == "--inside":
        try:
            raise SystemExit(_inside(*sys.argv[2:]))
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, LookupError, KeyboardInterrupt):
            raise SystemExit(1) from None
    raise SystemExit(main())
