import ctypes
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from aotg.autodev import model_net_filter as net_filter

_NATIVE_CHECKS = """\
import ctypes
import errno
import os
import socket
import subprocess
import sys

from aotg.autodev.model_net_filter import apply_model_network_filter

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
apply_model_network_filter()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as receiver:
    receiver.bind(("127.0.0.1", 0))
    receiver.listen(1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sender:
        sender.connect(receiver.getsockname())
        connection, _ = receiver.accept()
        with connection:
            sender.sendall(b"ok")
            assert connection.recv(2) == b"ok"

# NETLINK_ROUTE is used by the internal sandbox to look up nested loopback.
with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as route:
    assert route.fileno() >= 0

for flags in (0, socket.SOCK_CLOEXEC, socket.SOCK_NONBLOCK, socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK):
    source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM | flags)
    with source, target:
        source.sendall(b"ok")
        assert target.recv(2) == b"ok"

def check_denied(call, *args):
    try:
        value = call(*args)
    except OSError as exc:
        assert exc.errno == errno.EPERM
        return
    for handle in value if isinstance(value, tuple) else (value,):
        handle.close()
    raise AssertionError("the operation was not blocked")

for family in (socket.AF_UNIX, socket.AF_INET6, socket.AF_PACKET, 40):
    check_denied(socket.socket, family, socket.SOCK_STREAM)
for protocol in (2, 12, 15, 16):  # USERSOCK, NETFILTER, KOBJECT_UEVENT, GENERIC
    check_denied(socket.socket, socket.AF_NETLINK, socket.SOCK_RAW, protocol)
for kind in (0, socket.SOCK_DGRAM, socket.SOCK_RAW, socket.SOCK_SEQPACKET, socket.SOCK_STREAM | (1 << 23)):
    check_denied(socket.socketpair, socket.AF_UNIX, kind | socket.SOCK_CLOEXEC)
check_denied(socket.socketpair, socket.AF_INET, socket.SOCK_STREAM)

# Native x86-64 syscall numbers. Invalid harmless arguments still reach the
# seccomp check and must return EPERM before syscall argument validation.
for number in (101, 308, 310, 311, 425, 426, 427, 438):
    ctypes.set_errno(0)
    assert libc.syscall(number, -1, 0, 0, 0, 0, 0) == -1
    assert ctypes.get_errno() == errno.EPERM

child = '''
import errno
import socket
try:
    handle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
except OSError as exc:
    raise SystemExit(0 if exc.errno == errno.EPERM else 1)
handle.close()
raise SystemExit(1)
'''
subprocess.run((sys.executable, "-B", "-c", child), check=True)
"""


class ModelNetworkFilterTests(unittest.TestCase):
    def test_rejects_unsupported_platform_before_loading_a_library(self):
        with patch.object(net_filter.sys, "platform", "win32"):
            with patch.object(net_filter.ctypes, "CDLL") as library:
                with self.assertRaisesRegex(net_filter.ModelNetworkFilterError, "ABI"):
                    net_filter.apply_model_network_filter()
        library.assert_not_called()

    def test_missing_library_fails_closed(self):
        with patch.object(net_filter, "_require_unprivileged_linux"):
            with patch.object(net_filter.ctypes, "CDLL", side_effect=OSError("private native error")):
                with self.assertRaisesRegex(net_filter.ModelNetworkFilterError, "unavailable"):
                    net_filter.apply_model_network_filter()

    @unittest.skipUnless(sys.platform == "linux" and os.uname().machine == "x86_64", "native Linux x86-64 required")
    def test_rejects_either_effective_or_permitted_capabilities(self):
        for field in ("effective", "permitted"):
            with self.subTest(capability=field):
                libc = Mock()

                def read_capabilities(header, words):
                    setattr(words[1], field, 1)
                    return 0

                libc.capget.side_effect = read_capabilities
                with patch.object(net_filter.os, "geteuid", return_value=1000):
                    with patch.object(net_filter.ctypes, "CDLL", return_value=libc):
                        with self.assertRaisesRegex(net_filter.ModelNetworkFilterError, "has Linux capabilities"):
                            net_filter.apply_model_network_filter()

    @unittest.skipUnless(sys.platform == "linux", "Linux socket flags required")
    def test_load_failure_stops_and_releases_the_filter(self):
        library = Mock()
        library.seccomp_arch_native.return_value = net_filter._X86_64
        library.seccomp_init.return_value = 17
        library.seccomp_attr_set.return_value = 0
        library.seccomp_syscall_resolve_name.return_value = 42
        library.seccomp_rule_add_exact_array.return_value = 0
        library.seccomp_load.return_value = -1
        libc = Mock()
        libc.prctl.side_effect = [0, 1]
        with patch.object(net_filter, "_require_unprivileged_linux", return_value=libc):
            with patch.object(net_filter.ctypes, "CDLL", return_value=library):
                with self.assertRaisesRegex(net_filter.ModelNetworkFilterError, "install"):
                    net_filter.apply_model_network_filter()
        library.seccomp_release.assert_called_once_with(17)

    @unittest.skipUnless(
        sys.platform == "linux" and os.uname().machine == "x86_64" and os.geteuid() != 0,
        "unprivileged native Linux x86-64 required",
    )
    def test_kernel_filter_socket_rules_and_descendant_inheritance(self):
        try:
            ctypes.CDLL("libseccomp.so.2")
        except OSError:
            self.skipTest("libseccomp unavailable")
        subprocess.run((sys.executable, "-B", "-c", _NATIVE_CHECKS), check=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
