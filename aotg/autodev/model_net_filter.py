"""Restrict model-client socket families after its private Linux network is ready."""

import ctypes
import errno
import os
import socket
import sys
from pathlib import Path

_X86_64 = 0xC000003E  # AUDIT_ARCH_X86_64 / SCMP_ARCH_X86_64
_SCMP_ACT_ALLOW = 0x7FFF0000
_SCMP_ACT_KILL_PROCESS = 0x80000000
_SCMP_ACT_EPERM = 0x00050000 | errno.EPERM
_SCMP_FLTATR_ACT_BADARCH = 2
_SCMP_FLTATR_CTL_TSYNC = 4
_SCMP_CMP_NE = 1
_SCMP_CMP_EQ = 4
_SCMP_CMP_GT = 6
_SCMP_CMP_MASKED_EQ = 7
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_NETLINK_ROUTE = 0
_DENIED_CALLS = (
    b"setns", b"ptrace", b"process_vm_readv", b"process_vm_writev",
    b"pidfd_getfd", b"io_uring_setup", b"io_uring_enter", b"io_uring_register",
)


class ModelNetworkFilterError(RuntimeError):
    """The model client cannot be safely started."""


class _ArgumentComparison(ctypes.Structure):
    _fields_ = [
        ("argument", ctypes.c_uint),
        ("operator", ctypes.c_int),
        ("first", ctypes.c_uint64),
        ("second", ctypes.c_uint64),
    ]


class _CapabilityHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapabilityWord(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ("effective", "permitted", "inheritable")]


def _bind(library, name, result, *arguments):
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


def _require_unprivileged_linux():
    if sys.platform != "linux" or os.uname().machine != "x86_64" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ModelNetworkFilterError("Unsupported model network filter ABI")
    # Capabilities are per thread. The trusted relay belongs in a separate
    # process and no client threads may exist before this check.
    if os.geteuid() == 0 or {entry.name for entry in Path("/proc/self/task").iterdir()} != {str(os.getpid())}:
        raise ModelNetworkFilterError("The client must be a single unprivileged process")
    libc = ctypes.CDLL(None, use_errno=True)
    capget = _bind(libc, "capget", ctypes.c_int, ctypes.POINTER(_CapabilityHeader),
                   ctypes.POINTER(_CapabilityWord))
    header = _CapabilityHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    words = (_CapabilityWord * 2)()
    if capget(ctypes.byref(header), words) != 0 or any(word.effective or word.permitted for word in words):
        raise ModelNetworkFilterError("The client still has Linux capabilities")
    return libc


def _pair_comparisons():
    stream = int(socket.SOCK_STREAM)
    valid = stream | int(socket.SOCK_CLOEXEC) | int(socket.SOCK_NONBLOCK)
    yield _ArgumentComparison(0, _SCMP_CMP_NE, socket.AF_UNIX, 0)
    yield _ArgumentComparison(1, _SCMP_CMP_MASKED_EQ, stream, 0)
    # libseccomp has masked equality but no masked inequality. Deny each
    # forbidden bit individually, so only stream and these two flags remain.
    for bit_number in range(32):
        bit = 1 << bit_number
        if not valid & bit:
            yield _ArgumentComparison(1, _SCMP_CMP_MASKED_EQ, bit, bit)


def apply_model_network_filter():
    """Install the inherited model-client filter, or raise before executing it.

    The caller must create a fresh IPv4-loopback-only namespace and close host
    descriptors first. The filter does not impose an address policy on IPv4
    sockets itself. Nested namespaces required by Codex remain available.
    """
    try:
        libc = _require_unprivileged_linux()
        library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
        context_type = ctypes.c_void_p
        arch = _bind(library, "seccomp_arch_native", ctypes.c_uint32)
        if arch() != _X86_64:
            raise ModelNetworkFilterError("Unexpected libseccomp architecture")
        resolve = _bind(library, "seccomp_syscall_resolve_name", ctypes.c_int, ctypes.c_char_p)
        init = _bind(library, "seccomp_init", context_type, ctypes.c_uint32)
        release = _bind(library, "seccomp_release", None, context_type)
        attribute = _bind(library, "seccomp_attr_set", ctypes.c_int, context_type, ctypes.c_int,
                          ctypes.c_uint32)
        add_rule = _bind(library, "seccomp_rule_add_exact_array", ctypes.c_int, context_type, ctypes.c_uint32,
                         ctypes.c_int, ctypes.c_uint, ctypes.POINTER(_ArgumentComparison))
        load = _bind(library, "seccomp_load", ctypes.c_int, context_type)
        prctl = _bind(libc, "prctl", ctypes.c_int, ctypes.c_int, *(ctypes.c_ulong,) * 4)
        context = init(_SCMP_ACT_ALLOW)
        if not context:
            raise ModelNetworkFilterError("Could not allocate the model network filter")

        def deny(call, *comparisons):
            number = resolve(call)
            arguments = (_ArgumentComparison * len(comparisons))(*comparisons) if comparisons else None
            if number < 0 or add_rule(context, _SCMP_ACT_EPERM, number, len(comparisons), arguments) != 0:
                raise ModelNetworkFilterError("Could not add a required model network rule")

        try:
            if (
                attribute(context, _SCMP_FLTATR_ACT_BADARCH, _SCMP_ACT_KILL_PROCESS) != 0
                or attribute(context, _SCMP_FLTATR_CTL_TSYNC, 1) != 0
            ):
                raise ModelNetworkFilterError("Could not require the model network filter attributes")
            families = {socket.AF_INET, socket.AF_NETLINK}
            deny(b"socket", _ArgumentComparison(0, _SCMP_CMP_GT, max(families), 0))
            for family in range(max(families)):
                if family not in families:
                    deny(b"socket", _ArgumentComparison(0, _SCMP_CMP_EQ, family, 0))
            # Bubblewrap uses route netlink to set up loopback in its own nested
            # namespace. Other netlink protocols are outside the model boundary.
            deny(
                b"socket",
                _ArgumentComparison(0, _SCMP_CMP_EQ, socket.AF_NETLINK, 0),
                _ArgumentComparison(2, _SCMP_CMP_NE, _NETLINK_ROUTE, 0),
            )
            for comparison in _pair_comparisons():
                deny(b"socketpair", comparison)
            for call in _DENIED_CALLS:
                deny(call)
            if prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 or prctl(_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
                raise ModelNetworkFilterError("Could not prevent new model-client privileges")
            if load(context) != 0:
                raise ModelNetworkFilterError("Could not install the model network filter")
        finally:
            release(context)
    except (AttributeError, OSError, ctypes.ArgumentError):
        raise ModelNetworkFilterError("The Linux model network filter is unavailable") from None
