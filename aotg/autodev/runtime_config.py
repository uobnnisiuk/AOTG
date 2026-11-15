"""Load operator-owned approval and authentication inputs outside the checkout."""

import json
import os
import re
from pathlib import Path

from aotg.artifacts import _unique_object

from .ledger import _validate_path
from .queue import POLICY, REPOSITORY, ApprovedScope, _approval_valid


class ConfigError(ValueError):
    """Private configuration could not be verified."""


def _private_bytes(path, limit):
    # The live deployment is on WSL. POSIX mode bits on Windows do not prove a private DACL.
    if os.name != "posix":
        raise ConfigError("Private configuration requires the WSL filesystem")
    path = Path(path)
    checkout = Path(__file__).resolve().parents[2]
    if not path.is_absolute() or ".." in path.parts or path.is_relative_to(checkout):
        raise ConfigError("Use a private absolute path outside the source checkout")
    try:
        for parent in reversed(path.parents):
            _validate_path(parent, directory=True, private=parent == path.parent)
        _validate_path(path, directory=False)
        expected = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            _validate_path(path, directory=False)
            actual = os.fstat(stream.fileno())
            if not os.path.samestat(expected, actual):
                raise ConfigError("Private input changed while opening")
            content = stream.read(limit + 1)
            final = os.fstat(stream.fileno())
            if (final.st_mtime_ns != actual.st_mtime_ns or final.st_size != actual.st_size
                    or len(content) > limit):
                raise ConfigError("Private input changed or exceeded its bound")
    except (OSError, ValueError):
        raise ConfigError("Could not verify private input") from None
    return content


def parse_approvals(content):
    """Validate a finite owner registry. A digest detects edits, not impersonation."""
    try:
        document = json.loads(content, object_pairs_hook=_unique_object)
        if (type(document) is not dict or document.keys() != {"version", "policy", "repo", "scopes"}
                or type(document["version"]) is not int or document["version"] != 1
                or document["policy"] != POLICY or document["repo"] != REPOSITORY
                or type(document["scopes"]) is not list or len(document["scopes"]) > 8):
            raise ValueError
        approvals = []
        for row in document["scopes"]:
            fields = {"issue", "github_issue", "revision", "allowed_paths", "dependencies", "approval_sha"}
            if (type(row) is not dict or row.keys() != fields
                    or type(row["allowed_paths"]) is not list or type(row["dependencies"]) is not list
                    or len(row["allowed_paths"]) > 32 or len(row["dependencies"]) > 32):
                raise ValueError
            scope = ApprovedScope(
                row["issue"], row["github_issue"], row["revision"], tuple(row["allowed_paths"]),
                tuple(row["dependencies"]), row["approval_sha"],
            )
            if not _approval_valid(scope):
                raise ValueError
            approvals.append(scope)
        if len({scope.issue for scope in approvals}) != len(approvals) or len(
            {scope.github_issue for scope in approvals}
        ) != len(approvals):
            raise ValueError
    except (TypeError, ValueError, RecursionError):
        raise ConfigError("Malformed or ambiguous approval registry") from None
    return tuple(approvals)


def load_approvals(path):
    return parse_approvals(_private_bytes(path, 32 * 1024))


def load_linear_authorization(path):
    try:
        value = _private_bytes(path, 4096).decode("ascii").rstrip("\n")
    except (ConfigError, UnicodeError):
        raise ConfigError("Could not verify Linear authorization input") from None
    if not re.fullmatch(r"(?:lin_api_[A-Za-z0-9_-]+|Bearer [A-Za-z0-9._~+/-]+=*)", value):
        raise ConfigError("Unrecognized Linear authorization format")
    return value
