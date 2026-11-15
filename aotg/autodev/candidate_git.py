"""Transfer a verified text diff through a separate, trusted Git checkout."""

import os
import re
import shlex
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from .coordinator import Candidate, _valid_candidate
from .queue import REPOSITORY, _approval_valid, valid_change_path
from .worker import (
    ChangeSet,
    PreparedCheckout,
    WorkerError,
    _git,
    _git_bytes,
    capture_changes,
    prepare_checkout,
)

_SHA = re.compile(r"(?!0{40})[0-9a-f]{40}")
_REMOTE = f"https://github.com/{REPOSITORY}.git"
_ORDINARY_GIT_CONFIG = {
    "core.bare", "core.filemode", "core.ignorecase", "core.logallrefupdates",
    "core.precomposeunicode", "core.repositoryformatversion", "core.symlinks",
}
_BLOCKED_METADATA = ("commondir", "objects/info/alternates", "info/grafts", "refs/replace", "packed-refs", "shallow")


class CandidateGitError(WorkerError):
    """The exact candidate, reservation, or publication could not be verified."""


@dataclass(frozen=True)
class CandidateArtifact:
    candidate: Candidate
    checkout: Path
    changes: ChangeSet
    approval_sha: str
    baseline: PreparedCheckout


def _known_scope(scope):
    try:
        known = _approval_valid(scope)
    except (AttributeError, TypeError, ValueError):
        known = False
    if not known:
        raise CandidateGitError("An exact approval is required to build or publish a candidate")


def _known_changes(changes, scope):
    if (
        type(changes) is not ChangeSet or type(changes.paths) is not tuple or not changes.paths
        or any(not valid_change_path(path) or path not in scope.allowed_paths for path in changes.paths)
        or tuple(sorted(set(changes.paths))) != changes.paths or type(changes.patch) is not bytes
        or not 0 < len(changes.patch) <= 1024 * 1024
    ):
        raise CandidateGitError("Candidate patch or paths were not verified")


def _git_paths(checkout, *args):
    raw = _git_bytes(checkout, *args)
    if not raw.endswith(b"\0"):
        raise CandidateGitError("Git did not return a complete file list")
    try:
        return tuple(sorted(name.decode("ascii") for name in raw[:-1].split(b"\0")))
    except UnicodeError:
        raise CandidateGitError("Git returned an unexpected candidate path") from None


def _trusted_metadata(checkout):
    try:
        info = checkout.lstat()
    except OSError:
        raise CandidateGitError("The publication checkout could not be verified") from None
    if not stat.S_ISDIR(info.st_mode) or (
        os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077)
    ):
        raise CandidateGitError("The publication checkout is not owner-private")
    meta = checkout / ".git"
    if not meta.is_dir() or meta.is_symlink() or (meta / "config").is_symlink() or any(
        os.path.lexists(meta / name) for name in _BLOCKED_METADATA
    ):
        raise CandidateGitError("The publication checkout Git metadata changed")
    config = _git_bytes(checkout, "config", "--local", "--no-includes", "--name-only", "--null", "--list")
    try:
        names = {key.decode("ascii") for key in config.split(b"\0") if key}
    except UnicodeError:
        raise CandidateGitError("The publication checkout Git config changed") from None
    if not names <= _ORDINARY_GIT_CONFIG:
        raise CandidateGitError("The publication checkout Git config changed")


def _assert_applied(prepared, changes, scope):
    if capture_changes(prepared, scope.allowed_paths) != changes:
        raise CandidateGitError("The candidate differs from the verified patch")
    if _git_paths(
        prepared.path, "diff", "--cached", "--name-only", "-z", "--no-renames", "--",
    ) != changes.paths:
        raise CandidateGitError("The index differs from the verified file list")


def _verify_artifact(artifact, scope):
    _known_scope(scope)
    if type(artifact) is not CandidateArtifact or artifact.approval_sha != scope.approval_sha:
        raise CandidateGitError("The publication artifact is outside the approved task")
    _known_changes(artifact.changes, scope)
    candidate = artifact.candidate
    if (
        type(artifact.baseline) is not PreparedCheckout or artifact.baseline.path != artifact.checkout
        or not _valid_candidate(candidate, scope, artifact.baseline.base_sha)
        or candidate.paths != artifact.changes.paths
    ):
        raise CandidateGitError("The candidate evidence did not match the publication artifact")
    checkout = artifact.checkout
    _trusted_metadata(checkout)
    _assert_applied(artifact.baseline, artifact.changes, scope)
    if (
        _git(checkout, "rev-parse", "HEAD") != candidate.base
        or _git(checkout, "rev-list", "--parents", "-n", "1", candidate.head)
        != f"{candidate.head} {candidate.base}"
        or _git(checkout, "rev-parse", candidate.head + "^{tree}") != _git(checkout, "write-tree")
        or _git_paths(
            checkout, "diff-tree", "--no-commit-id", "--name-only", "-z", "--no-renames",
            "-r", candidate.base, candidate.head, "--",
        ) != candidate.paths
    ):
        raise CandidateGitError("The candidate commit differed from its verified tree or base")


def build_candidate(source: Path, trusted_checkout: Path, base_sha: str, changes: ChangeSet, scope):
    """Create a single-parent commit from a patch already verified by the caller.

    Use a location unavailable to the model and test processes. Never run
    candidate code or consult its .git directory to obtain the commit.
    """
    _known_scope(scope)
    _known_changes(changes, scope)
    if type(base_sha) is not str or not _SHA.fullmatch(base_sha):
        raise CandidateGitError("A pinned base SHA is required")
    prepared = prepare_checkout(source, trusted_checkout, base_sha)
    checkout = prepared.path
    _trusted_metadata(checkout)
    _git_bytes(checkout, "apply", "--index", "--whitespace=nowarn", "-", input_data=changes.patch)
    _assert_applied(prepared, changes, scope)
    tree = _git(checkout, "write-tree")
    head = _git(
        checkout, "-c", "user.name=AOTG AutoDev", "-c", "user.email=aotg-autodev@users.noreply.github.com",
        "commit-tree", tree, "-p", base_sha, "--no-gpg-sign", "-m", f"{scope.issue} offline candidate",
    )
    artifact = CandidateArtifact(
        Candidate(base_sha, head, changes.paths, True), checkout, changes, scope.approval_sha, prepared,
    )
    _verify_artifact(artifact, scope)
    return artifact


def _observed_head(branch_head, branch):
    try:
        return branch_head(branch)
    except Exception:
        raise CandidateGitError("The remote reservation head could not be verified") from None


def _write_gate(directory, branch, base, head):
    """Reject a moved reservation using Git's advertised remote object ID."""
    target = "refs/heads/" + branch
    hook = directory / "pre-push"
    # branch and SHAs are fixed by the validated scope and artifact.
    script = (
        "#!/bin/sh\n"
        "set -eu\n"
        f'test "$2" = "{_REMOTE}"\n'
        "read -r local_ref local_oid remote_ref remote_oid extra\n"
        f'test "$local_oid" = "{head}"\n'
        f'test "$remote_ref" = "{target}"\n'
        f'test "$remote_oid" = "{base}"\n'
        'test -z "$extra"\n'
        "if read -r unexpected; then exit 1; fi\n"
    )
    with hook.open("x", encoding="ascii", newline="\n") as stream:
        stream.write(script)
    hook.chmod(0o700)


def _trusted_executable(path, name):
    path = Path(path)
    if not path.is_absolute() or path.name != name:
        raise CandidateGitError("Explicit trusted Git and GitHub CLI paths are required")
    try:
        binary = path.resolve(strict=True)
    except OSError:
        raise CandidateGitError("The trusted Git executable is unavailable") from None
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise CandidateGitError("The trusted Git executable is unavailable")
    return binary


def _publication_env(gh_config_dir):
    # Preserve the trusted account's supported config discovery, not ambient
    # tokens, proxies, hooks, askpass, optional Git configs, or debug flags.
    names = ("HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
    env = {name: os.environ[name] for name in names if name in os.environ}
    env.update(
        PATH="/usr/bin:/bin", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/false", GH_PROMPT_DISABLED="1",
        GH_NO_UPDATE_NOTIFIER="1", GH_HOST="github.com",
    )
    if gh_config_dir is not None:
        config = Path(gh_config_dir)
        if not config.is_absolute() or not config.is_dir():
            raise CandidateGitError("GitHub authentication config must be a trusted absolute directory")
        env["GH_CONFIG_DIR"] = os.fspath(config)
    return env


def _push_https(artifact, branch, git, gh, gh_config_dir):
    if os.name != "posix":
        raise CandidateGitError("The publication gateway requires the verified WSL environment")
    git = _trusted_executable(git, "git")
    gh = _trusted_executable(gh, "gh")
    env = _publication_env(gh_config_dir)
    # Git requires a shell-form credential helper. Only the trusted normalized
    # binary is inserted, as one shell-quoted argument. No issue text or secret
    # is interpolated into the helper command.
    credential = "credential.https://github.com.helper=!" + shlex.quote(os.fspath(gh)) + " auth git-credential"
    candidate = artifact.candidate
    try:
        with TemporaryDirectory(prefix="aotg-push-gate-") as name:
            hooks = Path(name)
            _write_gate(hooks, branch, candidate.base, candidate.head)
            subprocess.run(
                [os.fspath(git), "-C", os.fspath(artifact.checkout),
                 "-c", "credential.helper=", "-c", credential, "-c", f"core.hooksPath={hooks}",
                 "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                 "-c", "http.followRedirects=false", "-c", "http.sslVerify=true",
                 "push", "--porcelain", "--no-follow-tags", "--no-signed",
                 "--recurse-submodules=no", "--", _REMOTE, f"{candidate.head}:refs/heads/{branch}"],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=30, check=True, shell=False,
            )
    except (OSError, subprocess.SubprocessError):
        raise CandidateGitError("The Git transport did not confirm the candidate publication") from None


def push_candidate(artifact, scope, branch, *, branch_head, git: Path, gh: Path, gh_config_dir: Path | None = None):
    """Publish the exact object to its reservation, with no force or retry."""
    _verify_artifact(artifact, scope)
    if branch != "autodev/" + scope.issue.lower():
        raise CandidateGitError("The destination is not the approved reservation")
    if _observed_head(branch_head, branch) != artifact.candidate.base:
        raise CandidateGitError("The remote reservation changed before publication")
    try:
        _push_https(artifact, branch, git, gh, gh_config_dir)
    except CandidateGitError:
        # An interrupted response can hide success. Always verify the receipt
        # with a separate remote read. No second push is allowed.
        pass
    if _observed_head(branch_head, branch) != artifact.candidate.head:
        raise CandidateGitError("Exact candidate publication could not be verified")
