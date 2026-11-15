"""Assemble the production ports for a single explicitly released offline pilot."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

from aotg.artifacts import _unique_object

from .candidate_git import push_candidate
from .coordinator import Readiness, Result
from .github_runtime import _TIMEOUT, GitHubResultComments, GitHubRuntime, _run_gh
from .isolated_process import CodexDeployment, IsolatedProcess, _approved
from .ledger import Ledger
from .linear_read import LinearIntake, _post
from .pilot_runtime import (
    PilotAttemptBoundary,
    PilotError,
    PilotPorts,
    load_release,
    run_approved_pilot,
)
from .pilot_worker import PILOT_PROMPT, PilotWorker
from .receipt_transport import _MUTATION, LinearResultComments, ReceiptTransport
from .remote_results import BOOTSTRAP_BODY, CommentTarget, RemoteResultSlot
from .result_slot import LocalResultSlot, ResultSlotError, _present
from .runtime_config import (
    ConfigError,
    _private_bytes,
    load_approvals,
    load_linear_authorization,
)
from .worker import MAX_RUNTIME_SECONDS


@dataclass(frozen=True, slots=True)
class PilotInstallation:
    """The AOTG-only trusted launcher supplies executable and device identities."""

    root: Path
    git: Path
    gh: Path
    codex: CodexDeployment
    gh_config_dir: Path | None = None


def _receipt_targets(path):
    try:
        data = json.loads(_private_bytes(path, 4096), object_pairs_hook=_unique_object)
        if (type(data) is not dict or data.keys() != {"version", "github", "linear"}
                or type(data["version"]) is not int or data["version"] != 1):
            raise ValueError
        git = data["github"]
        linear = data["linear"]
        if (
            type(git) is not dict or git.keys() != {"issue", "comment_id", "author_id"}
            or type(git["issue"]) is not int or git["issue"] != 3
            or type(linear) is not dict
            or linear.keys() != {"issue", "issue_id", "comment_id", "author_id"}
            or linear["issue"] != "UOB-58"
        ):
            raise ValueError
        return (
            CommentTarget("github", "uobnnisiuk/AOTG#3", 3, git["comment_id"], git["author_id"]),
            CommentTarget("linear", "UOB-58", linear["issue_id"], linear["comment_id"],
                          linear["author_id"]),
        )
    except (ValueError, TypeError, RecursionError):
        raise ConfigError("The pilot receipt targets could not be verified") from None


def _verify_slot(local, slot, github_target, linear_target, transport):
    if _present(slot.lock) or _present(slot.pending):
        raise ResultSlotError("A previous receipt update awaits inspection")
    if _present(local.path):
        slot.read()
        return
    if any(transport.read(target).body != BOOTSTRAP_BODY for target in (
        github_target, linear_target,
    )):
        raise ResultSlotError("A bootstrap receipt changed")


def _run_github(boundary, argv, payload, *, cwd, env):
    # GitHub's own precondition reads can consume time after the port's outer guard.
    method = argv[5]
    if method in {"POST", "PATCH"}:
        boundary.require_quiet(minimum_seconds=_TIMEOUT)
    elif method == "GET":
        boundary.remaining()
    else:
        raise PilotError("Unexpected GitHub request method")
    response = _run_gh(argv, payload, cwd=cwd, env=env)
    boundary.remaining()
    return response


def _request_linear(boundary, authorization, query, variables):
    if query == _MUTATION:
        boundary.require_quiet(minimum_seconds=8)
    elif query.lstrip().startswith("query "):
        boundary.remaining()
    else:
        raise PilotError("Unexpected Linear request operation")
    response = _post(query, variables, authorization)
    boundary.remaining()
    return response


def run_configured_pilot(installation, readiness, *, boundary=None, now=None):
    """Run the fixed pilot only from separately released private configuration.

    The launcher provides a live host check and an absolute monotonic deadline.
    The model receives only the reviewed public prompt.
    """
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("A timezone-aware invocation time is required")
    timestamp = now.astimezone(timezone.utc).isoformat(timespec="seconds")
    blocked = Result("blocked", "deployment-gate", time_utc=timestamp)
    if (
        type(installation) is not PilotInstallation or type(readiness) is not Readiness
        or not readiness.ready() or type(installation.codex) is not CodexDeployment
        or type(boundary) is not PilotAttemptBoundary
        or not isinstance(installation.root, Path) or not installation.root.is_absolute()
    ):
        return blocked
    root = installation.root
    config = root / "config"
    try:
        boundary.worker_seconds()
        authorization = installation.codex.model_authorization
        if not _approved(authorization, PILOT_PROMPT, 1) or authorization.max_seconds != MAX_RUNTIME_SECONDS:
            return blocked
        release = load_release(config / "first-pilot-release.json")
        scopes = load_approvals(config / "approvals.json")
        if (
            len(scopes) != 1 or not release.permits(scopes[0], release.base, now)
            or authorization.expires_at > release.expires_at
        ):
            return blocked
        boundary.constrain_authorization(release.issued_at, authorization.expires_at)
        boundary.worker_seconds()
        authentication = load_linear_authorization(config / "linear-authorization")
        github_target, linear_target = _receipt_targets(config / "receipt-targets.json")
        github = GitHubRuntime(
            installation.gh, run=partial(_run_github, boundary), config_dir=installation.gh_config_dir,
        )
        request_linear = partial(_request_linear, boundary, authentication)
        linear = LinearIntake(request=request_linear)
        transport = ReceiptTransport(
            GitHubResultComments(github), LinearResultComments(request=request_linear),
        )
        local = LocalResultSlot(root / "results" / "latest.json")
        slot = RemoteResultSlot(local, github_target, linear_target, transport)
        worker = PilotWorker(
            root / "checkout", root / "runs", IsolatedProcess(installation.codex), boundary=boundary,
        )
        push = partial(
            push_candidate, git=installation.git, gh=installation.gh,
            gh_config_dir=installation.gh_config_dir,
        )
        ports = PilotPorts(github, linear, scopes[0], worker, push, base=release.base, boundary=boundary)
        _verify_slot(local, slot, github_target, linear_target, transport)
    except (ValueError, OSError, RuntimeError):
        return blocked
    return run_approved_pilot(Ledger(root / "ledger"), ports, slot, release, readiness, now=now)
