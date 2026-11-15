"""Assemble the production ports for a single explicitly released offline pilot."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

from aotg.artifacts import _unique_object

from .candidate_git import push_candidate
from .coordinator import Readiness, Result
from .github_runtime import GitHubResultComments, GitHubRuntime
from .isolated_process import CodexDeployment, IsolatedProcess, _approved
from .ledger import Ledger
from .linear_read import LinearIntake
from .pilot_runtime import PilotPorts, load_release, run_approved_pilot
from .pilot_worker import PILOT_PROMPT, PilotWorker
from .receipt_transport import LinearResultComments, ReceiptTransport
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


def run_configured_pilot(installation, readiness, *, now=None):
    """Run the fixed pilot only from separately released private configuration.

    There is no scheduler entry or automatic retry. The launcher verifies the
    deployment and its authorization before this function, and does not send
    configuration files or issue descriptions to the model.
    """
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("A timezone-aware invocation time is required")
    timestamp = now.astimezone(timezone.utc).isoformat(timespec="seconds")
    blocked = Result("blocked", "deployment-gate", time_utc=timestamp)
    if (
        type(installation) is not PilotInstallation or type(readiness) is not Readiness
        or not readiness.ready() or type(installation.codex) is not CodexDeployment
        or not _approved(installation.codex.model_authorization, PILOT_PROMPT, MAX_RUNTIME_SECONDS)
        or not isinstance(installation.root, Path) or not installation.root.is_absolute()
    ):
        return blocked
    root = installation.root
    config = root / "config"
    try:
        release = load_release(config / "first-pilot-release.json")
        scopes = load_approvals(config / "approvals.json")
        if (
            len(scopes) != 1 or not release.permits(scopes[0], release.base, now)
            or installation.codex.model_authorization.expires_at > release.expires_at
        ):
            return blocked
        authentication = load_linear_authorization(config / "linear-authorization")
        github_target, linear_target = _receipt_targets(config / "receipt-targets.json")
        github = GitHubRuntime(installation.gh)
        linear = LinearIntake(authentication)
        transport = ReceiptTransport(GitHubResultComments(github), LinearResultComments(authentication))
        local = LocalResultSlot(root / "results" / "latest.json")
        slot = RemoteResultSlot(local, github_target, linear_target, transport)
        worker = PilotWorker(root / "checkout", root / "runs", IsolatedProcess(installation.codex))
        push = partial(push_candidate, git=installation.git, gh=installation.gh)
        ports = PilotPorts(github, linear, scopes[0], worker, push, base=release.base)
        _verify_slot(local, slot, github_target, linear_target, transport)
    except (ValueError, OSError, RuntimeError):
        return blocked
    return run_approved_pilot(Ledger(root / "ledger"), ports, slot, release, readiness, now=now)
