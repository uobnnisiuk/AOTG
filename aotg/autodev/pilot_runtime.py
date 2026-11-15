"""Connect the first approved offline pilot to the existing attempt coordinator."""

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from aotg.artifacts import _unique_object

from .coordinator import Candidate, Coordinator, Readiness, Result, Snapshot
from .queue import OWNER, POLICY, ApprovedScope, _approval_valid
from .runtime_config import ConfigError, _private_bytes

BOOTSTRAP_ISSUE = "UOB-50"
BOOTSTRAP_GITHUB_ISSUE = 7
BOOTSTRAP_PATHS = frozenset({
    "aotg/offline_bench.py",
    "docs/offline-bench.md",
    "tests/test_offline_bench.py",
})
_SHA = re.compile(r"(?!0{40})[0-9a-f]{40}")
_SCOPE = re.compile(r"(?!0{64})[0-9a-f]{64}")
_PRIVATE_TEXT = re.compile(
    r"(?i)(?:/home/[^\s/]+/|/mnt/[a-z]/users/|[a-z]:[/\\]users[/\\]|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[a-z0-9]{20,}|"
    r"github_pat_[a-z0-9_]{20,}|lin_api_[a-z0-9_-]{12,}|"
    r"sk-(?:proj-)?[a-z0-9_-]{20,})"
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


class PilotError(ValueError):
    """A bootstrap boundary or external observation is unverified."""


@dataclass(frozen=True, slots=True)
class PilotRelease:
    """An owner-authorized fixed pilot; it grants no scheduler or merge permission."""

    base: str
    scope_digest: str
    issued_at: datetime
    expires_at: datetime

    def permits(self, scope, base, now):
        return (
            _is_first_scope(scope) and type(base) is str and _SHA.fullmatch(base) is not None
            and self.base == base and self.scope_digest == scope.approval_sha
            and isinstance(self.issued_at, datetime) and self.issued_at.utcoffset() == timedelta(0)
            and isinstance(self.expires_at, datetime) and self.expires_at.utcoffset() == timedelta(0)
            and self.issued_at <= now < self.expires_at
        )


def _utc(value):
    if type(value) is not str:
        raise ValueError
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() != timedelta(0) or parsed.isoformat(timespec="seconds") != value:
        raise ValueError
    return parsed


def load_release(path):
    """Load a separate private owner record for one approved ChatGPT-plan run."""
    fields = {
        "version", "policy", "approved_by", "issue", "github_issue", "base",
        "scope_digest", "issued_at", "expires_at", "authorization",
    }
    try:
        value = json.loads(_private_bytes(path, 4096), object_pairs_hook=_unique_object)
        if (
            type(value) is not dict or value.keys() != fields
            or type(value["version"]) is not int or value["version"] != 1
            or value["policy"] != POLICY or value["approved_by"] != OWNER
            or value["issue"] != BOOTSTRAP_ISSUE
            or type(value["github_issue"]) is not int or value["github_issue"] != BOOTSTRAP_GITHUB_ISSUE
            or value["authorization"] != "one-chatgpt-plan-pilot-no-extra-charge"
            or not isinstance(value["base"], str) or not _SHA.fullmatch(value["base"])
            or not isinstance(value["scope_digest"], str) or not _SCOPE.fullmatch(value["scope_digest"])
        ):
            raise ValueError
        issued = _utc(value["issued_at"])
        expires = _utc(value["expires_at"])
        if expires <= issued:
            raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise ConfigError("The first live pilot release could not be verified") from None
    return PilotRelease(value["base"], value["scope_digest"], issued, expires)


def _is_first_scope(scope):
    return (
        type(scope) is ApprovedScope and _approval_valid(scope)
        and scope.issue == BOOTSTRAP_ISSUE and scope.github_issue == BOOTSTRAP_GITHUB_ISSUE
        and frozenset(scope.allowed_paths) == BOOTSTRAP_PATHS
        and scope.dependencies == ("UOB-49",)
    )


def _verify_publication(patch):
    """Fail closed on private network references or recognizable local secrets."""
    if type(patch) is not bytes or not patch or len(patch) > 1024 * 1024:
        raise PilotError("The candidate patch is unavailable or exceeds its bound")
    try:
        contents = patch.decode("utf-8")
    except UnicodeError:
        raise PilotError("The candidate patch is not public text") from None
    if _PRIVATE_TEXT.search(contents):
        raise PilotError("Candidate contains a potentially private literal")
    for match in _IPV4.finditer(contents):
        try:
            address = ipaddress.ip_address(match[0])
        except ValueError:
            continue
        if not address.is_global:
            raise PilotError("Candidate contains a nonpublic network address")


class PilotPorts:
    """Build snapshots from authenticated sources and hand off exact commits."""

    def __init__(self, github, linear, scope, worker, push_verified, *, base):
        if not _is_first_scope(scope) or type(base) is not str or not _SHA.fullmatch(base):
            raise PilotError("The bootstrap pilot requires its fixed approved scope")
        self.github = github
        self.linear = linear
        self.scope = scope
        self.base = base
        self.worker = worker
        self.push_verified = push_verified

    def snapshot(self):
        observed = self.github.snapshot()
        if observed.main_sha != self.base:
            raise PilotError("The released base changed")
        if not observed.initial_pr_merged or observed.open_pr_numbers:
            return Snapshot((), (), (), observed, False)
        issue = self.github.read_issue(self.scope.github_issue)
        if issue.number != self.scope.github_issue or issue.author != OWNER:
            raise PilotError("The GitHub issue owner or identity was not verified")
        issues, done = self.linear.snapshot((self.scope,))
        if issue.state != "open" and not (issue.state == "closed" and self.scope.issue in done):
            raise PilotError("GitHub issue state did not match the pilot")
        return Snapshot((self.scope,), issues, done, observed, True)

    def reserve_branch(self, branch, base):
        self.github.reserve_branch(branch, base)

    def branch_head(self, branch):
        return self.github.branch_head(branch)

    def publish_draft(self, scope, candidate):
        if scope != self.scope or type(candidate) is not Candidate:
            raise PilotError("Candidate does not match the approved pilot")
        artifact = self.worker.artifact_for(candidate)
        branch = "autodev/uob-50"
        if artifact.candidate != candidate:
            raise PilotError("Candidate did not originate from the verified worker")
        _verify_publication(artifact.changes.patch)
        self.push_verified(artifact, scope, branch, branch_head=self.github.branch_head)
        if self.github.branch_head(branch) != candidate.head:
            raise PilotError("Candidate push could not be verified")
        return self.github.publish_draft(scope, candidate)

    def read_draft(self, number):
        return self.github.read_draft(number)


def run_approved_pilot(ledger, ports, slot, release, readiness, *, now=None):
    """Start at most one model attempt behind the explicit release and readiness gates."""
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("A timezone-aware invocation time is required")
    timestamp = now.astimezone(timezone.utc).isoformat(timespec="seconds")
    if (
        type(release) is not PilotRelease or type(ports) is not PilotPorts
        or type(readiness) is not Readiness or not readiness.ready()
    ):
        return Result("blocked", "deployment-gate", time_utc=timestamp)
    try:
        remote = ports.github.snapshot()
    except Exception:
        return Result("unknown", "github-evidence-unavailable", time_utc=timestamp)
    if remote.main_sha != ports.base or not release.permits(ports.scope, ports.base, now):
        return Result("blocked", "deployment-gate", time_utc=timestamp)

    return Coordinator(ledger, ports, ports.worker, slot).run_once(
        now, readiness=readiness, execute=True,
    )
