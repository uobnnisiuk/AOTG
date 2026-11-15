"""Connect the first approved offline pilot to the existing attempt coordinator."""

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import partial
from time import monotonic_ns

from aotg.artifacts import _unique_object

from .coordinator import Candidate, Coordinator, Readiness, Result, Snapshot
from .queue import OWNER, POLICY, ApprovedScope, _approval_valid
from .runtime_config import ConfigError, _private_bytes
from .worker import MAX_RUNTIME_SECONDS

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

_NANOSECONDS = 1_000_000_000
# Keep time for the final inventory, exact push, Draft read-back, and both receipts.
_PUBLICATION_MARGIN_SECONDS = 120


class PilotError(ValueError):
    """A bootstrap boundary or external observation is unverified."""


def _utc_now():
    return datetime.now(timezone.utc)


class PilotAttemptBoundary:
    """A single trusted launcher deadline and a live, fail-closed host check."""

    def __init__(self, deadline_ns: int, host_quiet: Callable[[], bool]):
        if (
            type(deadline_ns) is not int or not callable(host_quiet)
            or not 0 < deadline_ns - monotonic_ns() <= MAX_RUNTIME_SECONDS * _NANOSECONDS
        ):
            raise PilotError("The launcher must supply a live deadline of at most forty minutes")
        self._deadline_ns = deadline_ns
        self._host_quiet = host_quiet
        self._issued_at = None
        self._expires_at = None
        self._stopped = False

    @classmethod
    def from_deadline(cls, deadline_ns: int, host_quiet: Callable[[], bool]):
        return cls(deadline_ns, host_quiet)

    def constrain_authorization(self, issued_at: datetime, expires_at: datetime):
        """Keep the narrower UTC window even if the wall clock later moves back."""
        if self._issued_at is not None:
            self._stopped = True
            raise PilotError("The pilot boundary was already used")
        if not all(
            isinstance(value, datetime) and value.utcoffset() == timedelta(0)
            for value in (issued_at, expires_at)
        ):
            self._stopped = True
            raise PilotError("The pilot authorization window was not verified")
        self.remaining()
        monotonic_sample = monotonic_ns()
        now = _utc_now()
        if not issued_at <= now < expires_at:
            self._stopped = True
            raise PilotError("The pilot authorization window is closed")
        self._issued_at = issued_at
        self._expires_at = expires_at
        available = expires_at - now
        self._deadline_ns = min(
            self._deadline_ns,
            monotonic_sample + available // timedelta(microseconds=1) * 1_000,
        )

    def remaining(self, *, minimum_seconds=0):
        if self._stopped:
            raise PilotError("The pilot boundary was closed")
        remaining = self._deadline_ns - monotonic_ns()
        if self._expires_at is not None:
            now = _utc_now()
            if now < self._issued_at:
                self._stopped = True
                raise PilotError("The pilot authorization window is closed")
            remaining = min(
                remaining, (self._expires_at - now) // timedelta(microseconds=1) * 1_000,
            )
        if remaining <= minimum_seconds * _NANOSECONDS:
            self._stopped = True
            raise TimeoutError("The pilot has insufficient time at this boundary")
        return remaining / _NANOSECONDS

    def require_quiet(self, *, minimum_seconds=0):
        self.remaining(minimum_seconds=minimum_seconds)
        try:
            quiet = self._host_quiet()
        except Exception:
            quiet = False
        if quiet is not True:
            self._stopped = True
            raise PilotError("The host could not be verified as quiet")
        return self.remaining(minimum_seconds=minimum_seconds)

    def worker_seconds(self):
        return self.require_quiet(
            minimum_seconds=_PUBLICATION_MARGIN_SECONDS,
        ) - _PUBLICATION_MARGIN_SECONDS


class _BoundResultSlot:
    """Leave the ledger reservation in place if its receipt cannot complete safely."""

    def __init__(self, slot, boundary):
        self.slot = slot
        self.boundary = boundary

    def write(self, result):
        self.boundary.require_quiet()
        self.slot.write(result)
        self.boundary.remaining()

    def read(self):
        self.boundary.remaining()
        result = self.slot.read()
        self.boundary.require_quiet()
        return result


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

    def __init__(self, github, linear, scope, worker, push_verified, *, base, boundary=None):
        if (
            not _is_first_scope(scope) or type(base) is not str or not _SHA.fullmatch(base)
            or (boundary is not None and type(boundary) is not PilotAttemptBoundary)
        ):
            raise PilotError("The bootstrap pilot requires its fixed approved scope")
        self.github = github
        self.linear = linear
        self.scope = scope
        self.base = base
        self.worker = worker
        self.push_verified = push_verified
        self.boundary = boundary

    def snapshot(self):
        if self.boundary is not None:
            self.boundary.require_quiet()
        snapshot = self._snapshot()
        if self.boundary is not None:
            self.boundary.require_quiet()
        return snapshot

    def _snapshot(self):
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
        if self.boundary is not None:
            self.boundary.worker_seconds()
        self.github.reserve_branch(branch, base)

    def branch_head(self, branch):
        if self.boundary is not None:
            self.boundary.remaining()
        head = self.github.branch_head(branch)
        if self.boundary is not None:
            self.boundary.remaining()
        return head

    def implement(self, scope, base, *, timeout_seconds):
        if self.boundary is not None:
            timeout_seconds = min(timeout_seconds, self.boundary.worker_seconds())
        candidate = self.worker.implement(scope, base, timeout_seconds=timeout_seconds)
        if self.boundary is not None:
            self.boundary.require_quiet()
        return candidate

    def _publication_head(self, branch):
        head = self.branch_head(branch)
        if self.boundary is not None and head == self.base:
            # The verified Git adapter reads the reservation again before starting its 30-second push.
            self.boundary.require_quiet(minimum_seconds=30)
        return head

    def publish_draft(self, scope, candidate):
        if scope != self.scope or type(candidate) is not Candidate:
            raise PilotError("Candidate does not match the approved pilot")
        artifact = self.worker.artifact_for(candidate)
        branch = "autodev/uob-50"
        if artifact.candidate != candidate:
            raise PilotError("Candidate did not originate from the verified worker")
        _verify_publication(artifact.changes.patch)
        if self.boundary is not None:
            self.boundary.require_quiet(minimum_seconds=30)
        self.push_verified(artifact, scope, branch, branch_head=self._publication_head)
        if self.branch_head(branch) != candidate.head:
            raise PilotError("Candidate push could not be verified")
        if self.boundary is not None:
            self.boundary.require_quiet()
        return self.github.publish_draft(scope, candidate)

    def read_draft(self, number):
        if self.boundary is not None:
            self.boundary.remaining()
        draft = self.github.read_draft(number)
        if self.boundary is not None:
            self.boundary.remaining()
        return draft


def _reservation_time(ports, release):
    ports.boundary.worker_seconds()
    now = _utc_now()
    if not release.permits(ports.scope, ports.base, now):
        raise PilotError("The released scope could not be verified at reservation")
    return now


def run_approved_pilot(ledger, ports, slot, release, readiness, *, now=None):
    """Start at most one model attempt behind the explicit release and readiness gates."""
    now = _utc_now() if now is None else now
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("A timezone-aware invocation time is required")
    timestamp = now.astimezone(timezone.utc).isoformat(timespec="seconds")
    if (
        type(release) is not PilotRelease or type(ports) is not PilotPorts
        or type(readiness) is not Readiness or not readiness.ready()
        or not release.permits(ports.scope, ports.base, now)
    ):
        return Result("blocked", "deployment-gate", time_utc=timestamp)
    reservation_clock = None
    if ports.boundary is not None:
        try:
            ports.boundary.worker_seconds()
        except (PilotError, TimeoutError):
            return Result("blocked", "deployment-gate", time_utc=timestamp)
        slot = _BoundResultSlot(slot, ports.boundary)
        reservation_clock = partial(_reservation_time, ports, release)
    try:
        remote = ports.github.snapshot()
        if ports.boundary is not None:
            ports.boundary.worker_seconds()
    except Exception:
        return Result("unknown", "github-evidence-unavailable", time_utc=timestamp)
    if remote.main_sha != ports.base:
        return Result("blocked", "deployment-gate", time_utc=timestamp)

    return Coordinator(ledger, ports, ports, slot).run_once(
        now, readiness=readiness, execute=True, reservation_clock=reservation_clock,
    )
