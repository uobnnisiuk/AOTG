"""Advance one approved software issue through an independently verified Draft PR."""

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Protocol

from .ledger import Ledger, LedgerError, ReservationBlocked
from .worker import CandidateRejected
from .queue import (
    ApprovedScope,
    GitHubSnapshot,
    IssueSnapshot,
    select_candidate,
    valid_change_path,
)

_SHA = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class Snapshot:
    approvals: tuple[ApprovedScope, ...]
    issues: tuple[IssueSnapshot, ...]
    done_issues: tuple[str, ...]
    github: GitHubSnapshot
    linear_complete: bool


@dataclass(frozen=True)
class Readiness:
    """Attestations from trusted infrastructure, independently of Issue content."""

    chatgpt_plan_authorized: bool = False
    code_execution_isolated: bool = False
    checkout_verified: bool = False
    host_quiet: bool = False

    def ready(self):
        return all(value is True for value in (
            self.chatgpt_plan_authorized,
            self.code_execution_isolated,
            self.checkout_verified,
            self.host_quiet,
        ))


@dataclass(frozen=True)
class Candidate:
    base: str
    head: str
    paths: tuple[str, ...]
    local_checks_passed: bool


@dataclass(frozen=True)
class Draft:
    number: int
    branch: str
    base: str
    head: str
    is_draft: bool


@dataclass(frozen=True)
class Result:
    status: str
    reason: str
    issue: str | None = None
    time_utc: str | None = None
    base: str | None = None
    head: str | None = None
    pr: int | None = None

    def redacted(self):
        """Emit fixed fields only. Adapter exceptions and candidate output stay local."""
        return {
            "policy": "AOTG-AUTODEV-V1",
            "status": self.status,
            "reason": self.reason,
            "issue": self.issue,
            "time_utc": self.time_utc,
            "base": self.base,
            "head": self.head,
            "pr": self.pr,
        }


class GitHubPort(Protocol):
    def snapshot(self) -> Snapshot: ...
    def reserve_branch(self, branch: str, base: str) -> None: ...
    def branch_head(self, branch: str) -> str | None: ...
    def publish_draft(self, scope: ApprovedScope, candidate: Candidate) -> int: ...
    def read_draft(self, number: int) -> Draft: ...


class WorkerPort(Protocol):
    def implement(self, scope: ApprovedScope, base: str, *, timeout_seconds: int) -> Candidate: ...


class ResultSlot(Protocol):
    def write(self, result: dict) -> None: ...
    def read(self) -> dict: ...


class Coordinator:
    """A single attempt with trusted ports. Observe mode never invokes write ports."""

    def __init__(self, ledger: Ledger, github: GitHubPort, worker: WorkerPort, slot: ResultSlot):
        self.ledger = ledger
        self.github = github
        self.worker = worker
        self.slot = slot

    def run_once(
        self, now: datetime, *, readiness: Readiness | None = None, execute=False,
        reservation_clock: Callable[[], datetime] | None = None,
    ):
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise ValueError("A timezone-aware invocation time is required")
        now_utc = now.astimezone(timezone.utc)
        timestamp = now_utc.isoformat(timespec="seconds")
        try:
            selection = _select(self.github.snapshot())
        except Exception:
            return Result("unknown", "snapshot-unavailable", time_utc=timestamp)

        if selection.status != "eligible":
            return Result(selection.status, selection.reason, time_utc=timestamp)
        scope, base = selection.scope, selection.main_sha
        result = Result("blocked", "shadow-eligible", scope.issue, timestamp, base)
        # A live reservation with a trusted clock checks admission atomically
        # using the new sample after the fresh snapshot.
        if execute is not True or reservation_clock is None:
            try:
                self.ledger.check(scope.issue, now)
            except ReservationBlocked as exc:
                return replace(result, reason=exc.reason)
            except LedgerError:
                return replace(result, status="unknown", reason="ledger-unavailable")

        if execute is not True:
            return result
        if not isinstance(readiness, Readiness) or not readiness.ready():
            return replace(result, reason="deployment-gate")

        try:
            fresh = _select(self.github.snapshot())
        except Exception:
            return replace(result, status="unknown", reason="snapshot-unavailable")
        if fresh != selection:
            return replace(result, reason="snapshot-changed")

        started_at = now
        if reservation_clock is not None:
            try:
                sampled = reservation_clock()
                if not isinstance(sampled, datetime) or sampled.utcoffset() is None:
                    raise ValueError("A timezone-aware reservation time is required")
                started_at = sampled.astimezone(timezone.utc)
                if started_at < now_utc:
                    raise ValueError("The reservation clock predates invocation")
            except Exception:
                return replace(result, reason="deployment-gate")
            result = replace(result, time_utc=started_at.isoformat(timespec="seconds"))

        try:
            attempt = self.ledger.reserve(scope.issue, started_at)
        except ReservationBlocked as exc:
            return replace(result, reason=exc.reason)
        except LedgerError:
            return replace(result, status="unknown", reason="reservation-unconfirmed")

        branch = "autodev/" + scope.issue.lower()
        stage = "branch-unconfirmed"
        try:
            self.github.reserve_branch(branch, base)
            if self.github.branch_head(branch) != base:
                return self._finish(attempt, "unknown", replace(result, status="unknown", reason=stage))

            stage = "claim-result-unconfirmed"
            if not self._save(replace(result, status="claim_started", reason="reserved")):
                return self._finish(attempt, "unknown", replace(result, status="unknown", reason=stage))

            stage = "worker-result-unconfirmed"
            candidate = self.worker.implement(scope, base, timeout_seconds=40 * 60)
            if not _valid_candidate(candidate, scope, base):
                return self._finish(
                    attempt, "failure", replace(result, reason="candidate-rejected")
                )

            stage = "prepublication-state-unconfirmed"
            observed = self.github.snapshot()
            if not isinstance(observed, Snapshot) or not isinstance(observed.github, GitHubSnapshot):
                return self._finish(attempt, "unknown", replace(result, status="unknown", reason=stage))
            names = observed.github.branch_names
            if type(names) is not tuple or names.count(branch) != 1:
                return self._finish(attempt, "unknown", replace(result, status="unknown", reason=stage))
            without_own_branch = replace(observed.github, branch_names=tuple(
                name for name in names if name != branch
            ))
            if (_select(replace(observed, github=without_own_branch)) != selection
                    or self.github.branch_head(branch) != base):
                return self._finish(attempt, "failure", replace(result, reason="prepublication-changed"))

            stage = "draft-unconfirmed"
            pr = self.github.publish_draft(scope, candidate)
            if type(pr) is not int or pr < 1 or self.github.read_draft(pr) != Draft(
                pr, branch, base, candidate.head, True
            ) or self.github.branch_head(branch) != candidate.head:
                return self._finish(attempt, "unknown", replace(result, status="unknown", reason=stage))
            final_snapshot = self.github.snapshot()
            if (not isinstance(final_snapshot, Snapshot)
                    or not isinstance(final_snapshot.github, GitHubSnapshot)
                    or final_snapshot.github.complete is not True
                    or final_snapshot.github.initial_pr_merged is not True
                    or final_snapshot.github.repo != observed.github.repo
                    or final_snapshot.github.main_sha != base
                    or final_snapshot.github.open_pr_numbers != (pr,)):
                return self._finish(attempt, "unknown", replace(
                    result, status="unknown", reason="draft-unconfirmed", head=candidate.head, pr=pr,
                ))
            return self._finish(attempt, "success", replace(
                result, status="draft_pr", reason="draft-verified", head=candidate.head, pr=pr,
            ))
        except CandidateRejected:
            if stage == "worker-result-unconfirmed":
                return self._finish(attempt, "failure", replace(result, reason="candidate-rejected"))
            return self._finish(attempt, "unknown", replace(result, status="unknown", reason=stage))
        except TimeoutError:
            if stage == "worker-result-unconfirmed":
                return self._finish(attempt, "timeout", replace(result, reason="worker-timeout"))
            return self._finish(attempt, "unknown", replace(result, status="unknown", reason=stage))
        except Exception:
            return self._finish(attempt, "unknown", replace(result, status="unknown", reason=stage))

    def _save(self, result):
        payload = result.redacted()
        self.slot.write(payload)
        return self.slot.read() == payload

    def _finish(self, attempt, outcome, result):
        try:
            if self._save(result):
                self.ledger.finish(attempt, outcome)
                return result
        except Exception:
            pass
        # The existing reservation remains consumed and blocks unattended recovery.
        return replace(result, status="unknown", reason="result-unconfirmed")


def _select(snapshot):
    if not isinstance(snapshot, Snapshot):
        raise ValueError("A trusted source snapshot is required")
    return select_candidate(
        approvals=snapshot.approvals, issues=snapshot.issues, done_issues=snapshot.done_issues,
        github=snapshot.github, linear_complete=snapshot.linear_complete,
    )


def _valid_candidate(candidate, scope, base):
    return (
        type(candidate) is Candidate and candidate.base == base
        and isinstance(candidate.head, str) and _SHA.fullmatch(candidate.head)
        and candidate.head not in (base, "0" * 40) and candidate.local_checks_passed is True
        and type(candidate.paths) is tuple and bool(candidate.paths)
        and all(valid_change_path(path) and path in scope.allowed_paths for path in candidate.paths)
        and len(set(candidate.paths)) == len(candidate.paths)
    )
