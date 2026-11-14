"""Read-only selection over independently collected GitHub and Linear evidence.

An ApprovedScope is supplied by the operator's trusted approval source, never by
issue content, comments or labels. The digest binds its fields for comparison;
it does not authenticate the source.
"""

import hashlib
import json
import re
from dataclasses import dataclass

REPOSITORY = "uobnnisiuk/AOTG"
OWNER = "uobnnisiuk"
POLICY = "AOTG-AUTODEV-V1"

# Infrastructure and real experiment issues require separate approval.
_HELD = frozenset({"UOB-48", "UOB-49", "UOB-51", "UOB-52", "UOB-54", "UOB-56",
                   "UOB-57", "UOB-58", "UOB-59"})
_ISSUE = re.compile(r"UOB-[1-9][0-9]{0,8}")
_FILENAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_WINDOWS_DEVICE = re.compile(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", re.I)
_PATH_SUFFIXES = {
    "aotg": frozenset({".py"}),
    "docs": frozenset({".md"}),
    "tests": frozenset({".py", ".json", ".txt", ".cpp", ".cs"}),
}


@dataclass(frozen=True, slots=True)
class ApprovedScope:
    issue: str
    github_issue: int
    revision: str
    allowed_paths: tuple[str, ...]
    dependencies: tuple[str, ...]
    approval_sha: str
    repo: str = REPOSITORY
    approved_by: str = OWNER
    kind: str = "offline-software"


@dataclass(frozen=True, slots=True)
class IssueSnapshot:
    issue: str
    github_issue: int
    revision: str
    dependencies: tuple[str, ...]
    eligible: bool
    repo: str = REPOSITORY


@dataclass(frozen=True, slots=True)
class GitHubSnapshot:
    main_sha: str
    open_pr_numbers: tuple[int, ...]
    branch_names: tuple[str, ...]
    complete: bool
    initial_pr_merged: bool
    repo: str = REPOSITORY


@dataclass(frozen=True, slots=True)
class QueueResult:
    status: str
    reason: str
    scope: ApprovedScope | None = None
    main_sha: str | None = None


def _issue_id(value):
    return isinstance(value, str) and _ISSUE.fullmatch(value) is not None


def _issue_number(number):
    return type(number) is int and number > 0


def _hex(value, width):
    return (
        isinstance(value, str)
        and re.fullmatch(rf"[0-9a-f]{{{width}}}", value) is not None
        and value != "0" * width
    )


def _items(values, valid, *, unique=True):
    return (
        type(values) is tuple
        and all(valid(value) for value in values)
        and (not unique or len(set(values)) == len(values))
    )


def valid_change_path(path):
    """Check a literal repository-relative path before applying scope membership."""
    if not isinstance(path, str) or len(path) > 255:
        return False
    if path == "README.md":
        return True
    parts = path.split("/")
    if len(parts) < 2 or parts[0] not in _PATH_SUFFIXES:
        return False
    if any(
        not _FILENAME.fullmatch(part)
        or part.endswith(".")
        or _WINDOWS_DEVICE.fullmatch(part)
        or part.casefold() in {"autodev", "__pycache__", "private", "evidence"}
        for part in parts
    ):
        return False
    name = parts[-1]
    stem, separator, suffix = name.rpartition(".")
    return (
        separator == "."
        and bool(stem)
        and stem.casefold().split(".")[0] not in {"conftest", "sitecustomize", "usercustomize"}
        and "." + suffix in _PATH_SUFFIXES[parts[0]]
    )


def scope_digest(scope):
    """Digest of the owner-approved task identity, revision and allowed changes."""
    data = {
        "policy": POLICY,
        "repo": scope.repo,
        "approved_by": scope.approved_by,
        "kind": scope.kind,
        "issue": scope.issue,
        "github_issue": scope.github_issue,
        "revision": scope.revision,
        "allowed_paths": sorted(scope.allowed_paths),
        "dependencies": sorted(scope.dependencies),
    }
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _branch_name(name):
    if not isinstance(name, str) or not name or len(name) > 1024:
        return False
    return (
        name != "@"
        and not name.startswith("-")
        and ".." not in name
        and "@{" not in name
        and re.search(r"[\x00-\x20\x7f~^:?*\[\\]", name) is None
        and all(
            part and not part.startswith(".") and not part.endswith((".", ".lock"))
            for part in name.split("/")
        )
    )


def _github_valid(github):
    return (
        type(github) is GitHubSnapshot
        and github.repo == REPOSITORY
        and github.complete is True
        and type(github.initial_pr_merged) is bool
        and _hex(github.main_sha, 40)
        and _items(github.open_pr_numbers, _issue_number)
        and _items(github.branch_names, _branch_name)
        and "main" in github.branch_names
        and not (github.initial_pr_merged and 1 in github.open_pr_numbers)
    )


def _linear_issue_valid(snapshot):
    return (
        type(snapshot) is IssueSnapshot
        and snapshot.repo == REPOSITORY
        and _issue_id(snapshot.issue)
        and _issue_number(snapshot.github_issue)
        and _hex(snapshot.revision, 64)
        and _items(snapshot.dependencies, _issue_id)
        and snapshot.issue not in snapshot.dependencies
        and type(snapshot.eligible) is bool
    )


def _approval_valid(scope):
    return (
        type(scope) is ApprovedScope
        and scope.repo == REPOSITORY
        and scope.approved_by == OWNER
        and scope.kind == "offline-software"
        and _issue_id(scope.issue)
        and _issue_number(scope.github_issue)
        and _hex(scope.revision, 64)
        and _items(scope.dependencies, _issue_id)
        and scope.issue not in scope.dependencies
        and _items(scope.allowed_paths, valid_change_path)
        and bool(scope.allowed_paths)
        and len({path.casefold() for path in scope.allowed_paths}) == len(scope.allowed_paths)
        and _hex(scope.approval_sha, 64)
        and scope_digest(scope) == scope.approval_sha
    )


def select_candidate(*, approvals, issues, done_issues, github, linear_complete):
    """Pick at most one approved, low-risk task from complete input snapshots.

    The caller supplies both source inventories from trusted providers and flags
    incomplete pagination. 'eligible' carries the pinned base but reserves nothing.
    The caller must independently recheck the remote state before claiming work.
    """
    if not _github_valid(github):
        return QueueResult("unknown", "github-evidence-unavailable")
    if not github.initial_pr_merged:
        return QueueResult("awaiting_initial_work", "initial-pr-not-merged")
    if github.open_pr_numbers:
        return QueueResult("blocked", "open-pr")
    if (
        linear_complete is not True
        or not _items(issues, _linear_issue_valid, unique=False)
        or not _items(done_issues, _issue_id)
    ):
        return QueueResult("unknown", "linear-evidence-unavailable")
    by_issue = {snapshot.issue: snapshot for snapshot in issues}
    if (
        len(by_issue) != len(issues)
        or len({snapshot.github_issue for snapshot in issues}) != len(issues)
        or any(snapshot.eligible and snapshot.issue in done_issues for snapshot in issues)
    ):
        return QueueResult("unknown", "contradictory-issue-evidence")

    if not _items(approvals, _approval_valid, unique=False):
        return QueueResult("blocked", "unverified-approval")
    if (
        len({scope.issue for scope in approvals}) != len(approvals)
        or len({scope.github_issue for scope in approvals}) != len(approvals)
    ):
        return QueueResult("blocked", "ambiguous-approval")

    branch_names = {branch.casefold() for branch in github.branch_names}
    blocked = None
    for scope in sorted(approvals, key=lambda candidate: int(candidate.issue[4:])):
        if scope.issue in done_issues:
            continue
        if scope.issue in _HELD or scope.github_issue in (1, 2, 3, 4):
            blocked = blocked or "separate-approval-required"
            continue
        task = by_issue.get(scope.issue)
        if task is None:
            return QueueResult("unknown", "approval-issue-missing")
        if not task.eligible:
            continue
        if (
            scope.github_issue != task.github_issue
            or scope.revision != task.revision
            or set(scope.dependencies) != set(task.dependencies)
        ):
            return QueueResult("blocked", "approval-scope-changed")
        if set(scope.dependencies) - set(done_issues):
            blocked = blocked or "dependencies-incomplete"
            continue
        expected = f"autodev/{scope.issue.lower()}"
        if any(
            branch == expected or expected.startswith(branch + "/") or branch.startswith(expected + "/")
            for branch in branch_names
        ):
            return QueueResult("blocked", "candidate-already-claimed")
        return QueueResult("eligible", "approved-issue-ready", scope, github.main_sha)
    if blocked:
        return QueueResult("blocked", blocked)
    return QueueResult("empty_queue", "no-eligible-approved-issue")