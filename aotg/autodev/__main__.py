"""Read and test the configured AOTG queue without consuming an attempt."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .github_read import GitHubReadError, PublicGitHubInventory
from .github_runtime import GitHubRuntime
from .ledger import Ledger, LedgerError, ReservationBlocked
from .linear_read import LinearIntake, LinearReadError
from .queue import OWNER, select_candidate
from .runtime_config import ConfigError, load_approvals, load_linear_authorization


def shadow(args):
    try:
        github = GitHubRuntime(args.github_cli) if args.github_cli else PublicGitHubInventory()
        remote = github.snapshot()
    except (GitHubReadError, OSError, ValueError, RuntimeError):
        return {"status": "unknown", "reason": "github-evidence-unavailable"}
    result = {"base": remote.main_sha}
    if not remote.initial_pr_merged:
        return dict(result, status="awaiting_initial_work", reason="initial-pr-not-merged")
    if remote.open_pr_numbers:
        return dict(result, status="blocked", reason="open-pr")
    if args.approvals is None:
        return dict(result, status="blocked", reason="trusted-linear-approval-source-not-configured")
    try:
        approvals = load_approvals(args.approvals)
    except ConfigError:
        return dict(result, status="unknown", reason="private-configuration-unavailable")
    if not approvals:
        return dict(result, status="empty_queue", reason="no-eligible-approved-issue")
    if not (args.github_cli and args.linear_authorization and args.ledger):
        return dict(result, status="blocked", reason="deployment-gate")
    closed = set()
    try:
        for approval in approvals:
            match = github.read_issue(approval.github_issue)
            if match.number != approval.github_issue or match.author != OWNER or match.state not in {"open", "closed"}:
                return dict(result, status="blocked", reason="unverified-github-issue")
            if match.state == "closed":
                closed.add(approval.issue)
    except (GitHubReadError, OSError, ValueError, RuntimeError):
        return dict(result, status="unknown", reason="github-evidence-unavailable")
    try:
        auth = load_linear_authorization(args.linear_authorization)
        issues, done = LinearIntake(auth).snapshot(approvals)
    except (ConfigError, LinearReadError):
        return dict(result, status="unknown", reason="linear-evidence-unavailable")
    if closed.difference(done):
        return dict(result, status="blocked", reason="unverified-github-issue")
    selection = select_candidate(
        approvals=approvals, issues=issues, done_issues=done, github=remote, linear_complete=True,
    )
    if selection.status != "eligible":
        return dict(result, status=selection.status, reason=selection.reason)
    result["issue"] = selection.scope.issue
    try:
        Ledger(args.ledger).check(selection.scope.issue, datetime.now(timezone.utc))
    except ReservationBlocked as exc:
        return dict(result, status="blocked", reason=exc.reason)
    except LedgerError:
        return dict(result, status="unknown", reason="ledger-unavailable")
    return dict(result, status="blocked", reason="shadow-eligible")


def main():
    parser = argparse.ArgumentParser(description="Check the AOTG queue without taking an attempt")
    parser.add_argument("command", choices=("shadow",))
    parser.add_argument("--approvals", type=Path, help="Owner-controlled scope registry")
    parser.add_argument("--github-cli", type=Path, help="Pinned authenticated GitHub CLI")
    parser.add_argument("--linear-authorization", type=Path, help="Private Linear header file")
    parser.add_argument("--ledger", type=Path, help="Dedicated AOTG ledger directory")
    result = shadow(parser.parse_args())
    print(json.dumps(result, sort_keys=True))
    return 2 if result["status"] == "unknown" else 0


if __name__ == "__main__":
    raise SystemExit(main())
