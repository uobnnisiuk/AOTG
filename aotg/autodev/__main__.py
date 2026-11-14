"""Read-only checks for a local deployment or the public AOTG repository."""

import argparse
import json

from .github_read import GitHubReadError, PublicGitHubInventory


def main():
    parser = argparse.ArgumentParser(description="Check the public AOTG queue gate without making changes")
    parser.add_argument("command", choices=("shadow",))
    parser.parse_args()
    try:
        remote = PublicGitHubInventory().snapshot()
    except (GitHubReadError, OSError, ValueError):
        result = {"status": "unknown", "reason": "github-evidence-unavailable"}
    else:
        result = {"base": remote.main_sha}
        if not remote.initial_pr_merged:
            result.update(status="awaiting_initial_work", reason="initial-pr-not-merged")
        elif remote.open_pr_numbers:
            result.update(status="blocked", reason="open-pr")
        else:
            result.update(status="blocked", reason="trusted-linear-approval-source-not-configured")
    print(json.dumps(result, sort_keys=True))
    return 2 if result["status"] == "unknown" else 0


if __name__ == "__main__":
    raise SystemExit(main())
