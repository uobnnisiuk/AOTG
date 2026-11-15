"""Authenticated GitHub operations for the pinned AOTG repository."""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from time import monotonic

from .coordinator import Candidate, Draft
from .github_read import GitHubReadError, PublicGitHubInventory, _next_page
from .queue import OWNER, REPOSITORY, ApprovedScope, _approval_valid, valid_change_path
from .remote_results import (
    BOOTSTRAP_BODY,
    CommentObservation,
    CommentTarget,
    _body,
    _valid_target,
)

_API_REPO = f"https://api.github.com/repos/{REPOSITORY}"
_REPO = f"/repos/{REPOSITORY}"
_BRANCH = re.compile(r"autodev/uob-[1-9][0-9]{0,8}")
_SHA = re.compile(r"(?!0{40})[0-9a-f]{40}")
_MAX_PAYLOAD = 8192
_MAX_RESPONSE = 4 * 1024 * 1024
_TIMEOUT = 12
_INVENTORY_PATH = re.compile(
    r"/(?:branches/main|pulls/1|branches\?per_page=100&page=[1-4]|"
    r"pulls\?state=open&per_page=100&page=[1-4])"
)


class GitHubRuntimeError(ValueError):
    """A remote read or write could not be verified."""


@dataclass(frozen=True)
class GitHubIssue:
    number: int
    author: str
    state: str
    updated_at: str


def _sha(value):
    return type(value) is str and _SHA.fullmatch(value)


def _number(value):
    return type(value) is int and 1 <= value <= 2_147_483_647


def _branch(value):
    return type(value) is str and _BRANCH.fullmatch(value)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate remote field")
        result[key] = value
    return result


def _response(raw):
    if type(raw) is not bytes or len(raw) > _MAX_RESPONSE:
        raise GitHubRuntimeError("GitHub response exceeded its bound")
    header, sep, payload = raw.replace(b"\r\n", b"\n").partition(b"\n\n")
    if not sep or len(header) > 16384:
        raise GitHubRuntimeError("Missing GitHub response headers")
    status, *fields = header.split(b"\n")
    match = re.fullmatch(rb"HTTP/[12](?:\.[01])? ([0-9]{3})(?: [^\r\n]*)?", status)
    if not match:
        raise GitHubRuntimeError("Invalid GitHub response status")
    links = []
    content_types = []
    for field in fields:
        key, delimiter, value = field.partition(b":")
        if not delimiter or not re.fullmatch(rb"[A-Za-z0-9-]+", key):
            raise GitHubRuntimeError("Invalid GitHub response header")
        if key.lower() == b"link":
            links.append(value.strip().decode("ascii"))
        elif key.lower() == b"content-type":
            content_types.append(value.strip().split(b";", 1)[0].lower())
    if content_types != [b"application/json"]:
        raise GitHubRuntimeError("GitHub response was not JSON")
    return int(match[1]), ",".join(links), json.loads(payload, object_pairs_hook=_unique)


def _run_gh(argv, payload, *, cwd, env):
    """Read bounded output and keep the CLI response out of logs."""
    deadline = monotonic() + _TIMEOUT
    with tempfile.TemporaryFile() as stdin:
        if payload is not None:
            stdin.write(payload)
            stdin.seek(0)
        with subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False,
        ) as proc:
            output = []

            def drain():
                try:
                    output.append(proc.stdout.read(_MAX_RESPONSE + 1))
                except OSError:
                    pass

            reader = Thread(target=drain, daemon=True)
            reader.start()
            reader.join(max(0, deadline - monotonic()))
            try:
                if reader.is_alive() or not output or len(output[0]) > _MAX_RESPONSE:
                    raise GitHubRuntimeError("GitHub CLI output could not be read within bounds")
                if proc.wait(timeout=max(0, deadline - monotonic())) != 0:
                    raise GitHubRuntimeError("GitHub CLI operation was not confirmed")
                return output[0]
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


class GitHubRuntime:
    """Run fixed GitHub API operations outside the generated worker environment."""

    def __init__(self, gh_executable, *, run=None, config_dir=None):
        executable = Path(gh_executable)
        if not executable.is_absolute() or executable.name.lower() not in ("gh", "gh.exe"):
            raise GitHubRuntimeError("A trusted absolute GitHub CLI executable is required")
        self.executable = os.fspath(executable)
        self.cwd = executable.parent
        # Use existing GH authentication, not arbitrary inherited token or debug settings.
        names = (
            "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
            "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
        )
        self.env = {key: os.environ[key] for key in names if key in os.environ}
        self.env.update(GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1", NO_COLOR="1")
        if config_dir is not None:
            config = Path(config_dir)
            if not config.is_absolute():
                raise GitHubRuntimeError("GitHub configuration must be a trusted absolute path")
            self.env["GH_CONFIG_DIR"] = os.fspath(config)
        self.run = _run_gh if run is None else run

    def _call(self, method, path, body=None, *, status=200):
        argv = [
            self.executable, "api", "--hostname", "github.com", "--method", method,
            "--include", "-H", "Accept: application/vnd.github+json", "-H",
            "X-GitHub-Api-Version: 2022-11-28", path,
        ]
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            if len(payload) > _MAX_PAYLOAD:
                raise GitHubRuntimeError("GitHub request exceeded its bound")
            argv += ["--input", "-"]
        try:
            received_status, link, data = _response(
                self.run(tuple(argv), payload, cwd=self.cwd, env=dict(self.env))
            )
            if received_status != status:
                raise GitHubRuntimeError("GitHub rejected the requested operation")
            return data, _next_page(link, path)
        except GitHubRuntimeError:
            raise
        except (OSError, ValueError, RecursionError, subprocess.SubprocessError) as exc:
            raise GitHubRuntimeError("GitHub operation was not confirmed") from exc

    def _item(self, path):
        item, next_page = self._call("GET", path)
        if next_page or type(item) is not dict:
            raise GitHubRuntimeError("GitHub item response was incomplete")
        return item

    def get_json(self, path):
        """Supply a pinned paginated reader to PublicGitHubInventory."""
        if not path.startswith(_REPO) or not _INVENTORY_PATH.fullmatch(path[len(_REPO):]):
            raise GitHubRuntimeError("Unexpected GitHub inventory request")
        return self._call("GET", path)

    def snapshot(self):
        try:
            return PublicGitHubInventory(self.get_json).snapshot()
        except GitHubReadError as exc:
            raise GitHubRuntimeError("GitHub inventory was not verified") from exc

    def read_issue(self, number):
        """Report a known owner-authored issue without trusting its free-form text."""
        if not _number(number) or number <= 4:
            raise GitHubRuntimeError("A scoped GitHub issue number is required")
        item = self._item(f"{_REPO}/issues/{number}")
        author = item.get("user")
        updated = item.get("updated_at")
        if (
            type(item.get("number")) is not int or item["number"] != number
            or item.get("repository_url") != _API_REPO or "pull_request" in item
            or type(author) is not dict or author.get("login") != OWNER
            or item.get("author_association") != "OWNER"
            or item.get("state") not in ("open", "closed")
            or not isinstance(updated, str)
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", updated)
        ):
            raise GitHubRuntimeError("GitHub issue ownership or identity was not verified")
        return GitHubIssue(number, OWNER, item["state"], updated)

    def _check_write_identity(self):
        repo = self._item(_REPO)
        if (repo.get("full_name") != REPOSITORY or repo.get("default_branch") != "main"
                or repo.get("private") is not False or self._item("/user").get("login") != OWNER):
            raise GitHubRuntimeError("The GitHub CLI account is not the expected owner")

    def branch_head(self, branch):
        if not _branch(branch):
            raise GitHubRuntimeError("A scoped reservation branch is required")
        ref = f"refs/heads/{branch}"
        items, next_page = self._call("GET", f"{_REPO}/git/matching-refs/heads/{branch}")
        if next_page or type(items) is not list or len(items) > 100:
            raise GitHubRuntimeError("Branch response was incomplete")
        if not items:
            return None
        if len(items) != 1 or type(items[0]) is not dict or items[0].get("ref") != ref:
            raise GitHubRuntimeError("Ambiguous branch response")
        obj = items[0].get("object")
        if type(obj) is not dict or obj.get("type") != "commit" or not _sha(obj.get("sha")):
            raise GitHubRuntimeError("Branch target was not verified")
        return obj["sha"]

    def reserve_branch(self, branch, base):
        """Create a new reservation ref, with no ref update or retry."""
        if not _branch(branch) or not _sha(base):
            raise GitHubRuntimeError("Invalid GitHub reservation")
        self._check_write_identity()
        inventory = self.snapshot()
        if (not inventory.initial_pr_merged or inventory.open_pr_numbers
                or inventory.main_sha != base or self.branch_head(branch) is not None):
            raise GitHubRuntimeError("GitHub reservation preconditions changed")
        ref = f"refs/heads/{branch}"
        item, next_page = self._call(
            "POST", f"{_REPO}/git/refs", {"ref": ref, "sha": base}, status=201,
        )
        if next_page or type(item) is not dict or item.get("ref") != ref:
            raise GitHubRuntimeError("GitHub reservation result was unconfirmed")
        if self.branch_head(branch) != base:
            raise GitHubRuntimeError("GitHub reservation read-back did not match")

    def _check_commit(self, scope, candidate):
        if (
            type(scope) is not ApprovedScope or not _approval_valid(scope) or type(candidate) is not Candidate
            or scope.repo != REPOSITORY or scope.approved_by != OWNER
            or scope.kind != "offline-software" or not isinstance(scope.issue, str)
            or not _branch(f"autodev/{scope.issue.lower()}")
            or not _sha(candidate.head) or not _sha(candidate.base)
            or candidate.head == candidate.base or candidate.local_checks_passed is not True
            or type(candidate.paths) is not tuple or not 1 <= len(candidate.paths) <= 100
            or any(not valid_change_path(p) or p not in scope.allowed_paths for p in candidate.paths)
            or len({p.casefold() for p in candidate.paths}) != len(candidate.paths)
        ):
            raise GitHubRuntimeError("Candidate publication requires verified scope and checks")
        item, next_page = self._call("GET", f"{_REPO}/commits/{candidate.head}?per_page=100&page=1")
        parents = item.get("parents") if type(item) is dict else None
        files = item.get("files") if type(item) is dict else None
        if (next_page or type(parents) is not list or len(parents) != 1
                or type(parents[0]) is not dict or parents[0].get("sha") != candidate.base
                or item.get("sha") != candidate.head or type(files) is not list
                or len(files) != len(candidate.paths)):
            raise GitHubRuntimeError("GitHub candidate commit was incomplete or changed")
        paths = []
        for change in files:
            if (
                type(change) is not dict or change.get("status") not in ("added", "modified", "removed")
                or not valid_change_path(change.get("filename")) or "previous_filename" in change
            ):
                raise GitHubRuntimeError("Unexpected GitHub candidate file change")
            paths.append(change["filename"])
        if sorted(paths) != sorted(candidate.paths):
            raise GitHubRuntimeError("GitHub candidate paths did not match the verified scope")

    def publish_draft(self, scope, candidate):
        """Open a Draft for a commit already published by a separate trusted boundary.

        Coordinator's GitHubPort needs a wrapper to publish the verified commit
        to the reserved base before calling this exact-head operation.
        """
        self._check_commit(scope, candidate)
        self._check_write_identity()
        if self.read_issue(scope.github_issue).state != "open":
            raise GitHubRuntimeError("The candidate GitHub issue is no longer open")
        branch = f"autodev/{scope.issue.lower()}"
        inventory = self.snapshot()
        if (not inventory.initial_pr_merged or inventory.open_pr_numbers
                or inventory.main_sha != candidate.base or self.branch_head(branch) != candidate.head):
            raise GitHubRuntimeError("Draft publication preconditions changed")
        issue = f"{REPOSITORY}#{scope.github_issue}"
        item, next_page = self._call("POST", f"{_REPO}/pulls", {
            "base": "main", "draft": True, "head": branch,
            "title": f"{scope.issue} offline software candidate",
            "body": f"AOTG-AUTODEV-V1 candidate for {scope.issue} ({issue}).",
        }, status=201)
        number = item.get("number") if type(item) is dict else None
        if next_page or not _number(number):
            raise GitHubRuntimeError("GitHub Draft result was unconfirmed")
        if self.read_draft(number) != Draft(number, branch, candidate.base, candidate.head, True):
            raise GitHubRuntimeError("GitHub Draft read-back did not match")
        return number

    def read_draft(self, number):
        if not _number(number):
            raise GitHubRuntimeError("A pull request number is required")
        item = self._item(f"{_REPO}/pulls/{number}")
        head, base = item.get("head"), item.get("base")
        if (type(item.get("number")) is not int or item["number"] != number
                or item.get("state") != "open" or type(item.get("draft")) is not bool
                or type(head) is not dict or type(base) is not dict):
            raise GitHubRuntimeError("Draft identity could not be verified")
        for endpoint in (head, base):
            repo = endpoint.get("repo")
            if type(repo) is not dict or repo.get("full_name") != REPOSITORY or not _sha(endpoint.get("sha")):
                raise GitHubRuntimeError("Draft repository or commit did not match")
        if not _branch(head.get("ref")) or base.get("ref") != "main":
            raise GitHubRuntimeError("Unexpected Draft branch pair")
        return Draft(number, head["ref"], base["sha"], head["sha"], item["draft"])

    def read_result_comment(self, comment_id):
        if not (
            type(comment_id) is int and 1 <= comment_id <= (1 << 53) - 1
        ):
            raise GitHubRuntimeError("A GitHub comment ID is required")
        item = self._item(f"{_REPO}/issues/comments/{comment_id}")
        if (type(item.get("id")) is not int or item["id"] != comment_id
                or item.get("issue_url") != f"{_API_REPO}/issues/3"):
            raise GitHubRuntimeError("GitHub comment is not the pinned AOTG issue result")
        return item

    def update_result_comment(self, comment_id, body, *, expected_body, author_id):
        """Patch only the pinned issue's owned comment after an exact read-back."""
        if body == BOOTSTRAP_BODY or not (_is_result_body(body) and _is_result_body(expected_body)) or not (
            type(author_id) is int and 1 <= author_id <= (1 << 53) - 1
        ):
            raise GitHubRuntimeError("Verified result contents and author are required")
        self._check_write_identity()
        observed = self.read_result_comment(comment_id)
        author = observed.get("user")
        if (type(author) is not dict or type(author.get("id")) is not int
                or author["id"] != author_id or author.get("login") != OWNER
                or observed.get("body") != expected_body):
            raise GitHubRuntimeError("GitHub result comment changed or has a different author")
        self._call("PATCH", f"{_REPO}/issues/comments/{comment_id}", {"body": body})
        after = self.read_result_comment(comment_id)
        if after.get("body") != body or after.get("user", {}).get("id") != author_id:
            raise GitHubRuntimeError("GitHub result comment read-back did not match")

def _is_result_body(body):
    prefix = BOOTSTRAP_BODY + "\n\n```json\n"
    if body == BOOTSTRAP_BODY:
        return True
    if not isinstance(body, str) or not body.startswith(prefix) or len(body) > _MAX_PAYLOAD:
        return False
    try:
        value = json.loads(body[len(prefix):-3], object_pairs_hook=_unique)
        return _body(value) == body
    except (ValueError, TypeError, RecursionError):
        return False


class GitHubResultComments:
    """GitHub half of the dedicated remote receipt transport."""

    def __init__(self, runtime: GitHubRuntime):
        self.runtime = runtime

    def read(self, target: CommentTarget) -> CommentObservation:
        if not _valid_target(target, "github"):
            raise GitHubRuntimeError("GitHub receipt target was not verified")
        item = self.runtime.read_result_comment(target.comment_id)
        author = item.get("user")
        body = item.get("body")
        if (type(author) is not dict or type(author.get("id")) is not int
                or author["id"] != target.author_id or author.get("login") != OWNER
                or not _is_result_body(body)):
            raise GitHubRuntimeError("Unexpected GitHub receipt author or body")
        return CommentObservation(target, body)

    def update(self, target: CommentTarget, body: str, *, expected_body: str) -> None:
        if not _valid_target(target, "github"):
            raise GitHubRuntimeError("GitHub receipt target was not verified")
        self.runtime.update_result_comment(
            target.comment_id, body, expected_body=expected_body, author_id=target.author_id,
        )
