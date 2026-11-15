"""Bounded public reads for the AOTG GitHub inventory."""

import json
import re
from datetime import datetime
from http.client import HTTPException
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .queue import REPOSITORY, GitHubSnapshot

_API = "https://api.github.com"
_REPO = f"/repos/{REPOSITORY}"
_PAGE_SIZE = 100
_MAX_PAGES = 4
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_GIT_SHA = re.compile(r"(?!0{40})[0-9a-f]{40}")
_LINK = re.compile(r'<([^<>]+)>;\s*rel="([a-z]+)"')


class GitHubReadError(ValueError):
    """The official public inventory could not be confirmed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GitHubReadError("A GitHub inventory request was redirected")


def _next_page(link_header, request_path):
    if not link_header:
        return False
    next_link = None
    for entry in link_header.split(","):
        match = _LINK.fullmatch(entry.strip())
        if not match:
            raise GitHubReadError("Malformed GitHub pagination metadata")
        if match[2] == "next":
            if next_link is not None:
                raise GitHubReadError("Ambiguous GitHub pagination metadata")
            next_link = match[1]
    if next_link is None:
        return False

    requested = urlsplit(request_path)
    next_url = urlsplit(next_link)
    query = dict(parse_qsl(requested.query, strict_parsing=True))
    if "page" not in query:
        raise GitHubReadError("Unexpected pagination for a single GitHub item")
    query["page"] = str(int(query["page"]) + 1)
    next_pairs = parse_qsl(next_url.query, strict_parsing=True)
    if (
        next_url.scheme != "https"
        or next_url.netloc != "api.github.com"
        or next_url.path != requested.path
        or next_url.fragment
        or len(next_pairs) != len(query)
        or dict(next_pairs) != query
    ):
        raise GitHubReadError("Unexpected next page for the GitHub inventory")
    # The caller computes the next path. The header is never used as a destination.
    return True


def _get_json(path):
    request = Request(
        _API + path,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AOTG-AutoDev-public-inventory",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        with opener.open(request, timeout=5) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise GitHubReadError("Unexpected GitHub inventory response")
            content = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(content) > _MAX_RESPONSE_BYTES:
                raise GitHubReadError("GitHub inventory response exceeded its limit")
            header = ",".join(response.headers.get_all("Link", ()))
            return json.loads(content), _next_page(header, path)
    except GitHubReadError:
        raise
    except (OSError, HTTPException, ValueError, RecursionError) as exc:
        raise GitHubReadError("Could not read the public GitHub inventory") from exc


def _commit_sha(branch):
    commit = branch.get("commit") if type(branch) is dict else None
    sha = commit.get("sha") if type(commit) is dict else None
    if not isinstance(sha, str) or not _GIT_SHA.fullmatch(sha):
        raise GitHubReadError("Missing or invalid GitHub commit SHA")
    return sha


def _branch_name(branch):
    name = branch.get("name") if type(branch) is dict else None
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 1024
        or any(ord(char) <= 32 or ord(char) == 127 for char in name)
    ):
        raise GitHubReadError("Missing or invalid GitHub branch name")
    return name


def _open_pr_number(pr):
    if type(pr) is dict:
        number = pr.get("number")
        if type(number) is int and number > 0 and pr.get("state") == "open":
            if type(pr.get("draft")) is bool:
                return number
    raise GitHubReadError("Malformed open GitHub pull request")


def _merge_timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        return datetime.fromisoformat(value).utcoffset() is not None
    except ValueError:
        return False


def _base_is_main(pr):
    base = pr.get("base") if type(pr) is dict else None
    if type(base) is not dict or base.get("ref") != "main":
        return False
    repo = base.get("repo")
    return type(repo) is dict and repo.get("full_name") == REPOSITORY


class PublicGitHubInventory:
    """Read public GitHub state without credentials or write operations.

    An injectable transport receives a pinned API path and returns the decoded
    JSON plus a boolean identifying a verified next page.
    """

    def __init__(self, get_json=None):
        self._get = _get_json if get_json is None else get_json

    def _read(self, suffix):
        response = self._get(_REPO + suffix)
        if type(response) is not tuple or len(response) != 2 or type(response[1]) is not bool:
            raise GitHubReadError("Invalid public GitHub read result")
        return response

    def _item(self, suffix):
        data, has_next = self._read(suffix)
        if has_next or type(data) is not dict:
            raise GitHubReadError("Incomplete GitHub item response")
        return data

    def _all(self, suffix, **filters):
        rows = []
        for page in range(1, _MAX_PAGES + 1):
            query = urlencode({**filters, "per_page": _PAGE_SIZE, "page": page})
            data, has_next = self._read(f"{suffix}?{query}")
            if type(data) is not list or len(data) > _PAGE_SIZE:
                raise GitHubReadError("Invalid paginated GitHub response")
            if has_next and len(data) != _PAGE_SIZE:
                raise GitHubReadError("Incomplete GitHub page")
            rows.extend(data)
            if not has_next:
                return rows
        raise GitHubReadError("Public GitHub inventory exceeded its page limit")

    def _main(self):
        branch = self._item("/branches/main")
        if _branch_name(branch) != "main":
            raise GitHubReadError("Unexpected default branch response")
        return _commit_sha(branch)

    def _initial(self):
        pr = self._item("/pulls/1")
        state, merged = pr.get("state"), pr.get("merged")
        if (
            type(pr.get("number")) is not int
            or pr.get("number") != 1
            or not _base_is_main(pr)
            or state not in ("open", "closed")
            or type(merged) is not bool
            or (merged and state != "closed")
        ):
            raise GitHubReadError("Initial pull request state is unconfirmed")
        merge_sha = pr.get("merge_commit_sha")
        if merged and (
            not isinstance(merge_sha, str) or not _GIT_SHA.fullmatch(merge_sha)
            or not _merge_timestamp(pr.get("merged_at"))
        ):
            raise GitHubReadError("Initial pull request merge evidence is incomplete")
        return state, merged, merge_sha if merged else None

    def _open_prs(self):
        numbers = tuple(sorted(_open_pr_number(pr) for pr in self._all("/pulls", state="open")))
        if len(set(numbers)) != len(numbers):
            raise GitHubReadError("Inconsistent open pull request inventory")
        return numbers

    def snapshot(self):
        main_sha = self._main()
        initial = self._initial()
        open_prs = self._open_prs()
        if (1 in open_prs) != (initial[0] == "open"):
            raise GitHubReadError("Inconsistent open pull request inventory")

        branches = {}
        for branch in self._all("/branches"):
            name = _branch_name(branch)
            if name in branches:
                raise GitHubReadError("Duplicate branch in GitHub inventory")
            branches[name] = _commit_sha(branch)
        if (
            branches.get("main") != main_sha
            or self._open_prs() != open_prs
            or self._main() != main_sha
            or self._initial() != initial
        ):
            raise GitHubReadError("GitHub state changed while collecting the inventory")

        return GitHubSnapshot(
            main_sha=main_sha,
            open_pr_numbers=open_prs,
            branch_names=tuple(sorted(branches)),
            complete=True,
            initial_pr_merged=initial[1],
        )