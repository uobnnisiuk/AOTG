"""Check dedicated AOTG receipt read access and report fixed public booleans."""

import argparse
import json
import os
from dataclasses import dataclass
from http.client import HTTPException, HTTPSConnection
from pathlib import Path

from aotg.artifacts import _unique_object

from .auth_import import _LINEAR_TOKEN, _github_hosts
from .github_runtime import _is_result_body
from .ledger import _validate_path
from .linear_read import _uuid
from .pilot_installation import _receipt_targets
from .queue import OWNER, REPOSITORY
from .receipt_transport import _QUERY as _LINEAR_RECEIPT_QUERY
from .receipt_transport import LinearResultComments
from .remote_results import _valid_target
from .runtime_config import _private_bytes, load_linear_authorization

_GITHUB = "api.github.com"
_LINEAR = "api.linear.app"
_GITHUB_ISSUE = f"https://{_GITHUB}/repos/{REPOSITORY}/issues/3"
_LINEAR_TEAM = "UOB"
# GraphQL merges this extra selection under the same issue. Use the existing
# receipt adapter to validate its fixed workspace, project, identity and body.
_LINEAR_QUERY_WITH_TEAM = _LINEAR_RECEIPT_QUERY.replace(
    "comment(id: $id) {", "comment(id: $id) { issue { team { id key } }", 1,
)
_TRANSPORT_TIMEOUT = 5
_RESPONSE_LIMIT = 16 * 1024
_ERRORS = (OSError, ValueError, TypeError, RuntimeError, HTTPException)


@dataclass(frozen=True, slots=True)
class AuthVerification:
    """Verified dedicated read access to the fixed receipt targets."""

    github_read: bool = False
    linear_read: bool = False


def _private_config(root):
    if os.name != "posix" or not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
        raise ValueError("A private WSL installation root is required")
    for parent in reversed(root.parents):
        _validate_path(parent, directory=True, private=False)
    config = root / "config"
    _validate_path(root, directory=True)
    _validate_path(config, directory=True)
    return config


def _github_token(config):
    payload = _private_bytes(config / "hosts.yml", 4096)
    _, marker, value = payload.partition(b"\n    oauth_token: ")
    if not marker:
        raise ValueError("The dedicated GitHub authorization could not be verified")
    token = value.split(b"\n", 1)[0].decode("ascii")
    if _github_hosts(token) != payload:
        raise ValueError("The dedicated GitHub authorization could not be verified")
    return token


def _json_response(host, path, method, authorization, *, request=None):
    """Use direct HTTPS without a redirect or proxy handler."""
    headers = {
        "Accept": "application/json",
        "Authorization": authorization,
        "User-Agent": "AOTG-AutoDev-read-verification",
    }
    if host == _GITHUB:
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        headers["Accept"] = "application/vnd.github+json"
    if request is not None:
        headers["Content-Type"] = "application/json"
    connection = HTTPSConnection(host, timeout=_TRANSPORT_TIMEOUT)
    try:
        connection.request(method, path, body=request, headers=headers)
        with connection.getresponse() as response:
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower().strip()
            if response.status != 200 or content_type not in {"application/json", "application/vnd.github+json"}:
                raise ValueError("The receipt read was not confirmed")
            content = response.read(_RESPONSE_LIMIT + 1)
        if len(content) > _RESPONSE_LIMIT:
            raise ValueError("The receipt read exceeded its size bound")
        payload = json.loads(content, object_pairs_hook=_unique_object)
        if type(payload) is not dict:
            raise ValueError("The receipt read returned unexpected data")
        return payload
    finally:
        connection.close()


def _read_github(config, target):
    if not _valid_target(target, "github") or target.comment_id > (1 << 53) - 1:
        return False
    authorization = "Bearer " + _github_token(config)
    user = _json_response(_GITHUB, "/user", "GET", authorization)
    if user.get("login") != OWNER or type(user.get("id")) is not int or user["id"] != target.author_id:
        return False
    comment = _json_response(
        _GITHUB, f"/repos/{REPOSITORY}/issues/comments/{target.comment_id}", "GET", authorization,
    )
    author = comment.get("user")
    return (
        type(comment.get("id")) is int and comment["id"] == target.comment_id
        and comment.get("issue_url") == _GITHUB_ISSUE
        and type(author) is dict and author.get("login") == OWNER
        and type(author.get("id")) is int and author["id"] == target.author_id
        and _is_result_body(comment.get("body"))
    )


def _read_linear(config, target):
    if not _valid_target(target, "linear"):
        return False
    authorization = load_linear_authorization(config / "linear-authorization")
    if not _LINEAR_TOKEN.fullmatch(authorization):
        return False

    def request(query, variables):
        if query != _LINEAR_RECEIPT_QUERY or variables != {"id": target.comment_id}:
            raise ValueError("Only the configured Linear receipt read is permitted")
        body = json.dumps(
            {"query": _LINEAR_QUERY_WITH_TEAM, "variables": variables}, ensure_ascii=True,
        ).encode("ascii")
        result = _json_response(_LINEAR, "/graphql", "POST", authorization, request=body)
        data = result.get("data")
        comment = data.get("comment") if type(data) is dict else None
        issue = comment.get("issue") if type(comment) is dict else None
        team = issue.get("team") if type(issue) is dict else None
        if type(team) is not dict or not _uuid(team.get("id")) or team.get("key") != _LINEAR_TEAM:
            raise ValueError("The Linear receipt team did not match")
        return result

    return LinearResultComments(request=request).read(target).target == target


def verify_dedicated_auth(root: Path) -> AuthVerification:
    """Verify only project receipt reads with dedicated local authentication."""
    try:
        config = _private_config(root)
        github_target, linear_target = _receipt_targets(config / "receipt-targets.json")
    except _ERRORS:
        return AuthVerification()
    try:
        github_read = _read_github(config / "github", github_target)
    except _ERRORS:
        github_read = False
    try:
        linear_read = _read_linear(config, linear_target)
    except _ERRORS:
        linear_read = False
    return AuthVerification(github_read, linear_read)


class _Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("Unverified arguments")


def main(argv=None):
    parser = _Arguments(prog="aotg-auth-verify", allow_abbrev=False)
    parser.add_argument("--root", required=True, type=Path)
    try:
        args = parser.parse_args(argv)
    except ValueError:
        result = AuthVerification()
    else:
        result = verify_dedicated_auth(args.root)
    print(json.dumps({"github_read": result.github_read, "linear_read": result.linear_read},
                     separators=(",", ":")))
    return 0 if result.github_read and result.linear_read else 1


if __name__ == "__main__":
    raise SystemExit(main())
