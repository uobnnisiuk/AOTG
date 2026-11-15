"""Read only approved AOTG issues and their blockers from the Linear API."""

import hashlib
import json
import re
from http.client import HTTPException
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .queue import REPOSITORY, ApprovedScope, IssueSnapshot

_ENDPOINT = "https://api.linear.app/graphql"
_WORKSPACE = "uobnnisiuk"
_PROJECT_SLUG_ID = "db9d5646feea"
_MAX_SCOPES = 8
_MAX_RELATIONS = 50
_MAX_RESPONSE_BYTES = 512 * 1024
_ISSUE = re.compile(r"UOB-[1-9][0-9]{0,8}")
_UUID = re.compile(r"(?!00000000-0000-0000-0000-000000000000)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_AUTHORIZATION = re.compile(r"(?:Bearer )?[A-Za-z0-9._~+/-]{16,2048}={0,2}")
_ELIGIBLE_STATES = {"backlog", "unstarted"}
_KNOWN_STATES = _ELIGIBLE_STATES | {"triage", "started", "completed", "canceled", "duplicate"}
_KNOWN_RELATIONS = {"blocks", "duplicate", "related", "similar"}

# IssueRelation.issue is the source and relatedIssue the target. Only an
# incoming blocks relation is a prerequisite for the selected task.
_QUERY = """
query AotgReadIssue($id: String!) {
  organization { id urlKey }
  issue(id: $id) {
    id identifier title description archivedAt state { type }
    project { id url }
    inverseRelations(first: 50) {
      nodes {
        type
        issue { id identifier archivedAt state { type } }
        relatedIssue { id identifier }
      }
      pageInfo { hasNextPage hasPreviousPage }
    }
  }
}
"""


class LinearReadError(ValueError):
    """An authenticated Linear observation was unavailable or incomplete."""


class _RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LinearReadError("Linear intake cannot follow redirects")


def _unique_fields(pairs):
    result = dict(pairs)
    if len(pairs) != len(result):
        raise LinearReadError("Ambiguous Linear response fields")
    return result


def _post(query, variables, authorization):
    request = Request(
        _ENDPOINT,
        data=json.dumps({"query": query, "variables": variables}).encode("utf-8"),
        headers={
            "Authorization": authorization,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AOTG-AutoDev-Linear-read",
        },
        method="POST",
    )
    try:
        opener = build_opener(ProxyHandler({}), _RejectRedirect())
        with opener.open(request, timeout=8) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise LinearReadError("Unexpected Linear HTTP response")
            data = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(data) > _MAX_RESPONSE_BYTES:
            raise LinearReadError("Linear response exceeded its size limit")
        return json.loads(data, object_pairs_hook=_unique_fields)
    except LinearReadError:
        raise
    except (OSError, HTTPException, ValueError, RecursionError):
        raise LinearReadError("Linear request could not be confirmed") from None


def _uuid(value):
    return type(value) is str and _UUID.fullmatch(value) is not None


def _identity(issue):
    if (
        type(issue) is not dict
        or not _uuid(issue.get("id"))
        or type(issue.get("identifier")) is not str
        or not _ISSUE.fullmatch(issue["identifier"])
    ):
        raise LinearReadError("Missing or invalid Linear issue identity")
    return issue["identifier"], issue["id"]


def _state(row):
    state = row.get("state")
    category = state.get("type") if type(state) is dict else None
    if (
        type(category) is not str
        or category not in _KNOWN_STATES
        or "archivedAt" not in row
        or (row["archivedAt"] is not None and not _text(row["archivedAt"], 64))
    ):
        raise LinearReadError("Missing or invalid Linear issue state")
    return category, row["archivedAt"] is not None


def _text(value, limit, *, allow_empty=False):
    if type(value) is not str or (not allow_empty and not value.strip()):
        return False
    try:
        return len(value.encode("utf-8")) <= limit and "\0" not in value
    except UnicodeError:
        return False


def _project_id(project):
    if type(project) is not dict or not _uuid(project.get("id")) or not _text(project.get("url"), 512):
        raise LinearReadError("Missing AOTG project identity")
    try:
        url = urlsplit(project["url"])
    except ValueError:
        raise LinearReadError("Invalid AOTG project identity") from None
    if (
        url.scheme != "https" or url.netloc != "linear.app" or url.query or url.fragment
        or not re.fullmatch(rf"/{_WORKSPACE}/project/[a-z0-9-]+-{_PROJECT_SLUG_ID}/?", url.path)
    ):
        raise LinearReadError("The issue is outside the AOTG project")
    return project["id"]


def _observe(row, observed):
    identity = _identity(row)
    category, archived = _state(row)
    previous = observed.setdefault(identity[0], (identity[1], category, archived))
    if previous != (identity[1], category, archived):
        raise LinearReadError("Inconsistent Linear issue snapshots")
    return identity, category, archived


def _dependencies(row, identity, observed):
    connection = row.get("inverseRelations")
    if type(connection) is not dict:
        raise LinearReadError("Missing Linear dependency snapshot")
    page = connection.get("pageInfo")
    nodes = connection.get("nodes")
    if (
        type(page) is not dict
        or page.get("hasPreviousPage") is not False
        or page.get("hasNextPage") is not False
        or type(nodes) is not list
        or len(nodes) > _MAX_RELATIONS
    ):
        raise LinearReadError("Incomplete Linear dependency snapshot")
    found = {}
    for relation in nodes:
        kind = relation.get("type") if type(relation) is dict else None
        if type(kind) is not str or kind not in _KNOWN_RELATIONS:
            raise LinearReadError("Unrecognized Linear dependency relation")
        if _identity(relation.get("relatedIssue")) != identity:
            raise LinearReadError("Linear relation points to a different issue")
        if kind != "blocks":
            continue
        (identifier, uuid), _, _ = _observe(relation.get("issue"), observed)
        if identifier == identity[0] or uuid == identity[1] or identifier in found or uuid in found.values():
            raise LinearReadError("Ambiguous Linear dependency identity")
        found[identifier] = uuid
    return tuple(sorted(found.items()))


def _revision(workspace, project, identity, title, description, dependencies):
    document = {
        "source": "linear-aotg-issue-v1",
        "workspace": workspace,
        "project": project,
        "issue": identity,
        "title": title,
        "description": description,
        "dependencies": dependencies,
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


class LinearIntake:
    """Return queue facts only. The caller supplies separately trusted approvals."""

    def __init__(self, authorization: str | None = None, *, request=None):
        # The injected request is a trusted, read-only transport for testing or a broker.
        if request is not None:
            if authorization is not None or not callable(request):
                raise LinearReadError("Provide one Linear authentication source")
            self._request = request
        else:
            if type(authorization) is not str or not _AUTHORIZATION.fullmatch(authorization):
                raise LinearReadError("An explicit Linear authorization header is required")
            self._request = lambda query, variables: _post(query, variables, authorization)

    def snapshot(self, scopes: tuple[ApprovedScope, ...]):
        """Return IssueSnapshots and completed IDs for the approved Linear scopes."""
        if (
            type(scopes) is not tuple
            or len(scopes) > _MAX_SCOPES
            or any(
                type(scope) is not ApprovedScope or scope.repo != REPOSITORY
                or type(scope.issue) is not str or not _ISSUE.fullmatch(scope.issue)
                or type(scope.github_issue) is not int or scope.github_issue < 1
                for scope in scopes
            )
            or len({scope.issue for scope in scopes}) != len(scopes)
            or len({scope.github_issue for scope in scopes}) != len(scopes)
        ):
            raise LinearReadError("Invalid or ambiguous Linear intake scope")

        issues = []
        observed = {}
        workspace_id = None
        project_id = None
        for scope in scopes:
            try:
                response = self._request(_QUERY, {"id": scope.issue})
            except Exception:
                raise LinearReadError("Linear request could not be confirmed") from None
            if type(response) is not dict or response.get("errors", []) != []:
                raise LinearReadError("Linear returned partial or unavailable issue data")
            data = response.get("data")
            if type(data) is not dict:
                raise LinearReadError("Missing Linear issue data")
            workspace = data.get("organization")
            if type(workspace) is not dict or workspace.get("urlKey") != _WORKSPACE or not _uuid(workspace.get("id")):
                raise LinearReadError("The Linear workspace could not be confirmed")
            row = data.get("issue")
            identity, category, archived = _observe(row, observed)
            project = _project_id(row.get("project"))
            if (
                identity[0] != scope.issue
                or workspace_id not in (None, workspace["id"])
                or project_id not in (None, project)
            ):
                raise LinearReadError("The selected Linear scope changed during lookup")
            workspace_id = workspace["id"]
            project_id = project
            title = row.get("title")
            description = row.get("description")
            if (
                not _text(title, 1024)
                or "description" not in row
                or (description is not None and not _text(description, 64 * 1024, allow_empty=True))
            ):
                raise LinearReadError("Linear issue content is missing or exceeds limits")
            dependencies = _dependencies(row, identity, observed)
            revision = _revision(workspace_id, project_id, identity, title, description, dependencies)
            issues.append(IssueSnapshot(
                scope.issue, scope.github_issue, revision,
                tuple(identifier for identifier, _ in dependencies),
                not archived and category in _ELIGIBLE_STATES,
            ))

        done = tuple(sorted(identifier for identifier, (_, state, archived) in observed.items()
                            if state == "completed" and not archived))
        return tuple(issues), done
