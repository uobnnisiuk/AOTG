"""Authenticated receipt adapters for the two provisioned AutoDev comments."""

from .github_runtime import _is_result_body
from .linear_read import (
    _AUTHORIZATION,
    _WORKSPACE,
    LinearReadError,
    _post,
    _project_id,
    _uuid,
)
from .remote_results import (
    BOOTSTRAP_BODY,
    CommentObservation,
    CommentTarget,
    _valid_target,
)
from .result_slot import ResultSlotError

_COMMENT_FIELDS = """
  id body archivedAt parentId quotedText
  externalThread { __typename }
  issue { id identifier archivedAt project { id url } }
  user { id }
"""

_QUERY = (
    """
    query AotgReadResult($id: String!) {
      organization { id urlKey }
      viewer { id }
      comment(id: $id) {
    """
    + _COMMENT_FIELDS
    + """
      }
    }
    """
)

_MUTATION = (
    """
    mutation AotgUpdateResult($id: String!, $input: CommentUpdateInput!) {
      commentUpdate(id: $id, input: $input) {
        success
        comment {
    """
    + _COMMENT_FIELDS
    + """
        }
      }
    }
    """
)


def _verify_contents(body, expected_body):
    if (
        type(body) is not str or body == BOOTSTRAP_BODY or not _is_result_body(body)
        or type(expected_body) is not str or not _is_result_body(expected_body)
    ):
        raise ResultSlotError("Only a canonical AutoDev receipt can replace a verified slot")


def _linear_comment(target, item):
    if (
        type(item) is not dict or item.get("id") != target.comment_id
        or any(field not in item or item[field] is not None
               for field in ("archivedAt", "parentId", "quotedText", "externalThread"))
    ):
        raise ResultSlotError("The Linear receipt is not the configured active top-level comment")
    issue, user, body = item.get("issue"), item.get("user"), item.get("body")
    if (
        type(issue) is not dict or issue.get("id") != target.issue_id
        or issue.get("identifier") != target.issue
        or "archivedAt" not in issue or issue["archivedAt"] is not None
        or type(user) is not dict or user.get("id") != target.author_id
        or type(body) is not str or not _is_result_body(body)
    ):
        raise ResultSlotError("The Linear receipt issue, author or contents do not match")
    try:
        _project_id(issue.get("project"))
    except LinearReadError:
        raise ResultSlotError("The Linear receipt is outside the AOTG project") from None
    actual = CommentTarget("linear", issue["identifier"], issue["id"], item["id"], user["id"])
    if not _valid_target(actual, "linear") or actual != target:
        raise ResultSlotError("The Linear receipt identity was not verified")
    return CommentObservation(actual, body)


class LinearResultComments:
    """Read and update only the configured author-owned UOB-58 receipt comment."""

    def __init__(self, authorization: str | None = None, *, request=None):
        if request is not None:
            if authorization is not None or not callable(request):
                raise ResultSlotError("Provide one Linear receipt authentication source")
            self._request = request
        else:
            if type(authorization) is not str or not _AUTHORIZATION.fullmatch(authorization):
                raise ResultSlotError("An explicit Linear authorization header is required")
            self._request = lambda query, variables: _post(query, variables, authorization)

    def _data(self, query, variables):
        try:
            response = self._request(query, variables)
        except Exception:
            raise ResultSlotError("Linear receipt request could not be confirmed") from None
        if (
            type(response) is not dict or response.get("errors", []) != []
            or type(response.get("data")) is not dict
        ):
            raise ResultSlotError("Linear returned partial or unavailable receipt data")
        return response["data"]

    def read(self, target: CommentTarget) -> CommentObservation:
        if not _valid_target(target, "linear"):
            raise ResultSlotError("Invalid Linear receipt target")
        data = self._data(_QUERY, {"id": target.comment_id})
        workspace, viewer = data.get("organization"), data.get("viewer")
        if (
            type(workspace) is not dict or workspace.get("urlKey") != _WORKSPACE
            or not _uuid(workspace.get("id")) or type(viewer) is not dict
            or viewer.get("id") != target.author_id
        ):
            raise ResultSlotError("The Linear receipt workspace or authenticated author did not match")
        return _linear_comment(target, data.get("comment"))

    def update(self, target: CommentTarget, body: str, *, expected_body: str) -> None:
        _verify_contents(body, expected_body)
        if self.read(target).body != expected_body:
            raise ResultSlotError("The Linear receipt changed before publication")
        if body == expected_body:
            return
        result = self._data(_MUTATION, {"id": target.comment_id, "input": {"body": body}}).get(
            "commentUpdate"
        )
        if (
            type(result) is not dict or result.get("success") is not True
            or _linear_comment(target, result.get("comment")).body != body
        ):
            raise ResultSlotError("The Linear receipt update response did not match")
        if self.read(target).body != body:
            raise ResultSlotError("The Linear receipt read-back did not match")


class ReceiptTransport:
    """Route only the fixed GitHub and Linear receipt targets."""

    def __init__(self, github, linear):
        self.github = github
        self.linear = linear

    def _port(self, target):
        if _valid_target(target, "github"):
            return self.github
        if _valid_target(target, "linear"):
            return self.linear
        raise ResultSlotError("Invalid AutoDev receipt target")

    def read(self, target: CommentTarget) -> CommentObservation:
        observation = self._port(target).read(target)
        if (
            type(observation) is not CommentObservation
            or not _valid_target(observation.target, target.provider)
            or observation.target != target or type(observation.body) is not str
            or not _is_result_body(observation.body)
        ):
            raise ResultSlotError("Unexpected AutoDev result slot response")
        return observation

    def update(self, target: CommentTarget, body: str, *, expected_body: str) -> None:
        _verify_contents(body, expected_body)
        self._port(target).update(target, body, expected_body=expected_body)
