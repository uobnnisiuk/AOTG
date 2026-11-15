import copy
import io
import json
import unittest
from dataclasses import replace
from email.message import Message
from unittest.mock import MagicMock, Mock, patch

from aotg.autodev.linear_read import LinearIntake, LinearReadError, _RejectRedirect
from aotg.autodev.queue import (
    ApprovedScope,
    GitHubSnapshot,
    scope_digest,
    select_candidate,
)

WORKSPACE_ID = "10000000-0000-4000-8000-000000000001"
PROJECT_ID = "10000000-0000-4000-8000-000000000002"
ISSUE_ID = "10000000-0000-4000-8000-000000000050"
BLOCKER_ID = "10000000-0000-4000-8000-000000000049"
SCOPE = ApprovedScope("UOB-50", 7, "b" * 64, ("docs/example.md",), ("UOB-49",), "a" * 64)


def _payload():
    return {
        "data": {
            "organization": {"id": WORKSPACE_ID, "urlKey": "uobnnisiuk"},
            "issue": {
                "id": ISSUE_ID,
                "identifier": "UOB-50",
                "title": "Synthetic issue title",
                "description": "Synthetic markdown 日本語",
                "archivedAt": None,
                "project": {
                    "id": PROJECT_ID,
                    "url": "https://linear.app/uobnnisiuk/project/example-db9d5646feea",
                },
                "state": {"type": "backlog"},
                "inverseRelations": {
                    "pageInfo": {"hasPreviousPage": False, "hasNextPage": False},
                    "nodes": [{
                        "type": "blocks",
                        "issue": {
                            "id": BLOCKER_ID, "identifier": "UOB-49",
                            "archivedAt": None, "state": {"type": "completed"},
                        },
                        "relatedIssue": {"id": ISSUE_ID, "identifier": "UOB-50"},
                    }],
                },
            },
        }
    }


def _observe(payload):
    return LinearIntake(request=lambda query, variables: payload).snapshot((SCOPE,))


class LinearIntakeTests(unittest.TestCase):
    def test_reads_only_approved_issue_and_returns_no_prose(self):
        transport = Mock(return_value=_payload())
        issues, done = LinearIntake(request=transport).snapshot((SCOPE,))
        transport.assert_called_once()
        query, variables = transport.call_args.args
        self.assertEqual(variables, {"id": "UOB-50"})
        self.assertIn("inverseRelations", query)
        self.assertNotIn("mutation", query)
        self.assertEqual(done, ("UOB-49",))
        self.assertEqual(issues[0].issue, "UOB-50")
        self.assertEqual(issues[0].github_issue, 7)
        self.assertEqual(issues[0].dependencies, ("UOB-49",))
        self.assertTrue(issues[0].eligible)
        self.assertRegex(issues[0].revision, r"^[a-f0-9]{64}$")
        self.assertNotIn("Synthetic", str((issues, done)))

    def test_scope_digest_changes_on_text_edit_or_dependency_identity_change(self):
        original, done = _observe(_payload())
        for field, value in (("title", "Modified title"), ("description", "Edited scope")):
            with self.subTest(field=field):
                changed = _payload()
                changed["data"]["issue"][field] = value
                self.assertNotEqual(original[0].revision, _observe(changed)[0][0].revision)
        changed = _payload()
        changed["data"]["issue"]["inverseRelations"]["nodes"][0]["issue"]["id"] = (
            "10000000-0000-4000-8000-000000000019"
        )
        self.assertNotEqual(original[0].revision, _observe(changed)[0][0].revision)

    def test_state_changes_invalidate_admission_without_changing_scope(self):
        items, done = _observe(_payload())
        scope = replace(SCOPE, revision=items[0].revision)
        scope = replace(scope, approval_sha=scope_digest(scope))
        github = GitHubSnapshot("d" * 40, (), ("main",), True, True)
        payload = _payload()
        dependency = payload["data"]["issue"]["inverseRelations"]["nodes"][0]["issue"]
        dependency["state"]["type"] = "started"
        reopened, new_done = _observe(payload)
        self.assertEqual(items, reopened)
        self.assertEqual(new_done, ())
        self.assertIsNone(select_candidate(
            approvals=(scope,), issues=reopened, done_issues=new_done,
            github=github, linear_complete=True,
        ).scope)
        payload["data"]["issue"]["state"]["type"] = "completed"
        closed, closed_done = _observe(payload)
        self.assertFalse(closed[0].eligible)
        self.assertEqual(closed[0].revision, items[0].revision)
        self.assertEqual(closed_done, ("UOB-50",))

    def test_archived_blocker_is_not_counted_done(self):
        payload = _payload()
        dependency = payload["data"]["issue"]["inverseRelations"]["nodes"][0]["issue"]
        dependency["archivedAt"] = "2025-01-01T00:00:00Z"
        self.assertEqual(_observe(payload)[1], ())

    def test_nonblocking_relation_is_not_a_dependency(self):
        payload = _payload()
        payload["data"]["issue"]["inverseRelations"]["nodes"][0]["type"] = "related"
        items, done = _observe(payload)
        self.assertEqual(items[0].dependencies, ())
        self.assertEqual(done, ())

    def test_rejects_partial_data_and_unverified_relation_pages(self):
        responses = []
        payload = _payload()
        payload["errors"] = [{"message": "private diagnostic"}]
        responses.append(payload)
        for flag, value in (("hasNextPage", True), ("hasPreviousPage", True), ("hasNextPage", None)):
            payload = _payload()
            payload["data"]["issue"]["inverseRelations"]["pageInfo"][flag] = value
            responses.append(payload)
        for response in responses:
            with self.assertRaises(LinearReadError) as exc:
                _observe(response)
            self.assertNotIn("private diagnostic", str(exc.exception))

    def test_rejects_unknown_issue_workspace_project_or_state(self):
        changes = (
            (("organization", "urlKey"), "somewhere-else"),
            (("issue", "identifier"), "UOB-55"),
            (("issue", "project", "url"), "https://fake.test/uobnnisiuk/project/x-db9d5646feea"),
            (("issue", "state", "type"), "mystery"),
            (("issue", "description"), "x" * 65537),
        )
        for keys, value in changes:
            with self.subTest(keys=keys):
                payload = _payload()
                row = payload["data"]
                for key in keys[:-1]:
                    row = row[key]
                row[keys[-1]] = value
                with self.assertRaises(LinearReadError):
                    _observe(payload)

    def test_rejects_wrong_dependency_direction_and_duplicates(self):
        payload = _payload()
        nodes = payload["data"]["issue"]["inverseRelations"]["nodes"]
        nodes.append(copy.deepcopy(nodes[0]))
        with self.assertRaises(LinearReadError):
            _observe(payload)
        nodes.pop()["relatedIssue"]["id"] = BLOCKER_ID
        nodes[0]["relatedIssue"]["id"] = BLOCKER_ID
        with self.assertRaises(LinearReadError):
            _observe(payload)

    def test_empty_or_invalid_approval_scope_never_contacts_transport(self):
        transport = Mock()
        reader = LinearIntake(request=transport)
        self.assertEqual(reader.snapshot(()), ((), ()))
        for bad in ((SCOPE, SCOPE), (replace(SCOPE, issue="UOB-50\n"),)):
            with self.assertRaises(LinearReadError):
                reader.snapshot(bad)
        transport.assert_not_called()

    def test_http_transport_uses_pinned_endpoint_explicit_auth_and_fixed_query(self):
        authorization = "Bearer synthetic-auth-header-for-test"
        response = Mock()
        response.status = 200
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        response.read.side_effect = io.BytesIO(json.dumps(_payload()).encode()).read
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch("aotg.autodev.linear_read.build_opener", return_value=opener) as make:
            LinearIntake(authorization).snapshot((SCOPE,))
        self.assertIsInstance(make.call_args.args[1], _RejectRedirect)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.linear.app/graphql")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), authorization)
        self.assertEqual(json.loads(request.data)["variables"], {"id": "UOB-50"})
        with self.assertRaises(LinearReadError):
            LinearIntake(authorization + "\n")
        with self.assertRaises(LinearReadError):
            _RejectRedirect().redirect_request(
                request, None, 302, "", {}, "https://example.invalid"
            )


if __name__ == "__main__":
    unittest.main()
