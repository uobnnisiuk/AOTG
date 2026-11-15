"""Check the fixed receipt wiring with synthetic comment and viewer identities."""

from copy import deepcopy
from dataclasses import replace
from unittest import TestCase
from unittest.mock import Mock, patch

from aotg.autodev.coordinator import Result
from aotg.autodev.receipt_transport import (
    _MUTATION,
    _QUERY,
    LinearResultComments,
    ReceiptTransport,
)
from aotg.autodev.remote_results import (
    BOOTSTRAP_BODY,
    CommentObservation,
    CommentTarget,
    _body,
)
from aotg.autodev.result_slot import ResultSlotError

GITHUB = CommentTarget("github", "uobnnisiuk/AOTG#3", 3, 44, 55)
LINEAR = CommentTarget(
    "linear", "UOB-58", "10000000-0000-4000-8000-000000000000",
    "20000000-0000-4000-8000-000000000000", "30000000-0000-4000-8000-000000000000",
)
WORKSPACE_ID = "40000000-0000-4000-8000-000000000000"
PROJECT_ID = "50000000-0000-4000-8000-000000000000"
APPROVED_BODY = _body(Result(
    "claim_started", "reserved", "UOB-50", "2026-01-01T00:00:00+00:00", "1" * 40,
).redacted())


class LinearServer:
    def __init__(self):
        self.item = {
            "id": LINEAR.comment_id, "body": BOOTSTRAP_BODY, "archivedAt": None,
            "parentId": None, "quotedText": None, "externalThread": None, "user": {"id": LINEAR.author_id},
            "issue": {
                "id": LINEAR.issue_id, "identifier": LINEAR.issue, "archivedAt": None,
                "project": {
                    "id": PROJECT_ID,
                    "url": "https://linear.app/uobnnisiuk/project/mock-aotg-db9d5646feea",
                },
            },
        }
        self.viewer = {"id": LINEAR.author_id}
        self.organization = {"id": WORKSPACE_ID, "urlKey": "uobnnisiuk"}
        self.requests = []
        self.query_error = False
        self.mutation_error = False
        self.changed_mutation_identity = False
        self.stale_readback = False

    def request(self, query, variables):
        self.requests.append((query, deepcopy(variables)))
        if query == _QUERY:
            response = {"data": {
                "organization": deepcopy(self.organization), "viewer": deepcopy(self.viewer),
                "comment": deepcopy(self.item),
            }}
            if self.query_error:
                response["errors"] = [{"message": "private content"}]
            return response
        if query != _MUTATION or variables["id"] != LINEAR.comment_id:
            raise AssertionError("Unexpected GraphQL request")
        item = {**self.item, "body": variables["input"]["body"]}
        if not self.stale_readback:
            self.item = item
        response = {"data": {"commentUpdate": {"success": True, "comment": deepcopy(item)}}}
        if self.changed_mutation_identity:
            response["data"]["commentUpdate"]["comment"]["issue"]["identifier"] = "UOB-59"
        if self.mutation_error:
            response["errors"] = [{"message": "private content"}]
        return response


class LinearResultCommentsTests(TestCase):
    def setUp(self):
        self.server = LinearServer()
        self.linear = LinearResultComments(request=self.server.request)

    def test_fixed_requests_and_exact_read_back(self):
        self.assertEqual(self.linear.read(LINEAR), CommentObservation(LINEAR, BOOTSTRAP_BODY))
        self.linear.update(LINEAR, APPROVED_BODY, expected_body=BOOTSTRAP_BODY)
        only_id = {"id": LINEAR.comment_id}
        self.assertEqual(self.server.requests, [
            (_QUERY, only_id), (_QUERY, only_id),
            (_MUTATION, {**only_id, "input": {"body": APPROVED_BODY}}), (_QUERY, only_id),
        ])
        self.assertEqual(self.linear.read(LINEAR).body, APPROVED_BODY)

    def test_credentials_go_only_to_pinned_client(self):
        with patch("aotg.autodev.receipt_transport._post", return_value=self.server.request(
            _QUERY, {"id": LINEAR.comment_id},
        )) as post:
            linear = LinearResultComments("Bearer synthetic-credential")
            linear.read(LINEAR)
            post.assert_called_once_with(_QUERY, {"id": LINEAR.comment_id}, "Bearer synthetic-credential")
        for value in (None, "invalid\nheader", "", "short"):
            with self.subTest(value=value), self.assertRaises(ResultSlotError):
                LinearResultComments(value)
        with self.assertRaises(ResultSlotError):
            LinearResultComments("Bearer synthetic-credential", request=self.server.request)

    def test_wrong_viewer_issue_author_project_or_body_blocks_before_update(self):
        for field, value in (
            ("viewer", {"id": PROJECT_ID}),
            ("organization", {"id": WORKSPACE_ID, "urlKey": "other"}),
            ("item", {**self.server.item, "user": {"id": PROJECT_ID}}),
            ("item", {**self.server.item, "archivedAt": "2026-01-01"}),
            ("item", {**self.server.item, "parentId": LINEAR.comment_id}),
            ("item", {**self.server.item, "quotedText": "a passage"}),
            ("item", {**self.server.item, "externalThread": {"__typename": "SyncedExternalThread"}}),
            ("item", {**self.server.item, "body": "Human audit comment"}),
            ("item", {**self.server.item, "issue": {**self.server.item["issue"], "id": PROJECT_ID}}),
            ("item", {**self.server.item, "issue": {**self.server.item["issue"], "identifier": "UOB-59"}}),
            ("item", {**self.server.item, "issue": {**self.server.item["issue"], "project": None}}),
        ):
            with self.subTest(field=field), patch.object(self.server, field, value):
                with self.assertRaises(ResultSlotError):
                    self.linear.update(LINEAR, APPROVED_BODY, expected_body=BOOTSTRAP_BODY)
        self.assertTrue(self.server.requests)
        self.assertTrue(all(request == _QUERY for request, _ in self.server.requests))

    def test_malformed_target_or_unrestricted_content_is_never_submitted(self):
        for target, body, expected in (
            (replace(LINEAR, issue="UOB-59"), APPROVED_BODY, BOOTSTRAP_BODY),
            (replace(LINEAR, comment_id="injection"), APPROVED_BODY, BOOTSTRAP_BODY),
            (LINEAR, "arbitrary Markdown", BOOTSTRAP_BODY),
            (LINEAR, APPROVED_BODY, "unverified"),
            (LINEAR, BOOTSTRAP_BODY, APPROVED_BODY),
        ):
            with self.subTest(target=target), self.assertRaises(ResultSlotError):
                self.linear.update(target, body, expected_body=expected)
        self.assertEqual(self.server.requests, [])

    def test_graphql_partial_result_fails_without_exposing_service_message(self):
        self.server.query_error = True
        with self.assertRaisesRegex(ResultSlotError, "partial or unavailable"):
            self.linear.update(LINEAR, APPROVED_BODY, expected_body=BOOTSTRAP_BODY)
        self.assertEqual([op for op, _ in self.server.requests], [_QUERY])

    def test_ambiguous_mutation_bad_receipt_or_readback_never_retries(self):
        for flag in ("mutation_error", "changed_mutation_identity", "stale_readback"):
            server = LinearServer()
            operation = LinearResultComments(request=server.request)
            setattr(server, flag, True)
            with self.subTest(flag=flag), self.assertRaises(ResultSlotError):
                operation.update(LINEAR, APPROVED_BODY, expected_body=BOOTSTRAP_BODY)
            self.assertEqual([kind for kind, _ in server.requests].count(_MUTATION), 1)


class ReceiptTransportTests(TestCase):
    def test_routes_only_matching_slots_and_refuses_result_reset(self):
        github, linear = Mock(), Mock()
        router = ReceiptTransport(github, linear)
        github.read.return_value = CommentObservation(GITHUB, BOOTSTRAP_BODY)
        linear.read.return_value = CommentObservation(LINEAR, APPROVED_BODY)
        self.assertEqual(router.read(GITHUB).body, BOOTSTRAP_BODY)
        self.assertEqual(router.read(LINEAR).body, APPROVED_BODY)
        router.update(GITHUB, APPROVED_BODY, expected_body=BOOTSTRAP_BODY)
        github.update.assert_called_once_with(GITHUB, APPROVED_BODY, expected_body=BOOTSTRAP_BODY)
        linear.update.assert_not_called()
        with self.assertRaises(ResultSlotError):
            router.update(LINEAR, BOOTSTRAP_BODY, expected_body=APPROVED_BODY)
        with self.assertRaises(ResultSlotError):
            router.read(replace(GITHUB, issue_id=4))
        github.read.return_value = CommentObservation(LINEAR, APPROVED_BODY)
        with self.assertRaises(ResultSlotError):
            router.read(GITHUB)
