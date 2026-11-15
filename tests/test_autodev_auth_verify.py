"""Test the read-only authentication verifier without using real accounts or the network."""

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from aotg.autodev.auth_import import _github_hosts
from aotg.autodev.auth_verify import (
    _GITHUB_ISSUE,
    _RESPONSE_LIMIT,
    AuthVerification,
    _github_token,
    _json_response,
    main,
    verify_dedicated_auth,
)
from aotg.autodev.queue import OWNER, REPOSITORY
from aotg.autodev.remote_results import BOOTSTRAP_BODY, CommentTarget

GITHUB = CommentTarget("github", f"{REPOSITORY}#3", 3, 44, 55)
LINEAR = CommentTarget(
    "linear", "UOB-58", "10000000-0000-4000-8000-000000000000",
    "20000000-0000-4000-8000-000000000000", "30000000-0000-4000-8000-000000000000",
)
TOKEN = "github_" + "pat_" + "SyntheticTokenOnlyForThisTest"
LINEAR_TOKEN = "lin_" + "api_" + "SyntheticTokenOnlyForThisTest"
GITHUB_USER = {"login": OWNER, "id": GITHUB.author_id}
GITHUB_COMMENT = {
    "id": GITHUB.comment_id, "issue_url": _GITHUB_ISSUE, "user": GITHUB_USER, "body": BOOTSTRAP_BODY,
}


def _linear_result(*, team="UOB", viewer=LINEAR.author_id):
    return {
        "data": {
            "organization": {"id": "40000000-0000-4000-8000-000000000000", "urlKey": OWNER},
            "viewer": {"id": viewer},
            "comment": {
                "id": LINEAR.comment_id, "body": BOOTSTRAP_BODY, "archivedAt": None,
                "parentId": None, "quotedText": None, "externalThread": None,
                "user": {"id": LINEAR.author_id},
                "issue": {
                    "identifier": LINEAR.issue, "id": LINEAR.issue_id, "archivedAt": None,
                    "team": {"id": "50000000-0000-4000-8000-000000000000", "key": team},
                    "project": {
                        "id": "60000000-0000-4000-8000-000000000000",
                        "url": f"https://linear.app/{OWNER}/project/aotg-db9d5646feea",
                    },
                },
            },
        },
    }


class AuthVerificationTests(TestCase):
    def setUp(self):
        self.config = Path("synthetic") / "config"
        self.targets = self.enterContext(patch(
            "aotg.autodev.auth_verify._receipt_targets", return_value=(GITHUB, LINEAR),
        ))
        self.enterContext(patch("aotg.autodev.auth_verify._private_config", return_value=self.config))
        self.github_token = self.enterContext(patch(
            "aotg.autodev.auth_verify._github_token", return_value=TOKEN,
        ))
        self.linear_token = self.enterContext(patch(
            "aotg.autodev.auth_verify.load_linear_authorization", return_value=LINEAR_TOKEN,
        ))
        self.http = self.enterContext(patch("aotg.autodev.auth_verify._json_response"))

    def verify(self):
        return verify_dedicated_auth(self.config.parent)

    def test_only_fixed_identity_and_receipt_reads(self):
        self.http.side_effect = (GITHUB_USER, GITHUB_COMMENT, _linear_result())
        self.assertEqual(self.verify(), AuthVerification(True, True))
        self.targets.assert_called_once_with(self.config / "receipt-targets.json")
        self.github_token.assert_called_once_with(self.config / "github")
        self.linear_token.assert_called_once_with(self.config / "linear-authorization")
        user, github, linear = self.http.call_args_list
        self.assertEqual(user.args, ("api.github.com", "/user", "GET", f"Bearer {TOKEN}"))
        self.assertEqual(
            github.args,
            ("api.github.com", f"/repos/{REPOSITORY}/issues/comments/{GITHUB.comment_id}", "GET",
             f"Bearer {TOKEN}"),
        )
        self.assertEqual(linear.args, ("api.linear.app", "/graphql", "POST", LINEAR_TOKEN))
        query = json.loads(linear.kwargs["request"])
        self.assertEqual(query["variables"], {"id": LINEAR.comment_id})
        self.assertTrue(query["query"].lstrip().startswith("query AotgReadResult("))
        self.assertIn("team { id key }", query["query"])
        self.assertNotIn("mutation", query["query"])

    def test_github_login_must_be_the_pinned_author_even_with_working_token(self):
        self.http.side_effect = ({**GITHUB_USER, "id": 99}, _linear_result())
        self.assertEqual(self.verify(), AuthVerification(False, True))
        self.assertEqual(self.http.call_count, 2)

    def test_github_comment_must_belong_to_the_pinned_issue(self):
        wrong_comment = {**GITHUB_COMMENT, "issue_url": _GITHUB_ISSUE[:-1] + "4"}
        self.http.side_effect = (GITHUB_USER, wrong_comment, _linear_result())
        self.assertEqual(self.verify(), AuthVerification(False, True))

    def test_linear_other_team_or_viewer_is_rejected(self):
        for invalid_result in (_linear_result(team="ALT"), _linear_result(viewer=LINEAR.issue_id)):
            with self.subTest(invalid_result=invalid_result):
                self.http.side_effect = (GITHUB_USER, GITHUB_COMMENT, invalid_result)
                self.assertEqual(self.verify(), AuthVerification(True, False))

    def test_linear_rejects_ambient_token_formats(self):
        self.linear_token.return_value = "Bearer example"
        self.http.side_effect = (GITHUB_USER, GITHUB_COMMENT)
        self.assertEqual(self.verify(), AuthVerification(True, False))
        self.assertEqual(self.http.call_count, 2)

    def test_no_receipt_configuration_never_uses_credentials_or_network(self):
        self.targets.side_effect = ValueError("synthetic unreadable configuration")
        self.assertEqual(self.verify(), AuthVerification())
        self.github_token.assert_not_called()
        self.linear_token.assert_not_called()
        self.http.assert_not_called()


class AuthTransportTests(TestCase):
    @patch("aotg.autodev.auth_verify._private_bytes")
    def test_github_uses_only_the_importers_private_fine_grained_profile(self, read):
        config = Path("synthetic") / "github"
        valid = _github_hosts(TOKEN)
        read.return_value = valid
        self.assertEqual(_github_token(config), TOKEN)
        read.assert_called_once_with(config / "hosts.yml", 4096)
        for altered in (
            valid.replace(b"git_protocol: https", b"git_protocol: ssh"),
            valid.replace(TOKEN.encode("ascii"), b"NotFineGrained"),
            valid.replace(b"            oauth_token: ", b"            oauth_token: wrong_", 1),
            valid + b"another.host:\n",
        ):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                read.return_value = altered
                _github_token(config)

    @patch("aotg.autodev.auth_verify.HTTPSConnection")
    def test_HTTPS_redirect_is_never_followed_or_read(self, HTTPSConnection):
        connection = HTTPSConnection.return_value
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 302
        response.getheader.return_value = "application/json"
        with self.assertRaises(ValueError):
            _json_response("api.github.com", "/user", "GET", f"Bearer {TOKEN}")
        HTTPSConnection.assert_called_once_with("api.github.com", timeout=5)
        connection.request.assert_called_once()
        response.read.assert_not_called()
        connection.close.assert_called_once()

    @patch("aotg.autodev.auth_verify.HTTPSConnection")
    def test_HTTP_body_is_bounded(self, HTTPSConnection):
        connection = HTTPSConnection.return_value
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 200
        response.getheader.return_value = "application/json"
        response.read.return_value = b"!" * (_RESPONSE_LIMIT + 1)
        with self.assertRaises(ValueError):
            _json_response("api.linear.app", "/graphql", "POST", TOKEN, request=b"{}")
        response.read.assert_called_once_with(_RESPONSE_LIMIT + 1)
        connection.close.assert_called_once()

    @patch("aotg.autodev.auth_verify.verify_dedicated_auth")
    def test_cli_never_echoes_invalid_arguments_or_details(self, verify):
        standard, error = io.StringIO(), io.StringIO()
        with redirect_stdout(standard), redirect_stderr(error):
            code = main(["--secret", "SyntheticSensitiveArgument"])
        self.assertEqual(code, 1)
        self.assertEqual(standard.getvalue(), '{"github_read":false,"linear_read":false}\n')
        self.assertEqual(error.getvalue(), "")
        verify.assert_not_called()
