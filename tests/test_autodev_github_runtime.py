import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from aotg.autodev.coordinator import Candidate, Draft, Result
from aotg.autodev.github_runtime import (
    GitHubResultComments,
    GitHubRuntime,
    GitHubRuntimeError,
    _run_gh,
)
from aotg.autodev.queue import (
    OWNER,
    REPOSITORY,
    ApprovedScope,
    GitHubSnapshot,
    scope_digest,
)
from aotg.autodev.remote_results import BOOTSTRAP_BODY, CommentTarget, _body

BASE = "a" * 40
HEAD = "b" * 40
PATH = "tests/test_harness.py"
BRANCH = "autodev/uob-50"
REF = f"refs/heads/{BRANCH}"
REPO = f"/repos/{REPOSITORY}"
REPO_URL = f"https://api.github.com{REPO}"
EXE = Path(sys.executable).with_name("gh.exe" if sys.platform == "win32" else "gh")
IAM = {"login": OWNER, "id": 1001}
COMMENT = 5_000_000_001
RECEIPT = _body(Result(
    "claim_started", "reserved", "UOB-50", "2026-01-01T00:00:00+00:00", BASE
).redacted())


def _wire(data, status=200, *, extra_headers=b""):
    return (
        f"HTTP/2.0 {status} OK\r\nContent-Type: application/json; charset=UTF-8\r\n".encode()
        + extra_headers + b"\r\n" + json.dumps(data).encode()
    )


def _snapshot(*, open_prs=(), main=BASE):
    return GitHubSnapshot(main, open_prs, ("main", BRANCH), True, True)


def _ref(sha):
    return {"ref": REF, "object": {"type": "commit", "sha": sha}}


def _issue(**changes):
    return {
        "number": 7,
        "repository_url": REPO_URL,
        "author_association": "OWNER",
        "user": IAM,
        "state": "open",
        "updated_at": "2026-01-01T00:00:00Z",
        "body": "untrusted instructions",
        **changes,
    }


def _draft(**changes):
    repo = {"full_name": REPOSITORY}
    return {
        "number": 8, "state": "open", "draft": True,
        "head": {"repo": repo, "ref": BRANCH, "sha": HEAD},
        "base": {"repo": repo, "ref": "main", "sha": BASE},
        **changes,
    }


def _commit(**changes):
    return {
        "sha": HEAD,
        "parents": [{"sha": BASE}],
        "files": [{"filename": PATH, "status": "added"}],
        **changes,
    }


def _comment(body=BOOTSTRAP_BODY, **changes):
    return {"id": COMMENT, "user": IAM, "body": body, "issue_url": f"{REPO_URL}/issues/3", **changes}


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.responder = Mock()
        self.runtime = GitHubRuntime(EXE, run=self.responder)
        scope = ApprovedScope("UOB-50", 7, "c" * 64, (PATH,), (), "")
        self.scope = replace(scope, approval_sha=scope_digest(scope))
        self.candidate = Candidate(BASE, HEAD, (PATH,), True)
        self.target = CommentTarget("github", f"{REPOSITORY}#3", 3, COMMENT, IAM["id"])

    def replies(self, *values):
        self.responder.side_effect = [
            _wire(value) if not isinstance(value, (bytes, Exception)) else value for value in values
        ]

    def writes(self):
        return [
            (call.args[0][5], call.args[0][11], json.loads(call.args[1]))
            for call in self.responder.call_args_list if call.args[1] is not None
        ]

    def as_owner(self):
        return {"full_name": REPOSITORY, "private": False, "default_branch": "main"}, IAM

    @patch.dict("os.environ", {"GH_TOKEN": "token-not-for-this-job", "GH_DEBUG": "api"})
    def test_gh_api_is_pinned_and_does_not_inherit_token(self):
        runtime = GitHubRuntime(EXE, run=self.responder)
        self.replies(_issue())
        observed = runtime.read_issue(7)
        self.assertEqual((observed.number, observed.author, observed.state), (7, OWNER, "open"))
        args, payload = self.responder.call_args.args
        self.assertEqual(args[:5], (str(EXE), "api", "--hostname", "github.com", "--method"))
        self.assertIn(f"{REPO}/issues/7", args)
        self.assertIsNone(payload)
        env = self.responder.call_args.kwargs["env"]
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("GH_DEBUG", env)
        self.assertIn("GH_PROMPT_DISABLED", env)

    def test_refuses_issue_identity_and_unsafe_requests(self):
        self.replies(
            _issue(user={"login": "other"}),
            _issue(pull_request={}),
            _issue(repository_url="https://api.github.com/repos/other/AOTG"),
        )
        for _ in range(3):
            with self.assertRaises(GitHubRuntimeError):
                self.runtime.read_issue(7)
        for invalid in (3, True, "7"):
            with self.assertRaises(GitHubRuntimeError):
                self.runtime.read_issue(invalid)
        for invalid in ("/user", REPO + "/pulls/2", REPO + "/branches?next=https://test"):
            with self.assertRaises(GitHubRuntimeError):
                self.runtime.get_json(invalid)
        self.assertEqual(self.responder.call_count, 3)

    def test_read_inventory_uses_strict_link(self):
        path = f"{REPO}/branches?per_page=100&page=1"
        self.replies(_wire([], extra_headers=(
            f'Link: <https://api.github.com{REPO}/branches?per_page=100&page=2>; rel="next"\r\n'
        ).encode()))
        self.assertEqual(self.runtime.get_json(path), ([], True))

    def test_rejects_malformed_http_and_duplicate_json(self):
        self.replies(
            b'{"bad":"header"}',
            b'HTTP/2.0 200 OK\nContent-Type: application/json\n\n{"name":1,"name":2}',
            _wire(_issue(), status=403),
        )
        for _ in range(3):
            with self.assertRaises(GitHubRuntimeError):
                self.runtime.read_issue(7)

    def test_create_only_reserves_ref_and_reads_back(self):
        self.replies(*self.as_owner(), [], _wire(_ref(BASE), 201), [_ref(BASE)])
        with patch.object(self.runtime, "snapshot", return_value=_snapshot()):
            self.runtime.reserve_branch(BRANCH, BASE)
        self.assertEqual(self.writes(), [("POST", f"{REPO}/git/refs", {"ref": REF, "sha": BASE})])

    def test_existing_ref_conflicting_prefix_and_open_pr_block_creation(self):
        self.replies(*self.as_owner(), [_ref(BASE)],
                     *self.as_owner(), [{"ref": REF + "-other", "object": {"sha": BASE}}],
                     *self.as_owner())
        for open_prs in ((), (), (4,)):
            with (patch.object(self.runtime, "snapshot", return_value=_snapshot(open_prs=open_prs)),
                  self.assertRaises(GitHubRuntimeError)):
                self.runtime.reserve_branch(BRANCH, BASE)
        self.assertEqual(self.writes(), [])

    def test_uncertain_reservation_is_not_retried(self):
        self.replies(*self.as_owner(), [], TimeoutError("private stderr"))
        with (patch.object(self.runtime, "snapshot", return_value=_snapshot()),
              self.assertRaisesRegex(GitHubRuntimeError, "not confirmed")):
            self.runtime.reserve_branch(BRANCH, BASE)
        self.assertEqual(len(self.writes()), 1)

    def test_publication_checks_commit_then_reads_exact_draft(self):
        self.replies(_commit(), *self.as_owner(), _issue(), [_ref(HEAD)],
                     _wire({"number": 8}, 201), _draft())
        with patch.object(self.runtime, "snapshot", return_value=_snapshot()):
            self.assertEqual(self.runtime.publish_draft(self.scope, self.candidate), 8)
        self.assertEqual(self.writes(), [
            ("POST", f"{REPO}/pulls", {
                "base": "main", "draft": True, "head": BRANCH,
                "title": "UOB-50 offline software candidate",
                "body": f"AOTG-AUTODEV-V1 candidate for UOB-50 ({REPOSITORY}#7).",
            })
        ])

    def test_publication_never_writes_if_unreviewed_or_changed(self):
        self.replies(_commit(files=[{"filename": ".github/workflows/ci.yml", "status": "added"}]),
                     _commit(parents=[{"sha": HEAD}]),
                     _commit(), *self.as_owner(), _issue(), [_ref(BASE)])
        with patch.object(self.runtime, "snapshot", return_value=_snapshot()):
            for _ in range(3):
                with self.assertRaises(GitHubRuntimeError):
                    self.runtime.publish_draft(self.scope, self.candidate)
        self.assertEqual(self.writes(), [])

    def test_draft_must_use_same_repo(self):
        self.replies(_draft(head={"repo": {"full_name": "fork/AOTG"}, "ref": BRANCH, "sha": HEAD}),
                     _draft())
        with self.assertRaises(GitHubRuntimeError):
            self.runtime.read_draft(8)
        self.assertEqual(self.runtime.read_draft(8), Draft(8, BRANCH, BASE, HEAD, True))

    def test_dedicated_comment_reads_before_and_after_one_write(self):
        self.replies(*self.as_owner(), _comment(), _comment(RECEIPT), _comment(RECEIPT), _comment(RECEIPT))
        transport = GitHubResultComments(self.runtime)
        transport.update(self.target, RECEIPT, expected_body=BOOTSTRAP_BODY)
        self.assertEqual(transport.read(self.target).body, RECEIPT)
        self.assertEqual(self.writes(), [
            ("PATCH", f"{REPO}/issues/comments/{COMMENT}", {"body": RECEIPT})
        ])

    def test_rejects_other_comment_author_issue_and_arbitrary_body(self):
        self.replies(*self.as_owner(), _comment(user={"login": "other", "id": 1}),
                     *self.as_owner(), _comment(issue_url=f"{REPO_URL}/issues/4"))
        transport = GitHubResultComments(self.runtime)
        for _ in range(2):
            with self.assertRaises(GitHubRuntimeError):
                transport.update(self.target, RECEIPT, expected_body=BOOTSTRAP_BODY)
        with self.assertRaises(GitHubRuntimeError):
            transport.update(self.target, "unstructured prose", expected_body=BOOTSTRAP_BODY)
        self.assertEqual(self.writes(), [])

    def test_subprocess_capture_accepts_bounded_output_and_rejects_oversized_response(self):
        prefix = (sys.executable, "-I", "-B", "-c")
        self.assertEqual(_run_gh(
            prefix + ("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",),
            b"expected",
            cwd=EXE.parent,
            env=self.runtime.env,
        ), b"expected")
        with patch("aotg.autodev.github_runtime._MAX_RESPONSE", 64):
            with self.assertRaisesRegex(GitHubRuntimeError, "within bounds"):
                _run_gh(
                    prefix + ("import sys; sys.stdout.buffer.write(b'x' * 4096)",),
                    None,
                    cwd=EXE.parent,
                    env=self.runtime.env,
                )
