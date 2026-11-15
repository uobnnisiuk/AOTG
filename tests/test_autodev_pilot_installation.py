"""Check that installation reads the owner release before remote prerequisites."""

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns
from unittest import TestCase
from unittest.mock import Mock, patch

from aotg.autodev.coordinator import Readiness, Result
from aotg.autodev.isolated_process import CodexDeployment, ModelAuthorization
from aotg.autodev.pilot_installation import (
    PilotInstallation,
    _receipt_targets,
    _request_linear,
    _run_github,
    run_configured_pilot,
)
from aotg.autodev.pilot_runtime import PilotAttemptBoundary, PilotError
from aotg.autodev.receipt_transport import _MUTATION
from aotg.autodev.remote_results import (
    BOOTSTRAP_BODY,
    CommentObservation,
    CommentTarget,
    RemoteResultSlot,
)
from aotg.autodev.result_slot import LocalResultSlot, ResultSlotError
from aotg.autodev.runtime_config import ConfigError

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
AUTHORIZED = Readiness(True, True, True, True)


class InstallationTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.authorization = ModelAuthorization("test-model", "2" * 64, NOW + timedelta(minutes=35), 2400)
        self.boundary = PilotAttemptBoundary.from_deadline(monotonic_ns() + 300_000_000_000, lambda: True)
        self.installation = PilotInstallation(
            self.root, Path("/example/git"), Path("/example/gh"),
            CodexDeployment(Path("/example/codex"), "1" * 64, 99, model_authorization=self.authorization),
        )

    @patch("aotg.autodev.pilot_installation.load_release")
    def test_disabled_readiness_never_reads_release(self, release):
        result = run_configured_pilot(self.installation, Readiness(), boundary=self.boundary, now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        release.assert_not_called()

    @patch("aotg.autodev.pilot_installation._approved", return_value=True)
    @patch("aotg.autodev.pilot_installation.load_linear_authorization")
    @patch("aotg.autodev.pilot_installation.load_release", side_effect=ConfigError("missing"))
    def test_missing_release_never_reads_credentials(self, release, credentials, approval):
        result = run_configured_pilot(self.installation, AUTHORIZED, boundary=self.boundary, now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        release.assert_called_once_with(self.root / "config" / "first-pilot-release.json")
        credentials.assert_not_called()

    @patch("aotg.autodev.pilot_installation._approved", return_value=True)
    @patch("aotg.autodev.pilot_installation.load_linear_authorization")
    @patch("aotg.autodev.pilot_installation.load_approvals", return_value=())
    @patch("aotg.autodev.pilot_installation.load_release")
    def test_empty_registry_does_not_read_credentials(self, release, scopes, credentials, approval):
        release.return_value = Mock(base="1" * 40, expires_at=NOW + timedelta(hours=1))
        result = run_configured_pilot(self.installation, AUTHORIZED, boundary=self.boundary, now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        scopes.assert_called_once()
        credentials.assert_not_called()

    @patch("aotg.autodev.pilot_installation._private_bytes")
    def test_targets_are_restricted_to_preprovisioned_issue_pair(self, private_bytes):
        value = {
            "version": 1,
            "github": {"issue": 3, "comment_id": 100, "author_id": 101},
            "linear": {
                "issue": "UOB-58", "issue_id": "sample", "comment_id": "sample", "author_id": "sample",
            },
        }
        private_bytes.return_value = json.dumps(value).encode()
        github, linear = _receipt_targets(self.root / "receipt-targets.json")
        self.assertEqual((github.issue, linear.issue), ("uobnnisiuk/AOTG#3", "UOB-58"))
        value["linear"]["issue"] = "UOB-59"
        private_bytes.return_value = json.dumps(value).encode()
        with self.assertRaises(ConfigError):
            _receipt_targets(self.root / "receipt-targets.json")

    @patch("aotg.autodev.pilot_installation._approved", return_value=True)
    @patch("aotg.autodev.pilot_installation.load_linear_authorization")
    @patch("aotg.autodev.pilot_installation.load_approvals", return_value=(object(),))
    @patch("aotg.autodev.pilot_installation.load_release")
    def test_expired_release_cannot_be_extended_by_model_authorization(
        self, release, scopes, credentials, approval,
    ):
        release.return_value = Mock(base="1" * 40, expires_at=NOW + timedelta(minutes=40))
        authorization = ModelAuthorization("test-model", "2" * 64, NOW + timedelta(hours=2), 2400)
        codex = replace(self.installation.codex, model_authorization=authorization)
        installation = replace(self.installation, codex=codex)
        result = run_configured_pilot(installation, AUTHORIZED, boundary=self.boundary, now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        credentials.assert_not_called()

    @patch("aotg.autodev.pilot_installation.load_release")
    def test_ready_flags_without_live_boundary_cannot_read_release(self, release):
        result = run_configured_pilot(self.installation, AUTHORIZED, now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        release.assert_not_called()

    @patch("aotg.autodev.pilot_installation._approved", return_value=True)
    @patch("aotg.autodev.pilot_installation.load_linear_authorization")
    @patch("aotg.autodev.pilot_installation.load_approvals", return_value=(object(),))
    @patch("aotg.autodev.pilot_installation.load_release")
    @patch("aotg.autodev.pilot_runtime._utc_now", return_value=NOW)
    def test_near_model_authorization_expiry_stops_before_credentials(
        self, clock, release, scopes, credentials, approval,
    ):
        release.return_value = Mock(
            base="1" * 40, issued_at=NOW - timedelta(seconds=10), expires_at=NOW + timedelta(hours=1),
        )
        authorization = replace(self.authorization, expires_at=NOW + timedelta(seconds=120))
        installation = replace(
            self.installation, codex=replace(self.installation.codex, model_authorization=authorization),
        )
        result = run_configured_pilot(installation, AUTHORIZED, boundary=self.boundary, now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        credentials.assert_not_called()

    @patch("aotg.autodev.pilot_installation._run_gh")
    def test_mutation_rechecks_host_after_github_precondition_read(self, github):
        quiet = Mock(return_value=True)
        boundary = PilotAttemptBoundary.from_deadline(monotonic_ns() + 180_000_000_000, quiet)
        prefix = ("gh", "api", "--hostname", "github.com", "--method")
        _run_github(boundary, (*prefix, "GET"), None, cwd=self.root, env={})
        quiet.return_value = False
        with self.assertRaises(PilotError):
            _run_github(boundary, (*prefix, "POST"), b"{}", cwd=self.root, env={})
        github.assert_called_once_with((*prefix, "GET"), None, cwd=self.root, env={})

    @patch("aotg.autodev.pilot_installation._post")
    @patch("aotg.autodev.pilot_runtime.monotonic_ns", return_value=0)
    def test_window_closing_between_remote_receipts_preserves_pending(self, clock, post):
        boundary = PilotAttemptBoundary.from_deadline(180_000_000_000, lambda: True)
        github = CommentTarget("github", "uobnnisiuk/AOTG#3", 3, 44, 55)
        linear = CommentTarget(
            "linear", "UOB-58", "10000000-0000-4000-8000-000000000000",
            "20000000-0000-4000-8000-000000000000", "30000000-0000-4000-8000-000000000000",
        )
        comments = {target: BOOTSTRAP_BODY for target in (github, linear)}

        def update(target, body, *, expected_body):
            self.assertEqual(comments[target], expected_body)
            if target == linear:
                _request_linear(boundary, "synthetic", _MUTATION, {"body": body})
            comments[target] = body
            if target == github:
                clock.return_value = 180_000_000_000

        transport = Mock()
        transport.read.side_effect = lambda target: CommentObservation(target, comments[target])
        transport.update.side_effect = update
        local = LocalResultSlot(self.root / "latest.json")
        slot = RemoteResultSlot(local, github, linear, transport)
        receipt = Result("claim_started", "reserved", "UOB-50", NOW.isoformat(), "1" * 40).redacted()
        with self.assertRaisesRegex(ResultSlotError, "Unconfirmed"):
            slot.write(receipt)
        post.assert_not_called()
        self.assertEqual(json.loads(slot.pending.read_bytes()), receipt)
        self.assertNotEqual(comments[github], BOOTSTRAP_BODY)
        self.assertEqual(comments[linear], BOOTSTRAP_BODY)
        self.assertFalse(local.path.exists())
        with self.assertRaisesRegex(ResultSlotError, "needs inspection"):
            slot.write(receipt)
        self.assertEqual(transport.update.call_count, 2)
