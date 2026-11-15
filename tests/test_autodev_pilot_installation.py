"""Check that installation reads the owner release before remote prerequisites."""

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from aotg.autodev.coordinator import Readiness
from aotg.autodev.isolated_process import CodexDeployment, ModelAuthorization
from aotg.autodev.pilot_installation import (
    PilotInstallation,
    _receipt_targets,
    run_configured_pilot,
)
from aotg.autodev.runtime_config import ConfigError

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
AUTHORIZED = Readiness(True, True, True, True)


class InstallationTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.installation = PilotInstallation(
            self.root, Path("/example/git"), Path("/example/gh"),
            CodexDeployment(Path("/example/codex"), "1" * 64, 99),
        )

    @patch("aotg.autodev.pilot_installation.load_release")
    def test_disabled_readiness_never_reads_release(self, release):
        result = run_configured_pilot(self.installation, Readiness(), now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        release.assert_not_called()

    @patch("aotg.autodev.pilot_installation._approved", return_value=True)
    @patch("aotg.autodev.pilot_installation.load_linear_authorization")
    @patch("aotg.autodev.pilot_installation.load_release", side_effect=ConfigError("missing"))
    def test_missing_release_never_reads_credentials(self, release, credentials, approval):
        result = run_configured_pilot(self.installation, AUTHORIZED, now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        release.assert_called_once_with(self.root / "config" / "first-pilot-release.json")
        credentials.assert_not_called()

    @patch("aotg.autodev.pilot_installation._approved", return_value=True)
    @patch("aotg.autodev.pilot_installation.load_linear_authorization")
    @patch("aotg.autodev.pilot_installation.load_approvals", return_value=())
    @patch("aotg.autodev.pilot_installation.load_release")
    def test_empty_registry_does_not_read_credentials(self, release, scopes, credentials, approval):
        release.return_value = Mock(base="1" * 40, expires_at=NOW + timedelta(hours=1))
        result = run_configured_pilot(self.installation, AUTHORIZED, now=NOW)
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
        result = run_configured_pilot(installation, AUTHORIZED, now=NOW)
        self.assertEqual(result.reason, "deployment-gate")
        credentials.assert_not_called()
