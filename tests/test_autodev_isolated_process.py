"""Exercise isolated launcher admission without invoking Codex or the model."""

import json
import os
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, skipUnless
from unittest.mock import Mock, patch

from aotg.autodev.isolated_process import (
    CodexDeployment,
    IsolatedProcess,
    ModelAuthorization,
    _approved,
    _profile,
    _trusted_codex_home,
)
from aotg.autodev.worker import CandidateRejected, RunResult, WorkerError

PROMPT = "Approved public fixture task."
SHA = sha256(PROMPT.encode("utf-8")).hexdigest()
CONTRACT = "assert 2 + 2 == 4\n"


def authorization(**changes):
    return replace(ModelAuthorization(
        model="approved-model",
        prompt_sha256=SHA,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        max_seconds=120,
        owner_approved=True,
        dedicated_chatgpt_login_verified=True,
        service_egress_verified=True,
        managed_tools_verified_disabled=True,
    ), **changes)


class BoundaryTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.checkout = Path(temp.name).resolve() / "candidate"
        self.checkout.mkdir()
        self.native = self.checkout.parent / "pinned-codex"
        self.home = self.checkout.parent / "config" / "codex"
        self.deployment = CodexDeployment(self.native, "a" * 64, 2000, authorization(), self.home)
        self.offline_homes = []
        self.runner = Mock(side_effect=self._simulate_process)
        self.boundary = IsolatedProcess(self.deployment, runner=self.runner)
        self._patch("_trusted_codex", return_value=str(self.native))
        self.auth_home = self._patch("_trusted_codex_home", return_value=self.home)
        self.identity = self._patch("_workspace", side_effect=lambda checkout, _: (checkout, 5, 6))

    def _patch(self, name, **changes):
        target = patch("aotg.autodev.isolated_process." + name, **changes)
        self.addCleanup(target.stop)
        return target.start()

    def _simulate_process(self, argv, _checkout, *, env, **_options):
        if "sandbox" in argv:
            home = Path(env["CODEX_HOME"])
            self.assertNotEqual(home, self.home)
            self.assertNotEqual(str(home), env.get("TMPDIR"))
            self.assertNotIn(home, self.offline_homes)
            self.assertEqual(list(home.iterdir()), [])
            if os.name == "posix":
                self.assertEqual(home.stat().st_mode & 0o777, 0o700)
            self.offline_homes.append(home)
            if argv[-1] == "write":
                Path(argv[-3]).write_bytes(b"verified")
        return RunResult(0, False)

    def _assert_offline_call(self, call):
        args = call.args[0]
        environment = call.kwargs["env"]
        self.assertIn("--net", args)
        self.assertIn('cli_auth_credentials_store="file"', args)
        self.assertNotIn("OPENAI_API_KEY", environment)
        home = Path(environment["CODEX_HOME"])
        self.assertFalse(home.exists())
        self.assertIn(json.dumps(str(home)) + '="deny"', args[args.index("-c") + 1])
        command = args.index("--", args.index("sandbox")) + 1
        self.assertEqual(args[command:command + 4], ("/usr/bin/env", "-u", "CODEX_HOME", "--"))

    def test_probe_requires_proof_and_network_is_offline(self):
        with patch.dict(os.environ, {"CODEX_HOME": str(self.home), "OPENAI_API_KEY": "synthetic"}):
            self.boundary.preflight(self.checkout, timeout_seconds=10)
        writable, read_only = self.runner.call_args_list
        for call in (writable, read_only):
            self._assert_offline_call(call)
            args = call.args[0]
            self.assertIn("--kill-child", args)
            self.assertIn("--mount-proc", args)
            self.assertIn("--map-current-user", args)
            self.assertIn("--net", args)
            self.assertIn("--include-managed-config", args)
            self.assertIn('":root"="deny"', args[args.index("-c") + 1])
            self.assertNotIn("exec", args)
        auth = Path(writable.args[0][-2])
        self.assertEqual(auth.name, "auth.json")
        self.assertEqual(Path(read_only.args[0][-3]), auth)
        self.assertNotEqual(read_only.kwargs["env"]["TMPDIR"], str(auth.parent))
        self.assertIn(json.dumps(str(auth.parent)) + '="deny"', read_only.args[0][read_only.args[0].index("-c") + 1])
        self.assertIn('":tmpdir"="write"', read_only.args[0][read_only.args[0].index("-c") + 1])
        self.assertEqual(writable.args[0][-1], "write")
        self.assertEqual(read_only.args[0][-2], "read")
        self.assertEqual(read_only.args[0][-1], read_only.kwargs["env"]["TMPDIR"])
        self.assertEqual(list(self.checkout.iterdir()), [])

    def test_unproven_or_changed_workspace_rejects_generation(self):
        with self.assertRaisesRegex(WorkerError, "Preflight"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.runner.assert_not_called()
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.identity.side_effect = lambda checkout, _: (checkout, 5, 7)
        with self.assertRaisesRegex(WorkerError, "Preflight"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.assertEqual(self.runner.call_count, 2)

    def test_exact_model_prompt_expiration_and_limits(self):
        self.assertTrue(_approved(authorization(), PROMPT, 120))
        for auth in (
            None, authorization(owner_approved=False), authorization(owner_approved=1),
            authorization(dedicated_chatgpt_login_verified=False),
            authorization(service_egress_verified=False),
            authorization(managed_tools_verified_disabled=False),
            authorization(prompt_sha256="b" * 64),
            authorization(max_seconds=119),
            authorization(expires_at=datetime.now(timezone.utc)),
            authorization(expires_at=datetime.now()),
            authorization(model="--unexpected"),
        ):
            with self.subTest(approval=auth):
                self.assertFalse(_approved(auth, PROMPT, 120))
        self.assertFalse(_approved(authorization(), "different", 120))

    def test_generate_requires_exact_prompt_and_consumes_one_attempt(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        with self.assertRaisesRegex(WorkerError, "Explicit authorization"):
            self.boundary.generate(self.checkout, "different", timeout_seconds=10)
        self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        args = self.runner.call_args.args[0]
        kwargs = self.runner.call_args.kwargs
        self.assertIn("exec", args)
        self.assertNotIn("--net", args)  # Service traffic enforced by the trusted deployment.
        self.assertNotIn("--sandbox", args)
        self.assertIn('default_permissions="aotg-pilot"', args)
        self.assertIn('forced_login_method="chatgpt"', args)
        self.assertIn('cli_auth_credentials_store="file"', args)
        self.assertIn('chatgpt_base_url="https://chatgpt.com/backend-api/"', args)
        self.assertIn('web_search="disabled"', args)
        self.assertIn("mcp_servers={}", args)
        self.assertIn("features.apps=false", args)
        self.assertIn("allow_login_shell=false", args)
        self.assertIn('shell_environment_policy.inherit="none"', args)
        self.assertNotIn(PROMPT, args)
        self.assertEqual(kwargs["input_text"], PROMPT)
        self.assertEqual(set(kwargs["env"]), {"PATH", "LANG", "LC_ALL", "CODEX_HOME"})
        self.assertEqual(kwargs["env"]["CODEX_HOME"], str(self.home))
        self.assertIn(json.dumps(str(self.home)) + '="deny"', "".join(args))
        self.auth_home.assert_called_once_with(self.deployment, checkout=self.checkout)
        with self.assertRaisesRegex(WorkerError, "Explicit authorization"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.assertEqual(self.runner.call_count, 3)

    def test_unverified_codex_home_stops_before_generation(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.auth_home.side_effect = WorkerError("Independent cache required")
        with self.assertRaisesRegex(WorkerError, "Independent cache"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.assertEqual(self.runner.call_count, 2)

    def test_probe_timeout_or_missing_proof_never_launches_model(self):
        for result, error in ((RunResult(-9, True), TimeoutError), (RunResult(0, False), WorkerError)):
            self.runner.side_effect = None
            self.runner.return_value = result
            with self.subTest(result=result), self.assertRaises(error):
                self.boundary.preflight(self.checkout, timeout_seconds=10)
            self.assertEqual(list(self.checkout.iterdir()), [])
            with self.assertRaisesRegex(WorkerError, "Preflight"):
                self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)

    def test_timeout_consumes_generation_attempt(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.runner.side_effect = None
        self.runner.return_value = RunResult(-9, True)
        with self.assertRaises(TimeoutError):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        with self.assertRaisesRegex(WorkerError, "Explicit authorization"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)

    def test_failed_independent_candidate_check_is_rejected(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.runner.side_effect = None
        self.runner.return_value = RunResult(1, False)
        with self.assertRaises(CandidateRejected):
            self.boundary.verify(self.checkout, timeout_seconds=10, contract=CONTRACT)

    def test_unknown_exit_in_candidate_check_remains_uncertain(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.runner.side_effect = None
        for exit_code in (2, -9):
            with self.subTest(exit_code=exit_code):
                self.runner.return_value = RunResult(exit_code, False)
                with self.assertRaises(WorkerError) as failure:
                    self.boundary.verify(self.checkout, timeout_seconds=10, contract=CONTRACT)
                self.assertNotIsInstance(failure.exception, CandidateRejected)

    def test_failed_generation_does_not_claim_candidate_rejection(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.runner.side_effect = None
        self.runner.return_value = RunResult(1, False)
        with self.assertRaises(WorkerError) as failure:
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.assertNotIsInstance(failure.exception, CandidateRejected)

    def test_verify_uses_read_only_checkout_and_independent_contract(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.boundary.verify(self.checkout, timeout_seconds=10, contract=CONTRACT)
        suite, independent = self.runner.call_args_list[2:]
        for call in (suite, independent):
            self._assert_offline_call(call)
            args = call.args[0]
            self.assertIn("--net", args)
            self.assertIn('":workspace_roots"={"."="read"}', args[args.index("-c") + 1])
            self.assertIn("TMPDIR", call.kwargs["env"])
            self.assertNotEqual(call.kwargs["env"]["TMPDIR"], str(self.checkout))
            self.assertIn(json.dumps(str(self.home)) + '="deny"', args[args.index("-c") + 1])
        self.assertNotEqual(suite.kwargs["env"]["TMPDIR"], independent.kwargs["env"]["TMPDIR"])
        self.assertEqual(len(self.offline_homes), 4)
        self.assertEqual(suite.args[0][-5:], ("-m", "unittest", "discover", "-s", "tests"))
        self.assertEqual(independent.args[0][-2:], ("-I", "-"))
        self.assertEqual(independent.kwargs["input_text"], CONTRACT)
        self.assertLessEqual(independent.kwargs["timeout_seconds"], suite.kwargs["timeout_seconds"])
        self.assertEqual(list(self.checkout.iterdir()), [])

    def test_profile_denies_external_read_and_model_command_network(self):
        profile = _profile(str(self.native), self.checkout, writable=True, scratch=False)
        for rule in ('":root"="deny"', '":minimal"="read"', '":tmpdir"="deny"',
                     '":slash_tmp"="deny"', '":workspace_roots"={"."="write"}',
                     "network={enabled=false}"):
            self.assertIn(rule, profile)


@skipUnless(sys.platform == "linux" and hasattr(os, "geteuid") and os.geteuid() != 0, "requires non-root Linux")
class CodexHomeTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        config = self.root / "config"
        config.mkdir(mode=0o700)
        self.home = config / "codex"
        self.home.mkdir(mode=0o700)
        self.auth = self.home / "auth.json"
        self.auth.write_bytes(b"synthetic test fixture")
        self.auth.chmod(0o600)
        self.deployment = CodexDeployment(self.root / "unused", "a" * 64, os.geteuid(), codex_home=self.home)

    def test_uses_metadata_only(self):
        with patch.object(Path, "open", side_effect=AssertionError("opened auth contents")):
            self.assertEqual(_trusted_codex_home(self.deployment), self.home)

    def test_missing_or_same_checkout_home_is_rejected(self):
        with self.assertRaisesRegex(WorkerError, "independent"):
            _trusted_codex_home(replace(self.deployment, codex_home=None))
        with self.assertRaisesRegex(WorkerError, "independent"):
            _trusted_codex_home(self.deployment, checkout=self.root)

    def test_linked_or_accessible_cache_is_rejected(self):
        link = self.home / "another-name"
        os.link(self.auth, link)
        with self.assertRaisesRegex(WorkerError, "not private"):
            _trusted_codex_home(self.deployment)
        link.unlink()
        self.auth.chmod(0o644)
        with self.assertRaisesRegex(WorkerError, "not private"):
            _trusted_codex_home(self.deployment)
