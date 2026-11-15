"""Exercise isolated launcher admission without invoking Codex or the model."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from aotg.autodev.isolated_process import (
    CodexDeployment,
    IsolatedProcess,
    ModelAuthorization,
    _approved,
    _profile,
)
from aotg.autodev.worker import RunResult, WorkerError

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
        self.deployment = CodexDeployment(self.native, "a" * 64, 2000, authorization())
        self.runner = Mock(side_effect=self._simulate_process)
        self.boundary = IsolatedProcess(self.deployment, runner=self.runner)
        self._patch("_trusted_codex", return_value=str(self.native))
        self.identity = self._patch("_workspace", side_effect=lambda checkout, _: (checkout, 5, 6))

    def _patch(self, name, **changes):
        target = patch("aotg.autodev.isolated_process." + name, **changes)
        self.addCleanup(target.stop)
        return target.start()

    @staticmethod
    def _simulate_process(argv, _checkout, **_options):
        if "sandbox" in argv and argv[-1] == "write":
            Path(argv[-3]).write_bytes(b"verified")
        return RunResult(0, False)

    def test_probe_requires_proof_and_network_is_offline(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        writable, read_only = self.runner.call_args_list
        for call in (writable, read_only):
            args = call.args[0]
            self.assertIn("--kill-child", args)
            self.assertIn("--mount-proc", args)
            self.assertIn("--map-current-user", args)
            self.assertIn("--net", args)
            self.assertIn("--include-managed-config", args)
            self.assertIn('":root"="deny"', args[args.index("-c") + 1])
            self.assertNotIn("exec", args)
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
        self.assertIn('web_search="disabled"', args)
        self.assertIn("mcp_servers={}", args)
        self.assertIn("features.apps=false", args)
        self.assertIn("allow_login_shell=false", args)
        self.assertIn('shell_environment_policy.inherit="none"', args)
        self.assertNotIn(PROMPT, args)
        self.assertEqual(kwargs["input_text"], PROMPT)
        self.assertEqual(set(kwargs["env"]), {"PATH", "LANG", "LC_ALL"})
        with self.assertRaisesRegex(WorkerError, "Explicit authorization"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.assertEqual(self.runner.call_count, 3)

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

    def test_verify_uses_read_only_checkout_and_independent_contract(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.boundary.verify(self.checkout, timeout_seconds=10, contract=CONTRACT)
        suite, independent = self.runner.call_args_list[2:]
        for call in (suite, independent):
            args = call.args[0]
            self.assertIn("--net", args)
            self.assertIn('":workspace_roots"={"."="read"}', args[args.index("-c") + 1])
            self.assertIn("TMPDIR", call.kwargs["env"])
            self.assertNotEqual(call.kwargs["env"]["TMPDIR"], str(self.checkout))
        self.assertNotEqual(suite.kwargs["env"]["TMPDIR"], independent.kwargs["env"]["TMPDIR"])
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
