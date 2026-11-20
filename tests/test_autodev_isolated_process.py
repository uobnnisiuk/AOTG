"""Exercise isolated launcher admission without invoking Codex or the model."""

import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import Mock, patch

from aotg.autodev.isolated_process import (
    _REJECTED_EXIT,
    _VERIFIER,
    CodexDeployment,
    IsolatedProcess,
    ModelAuthorization,
    _approved,
    _profile,
    _trusted_bwrap,
    _trusted_codex_home,
)
from aotg.autodev.pilot_worker import PILOT_CONTRACT
from aotg.autodev.worker import CandidateRejected, RunResult, WorkerError

PROMPT = "Approved public fixture task."
SHA = sha256(PROMPT.encode("utf-8")).hexdigest()
CONTRACT = "assert 2 + 2 == 4\n"


def pilot_grader(*, ignored_case=None, ignored_field=None):
    """A separate CLI fixture; mutants keep validation but omit one value field."""
    return f"ignored_case = {ignored_case!r}\nignored_field = {ignored_field!r}\n" + """
import json
import sys
from pathlib import Path

case = sys.argv[2]
catalog = json.loads(Path(sys.argv[4]).read_bytes())
spec = next(item for item in catalog["cases"] if item["id"] == case)
expected = spec["assertions"] if case == "cpp-half-open-interval" else spec["assertion_sequences"]

def valid(observations):
    if type(observations) is not list:
        return False
    if case == "cpp-half-open-interval":
        return all(
            type(item) is dict and set(item) == {"arguments", "result"}
            and type(item["result"]) is bool and type(item["arguments"]) is list
            and len(item["arguments"]) == 4
            and all(type(value) is int for value in item["arguments"])
            for item in observations
        )
    for group in observations:
        if (type(group) is not dict or set(group) != {"name", "operations"}
                or type(group["name"]) is not str or type(group["operations"]) is not list):
            return False
        for operation in group["operations"]:
            if type(operation) is not dict or type(operation.get("result")) is not bool:
                return False
            if set(operation) == {"try_register", "result"}:
                values = operation["try_register"]
                if type(values) is not list or not all(type(value) is str for value in values):
                    return False
            elif set(operation) == {"contains", "result"}:
                if type(operation["contains"]) is not str:
                    return False
            else:
                return False
    return True

def compared(value):
    if type(value) is list:
        return [compared(item) for item in value]
    if type(value) is dict:
        return {key: compared(item) for key, item in value.items()
                if not (case == ignored_case and key == ignored_field)}
    return value

try:
    request = json.load(sys.stdin)
except (ValueError, RecursionError):
    status = "malformed"
else:
    if type(request) is not dict:
        status = "malformed"
    elif type(request.get("timeout")) is bool and request["timeout"]:
        status = "timeout"
    elif "observations" not in request:
        status = "missing_observations"
    elif not valid(request["observations"]):
        status = "malformed"
    elif len(request["observations"]) < len(expected):
        status = "missing_observations"
    elif compared(request["observations"]) == compared(expected):
        status = "pass"
    else:
        status = "assertion_mismatch"
print(json.dumps({"version": 1, "case": case, "status": status}))
raise SystemExit(2 if status == "malformed" else 0)
"""


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
        self.bwrap = self.checkout.parent / "private-tools" / "bwrap"
        self.deployment = CodexDeployment(
            self.native, "a" * 64, 2000, authorization(), self.home, self.bwrap, "b" * 64,
        )
        self.offline_homes = []
        self.runner = Mock(side_effect=self._simulate_process)
        self.boundary = IsolatedProcess(self.deployment, runner=self.runner)
        self.model_client = self._patch("run_model_client", side_effect=self._simulate_model_client)
        self._patch("_trusted_codex", return_value=str(self.native))
        self.auth_home = self._patch("_trusted_codex_home", return_value=self.home)
        self.bwrap_pin = self._patch("_trusted_bwrap", return_value=self.bwrap)
        self.identity = self._patch("_workspace", side_effect=lambda checkout, _: (checkout, 5, 6))

    def _patch(self, name, **changes):
        target = patch("aotg.autodev.isolated_process." + name, **changes)
        self.addCleanup(target.stop)
        return target.start()

    @staticmethod
    def _simulate_model_client(argv, checkout, *, input_text, env, timeout_seconds, runner, sandbox_bin):
        return runner(
            argv, checkout, input_text=input_text, env=env, timeout_seconds=timeout_seconds,
            cancelled=lambda: False,
        )

    def _simulate_process(self, argv, _checkout, *, env, input_text, **_options):
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
            if argv[-4] == _VERIFIER:
                self._write_verdict(argv, input_text, "pass")
        return RunResult(0, False)

    def _write_verdict(self, argv, input_text, verdict, *, nonce=None):
        path = Path(argv[-3])
        if nonce is None:
            nonce = input_text.partition("\n")[0]
        path.write_text(f"{nonce} {verdict}\n", encoding="ascii", newline="\n")
        if os.name == "posix":
            path.chmod(0o600)
        return path

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
        self.model_client.assert_not_called()
        self.bwrap_pin.assert_not_called()
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
        self.model_client.assert_called_once()
        args, checkout = self.model_client.call_args.args
        kwargs = self.model_client.call_args.kwargs
        self.assertEqual(checkout, self.checkout)
        self.assertIs(kwargs["runner"], self.runner)
        self.assertEqual(kwargs["sandbox_bin"], self.bwrap.parent)
        self.assertEqual(args[0], str(self.native))
        self.assertIn("exec", args)
        self.assertNotIn("/usr/bin/unshare", args)
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
        self.bwrap_pin.assert_called_once_with(self.deployment, checkout=self.checkout)
        with self.assertRaisesRegex(WorkerError, "Explicit authorization"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.assertEqual(self.runner.call_count, 3)

    def test_egress_failure_has_no_model_fallback_and_consumes_the_attempt(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.model_client.side_effect = WorkerError("Egress unavailable")
        with self.assertRaisesRegex(WorkerError, "Egress unavailable") as failure:
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.assertNotIsInstance(failure.exception, CandidateRejected)
        with self.assertRaisesRegex(WorkerError, "Explicit authorization"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.model_client.assert_called_once()
        self.assertEqual(self.runner.call_count, 2)

    def test_missing_or_untrusted_bwrap_stops_before_model_launch(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.boundary.deployment = replace(self.deployment, bwrap=None)
        self.bwrap_pin.side_effect = _trusted_bwrap
        with self.assertRaisesRegex(WorkerError, "pinned bwrap"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)

        self.boundary.deployment = self.deployment
        self.bwrap_pin.side_effect = WorkerError("The pinned bwrap executable digest changed")
        with self.assertRaisesRegex(WorkerError, "digest changed"):
            self.boundary.generate(self.checkout, PROMPT, timeout_seconds=10)
        self.model_client.assert_not_called()
        self.assertEqual(self.runner.call_count, 2)

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
        def rejected(argv, checkout, *, input_text, **kwargs):
            self.assertEqual(argv[-2], "contract")
            self._write_verdict(argv, input_text, "reject")
            return RunResult(_REJECTED_EXIT, False)

        self.runner.side_effect = rejected
        with self.assertRaises(CandidateRejected):
            self.boundary.verify(self.checkout, timeout_seconds=10, contract=CONTRACT)

    def test_sandbox_startup_and_unverified_exit_remain_uncertain(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        self.runner.side_effect = None
        for exit_code in (0, 1, 2, _REJECTED_EXIT, -9):
            with self.subTest(exit_code=exit_code):
                self.runner.return_value = RunResult(exit_code, False)
                with self.assertRaises(WorkerError) as failure:
                    self.boundary.verify(self.checkout, timeout_seconds=10, contract=CONTRACT)
                self.assertNotIsInstance(failure.exception, CandidateRejected)

    def test_tampered_mismatched_or_lost_receipt_remains_uncertain(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        for fault in ("nonce", "verdict", "deleted", "exit"):
            def changed(argv, checkout, *, input_text, **kwargs):
                path = self._write_verdict(
                    argv, input_text, "pass" if fault == "verdict" else "reject",
                    nonce="0" * 64 if fault == "nonce" else None,
                )
                if fault == "deleted":
                    path.unlink()
                return RunResult(1 if fault == "exit" else _REJECTED_EXIT, False)

            self.runner.side_effect = changed
            with self.subTest(fault=fault), self.assertRaises(WorkerError) as result:
                self.boundary.verify(self.checkout, timeout_seconds=10, contract=CONTRACT)
            self.assertNotIsInstance(result.exception, CandidateRejected)

    def test_suite_exit_cannot_claim_independent_rejection(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        def rejected(argv, checkout, *, input_text, **kwargs):
            self.assertEqual(argv[-2], "suite")
            self._write_verdict(argv, input_text, "reject")
            return RunResult(_REJECTED_EXIT, False)

        self.runner.side_effect = rejected
        with self.assertRaises(WorkerError) as result:
            self.boundary.verify(self.checkout, timeout_seconds=10)
        self.assertNotIsInstance(result.exception, CandidateRejected)

    def test_verifier_timeout_has_precedence_over_rejection_evidence(self):
        self.boundary.preflight(self.checkout, timeout_seconds=10)
        def timed_out(argv, checkout, *, input_text, **kwargs):
            self._write_verdict(argv, input_text, "reject")
            return RunResult(_REJECTED_EXIT, True)

        self.runner.side_effect = timed_out
        with self.assertRaises(TimeoutError):
            self.boundary.verify(self.checkout, timeout_seconds=10, contract=CONTRACT)

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
        independent, suite = self.runner.call_args_list[2:]
        self.model_client.assert_not_called()
        self.bwrap_pin.assert_not_called()
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
        for call, mode, script in ((independent, "contract", CONTRACT), (suite, "suite", "")):
            self.assertEqual(call.args[0][-4], _VERIFIER)
            self.assertEqual(call.args[0][-2:], (mode, sha256(script.encode()).hexdigest()))
            nonce, _, configured = call.kwargs["input_text"].partition("\n")
            self.assertRegex(nonce, "^[a-f0-9]{64}$")
            self.assertEqual(configured, script)
            self.assertNotIn(nonce, call.args[0])
            self.assertNotIn(nonce, call.kwargs["env"].values())
        self.assertLessEqual(suite.kwargs["timeout_seconds"], independent.kwargs["timeout_seconds"])
        self.assertEqual(list(self.checkout.iterdir()), [])

    def test_profile_denies_external_read_and_model_command_network(self):
        profile = _profile(str(self.native), self.checkout, writable=True, scratch=False)
        for rule in ('":root"="deny"', '":minimal"="read"', '":tmpdir"="deny"',
                     '":slash_tmp"="deny"', '":workspace_roots"={"."="write"}',
                     "network={enabled=false}"):
            self.assertIn(rule, profile)


@skipUnless(sys.platform == "linux" and hasattr(os, "geteuid") and os.geteuid() != 0, "requires non-root Linux")
class BwrapPinTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="aotg-test-private-bin-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        self.checkout = root / "candidate"
        self.home = root / "config" / "codex"
        self.bin = root / "tools" / "private-bin"
        self.bin.parent.mkdir(mode=0o700)
        self.bin.mkdir(mode=0o700)

        # Keep real metadata inside the fixture while accounting for the
        # system's temporary directories, which can be shared.
        original_lstat = Path.lstat
        outside = frozenset(root.parents)

        def fixture_lstat(path):
            info = original_lstat(path)
            if path not in outside:
                return info
            return SimpleNamespace(
                st_mode=info.st_mode & ~0o022, st_uid=0, st_ino=info.st_ino,
                st_dev=info.st_dev, st_ctime_ns=info.st_ctime_ns,
            )

        self.enterContext(patch.object(Path, "lstat", fixture_lstat))
        self.bwrap = self.bin / "bwrap"
        native = Path(sys.executable).resolve().read_bytes()
        self.bwrap.write_bytes(native)
        self.bwrap.chmod(0o500)
        self.deployment = CodexDeployment(
            root / "unused-codex", "a" * 64, os.geteuid(),
            codex_home=self.home, bwrap=self.bwrap, bwrap_sha256=sha256(native).hexdigest(),
        )

    def test_only_the_pinned_binary_is_accepted(self):
        for mode in (0o500, 0o700):
            with self.subTest(mode=mode):
                self.bwrap.chmod(mode)
                self.assertEqual(_trusted_bwrap(self.deployment, checkout=self.checkout), self.bwrap)
        mismatched = replace(self.deployment, bwrap_sha256="f" * 64)
        with self.assertRaisesRegex(WorkerError, "digest changed"):
            _trusted_bwrap(mismatched, checkout=self.checkout)
        self.bwrap.chmod(0o755)
        with self.assertRaisesRegex(WorkerError, "private native"):
            _trusted_bwrap(self.deployment, checkout=self.checkout)

    def test_rejects_other_files_or_nonprivate_directory(self):
        extra = self.bin / "unexpected"
        extra.touch()
        with self.assertRaisesRegex(WorkerError, "must contain only"):
            _trusted_bwrap(self.deployment, checkout=self.checkout)
        extra.unlink()
        self.bin.chmod(0o755)
        with self.assertRaisesRegex(WorkerError, "could not be verified"):
            _trusted_bwrap(self.deployment, checkout=self.checkout)

    def test_rejects_pin_outside_deployment_or_below_writable_ancestor(self):
        outside = self.home.parent.parent.parent / "untrusted-bin" / "bwrap"
        with self.assertRaisesRegex(WorkerError, "inside the dedicated deployment"):
            _trusted_bwrap(replace(self.deployment, bwrap=outside), checkout=self.checkout)
        self.bin.parent.chmod(0o770)
        with self.assertRaisesRegex(WorkerError, "untrusted directory ancestors"):
            _trusted_bwrap(self.deployment, checkout=self.checkout)

    def test_rejects_binary_link_and_checkout_or_auth_overlap(self):
        for location in (self.checkout, self.home):
            with self.subTest(location=location), self.assertRaisesRegex(WorkerError, "outside"):
                _trusted_bwrap(replace(self.deployment, bwrap=location / "bwrap"), checkout=self.checkout)
        self.bwrap.unlink()
        self.bwrap.symlink_to(Path(sys.executable).resolve())
        with self.assertRaisesRegex(WorkerError, "canonical"):
            _trusted_bwrap(self.deployment, checkout=self.checkout)


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


@skipUnless(sys.platform == "linux" and os.geteuid() != 0, "requires non-root Linux")
class VerifierProcessTests(TestCase):
    @staticmethod
    def prepare_pilot(root, grader):
        (root / "aotg").mkdir()
        (root / "aotg" / "offline_bench.py").write_text(grader, encoding="utf-8")
        relative = Path("tests/fixtures/benchmark/catalog.json")
        catalog = root / relative
        catalog.parent.mkdir(parents=True)
        shutil.copyfile(Path(__file__).resolve().parents[1] / relative, catalog)

    def run_verifier(self, root, script, *, hashed_script=None):
        receipt = root / "verdict"
        nonce = "f" * 64
        digest = sha256((script if hashed_script is None else hashed_script).encode()).hexdigest()
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", _VERIFIER, str(receipt), "contract", digest],
            cwd=root, input=(nonce + "\n" + script).encode(), capture_output=True, timeout=8,
        )
        return result.returncode, receipt.read_bytes() if receipt.is_file() else None

    def test_only_explicit_trusted_checker_rejection_produces_receipt(self):
        for script, exit_code, verdict in (
            ("pass", 0, b"pass"),
            ("raise RejectCandidate()", _REJECTED_EXIT, b"reject"),
            ("raise SystemExit(1)", 1, None),
            ("raise SystemExit(42)", _REJECTED_EXIT, None),
        ):
            with self.subTest(script=script), TemporaryDirectory() as temporary:
                code, evidence = self.run_verifier(Path(temporary), script)
                self.assertEqual(code, exit_code)
                self.assertEqual(evidence, b"f" * 64 + b" " + verdict + b"\n" if verdict else None)

    def test_pilot_contract_accepts_a_value_comparing_cli_with_a_receipt(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare_pilot(root, pilot_grader())
            self.assertEqual(self.run_verifier(root, PILOT_CONTRACT), (0, b"f" * 64 + b" pass\n"))

    def test_pilot_contract_rejects_completed_cli_violations_with_a_receipt(self):
        grader_with_wrong_malformed_exit = """
import json
import sys
from pathlib import Path

case = sys.argv[2]
catalog = json.loads(Path(sys.argv[4]).read_bytes())
observations = next(item["assertions"] for item in catalog["cases"] if item["id"] == case)
try:
    request = json.load(sys.stdin)
except json.JSONDecodeError:
    status = "malformed"
else:
    if request.get("timeout"):
        status = "timeout"
    elif len(request["observations"]) < len(observations):
        status = "missing_observations"
    else:
        status = "pass"
print(json.dumps({"version": 1, "case": case, "status": status}))
"""
        for grader, exit_code, verdict in (
            (grader_with_wrong_malformed_exit, _REJECTED_EXIT, b"f" * 64 + b" reject\n"),
            ('print("debug\\n" + \'{"version": 1, "case": "cpp-half-open-interval", "status": "pass"}\')',
             _REJECTED_EXIT, b"f" * 64 + b" reject\n"),
            ("raise SystemExit(1)", 1, None),
        ):
            with self.subTest(exit_code=exit_code, grader=grader), TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.prepare_pilot(root, grader)
                self.assertEqual(self.run_verifier(root, PILOT_CONTRACT), (exit_code, verdict))

        for case, field in (
            ("cpp-half-open-interval", "result"),
            ("csharp-atomic-batch", "result"),
            ("cpp-half-open-interval", "arguments"),
            ("csharp-atomic-batch", "try_register"),
            ("csharp-atomic-batch", "contains"),
            ("csharp-atomic-batch", "name"),
        ):
            with self.subTest(case=case, ignored_field=field), TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.prepare_pilot(root, pilot_grader(ignored_case=case, ignored_field=field))
                self.assertEqual(self.run_verifier(root, PILOT_CONTRACT),
                                 (_REJECTED_EXIT, b"f" * 64 + b" reject\n"))

    def test_modified_checker_input_produces_no_receipt(self):
        with TemporaryDirectory() as temporary:
            self.assertEqual(self.run_verifier(Path(temporary), "pass", hashed_script="raise RejectCandidate()"),
                             (2, None))
