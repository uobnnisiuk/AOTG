"""Verify the outer start-to-stop budget without running a deployment."""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import patch

from aotg.autodev.pilot_supervisor import (
    SupervisorResult,
    _checkout_matches,
    _observe,
    _wsl_interop,
    supervise_pilot,
)

SHA = "a" * 40
START_NS = 10_000_000_000
UNIT = "aotg-pilot-0123456789abcdef.service"
PROGRAMS = ("/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/env", "/usr/bin/python3")


class SupervisorTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workdir = Path(temporary.name).resolve() / "checkout"
        self.home = self.workdir.parent / "home"
        self.runtime = self.workdir.parent / "runtime"
        self.source = self.workdir.parent / "pilot_supervisor.py"
        self.deploy = self.stub("_deployment", return_value=(PROGRAMS, self.home, self.runtime))
        self.trusted = self.stub("_trusted_supervisor", return_value=self.source)
        self.checkout_matches = self.stub("_checkout_matches", return_value=True)
        self.run = self.stub("_observe", return_value=(0, False))
        self.stop = self.stub("_stop")
        self.stub("secrets.token_hex", return_value="0123456789abcdef")
        self.stub("monotonic_ns", side_effect=[START_NS, START_NS + 300_000_000])
        self.stub("_wsl_interop", return_value=None)

    def stub(self, name, **options):
        target = patch("aotg.autodev.pilot_supervisor." + name, **options)
        self.addCleanup(target.stop)
        return target.start()

    def test_all_phases_share_outer_budget_and_fixed_child_arguments(self):
        result = supervise_pilot(self.workdir, expected_commit=SHA, probe=True)
        self.assertEqual(result, SupervisorResult("complete", 0))
        argv, env, watchdog_deadline = self.run.call_args.args
        self.assertEqual(argv[0], PROGRAMS[0])
        for option in (
            "--user", "--wait", "--collect", "--service-type=exec", f"--unit={UNIT}",
            "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
            "--property=FinalKillSignal=SIGKILL", "--property=Restart=no",
            "--property=StandardOutput=null", "--property=StandardError=null",
            "--property=Delegate=no", "--property=TimeoutStartSec=5s",
            "--property=RuntimeMaxSec=2374s", "--property=TimeoutStopSec=5s",
            "--property=RuntimeRandomizedExtraSec=0", "--property=NotifyAccess=none",
        ):
            self.assertIn(option, argv)
        self.assertIn(f"AOTG_PILOT_UNIT={UNIT}", argv)
        self.assertEqual(argv[argv.index("--") + 1:argv.index("--") + 5],
                         (PROGRAMS[2], "-i", "PATH=/usr/bin:/bin", "LANG=C.UTF-8"))
        self.assertEqual(argv[-7:-1], (str(self.source), "--child", "--deadline-ns",
                                      str(START_NS + 2_369_300_000_000), str(self.workdir), SHA))
        self.assertEqual(argv[-1], "--probe")
        self.assertEqual(watchdog_deadline, START_NS + 2_395_000_000_000)
        self.assertEqual(set(env), {
            "PATH", "LANG", "LC_ALL", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "SYSTEMD_COLORS",
        })
        self.stop.assert_not_called()
        self.checkout_matches.assert_called_once_with(
            self.workdir, SHA, deadline_ns=START_NS + 2_400_000_000_000,
        )

    def test_untrusted_arguments_do_not_reach_deployment_or_service(self):
        args = {"expected_commit": SHA, "probe": False, "timeout_seconds": 2400}
        for patch_args in (
            {"expected_commit": "0" * 40}, {"expected_commit": "--flag"}, {"probe": 1},
            {"timeout_seconds": True}, {"timeout_seconds": 2401}, {"timeout_seconds": 7},
        ):
            with self.subTest(patch_args=patch_args):
                self.assertEqual(supervise_pilot(self.workdir, **(args | patch_args)).status, "blocked")
        self.deploy.assert_not_called()
        self.run.assert_not_called()

    def test_unverified_deployment_does_not_start_service(self):
        self.deploy.side_effect = OSError("private example path")
        self.assertEqual(supervise_pilot(self.workdir, expected_commit=SHA), SupervisorResult("blocked"))
        self.run.assert_not_called()

    def test_unverified_checkout_does_not_start_service(self):
        self.checkout_matches.return_value = False
        self.assertEqual(supervise_pilot(self.workdir, expected_commit=SHA), SupervisorResult("blocked"))
        self.run.assert_not_called()

    def test_verified_service_timeout_has_fixed_status(self):
        self.run.return_value = (1, True)
        self.assertEqual(supervise_pilot(self.workdir, expected_commit=SHA), SupervisorResult("timeout", 1))
        self.assertNotIn("--probe", self.run.call_args.args[0])
        self.stop.assert_not_called()

    def test_unverified_outcome_stops_only_own_service(self):
        self.run.side_effect = subprocess.TimeoutExpired(("trusted",), 1)
        self.assertEqual(supervise_pilot(self.workdir, expected_commit=SHA), SupervisorResult("unconfirmed"))
        self.stop.assert_called_once()
        stop_program, unit, _, deadline = self.stop.call_args.args
        self.assertEqual((stop_program, unit), (PROGRAMS[1], UNIT))
        self.assertEqual(deadline, START_NS + 2_400_000_000_000)

    def test_nonzero_without_timeout_does_not_claim_completion(self):
        self.run.return_value = (2, False)
        self.assertEqual(supervise_pilot(self.workdir, expected_commit=SHA), SupervisorResult("unconfirmed", 2))
        self.stop.assert_called_once()


class InteropTests(TestCase):
    def test_untrusted_interop_socket_is_not_preserved(self):
        for value in ("", "/tmp/1_interop", "/run/WSL/../1_interop", "/run/WSL/1_interop\n"):
            with self.subTest(value=value), patch.dict(os.environ, {"WSL_INTEROP": value}, clear=True):
                self.assertIsNone(_wsl_interop())

    @skipUnless(sys.platform == "linux", "requires Linux socket metadata")
    def test_only_a_canonical_socket_owned_by_expected_identity_is_preserved(self):
        name = "/run/WSL/123_interop"
        with (
            patch.dict(os.environ, {"WSL_INTEROP": name}, clear=True),
            patch("aotg.autodev.pilot_supervisor._safe_path", return_value=True),
            patch("pathlib.Path.lstat", return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=0)),
        ):
            self.assertEqual(_wsl_interop(), name)


@skipUnless(sys.platform == "linux", "requires Linux pipe observation")
class StatusReaderTests(TestCase):
    def test_status_reader_reports_fixed_status_and_rejects_oversized_output(self):
        argv = (sys.executable, "-I", "-B", "-c", "print('Finished with result: timeout'); raise SystemExit(1)")
        self.assertEqual(_observe(argv, {}, monotonic_ns() + 5_000_000_000), (1, True))
        argv = (sys.executable, "-I", "-B", "-c", "print('x' * 5000)")
        with self.assertRaisesRegex(ValueError, "status size"):
            _observe(argv, {}, monotonic_ns() + 5_000_000_000)


@skipUnless(sys.platform == "linux" and hasattr(os, "geteuid") and os.geteuid() != 0
            and Path("/usr/bin/git").is_file(), "requires native non-root Linux and Git")
class BootstrapTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.source = self.root / "pilot_supervisor.py"
        shutil.copyfile(Path(__file__).resolve().parents[1] / "aotg" / "autodev" / self.source.name,
                        self.source)
        self.transport_env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null",
                              "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "--initial-branch=main")
        self.git("remote", "add", "origin", "https://github.com/uobnnisiuk/AOTG.git")
        self.git("config", "remote.origin.tagOpt", "--no-tags")
        self.implementation = self.checkout / "aotg" / "autodev" / "pilot_launch.py"
        self.implementation.parent.mkdir(parents=True)
        self.implementation.write_text("raise SystemExit(0)\n", encoding="ascii")
        (self.checkout / ".gitignore").write_text("ignored.txt\n__pycache__/\n", encoding="ascii")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture")
        self.commit = self.git("rev-parse", "HEAD").decode("ascii").strip()

    def git(self, *args):
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.checkout), *args], env=self.transport_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=5,
        ).stdout

    def child(self):
        return subprocess.run(
            (sys.executable, "-I", "-B", str(self.source), "--probe", "--child", "--deadline-ns",
             str(monotonic_ns() + 5_000_000_000), str(self.checkout), self.commit),
            cwd=self.checkout, env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=6,
        )

    def test_exact_clone_and_external_stdlib_bootstrap(self):
        self.assertTrue(_checkout_matches(self.checkout, self.commit))
        self.assertFalse(_checkout_matches(self.checkout, SHA))
        self.assertEqual(self.child().returncode, 0)

    def test_dirty_launcher_is_never_imported_even_if_index_hides_it(self):
        relative = self.implementation.relative_to(self.checkout)
        self.git("update-index", "--assume-unchanged", str(relative))
        self.implementation.write_text(
            "from pathlib import Path\nPath('started').touch()\nraise SystemExit(0)\n", encoding="ascii",
        )
        self.assertFalse(_checkout_matches(self.checkout, self.commit))
        self.assertEqual(self.child().returncode, 1)
        self.assertFalse((self.checkout / "started").exists())

    def test_ignored_bytecode_and_git_config_redirect_fail_closed(self):
        ignored = self.checkout / "ignored.txt"
        ignored.write_text("extra\n", encoding="ascii")
        self.assertFalse(_checkout_matches(self.checkout, self.commit))
        ignored.unlink()
        self.git("config", "include.path", str(self.root / "foreign-config"))
        self.assertFalse(_checkout_matches(self.checkout, self.commit))
