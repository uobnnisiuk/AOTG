import json
import os
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import patch

from aotg.autodev import pilot_launch
from aotg.autodev.worker import WorkerError

SHA = "8" * 40
UNIT = "aotg-pilot-0123456789abcdef.service"
CGROUP = f"0::/user.slice/app.slice/{UNIT}\n"


class PilotLaunchTests(unittest.TestCase):
    def test_rejects_a_marker_outside_its_unit(self):
        with patch.object(pilot_launch.subprocess, "run") as observe:
            self.assertFalse(pilot_launch._supervised({"AOTG_PILOT_UNIT": UNIT}, "0::/user.slice/other.service"))
        observe.assert_not_called()

    def test_checks_effective_runtime_and_cleanup(self):
        def observation(runtime, *, extra="0", final_signal="9"):
            values = {
                "ActiveState": "active", "Type": "exec", "Restart": "no", "KillMode": "control-group",
                "Delegate": "no", "SendSIGKILL": "yes", "NotifyAccess": "none", "MainPID": str(os.getpid()),
                "RuntimeMaxUSec": runtime, "TimeoutStartUSec": "5s", "TimeoutStopUSec": "5s",
                "RuntimeRandomizedExtraUSec": extra, "KillSignal": "15", "FinalKillSignal": final_signal,
            }
            return CompletedProcess([], 0, b"".join(f"{k}={v}\n".encode() for k, v in values.items()))

        with patch.object(pilot_launch.subprocess, "run") as observe:
            observe.return_value = observation("39min 35s")
            self.assertTrue(pilot_launch._supervised({"AOTG_PILOT_UNIT": UNIT}, CGROUP))
            observe.return_value = observation("40min")
            self.assertFalse(pilot_launch._supervised({"AOTG_PILOT_UNIT": UNIT}, CGROUP))
            observe.return_value = observation("38min", extra="2min")
            self.assertFalse(pilot_launch._supervised({"AOTG_PILOT_UNIT": UNIT}, CGROUP))
            observe.return_value = observation("38min", final_signal="15")
            self.assertFalse(pilot_launch._supervised({"AOTG_PILOT_UNIT": UNIT}, CGROUP))
            observe.return_value = observation("infinity")
            self.assertRaises(ValueError, pilot_launch._supervised, {"AOTG_PILOT_UNIT": UNIT}, CGROUP)

    def test_no_windows_observation_without_interop(self):
        with patch.dict(pilot_launch.os.environ, {}, clear=True), patch.object(pilot_launch.subprocess, "run") as run:
            self.assertFalse(pilot_launch._observe_windows(time.monotonic_ns() + 5_000_000_000))
        run.assert_not_called()

    def test_windows_requires_exact_success_sentinel(self):
        with (
            patch.dict(pilot_launch.os.environ, {"WSL_INTEROP": "/run/WSL/42_interop"}),
            patch.object(Path, "is_socket", return_value=True),
            patch.object(pilot_launch.subprocess, "run") as run,
        ):
            deadline = time.monotonic_ns() + 15_000_000_000
            run.return_value = CompletedProcess([], 1, b"quiet")
            self.assertFalse(pilot_launch._observe_windows(deadline))
            run.return_value = CompletedProcess([], 0, b"unverified")
            self.assertFalse(pilot_launch._observe_windows(deadline))
            run.return_value = CompletedProcess([], 0, b"quiet")
            self.assertTrue(pilot_launch._observe_windows(deadline))

    def test_probe_has_no_deployment_or_remote_operation(self):
        with (
            patch.object(pilot_launch.sys, "platform", "linux"),
            patch.object(Path, "read_text", return_value=CGROUP),
            patch.object(pilot_launch, "_supervised", return_value=True),
            patch.object(pilot_launch, "_checkout_matches", return_value=True),
            patch.object(pilot_launch, "_observe_windows", return_value=True),
            patch.object(pilot_launch, "_load_deployment") as load,
            patch.object(pilot_launch, "run_configured_pilot") as start,
        ):
            deadline = str(time.monotonic_ns() + 30_000_000_000)
            self.assertEqual(pilot_launch.main(["--expected-commit", SHA, "--deadline-ns", deadline, "--probe"]), 0)
        load.assert_not_called()
        start.assert_not_called()

    def test_expired_budget_or_missing_deployment_block_live_path(self):
        with (
            patch.object(pilot_launch.sys, "platform", "linux"),
            patch.object(Path, "read_text", return_value=CGROUP),
            patch.object(pilot_launch, "_supervised", return_value=True),
            patch.object(pilot_launch, "_checkout_matches", return_value=True),
            patch.object(pilot_launch, "_load_deployment", side_effect=ValueError("unavailable")) as load,
            patch.object(pilot_launch, "run_configured_pilot") as start,
        ):
            expired = str(time.monotonic_ns() - 1)
            self.assertEqual(pilot_launch.main(["--expected-commit", SHA, "--deadline-ns", expired]), 1)
            load.assert_not_called()
            deadline = str(time.monotonic_ns() + 30_000_000_000)
            self.assertEqual(pilot_launch.main(["--expected-commit", SHA, "--deadline-ns", deadline]), 1)
            load.assert_called_once()
        start.assert_not_called()

    def test_deployment_verifies_fixed_private_codex_home_and_bwrap(self):
        root = Path.cwd() / "aotg-deployment-fixture"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        release = SimpleNamespace(
            base=SHA, scope_digest="a" * 64, issued_at=now - timedelta(minutes=10),
            expires_at=now + timedelta(hours=1),
        )
        data = {
            "version": 1, "policy": pilot_launch.POLICY, "base": SHA, "scope_digest": release.scope_digest,
            "uid": 2000, "codex": "/example/codex", "codex_sha256": "b" * 64, "gh": "/example/gh",
            "bwrap": "/example/private-bin/bwrap", "bwrap_sha256": "c" * 64,
            "model": "approved-model", "verified_at": release.issued_at.isoformat(timespec="seconds"),
            "expires_at": release.expires_at.isoformat(timespec="seconds"),
            "attestations": sorted(pilot_launch._ATTESTATIONS),
        }
        with (
            patch.object(pilot_launch, "load_release", return_value=release),
            patch.object(pilot_launch, "_private_bytes", return_value=json.dumps(data).encode()) as records,
            patch.object(pilot_launch.os, "geteuid", return_value=2000, create=True),
            patch.object(pilot_launch, "_validate_path"),
            patch.object(pilot_launch, "_trusted_executable"),
            patch.object(pilot_launch, "_trusted_codex"),
            patch.object(pilot_launch, "_trusted_codex_home") as home,
            patch.object(pilot_launch, "_trusted_bwrap") as bwrap,
        ):
            installation = pilot_launch._load_deployment(root, SHA)
            self.assertEqual(installation.codex.codex_home, root / "config" / "codex")
            self.assertEqual(installation.gh_config_dir, root / "config" / "github")
            self.assertEqual(installation.codex.bwrap, Path(data["bwrap"]))
            self.assertEqual(installation.codex.bwrap_sha256, data["bwrap_sha256"])
            records.assert_called_once_with(root / "config" / "pilot-deployment.json", 8192)
            home.assert_called_once_with(installation.codex)
            bwrap.assert_called_once_with(installation.codex, checkout=root / "checkout")
            bwrap.side_effect = WorkerError("Untrusted sandbox pin")
            with self.assertRaisesRegex(WorkerError, "Untrusted sandbox pin"):
                pilot_launch._load_deployment(root, SHA)
            bwrap.side_effect = None
            bwrap.reset_mock()
            for field in ("bwrap", "bwrap_sha256"):
                invalid = {name: value for name, value in data.items() if name != field}
                records.return_value = json.dumps(invalid).encode()
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "could not be verified"):
                    pilot_launch._load_deployment(root, SHA)
            bwrap.assert_not_called()
            records.return_value = json.dumps(data).encode()
            home.side_effect = WorkerError("Dedicated login unavailable")
            with self.assertRaisesRegex(WorkerError, "Dedicated login"):
                pilot_launch._load_deployment(root, SHA)


if __name__ == "__main__":
    unittest.main()
