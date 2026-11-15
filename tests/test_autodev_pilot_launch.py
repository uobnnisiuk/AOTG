import os
import time
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from aotg.autodev import pilot_launch

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


if __name__ == "__main__":
    unittest.main()
