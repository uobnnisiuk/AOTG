"""Start the reviewed first pilot under the dedicated WSL supervisor."""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from aotg.artifacts import _unique_object

from .candidate_git import _trusted_executable
from .coordinator import Readiness
from .isolated_process import (
    CodexDeployment,
    ModelAuthorization,
    _trusted_codex,
    _trusted_codex_home,
)
from .ledger import _validate_path
from .pilot_installation import PilotInstallation, run_configured_pilot
from .pilot_runtime import PilotAttemptBoundary, _utc, load_release
from .pilot_supervisor import _checkout_matches
from .pilot_worker import PILOT_PROMPT
from .queue import POLICY
from .runtime_config import _private_bytes
from .task_definition import TASK_NAME
from .worker import MAX_RUNTIME_SECONDS

_UNIT = re.compile(r"aotg-pilot-[0-9a-f]{16}\.service")
_INTEROP = re.compile(r"/run/WSL/[0-9]+_interop")
_TIME_UNIT = {"min": 60_000_000, "s": 1_000_000, "ms": 1_000, "us": 1, "µs": 1}
_SERVICE_PROPERTIES = {
    "ActiveState": "active", "Type": "exec", "Restart": "no", "KillMode": "control-group",
    "Delegate": "no", "SendSIGKILL": "yes", "NotifyAccess": "none",
}
_SERVICE_TIMEOUTS = ("RuntimeMaxUSec", "TimeoutStartUSec", "TimeoutStopUSec")
_SERVICE_EXTRAS = {
    "RuntimeRandomizedExtraUSec": {"0", "0us", "0µs"},
    "KillSignal": {"15", "TERM", "SIGTERM"},
    "FinalKillSignal": {"9", "KILL", "SIGKILL"},
}
_POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
_ATTESTATIONS = frozenset({
    "dedicated-chatgpt-login", "chatgpt-plan-without-extra-charge",
    "provider-only-egress", "managed-tools-disabled",
})
_HOST_OBSERVATION = """
$ErrorActionPreference = 'Stop'
$query = @'
$ErrorActionPreference = 'Stop'
$tasks = @(Get-ScheduledTask)
$aotg = @($tasks | Where-Object { $_.TaskName -ceq '@TASK@' })
if ($aotg.Count -ne 1 -or $aotg[0].State.ToString() -cne 'Disabled' -or
    $aotg[0].Settings.Enabled) { return }
$others = @($tasks | Where-Object { $_.TaskName -match 'Footprint' })
if (!$others.Count) { return }
$until = (Get-Date).AddSeconds(@SECONDS@)
foreach ($task in $others) {
    if ($task.State.ToString() -ceq 'Disabled') { continue }
    if ($task.State.ToString() -cne 'Ready') { return }
    $next = (Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath).NextRunTime
    if ($next -isnot [DateTime] -or ($next.Year -ge 1900 -and $next -le $until)) { return }
}
'quiet'
'@
$reader = [PowerShell]::Create()
[void]$reader.AddScript($query)
$pending = $reader.BeginInvoke()
if (!$pending.AsyncWaitHandle.WaitOne(4000)) { [Environment]::Exit(2) }
$answer = $reader.EndInvoke($pending)
if ($reader.HadErrors -or $answer.Count -ne 1 -or "$($answer[0])" -cne 'quiet') { exit 1 }
[Console]::Write('quiet')
"""


def _microseconds(value):
    total = 0
    for piece in value.split():
        match = re.fullmatch(r"([0-9]{1,7})(min|ms|us|µs|s)", piece)
        if match is None:
            raise ValueError("Unknown service time")
        total += int(match[1]) * _TIME_UNIT[match[2]]
    if total <= 0:
        raise ValueError("Unknown service time")
    return total


def _supervised(environ, cgroup):
    unit = environ.get("AOTG_PILOT_UNIT", "")
    groups = [line[3:] for line in cgroup.splitlines() if line.startswith("0::/")]
    if not _UNIT.fullmatch(unit) or len(groups) != 1 or groups[0].rsplit("/", 1)[-1] != unit:
        return False
    properties = (*_SERVICE_PROPERTIES, *_SERVICE_TIMEOUTS, *_SERVICE_EXTRAS, "MainPID")
    response = subprocess.run(
        ["/usr/bin/systemctl", "--user", "--no-pager", "show", unit,
         *(f"--property={name}" for name in properties)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=3, check=False,
    )
    if response.returncode or len(response.stdout) > 2048:
        return False
    observed = {}
    for line in response.stdout.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in observed:
            return False
        observed[key] = value
    if observed.keys() != set(properties) or observed["MainPID"] != str(os.getpid()):
        return False
    if any(observed[key] != value for key, value in _SERVICE_PROPERTIES.items()):
        return False
    if any(observed[key] not in values for key, values in _SERVICE_EXTRAS.items()):
        return False
    duration = sum(_microseconds(observed[key]) for key in _SERVICE_TIMEOUTS)
    return duration < MAX_RUNTIME_SECONDS * 1_000_000


def _observe_windows(deadline_ns):
    """Check the disabled AOTG task and competing scheduled work through a fixed query."""
    seconds = (deadline_ns - time.monotonic_ns() + 999_999_999) // 1_000_000_000
    interop = os.environ.get("WSL_INTEROP", "")
    if not 8 <= seconds <= MAX_RUNTIME_SECONDS or not _INTEROP.fullmatch(interop):
        return False
    if not Path(interop).is_socket():
        return False
    script = _HOST_OBSERVATION.replace("@TASK@", TASK_NAME).replace("@SECONDS@", str(seconds))
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            [_POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            cwd="/", env={"PATH": "/usr/bin:/bin", "WSL_INTEROP": interop}, timeout=8,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout == b"quiet"


def _load_deployment(root, expected_commit):
    # The separate owner release authorizes a single scope. This file captures independent
    # safety checks made for the same release and exact dedicated runtime identity.
    config = root / "config"
    release = load_release(config / "first-pilot-release.json")
    now = datetime.now(timezone.utc)
    if release.base != expected_commit or not release.issued_at <= now < release.expires_at:
        raise ValueError("The current pilot release could not be verified")
    data = json.loads(_private_bytes(config / "pilot-deployment.json", 8192),
                      object_pairs_hook=_unique_object)
    fields = {
        "version", "policy", "base", "scope_digest", "uid", "codex", "codex_sha256",
        "gh", "model", "verified_at", "expires_at", "attestations",
    }
    if (
        type(data) is not dict or data.keys() != fields or type(data["version"]) is not int
        or data["version"] != 1 or data["policy"] != POLICY or data["base"] != expected_commit
        or data["scope_digest"] != release.scope_digest or type(data["uid"]) is not int
        or data["uid"] <= 0 or data["uid"] != os.geteuid()
        or type(data["attestations"]) is not list
        or len(data["attestations"]) != len(_ATTESTATIONS)
        or frozenset(data["attestations"]) != _ATTESTATIONS
    ):
        raise ValueError("The deployment safety evidence could not be verified")
    checked = _utc(data["verified_at"])
    expires = _utc(data["expires_at"])
    if not release.issued_at <= checked <= now < expires <= release.expires_at:
        raise ValueError("The deployment safety evidence is outside the owner release")
    credentials = config / "github"
    _validate_path(credentials, directory=True)
    gh = Path(data["gh"])
    git = Path("/usr/bin/git")
    _trusted_executable(git, "git")
    _trusted_executable(gh, "gh")
    authorization = ModelAuthorization(
        data["model"], hashlib.sha256(PILOT_PROMPT.encode("utf-8")).hexdigest(),
        expires, MAX_RUNTIME_SECONDS, owner_approved=True, dedicated_chatgpt_login_verified=True,
        service_egress_verified=True, managed_tools_verified_disabled=True,
    )
    codex = CodexDeployment(
        Path(data["codex"]), data["codex_sha256"], data["uid"], authorization,
        codex_home=config / "codex",
    )
    _trusted_codex(codex)
    _trusted_codex_home(codex)
    return PilotInstallation(root, git, gh, codex, gh_config_dir=credentials)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--deadline-ns", required=True, type=int)
    parser.add_argument("--probe", action="store_true")
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        return 1
    try:
        if not 0 < args.deadline_ns - time.monotonic_ns() <= MAX_RUNTIME_SECONDS * 1_000_000_000:
            return 1
        if not _supervised(os.environ, Path("/proc/self/cgroup").read_text(encoding="ascii")):
            return 1
        checkout = Path.cwd()
        if not _checkout_matches(checkout, args.expected_commit):
            return 1
        if args.probe:
            return 0 if _observe_windows(args.deadline_ns) else 1
        installation = _load_deployment(checkout.parent, args.expected_commit)
        boundary = PilotAttemptBoundary.from_deadline(
            args.deadline_ns, lambda: _observe_windows(args.deadline_ns),
        )
        result = run_configured_pilot(
            installation, Readiness(True, True, True, True), boundary=boundary,
        )
        return 0 if result.status == "draft_pr" else 1
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, RuntimeError):
        # Remote results and the private ledger are authoritative, especially on interruption.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
