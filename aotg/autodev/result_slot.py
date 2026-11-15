"""A local mirror of the latest redacted AutoDev result."""

import json
import os
import re
from datetime import datetime
from pathlib import Path

from aotg.artifacts import canonical_json

from .ledger import LedgerError, _sync_directory, _validate_path

_FIELDS = {"policy", "status", "reason", "issue", "time_utc", "base", "head", "pr"}
_MAX_BYTES = 1024
_SHA = re.compile(r"[0-9a-f]{40}")
_ISSUE = re.compile(r"UOB-[1-9][0-9]{0,8}")
_REASONS = {
    "awaiting_initial_work": {"initial-pr-not-merged"},
    "empty_queue": {"no-eligible-approved-issue"},
    "claim_started": {"reserved"},
    "draft_pr": {"draft-verified"},
    "blocked": {
        "active", "already-attempted", "ambiguous-approval", "approval-scope-changed",
        "candidate-already-claimed", "candidate-rejected", "daily-limit",
        "dependencies-incomplete", "deployment-gate", "lock-busy", "minimum-spacing",
        "open-pr", "prepublication-changed", "separate-approval-required", "shadow-eligible",
        "snapshot-changed", "trusted-linear-approval-source-not-configured",
        "unverified-approval", "worker-timeout",
    },
    "unknown": {
        "approval-issue-missing", "branch-unconfirmed", "claim-result-unconfirmed",
        "contradictory-issue-evidence", "draft-unconfirmed", "github-evidence-unavailable",
        "ledger-unavailable", "linear-evidence-unavailable", "prepublication-state-unconfirmed",
        "reservation-unconfirmed", "result-unconfirmed", "snapshot-unavailable",
        "worker-result-unconfirmed",
    },
}


class ResultSlotError(ValueError):
    """A local result could not be stored or verified."""


def _payload(result: dict) -> bytes:
    if type(result) is not dict or result.keys() != _FIELDS:
        raise ResultSlotError("Unexpected result fields")
    status, reason = result["status"], result["reason"]
    if (
        result["policy"] != "AOTG-AUTODEV-V1"
        or type(status) is not str
        or type(reason) is not str
        or reason not in _REASONS.get(status, ())
    ):
        raise ResultSlotError("Unknown result status or reason")
    timestamp = result["time_utc"]
    try:
        date = datetime.fromisoformat(timestamp)
        if not timestamp.endswith("+00:00") or date.isoformat(timespec="seconds") != timestamp:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ResultSlotError("Invalid result time") from exc
    issue, base, head, pr = (result[field] for field in ("issue", "base", "head", "pr"))
    if issue is not None and (type(issue) is not str or not _ISSUE.fullmatch(issue)):
        raise ResultSlotError("Invalid result issue")
    for sha in (base, head):
        if sha is not None and (type(sha) is not str or not _SHA.fullmatch(sha) or sha == "0" * 40):
            raise ResultSlotError("Invalid result revision")
    if pr is not None and (type(pr) is not int or not 1 <= pr <= 2_147_483_647):
        raise ResultSlotError("Invalid result pull request")
    if (issue is None) != (base is None):
        raise ResultSlotError("Incomplete result claim")
    if status in {"claim_started", "draft_pr"} and issue is None:
        raise ResultSlotError("Missing result claim")
    has_draft = head is not None or pr is not None
    if status == "draft_pr" or has_draft:
        if (
            issue is None or head is None or pr is None or head == base
            or (status != "draft_pr" and reason not in {"draft-unconfirmed", "result-unconfirmed"})
        ):
            raise ResultSlotError("Incomplete or unexpected draft result")
    return (canonical_json(result) + "\n").encode("ascii")


def _present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


class LocalResultSlot:
    """Store one canonical result in an existing private directory on local disk."""

    def __init__(self, path: str | Path):
        location = Path(path)
        if ".." in location.parts or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}\.json", location.name):
            raise ResultSlotError("Invalid result slot path")
        self.path = location.absolute()
        self.lock = self.path.with_suffix(".lock")
        self.pending = self.path.with_suffix(".pending")

    def _validate_parent(self) -> None:
        for parent in reversed(self.path.parent.parents):
            _validate_path(parent, directory=True, private=False)
        _validate_path(self.path.parent, directory=True)

    def _read(self) -> dict:
        _validate_path(self.path, directory=False)
        with self.path.open("rb") as stream:
            payload = stream.read(_MAX_BYTES + 1)
        if len(payload) > _MAX_BYTES:
            raise ResultSlotError("Result exceeds the slot limit")
        result = json.loads(payload.decode("ascii"))
        if _payload(result) != payload:
            raise ResultSlotError("Noncanonical result state")
        return result

    def read(self) -> dict:
        try:
            self._validate_parent()
            if _present(self.lock) or _present(self.pending):
                raise ResultSlotError("Unconfirmed result update")
            return self._read()
        except ResultSlotError:
            raise
        except (OSError, ValueError, RecursionError) as exc:
            raise ResultSlotError("Cannot verify result state") from exc

    def write(self, result: dict) -> None:
        payload = _payload(result)
        try:
            self._validate_parent()
            descriptor = os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.close(descriptor)
                if _present(self.pending):
                    raise ResultSlotError("Unconfirmed result update")
                if _present(self.path):
                    self._read()
                descriptor = os.open(self.pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(self.pending, self.path)
                    _sync_directory(self.path.parent)
                    if _payload(self._read()) != payload:
                        raise ResultSlotError("Result read-back mismatch")
                finally:
                    self.pending.unlink(missing_ok=True)
            finally:
                self.lock.unlink()
                _sync_directory(self.path.parent)
        except ResultSlotError:
            raise
        except (LedgerError, OSError, ValueError, RecursionError) as exc:
            raise ResultSlotError("Cannot publish local result") from exc
