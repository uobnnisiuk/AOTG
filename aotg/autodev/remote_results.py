"""Publish the canonical AutoDev receipt to two pre-provisioned comment slots."""

import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from .ledger import LedgerError, _sync_directory
from .result_slot import LocalResultSlot, ResultSlotError, _payload, _present

BOOTSTRAP_BODY = "`AOTG-AUTODEV-V1/result`"
_GITHUB_ISSUE = "uobnnisiuk/AOTG#3"
_LINEAR_ISSUE = "UOB-58"


@dataclass(frozen=True, slots=True)
class CommentTarget:
    """Configured identity of an existing comment and its issue and owner."""

    provider: str
    issue: str
    issue_id: int | str
    comment_id: int | str
    author_id: int | str


@dataclass(frozen=True, slots=True)
class CommentObservation:
    """Comment identity and body parsed from independently fetched metadata."""

    target: CommentTarget
    body: str


class CommentTransport(Protocol):
    def read(self, target: CommentTarget) -> CommentObservation: ...

    def update(self, target: CommentTarget, body: str, *, expected_body: str) -> None:
        """Revalidate identity and prior body and perform at most one update."""
        ...


def _positive_number(value):
    return type(value) is int and value > 0


def _canonical_uuid(value):
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return parsed.int != 0 and str(parsed) == value


def _valid_target(target, provider):
    if type(target) is not CommentTarget or target.provider != provider:
        return False
    ids = target.issue_id, target.comment_id, target.author_id
    if provider == "github":
        return target.issue == _GITHUB_ISSUE and target.issue_id == 3 and all(
            _positive_number(value) for value in ids
        )
    return target.issue == _LINEAR_ISSUE and all(_canonical_uuid(value) for value in ids)


def _body(result):
    if result is None:
        return BOOTSTRAP_BODY
    return BOOTSTRAP_BODY + "\n\n```json\n" + _payload(result).decode("ascii") + "```"


class RemoteResultSlot:
    """Keep a local receipt consistent with existing GitHub and Linear slots.

    The comments must have a single configured writer. Remote edits across the
    two services are not transactional. A durable pending record blocks later
    runs after any unverified or interrupted write.
    """

    def __init__(self, local: LocalResultSlot, github: CommentTarget, linear: CommentTarget,
                 transport: CommentTransport):
        if not _valid_target(github, "github") or not _valid_target(linear, "linear"):
            raise ResultSlotError("Invalid remote receipt targets")
        self.local = local
        self.targets = (github, linear)
        self.transport = transport
        self.lock = local.path.with_suffix(".remote-lock")
        self.pending = local.path.with_suffix(".remote-pending")

    @contextmanager
    def _exclusive(self):
        try:
            self.local._validate_parent()
            fd = os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.close(fd)
                if _present(self.pending):
                    raise ResultSlotError("A prior remote receipt write needs inspection")
                yield
            finally:
                self.lock.unlink()
                _sync_directory(self.lock.parent)
        except ResultSlotError:
            raise
        except (OSError, LedgerError) as exc:
            raise ResultSlotError("Cannot verify exclusive access to the remote receipt") from exc

    def _read_comment(self, target):
        try:
            comment = self.transport.read(target)
        except Exception:
            raise ResultSlotError("Cannot verify the remote receipt comment") from None
        if (
            type(comment) is not CommentObservation
            or not _valid_target(comment.target, target.provider)
            or comment.target != target
            or type(comment.body) is not str
        ):
            raise ResultSlotError("Unexpected remote receipt identity or body")
        return comment.body

    def _require_receipts(self, body):
        for target in self.targets:
            if self._read_comment(target) != body:
                raise ResultSlotError("Remote receipt differs from recorded local state")

    def _pending_write(self, payload):
        descriptor = os.open(self.pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _sync_directory(self.pending.parent)

    def _publish(self, target, prior, new):
        if self._read_comment(target) != prior:
            raise ResultSlotError("Remote receipt changed before publication")
        try:
            self.transport.update(target, new, expected_body=prior)
        except Exception:
            # A failed response can still represent an applied write. Read once;
            # never issue a second update to reconcile uncertainty.
            pass
        if self._read_comment(target) != new:
            raise ResultSlotError("Unconfirmed remote receipt update")

    def write(self, result):
        payload = _payload(result)
        next_body = _body(result)
        with self._exclusive():
            previous = self.local.read() if _present(self.local.path) else None
            prior_body = _body(previous)
            self._require_receipts(prior_body)
            if previous == result:
                return
            if previous is not None:
                if previous["time_utc"] > result["time_utc"]:
                    raise ResultSlotError("Cannot replace a newer result")
                if previous["time_utc"] == result["time_utc"] and (
                    previous["status"] != "claim_started"
                    or result["status"] not in {"draft_pr", "blocked", "unknown"}
                    or previous["issue"] != result["issue"]
                    or previous["base"] != result["base"]
                ):
                    raise ResultSlotError("Unexpected result transition at the same attempt time")
            self._pending_write(payload)
            for target in self.targets:
                self._publish(target, prior_body, next_body)
            self._require_receipts(next_body)
            self.local.write(result)
            if self.local.read() != result:
                raise ResultSlotError("Unconfirmed local receipt update")
            self.pending.unlink()
            _sync_directory(self.pending.parent)

    def read(self):
        with self._exclusive():
            result = self.local.read()
            self._require_receipts(_body(result))
            return result
