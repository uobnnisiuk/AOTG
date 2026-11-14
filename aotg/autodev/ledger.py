"""Durable admission records for the dedicated AOTG worker."""

import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

from aotg.artifacts import read_artifact

JST = timezone(timedelta(hours=9))
MIN_INTERVAL = timedelta(hours=3)
MAX_PER_DAY = 2
OUTCOMES = frozenset({"success", "failure", "timeout", "unknown"})
_LOCK_NAME = "reservation.lock"
_ISSUE = r"UOB-[1-9][0-9]{0,8}"
_RECORD_NAME = re.compile(rf"({_ISSUE})\.(reservation|outcome)\.json")


class LedgerError(ValueError):
    """The ledger or request could not be verified."""


class ReservationBlocked(LedgerError):
    """An otherwise valid request must wait or has already been attempted."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Reservation:
    issue: str
    started_at: str


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise LedgerError("A timezone-aware start time is required")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _request(issue: str, started_at: datetime) -> Reservation:
    if not isinstance(issue, str) or not re.fullmatch(_ISSUE, issue):
        raise LedgerError("A valid AOTG issue identifier is required")
    return Reservation(issue, _timestamp(started_at))


def _instant(value: object) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            pass
        else:
            if _timestamp(parsed) == value:
                return parsed
    raise LedgerError("Invalid ledger timestamp")


def _validate_path(path: Path, directory: bool, *, private: bool = True) -> None:
    details = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    is_reparse_point = bool(
        getattr(details, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )
    if not expected(details.st_mode) or is_reparse_point:
        raise LedgerError("Unexpected link or file type in the ledger path")
    if private and os.name == "posix":
        mode = 0o700 if directory else 0o600
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != mode:
            raise LedgerError("The ledger is not private to the current user")
    if not directory and details.st_nlink != 1:
        raise LedgerError("Unexpected link count in a ledger record")


def _sync_directory(path: Path) -> None:
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _publish(path: Path, value: dict) -> None:
    temporary = None
    try:
        with NamedTemporaryFile(dir=path.parent, prefix=".pending-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write((json.dumps(value, sort_keys=True) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            os.rename(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    _sync_directory(path.parent)


class Ledger:
    """One pending run at a time, with immutable reservation and outcome files."""

    def __init__(self, root: str | Path):
        path = Path(root)
        if ".." in path.parts:
            raise LedgerError("The ledger path must not traverse parent directories")
        self.root = path.absolute()

    def _root_exists(self) -> bool:
        for parent in reversed(self.root.parents):
            _validate_path(parent, directory=True, private=False)
        try:
            _validate_path(self.root, directory=True)
        except FileNotFoundError:
            return False
        return True

    @contextmanager
    def _locked(self, *, create: bool):
        try:
            if not self._root_exists():
                if not create:
                    raise LedgerError("Unknown reservation")
                try:
                    self.root.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                else:
                    _sync_directory(self.root.parent)
                _validate_path(self.root, directory=True)
            lock = self.root / _LOCK_NAME
            try:
                descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as exc:
                raise ReservationBlocked("lock-busy") from exc
            try:
                os.close(descriptor)
                yield
            finally:
                lock.unlink()
                _sync_directory(self.root)
        except OSError as exc:
            raise LedgerError("Ledger I/O failure") from exc

    def _state(self, *, locked: bool) -> dict[str, tuple[Reservation, str | None]]:
        reservations = {}
        outcomes = {}
        for path in self.root.iterdir():
            if path.name == _LOCK_NAME:
                if not locked:
                    raise ReservationBlocked("lock-busy")
                _validate_path(path, directory=False)
                continue
            match = _RECORD_NAME.fullmatch(path.name)
            if not match:
                raise LedgerError("Unexpected file in ledger")
            issue, kind = match.groups()
            _validate_path(path, directory=False)
            row = read_artifact(path)
            fields = {"version", "issue", "started_at"}
            if kind == "outcome":
                fields.add("outcome")
            if row.keys() != fields or type(row["version"]) is not int or row["version"] != 1:
                raise LedgerError("Unexpected ledger record format")
            if row["issue"] != issue:
                raise LedgerError("Ledger filename does not match its record")
            _instant(row["started_at"])
            if kind == "reservation":
                reservations[issue] = Reservation(issue, row["started_at"])
            else:
                if not isinstance(row["outcome"], str) or row["outcome"] not in OUTCOMES:
                    raise LedgerError("Invalid ledger outcome")
                outcomes[issue] = row
        for issue, row in outcomes.items():
            if issue not in reservations or row["started_at"] != reservations[issue].started_at:
                raise LedgerError("Outcome does not match a reservation")
        state = {
            issue: (reservation, outcomes.get(issue, {}).get("outcome"))
            for issue, reservation in reservations.items()
        }
        self._validate_history(state)
        return state

    @staticmethod
    def _validate_history(state: dict[str, tuple[Reservation, str | None]]) -> None:
        previous = None
        daily_counts = {}
        entries = [(_instant(record.started_at), outcome) for record, outcome in state.values()]
        entries.sort(key=lambda entry: entry[0])
        for index, (started_at, outcome) in enumerate(entries):
            if previous is not None and started_at - previous < MIN_INTERVAL:
                raise LedgerError("Recorded starts violate minimum spacing")
            previous = started_at
            day = started_at.astimezone(JST).date()
            daily_counts[day] = daily_counts.get(day, 0) + 1
            if daily_counts[day] > MAX_PER_DAY:
                raise LedgerError("Recorded starts exceed the daily limit")
            if outcome in (None, "unknown") and index != len(entries) - 1:
                raise LedgerError("A run followed an unresolved reservation")

    @staticmethod
    def _admit(state: dict[str, tuple[Reservation, str | None]], request: Reservation) -> None:
        if request.issue in state:
            raise ReservationBlocked("already-attempted")
        if any(outcome in (None, "unknown") for _, outcome in state.values()):
            raise ReservationBlocked("active")
        start = _instant(request.started_at)
        past = sorted(_instant(reservation.started_at) for reservation, _ in state.values())
        if past and start < past[-1]:
            raise LedgerError("Clock predates an earlier reservation")
        day = start.astimezone(JST).date()
        if sum(time.astimezone(JST).date() == day for time in past) >= MAX_PER_DAY:
            raise ReservationBlocked("daily-limit")
        if past and start - past[-1] < MIN_INTERVAL:
            raise ReservationBlocked("minimum-spacing")

    def check(self, issue: str, started_at: datetime) -> None:
        """Read-only admission preview. A later reservation rechecks the ledger."""
        request = _request(issue, started_at)
        try:
            if self._root_exists():
                self._admit(self._state(locked=False), request)
        except ReservationBlocked:
            raise
        except (OSError, ValueError, RecursionError) as exc:
            raise LedgerError("Cannot verify ledger admission") from exc

    def reserve(self, issue: str, started_at: datetime) -> Reservation:
        request = _request(issue, started_at)
        with self._locked(create=True):
            try:
                state = self._state(locked=True)
            except (ValueError, RecursionError) as exc:
                raise LedgerError("Cannot verify ledger records") from exc
            self._admit(state, request)
            _publish(self.root / f"{issue}.reservation.json", {"version": 1, **asdict(request)})
            if self._state(locked=True).get(issue) != (request, None):
                raise LedgerError("Reservation could not be read back")
        return request

    def finish(self, reservation: Reservation, outcome: str) -> None:
        if not isinstance(reservation, Reservation) or not isinstance(reservation.issue, str):
            raise LedgerError("Invalid reservation")
        if not isinstance(outcome, str) or outcome not in OUTCOMES:
            raise LedgerError("Invalid outcome")
        with self._locked(create=False):
            try:
                saved = self._state(locked=True).get(reservation.issue)
            except (ValueError, RecursionError) as exc:
                raise LedgerError("Cannot verify ledger records") from exc
            if saved is None or saved[0] != reservation:
                raise LedgerError("Unknown reservation")
            if saved[1] == outcome:
                return
            if saved[1] is not None:
                raise LedgerError("Cannot change a completed outcome")
            _publish(
                self.root / f"{reservation.issue}.outcome.json",
                {"version": 1, **asdict(reservation), "outcome": outcome},
            )
            if self._state(locked=True).get(reservation.issue) != (reservation, outcome):
                raise LedgerError("Outcome could not be read back")
