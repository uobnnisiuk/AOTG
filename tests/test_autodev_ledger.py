import json
import multiprocessing
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from aotg.autodev.ledger import Ledger, LedgerError, Reservation, ReservationBlocked

START = datetime(2026, 1, 1, 8, tzinfo=timezone.utc)


def competing_reservation(path, issue, ready, start, results):
    ready.put(issue)
    start.wait(20)
    try:
        Ledger(path).reserve(issue, START)
    except ReservationBlocked as exc:
        results.put(exc.reason)
    except LedgerError:
        results.put("invalid")
    else:
        results.put("reserved")


class LedgerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name).resolve() / "private-ledger"
        self.ledger = Ledger(self.path)

    def assertBlocked(self, reason, operation, *args):
        with self.assertRaises(ReservationBlocked) as caught:
            operation(*args)
        self.assertEqual(caught.exception.reason, reason)

    def test_preview_never_creates_state_or_reserves(self):
        self.ledger.check("UOB-50", START)
        self.assertFalse(self.path.exists())
        attempt = self.ledger.reserve("UOB-50", START)
        self.ledger.finish(attempt, "success")
        before = {file.name: file.read_bytes() for file in self.path.iterdir()}
        self.ledger.check("UOB-51", START + timedelta(hours=3))
        self.assertEqual(before, {file.name: file.read_bytes() for file in self.path.iterdir()})

    def test_two_attempts_per_jst_day_even_on_failure_or_timeout(self):
        a = self.ledger.reserve("UOB-50", START)
        self.ledger.finish(a, "failure")
        self.assertBlocked(
            "minimum-spacing", self.ledger.reserve, "UOB-51", START + timedelta(hours=2)
        )
        b = self.ledger.reserve("UOB-51", START + timedelta(hours=3))
        self.ledger.finish(b, "timeout")
        self.assertBlocked(
            "daily-limit", self.ledger.reserve, "UOB-52", START + timedelta(hours=6)
        )
        # 15:00 UTC starts the next JST date. The previous run started four hours before.
        self.ledger.check("UOB-52", START + timedelta(hours=7))
        self.assertBlocked(
            "already-attempted", self.ledger.reserve, "UOB-50", START + timedelta(days=2)
        )

    def test_spacing_carries_across_jst_midnight(self):
        started = START + timedelta(hours=6)
        prior = self.ledger.reserve("UOB-50", started)
        self.ledger.finish(prior, "success")
        self.assertBlocked(
            "minimum-spacing", self.ledger.check, "UOB-51", started + timedelta(hours=1)
        )
        self.ledger.reserve("UOB-51", started + timedelta(hours=3))

    def test_active_reservation_survives_restart(self):
        a = self.ledger.reserve("UOB-50", START)
        reopened = Ledger(self.path)
        self.assertBlocked("active", reopened.reserve, "UOB-51", START + timedelta(days=2))
        self.assertBlocked(
            "already-attempted", reopened.reserve, "UOB-50", START + timedelta(days=2)
        )
        reopened.finish(a, "unknown")
        reopened.finish(a, "unknown")
        self.assertBlocked("active", reopened.check, "UOB-51", START + timedelta(days=2))
        with self.assertRaisesRegex(LedgerError, "Cannot change"):
            reopened.finish(a, "success")

    def test_lock_left_by_crash_blocks_admission(self):
        self.path.mkdir(mode=0o700)
        (self.path / "reservation.lock").touch(mode=0o600)
        before = tuple(self.path.iterdir())
        self.assertBlocked("lock-busy", self.ledger.check, "UOB-50", START)
        self.assertBlocked("lock-busy", self.ledger.reserve, "UOB-50", START)
        self.assertEqual(before, tuple(self.path.iterdir()))

    def test_crash_before_atomic_publication_cannot_produce_attempt(self):
        with patch("aotg.autodev.ledger._publish", side_effect=OSError):
            with self.assertRaises(LedgerError):
                self.ledger.reserve("UOB-50", START)
        self.assertEqual([], list(self.path.iterdir()))
        self.ledger.reserve("UOB-50", START)

    def test_uncertain_publication_does_not_reopen_budget(self):
        from aotg.autodev.ledger import _publish

        def publish_then_fail(*args):
            _publish(*args)
            raise OSError

        with patch("aotg.autodev.ledger._publish", side_effect=publish_then_fail):
            with self.assertRaises(LedgerError):
                self.ledger.reserve("UOB-50", START)
        self.assertBlocked("active", self.ledger.reserve, "UOB-51", START + timedelta(days=2))

    def test_two_interpreters_cannot_reserve_at_once(self):
        ctx = multiprocessing.get_context("spawn")
        ready = ctx.Queue()
        start = ctx.Event()
        results = ctx.Queue()
        workers = [
            ctx.Process(target=competing_reservation, args=(self.path, issue, ready, start, results))
            for issue in ("UOB-50", "UOB-51")
        ]
        for worker in workers:
            worker.start()
        try:
            for _ in workers:
                ready.get(timeout=15)
            start.set()
            answers = [results.get(timeout=15) for _ in workers]
        finally:
            start.set()
            for worker in workers:
                worker.join(timeout=10)
                if worker.is_alive():
                    worker.terminate()
                    worker.join()
            for channel in (ready, results):
                channel.close()
                channel.join_thread()
        self.assertEqual(1, answers.count("reserved"))
        self.assertIn(next(result for result in answers if result != "reserved"), {"active", "lock-busy"})
        self.assertEqual(1, len(list(self.path.glob("*.reservation.json"))))

    def test_partial_or_unknown_state_is_rejected(self):
        self.path.mkdir(mode=0o700)
        for name, content in (
            ("old-state.json", "{}"),
            (".pending-abc", "{"),
            ("UOB-50.reservation.json", '{"version": 1, "version": 2}'),
            (
                "UOB-50.reservation.json",
                json.dumps({"version": 1, "issue": "UOB-51", "started_at": START.isoformat()}),
            ),
            (
                "UOB-50.outcome.json",
                json.dumps({"version": 1, "issue": "UOB-50",
                            "started_at": START.isoformat(timespec="microseconds"),
                            "outcome": "success"}),
            ),
        ):
            with self.subTest(name=name, content=content):
                record = self.path / name
                record.touch(mode=0o600)
                record.write_text(content, encoding="utf-8")
                with self.assertRaises(LedgerError):
                    self.ledger.reserve("UOB-51", START)
                self.assertEqual(list(self.path.iterdir()), [record])
                record.unlink()

    def test_valid_records_with_impossible_history_are_rejected(self):
        first = self.ledger.reserve("UOB-50", START)
        self.ledger.finish(first, "success")
        illegal_reservation = self.path / "UOB-51.reservation.json"
        illegal_reservation.touch(mode=0o600)
        illegal_reservation.write_text(
            json.dumps({"version": 1, "issue": "UOB-51", "started_at": first.started_at}),
            encoding="utf-8",
        )
        with self.assertRaises(LedgerError):
            self.ledger.reserve("UOB-52", START + timedelta(days=1))
        self.assertTrue(illegal_reservation.is_file())

    def test_wrong_reservation_and_clock_fail_closed(self):
        with self.assertRaisesRegex(LedgerError, "Unknown reservation"):
            self.ledger.finish(Reservation("UOB-50", "wrong timestamp"), "success")
        self.assertFalse(self.path.exists())
        attempt = self.ledger.reserve("UOB-50", START)
        with self.assertRaisesRegex(LedgerError, "Unknown reservation"):
            self.ledger.finish(Reservation("UOB-50", "wrong timestamp"), "success")
        self.ledger.finish(attempt, "success")
        with self.assertRaisesRegex(LedgerError, "Clock predates"):
            self.ledger.reserve("UOB-51", START - timedelta(hours=4))
        with self.assertRaisesRegex(LedgerError, "timezone-aware"):
            self.ledger.reserve("UOB-51", datetime(2026, 1, 1))

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics")
    def test_private_modes_and_link_rejection(self):
        attempt = self.ledger.reserve("UOB-50", START)
        self.ledger.finish(attempt, "success")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)
        for file in self.path.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        link = self.path.parent / "ledger-link"
        link.symlink_to(self.path)
        with self.assertRaises(LedgerError):
            Ledger(link).reserve("UOB-51", START + timedelta(hours=3))
        next(iter(self.path.iterdir())).chmod(0o644)
        with self.assertRaises(LedgerError):
            self.ledger.reserve("UOB-51", START + timedelta(hours=3))


if __name__ == "__main__":
    unittest.main()
