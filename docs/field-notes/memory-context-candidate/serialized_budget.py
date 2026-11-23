"""Offline-only producer-side JSONL budget prototype for PR #38.

No filesystem, proc, network, subprocess or model access. This is NOT wired into
private worker/collector, is NOT a runtime safety guarantee, and does not authorize
field sampling. Caller must bind passed_guard to the real, flushed guard verdict.
Run: python3 -I -S -B serialized_budget.py --self-test
"""
import json
import sys
import unittest
from dataclasses import dataclass


class BudgetStop(RuntimeError):
    """A fail-closed record/clock/guard error: caller must stop and recover."""


@dataclass(frozen=True)
class Limits:
    window_ms: int = 5_340_000
    primary_min_period_ms: int = 190
    context_min_period_ms: int = 2_000
    primary_line_bytes: int = 2_048
    context_line_bytes: int = 4_096
    max_rows: int = 60_001
    max_bytes: int = 128 * 1024 * 1024

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError('invalid-positive-limit')
        if self.context_min_period_ms > self.window_ms:
            raise ValueError('context-period-outside-window')


def _line(record, cap):
    if type(record) is not dict:
        raise BudgetStop('non-object-record')
    try:
        # ensure_ascii means size is stable and includes escaping plus newline.
        raw = (json.dumps(record, ensure_ascii=True, sort_keys=True,
                          allow_nan=False, separators=(',', ':')) + '\n').encode('ascii')
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise BudgetStop('invalid-json-record') from exc
    if len(raw) > cap:
        raise BudgetStop('serialized-line-cap')
    return raw


# Dict-only JSONL: the smallest accepted line is b'{}\n' (3 bytes).
_MIN_CONTEXT_JSONL_BYTES = len(b'{}\n')


class SerializedBudget:
    """A *pure* fail-closed admission prototype, not a durable writer.

    The primary producer supplies exactly one initial row then TWO rows per
    observation tick. A context row is *optional*, after a passed/flushed guard.
    Context skips are counted in memory only (NO line per skipped primary tick).
    Any violation latches stopped; no later call can turn an incomplete run into
    success. Time comes from the caller's single monotonic epoch in integer ms.
    """
    def __init__(self, limits=Limits()):
        self.limits = limits
        self.rows = 0
        self.bytes = 0
        self.primary_ticks = 0
        self.context_ticks = 0
        self.context_skipped_interval = 0
        self.context_skipped_guard = 0
        self.last_primary_ms = None
        self.last_context_ms = None
        self.last_seen_ms = None
        self.initial_written = False
        self.stopped_reason = None

    def _stop(self, reason):
        if self.stopped_reason is None:
            self.stopped_reason = reason
        raise BudgetStop(self.stopped_reason)

    def _time(self, at_ms):
        if self.stopped_reason is not None:
            self._stop(self.stopped_reason)
        if type(at_ms) is not int or at_ms < 0 or at_ms > self.limits.window_ms:
            self._stop('clock-or-window')
        if self.last_seen_ms is not None and at_ms < self.last_seen_ms:
            self._stop('clock-rollback')
        self.last_seen_ms = at_ms

    def _commit(self, records, line_cap):
        try:
            encoded = tuple(_line(row, line_cap) for row in records)
        except BudgetStop as exc:
            self._stop(str(exc))
        size = sum(map(len, encoded))
        if self.rows + len(encoded) > self.limits.max_rows:
            self._stop('aggregate-row-cap')
        if self.bytes + size > self.limits.max_bytes:
            self._stop('aggregate-byte-cap')
        self.rows += len(encoded)
        self.bytes += size
        return encoded

    def initial(self, at_ms, record):
        self._time(at_ms)
        if self.initial_written or self.primary_ticks:
            self._stop('duplicate-initial')
        lines = self._commit((record,), self.limits.primary_line_bytes)
        self.initial_written = True
        return lines

    def primary(self, at_ms, raw_sample, guard_record):
        self._time(at_ms)
        if not self.initial_written:
            self._stop('missing-initial')
        if (self.last_primary_ms is not None and
                at_ms - self.last_primary_ms < self.limits.primary_min_period_ms):
            self._stop('primary-period')
        lines = self._commit((raw_sample, guard_record), self.limits.primary_line_bytes)
        self.last_primary_ms = at_ms
        self.primary_ticks += 1
        return lines

    def context_after_guard(self, at_ms, passed_guard, sample):
        """Return (reason, serialized lines); never call sample on guard refusal.

        sample is an injected zero-argument callable (synthetic only here). The
        real integration MUST bind guard/pass to its durable verdict and priority
        order. This prototype cannot preempt a blocking syscall or prove flush.
        """
        self._time(at_ms)
        if type(passed_guard) is not bool:
            self._stop('unverified-guard-verdict')
        if not passed_guard:
            self.context_skipped_guard += 1
            self.stopped_reason = 'guard-rejected'
            return 'guard-rejected-no-context', ()
        if self.primary_ticks == 0 or self.last_primary_ms != at_ms:
            self._stop('context-without-same-tick-primary')
        if (self.last_context_ms is not None and
                at_ms - self.last_context_ms < self.limits.context_min_period_ms):
            self.context_skipped_interval += 1
            return 'interval-skipped-no-context', ()
        if (self.rows >= self.limits.max_rows or
                self.limits.max_bytes - self.bytes < _MIN_CONTEXT_JSONL_BYTES):
            self._stop('no-capacity-before-context-read')
        if not callable(sample):
            self._stop('invalid-sampler')
        try:
            value = sample()
        except BaseException:
            self.stopped_reason = 'context-sampler-failed'
            raise
        lines = self._commit((value,), self.limits.context_line_bytes)
        self.last_context_ms = at_ms
        self.context_ticks += 1
        return 'context-recorded', lines

    def summary(self):
        # Caller's persistence contract must store this in a SEPARATE, bounded
        # summary artifact. It does NOT consume unbudgeted observation JSONL.
        return {'artifact': 'aotg-offline-serialized-budget', 'version': 1,
                'runtime_qualified': False, 'rows': self.rows, 'bytes': self.bytes,
                'primary_ticks': self.primary_ticks, 'context_ticks': self.context_ticks,
                'context_skipped_interval': self.context_skipped_interval,
                'context_skipped_guard': self.context_skipped_guard,
                'stopped_reason': self.stopped_reason,
                'status': 'incomplete-unverified-runtime' if self.stopped_reason is None
                else 'incomplete-stopped'}


class Tests(unittest.TestCase):
    def new(self, **kwargs):
        a = SerializedBudget(Limits(**kwargs))
        a.initial(0, {'phase': 'initial'})
        return a

    def tick(self, a, at):
        return a.primary(at, {'phase': 'pre-guard'}, {'phase': 'guard-result'})

    def test_serialized_utf8_escape_newline_exact(self):
        encoded = _line({'v': '\u3042'}, 32)
        self.assertEqual(encoded, b'{"v":"\\u3042"}\n')
        self.assertEqual(len(encoded), 15)
        with self.assertRaisesRegex(BudgetStop, 'serialized-line-cap'):
            _line({'v': '\u3042'}, 14)

    def test_initial_and_two_records_per_tick(self):
        a = self.new()
        self.assertEqual(len(self.tick(a, 0)), 2)
        self.assertEqual(a.rows, 3)
        self.assertEqual(a.primary_ticks, 1)
        with self.assertRaisesRegex(BudgetStop, 'primary-period'):
            self.tick(a, 189)
        with self.assertRaises(BudgetStop):
            self.tick(a, 500)
        self.assertEqual(a.rows, 3)

    def test_two_second_context_thins_without_extra_rows(self):
        a = self.new()
        called = []
        for t in range(0, 2091, 190):
            self.tick(a, t)
            name, lines = a.context_after_guard(t, True, lambda: called.append(t) or {'t':t})
            self.assertEqual(bool(lines), name == 'context-recorded')
        self.assertEqual(called, [0, 2090])
        self.assertEqual(a.context_ticks, 2)
        self.assertEqual(a.context_skipped_interval, 10)
        self.assertEqual(a.rows, 1 + 12*2 + 2)

    def test_rejected_guard_calls_no_sampler_and_stops_forever(self):
        a = self.new()
        self.tick(a, 0)
        calls = []
        reason, lines = a.context_after_guard(0, False, lambda: calls.append(1))
        self.assertEqual((reason, lines), ('guard-rejected-no-context', ()))
        self.assertEqual(calls, [])
        self.assertEqual(a.summary()['status'], 'incomplete-stopped')
        with self.assertRaises(BudgetStop):
            self.tick(a, 190)

    def test_bad_guard_missing_primary_and_missing_initial(self):
        a = SerializedBudget()
        with self.assertRaisesRegex(BudgetStop, 'missing-initial'):
            a.primary(0, {}, {})
        b = self.new()
        with self.assertRaisesRegex(BudgetStop, 'context-without-same-tick-primary'):
            b.context_after_guard(0, True, lambda: {})
        c = self.new()
        self.tick(c, 0)
        with self.assertRaisesRegex(BudgetStop, 'unverified-guard-verdict'):
            c.context_after_guard(0, 1, lambda: {})

    def test_line_cap_and_non_finite_fail_closed_before_commit(self):
        a = self.new(primary_line_bytes=64)
        with self.assertRaisesRegex(BudgetStop, 'serialized-line-cap'):
            a.primary(0, {'secret': 'X'*100}, {})
        self.assertEqual(a.rows, 1)
        b = self.new()
        with self.assertRaisesRegex(BudgetStop, 'invalid-json-record'):
            b.primary(0, {'bad':float('nan')}, {})
        self.assertEqual(b.rows, 1)

    def test_context_failure_and_capacity_refusal(self):
        a = self.new(max_rows=3)
        self.tick(a, 0)
        with self.assertRaisesRegex(BudgetStop, 'no-capacity-before-context-read'):
            a.context_after_guard(0, True, lambda: self.fail('read happened'))
        b = self.new()
        self.tick(b, 0)
        with self.assertRaisesRegex(OSError, 'simulated'):
            b.context_after_guard(0, True, lambda: (_ for _ in ()).throw(OSError('simulated')))
        self.assertEqual(b.summary()['stopped_reason'], 'context-sampler-failed')
        self.assertEqual(b.context_ticks, 0)

    def test_context_known_impossible_bytes_refused_before_sample(self):
        baseline = self.new()
        self.tick(baseline, 0)
        prior_bytes = baseline.bytes
        self.assertEqual(_line({}, 3), b'{}\n')
        # Neither 1 nor 2 spare bytes can fit a valid dict JSONL line.
        for free_bytes in (1, 2):
            a = self.new(max_bytes=prior_bytes + free_bytes)
            self.tick(a, 0)
            calls = []
            with self.assertRaisesRegex(BudgetStop, 'no-capacity-before-context-read'):
                a.context_after_guard(0, True, lambda: calls.append(1) or {})
            self.assertEqual(calls, [])
            self.assertEqual((a.bytes, a.rows, a.context_ticks),
                             (prior_bytes, 3, 0))
            self.assertEqual(a.summary()['status'], 'incomplete-stopped')
            with self.assertRaisesRegex(BudgetStop, 'no-capacity-before-context-read'):
                a.context_after_guard(0, True, lambda: self.fail('repeat read'))

        # Positive boundary: exactly three bytes available, and {} fits.
        b = self.new(max_bytes=prior_bytes + 3)
        self.tick(b, 0)
        calls = []
        outcome, lines = b.context_after_guard(0, True,
                                               lambda: calls.append(1) or {})
        self.assertEqual(calls, [1])
        self.assertEqual((outcome, lines), ('context-recorded', (b'{}\n',)))
        self.assertEqual((b.bytes, b.rows, b.context_ticks),
                         (prior_bytes + 3, 4, 1))

    def test_cap_exact_and_exceeded_with_no_partial_batch(self):
        a = self.new(max_rows=5)
        self.tick(a, 0)
        self.tick(a, 190)
        self.assertEqual(a.rows, 5)
        with self.assertRaisesRegex(BudgetStop, 'aggregate-row-cap'):
            self.tick(a, 380)
        self.assertEqual(a.rows, 5)
        b = self.new(max_bytes=50)
        with self.assertRaisesRegex(BudgetStop, 'aggregate-byte-cap'):
            self.tick(b, 0)
        self.assertEqual(b.rows, 1)

    def test_clock_and_window_and_invalid_config(self):
        with self.assertRaises(ValueError):
            Limits(context_min_period_ms=True)
        for t in (-1, True, 5_340_001):
            a = self.new()
            with self.assertRaisesRegex(BudgetStop, 'clock-or-window'):
                self.tick(a, t)
        b = self.new()
        self.tick(b, 100)
        with self.assertRaisesRegex(BudgetStop, 'clock-rollback'):
            b.primary(99, {}, {})

    def test_repeated_initial_and_invalid_record(self):
        a = self.new()
        with self.assertRaisesRegex(BudgetStop, 'duplicate-initial'):
            a.initial(1, {})
        b = self.new()
        with self.assertRaisesRegex(BudgetStop, 'non-object-record'):
            b.primary(0, [], {})

    def test_unqualified_even_on_success(self):
        a = self.new()
        self.tick(a, 0)
        a.context_after_guard(0, True, lambda: {'status':'observed'})
        self.assertEqual(a.summary()['status'], 'incomplete-unverified-runtime')
        self.assertIs(a.summary()['runtime_qualified'], False)


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        raise SystemExit('usage: serialized_budget.py --self-test')
