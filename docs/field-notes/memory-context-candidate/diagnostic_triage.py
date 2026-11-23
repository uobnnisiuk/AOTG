"""Offline-only triage of one *synthetic or sanitized* swap-guard event.

Does not read the host, inspect the private worker, operate a model, or start a
run. Category names are EVIDENCE descriptions, never a proven root cause,
optimization choice, or runtime qualification. Only same-window observations
may be correlated with the guard. Run: python3 -I -S -B diagnostic_triage.py --self-test
"""
import sys
import unittest

FIELDS = frozenset((
    'trigger_recorded', 'fresh_anchor', 'same_guard_sample',
    'previous_pswpout', 'trigger_pswpout', 'context_same_window',
    'psi_full_total_delta_us', 'cgroup_memory_high_delta',
    'cgroup_memory_oom_delta', 'cgroup_swap_bytes',
    'mem_available_bytes',
))
CORROBORATORS = (
    'psi_full_total_delta_us', 'cgroup_memory_high_delta',
    'cgroup_memory_oom_delta',
)


def _count(value):
    return type(value) is int and 0 <= value < 2**64


def triage(record):
    """Return bounded conservative evidence categories, not a causal diagnosis.

    Required fields are explicit so missing data cannot silently become zero.
    Corroborators must describe the *guard window*, not later recovery samples.
    An inconsistent input fails closed as 'invalid-evidence', not as success.
    """
    def outcome(category, signals=(), missing=()):
        return {
            'artifact': 'aotg-offline-swap-evidence-triage', 'version': 1,
            'category': category, 'observed_signals': list(signals),
            'missing_or_unusable': list(missing),
            'status': 'incomplete', 'root_cause_proven': False,
            'runtime_qualified': False, 'authorizes_retry': False,
        }

    if type(record) is not dict or set(record) != FIELDS:
        return outcome('invalid-evidence', missing=('schema',))
    for flag in ('trigger_recorded', 'fresh_anchor', 'same_guard_sample',
                 'context_same_window'):
        if type(record[flag]) is not bool:
            return outcome('invalid-evidence', missing=(flag,))
    for name in FIELDS - {
        'trigger_recorded', 'fresh_anchor', 'same_guard_sample',
        'context_same_window',
    }:
        if record[name] is not None and not _count(record[name]):
            return outcome('invalid-evidence', missing=(name,))

    if not record['trigger_recorded']:
        return outcome('trigger-evidence-missing', missing=('trigger-record',))
    if (not record['fresh_anchor'] or not record['same_guard_sample']):
        return outcome('counter-or-sample-binding-unverified',
                       missing=('fresh-anchor-or-same-sample',))
    a, b = record['previous_pswpout'], record['trigger_pswpout']
    if a is None or b is None:
        return outcome('trigger-counter-missing', missing=('pswpout',))
    if b < a:
        return outcome('counter-discontinuity', signals=('pswpout-decreased',))
    if b == a:
        return outcome('swap-stop-counter-mismatch', signals=('no-new-pswpout',))
    signals = ['new-pswpout']
    if not record['context_same_window']:
        return outcome('swap-activity-unattributed', signals,
                       ('same-window-context',))
    missing = tuple(name for name in CORROBORATORS
                    if record[name] is None)
    if missing:
        return outcome('swap-activity-context-incomplete', signals, missing)
    evidence = [name for name in CORROBORATORS if record[name] > 0]
    if evidence:
        return outcome('concurrent-pressure-signals-observed', signals + evidence)
    # Zero contemporaneous signals cannot establish pressure ABSENCE, even if
    # a later MemAvailable value seems healthy. The process source is unknown.
    return outcome('swap-activity-pressure-unproven', signals)


class Tests(unittest.TestCase):
    def event(self, **changes):
        x = dict(trigger_recorded=True, fresh_anchor=True,
                 same_guard_sample=True, previous_pswpout=115,
                 trigger_pswpout=158, context_same_window=True,
                 psi_full_total_delta_us=0, cgroup_memory_high_delta=0,
                 cgroup_memory_oom_delta=0, cgroup_swap_bytes=0,
                 mem_available_bytes=100_000)
        x.update(changes)
        return x

    def test_old_stop_without_correlated_context_is_not_attributed(self):
        x = triage(self.event(context_same_window=False,
                              psi_full_total_delta_us=None))
        self.assertEqual(x['category'], 'swap-activity-unattributed')
        self.assertFalse(x['root_cause_proven'])
        self.assertFalse(x['authorizes_retry'])

    def test_pressure_signals_remain_noncausal(self):
        x = triage(self.event(psi_full_total_delta_us=300,
                              cgroup_memory_high_delta=1))
        self.assertEqual(x['category'], 'concurrent-pressure-signals-observed')
        self.assertFalse(x['root_cause_proven'])

    def test_all_zero_is_not_proof_pressure_absent(self):
        self.assertEqual(triage(self.event())['category'],
                         'swap-activity-pressure-unproven')

    def test_missing_one_corroborator_is_not_zero(self):
        x = triage(self.event(cgroup_memory_oom_delta=None))
        self.assertEqual(x['category'], 'swap-activity-context-incomplete')
        self.assertIn('cgroup_memory_oom_delta', x['missing_or_unusable'])

    def test_nonfresh_anchor_rejected(self):
        self.assertEqual(triage(self.event(fresh_anchor=False))['category'],
                         'counter-or-sample-binding-unverified')

    def test_counter_reset_is_not_pressure_or_false_positive(self):
        self.assertEqual(triage(self.event(trigger_pswpout=3))['category'],
                         'counter-discontinuity')

    def test_no_delta_cannot_be_misclassified_as_pressure(self):
        self.assertEqual(triage(self.event(trigger_pswpout=115,
                         psi_full_total_delta_us=9))['category'],
                         'swap-stop-counter-mismatch')

    def test_missing_trigger_remains_incomplete(self):
        self.assertEqual(triage(self.event(trigger_recorded=False))['category'],
                         'trigger-evidence-missing')

    def test_wrong_types_and_extra_fields_refused(self):
        for change in (dict(previous_pswpout=-1),
                       dict(previous_pswpout=True),
                       dict(context_same_window=1),
                       dict(cgroup_swap_bytes=-5)):
            self.assertEqual(triage(self.event(**change))['category'],
                             'invalid-evidence')
        self.assertEqual(triage(dict(self.event(), secret='private'))['category'],
                         'invalid-evidence')

    def test_no_result_can_be_success_or_authority(self):
        examples = [self.event(), self.event(context_same_window=False),
                    self.event(psi_full_total_delta_us=500),
                    self.event(fresh_anchor=False),
                    self.event(trigger_recorded=False)]
        for example in examples:
            result = triage(example)
            self.assertEqual(result['status'], 'incomplete')
            self.assertFalse(result['runtime_qualified'])
            self.assertFalse(result['authorizes_retry'])
            self.assertFalse(result['root_cause_proven'])


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        raise SystemExit('usage: diagnostic_triage.py --self-test')
