"""Synthetic tests for explicitly supplied trusted worker files; no live worker run."""
import argparse
import copy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load(name, filename):
    path = Path(filename)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError('Supply an absolute existing regular trusted worker path')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


worker = original = None


def sample():
    return {'utc': '2026-01-01T00:00:00+00:00', 'selected_gpu_bdf': 'synthetic-gpu',
            'temperatures_c': {'amdgpu:edge': 50, 'nvme:Composite': 40, 'nvme:Sensor 2': 42},
            'per_gpu_temperatures_c': {'synthetic-gpu': {'edge': 50}},
            'alarms': {'synthetic:alarm': 0}, 'host_mem_available_bytes': 64 * worker.GIB,
            'gpu': {'mem_info_vram_total': 96 * worker.GIB, 'mem_info_vram_used': 60 * worker.GIB,
                    'mem_info_gtt_used': worker.GIB},
            'swap_bytes': {'SwapTotal': 4 * worker.GIB, 'SwapFree': 4 * worker.GIB}}


class RecordingStream(io.StringIO):
    def __init__(self, reject=None):
        super().__init__()
        self.reject = reject
        self.flushed = []

    def write(self, text):
        if self.reject and self.reject(json.loads(text)):
            raise OSError('synthetic evidence write failure')
        return super().write(text)

    def flush(self):
        self.flushed = self.getvalue().splitlines()
        return super().flush()

    def records(self):
        return [json.loads(line) for line in self.getvalue().splitlines()]


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.plan = {'run_id': 'synthetic', 'gpu': {'bdf': 'synthetic-gpu'},
                     'required_alarm_keys': ['synthetic:alarm'], 'task_root': '/synthetic'}
        self.value = sample()
        self.telemetry = SimpleNamespace(sample=lambda *args: copy.deepcopy(self.value))
        self.accepted, self.events = RecordingStream(), RecordingStream()
        self.counter = self.enterContext(patch.object(worker, 'read_pswpout', return_value=48))
        self.enterContext(patch.object(worker.time, 'monotonic', return_value=10.0))
        self.enterContext(patch.object(worker, 'utc', return_value='2026-01-01T00:00:01+00:00'))
        self.enterContext(patch.object(worker.shutil, 'disk_usage', return_value=SimpleNamespace(free=200 * worker.GIB)))
        self.kernel = self.enterContext(patch.object(worker.Monitor, 'start_kernel'))
        self.enterContext(patch.object(worker.subprocess, 'Popen', side_effect=AssertionError('No process permitted')))

    def monitor(self):
        return worker.Monitor(self.plan, self.telemetry, self.accepted, 1000.0, self.events)

    def test_anchor_and_unchecked_sample_flushed_before_guard(self):
        real = worker.resource_check

        def inspect(*args, **kwargs):
            rows = [json.loads(line) for line in self.events.flushed]
            self.assertEqual(rows[0]['phase'], 'startup-anchor')
            self.assertEqual(rows[0]['anchor']['pswpout'], 48)
            self.assertEqual(rows[0]['guard_verdict'], 'not-evaluated')
            self.assertEqual(rows[-1]['phase'], 'observed')
            self.assertEqual(rows[-1]['sample']['pswpout'], 48)
            self.assertEqual(rows[-1]['guard_verdict'], 'not-evaluated')
            self.assertEqual(self.accepted.getvalue(), '')
            return real(*args, **kwargs)

        with patch.object(worker, 'resource_check', side_effect=inspect):
            monitor = self.monitor()
        rows = self.events.records()
        self.assertEqual(rows[-1]['guard_verdict'], 'passed')
        self.assertEqual(rows[-1]['sequence'], rows[-2]['sequence'])
        self.assertEqual(rows[-2]['anchor'], rows[0]['anchor'])
        self.assertEqual(rows[-2]['sample_utc'], self.value['utc'])
        self.assertEqual(monitor.pswpout, 48)
        self.assertEqual(len(self.accepted.records()), 1)
        self.assertNotIn('guard_verdict', self.accepted.records()[0])

    def test_counter_increment_and_reset_keep_trigger_without_accepting_it(self):
        for changed in (49, 0):
            with self.subTest(changed=changed):
                self.counter.return_value = 48
                self.accepted, self.events = RecordingStream(), RecordingStream()
                monitor = self.monitor()
                before = self.accepted.getvalue()
                self.counter.return_value = changed
                with self.assertRaisesRegex(worker.StopTrial, '^New swapout or counter reset$'):
                    monitor.tick(None, None, force=True)
                observed, verdict = self.events.records()[-2:]
                self.assertEqual(observed['sample']['pswpout'], changed)
                self.assertEqual(observed['anchor']['pswpout'], 48)
                self.assertEqual(verdict['sequence'], observed['sequence'])
                self.assertEqual(verdict['guard_verdict'], 'rejected')
                self.assertEqual(verdict['reason'], 'New swapout or counter reset')
                self.assertEqual(self.accepted.getvalue(), before)

    def test_invalid_counter_and_missing_resource_are_not_passed(self):
        for counter, missing, reason in ((None, False, 'Missing/invalid resource measurement'),
                                         (-1, False, 'Missing/invalid resource measurement'),
                                         (48, True, 'Required telemetry missing')):
            with self.subTest(counter=counter, missing=missing):
                self.value = sample()
                self.counter.return_value = 48
                self.accepted, self.events = RecordingStream(), RecordingStream()
                monitor = self.monitor()
                if missing:
                    del self.value['host_mem_available_bytes']
                self.counter.return_value = counter
                with self.assertRaisesRegex(worker.StopTrial, reason):
                    monitor.tick(None, None, force=True)
                self.assertEqual(self.events.records()[-1]['guard_verdict'], 'rejected')
                self.assertEqual(self.events.records()[-2]['sample']['pswpout'], counter)
                self.assertEqual(len(self.accepted.records()), 1)

    def test_startup_evidence_write_failure_prevents_monitor_start(self):
        self.events.reject = lambda row: row['phase'] == 'startup-anchor'
        with self.assertRaisesRegex(worker.StopTrial, 'Resource observation evidence write failed'):
            self.monitor()
        self.kernel.assert_not_called()
        self.assertEqual(self.accepted.getvalue(), '')

    def test_observation_write_failure_prevents_guard_and_accepted_sample(self):
        self.events.reject = lambda row: row['phase'] == 'observed'
        with patch.object(worker, 'resource_check') as guard:
            with self.assertRaisesRegex(worker.StopTrial, 'Resource observation evidence write failed'):
                self.monitor()
        guard.assert_not_called()
        self.assertEqual(self.accepted.getvalue(), '')

    def test_observation_flush_failure_fails_closed(self):
        monitor = self.monitor()
        with patch.object(self.events, 'flush', side_effect=OSError('synthetic flush failure')):
            with patch.object(worker, 'resource_check') as guard:
                with self.assertRaisesRegex(worker.StopTrial, 'Resource observation evidence write failed'):
                    monitor.tick(None, None, force=True)
        guard.assert_not_called()
        self.assertEqual(len(self.accepted.records()), 1)

    def test_rejection_write_failure_preserves_primary_guard_exception(self):
        monitor = self.monitor()
        self.counter.return_value = 49
        self.events.reject = lambda row: row.get('guard_verdict') == 'rejected'
        with self.assertRaisesRegex(worker.StopTrial, '^New swapout or counter reset$') as caught:
            monitor.tick(None, None, force=True)
        self.assertEqual(self.events.records()[-1]['phase'], 'observed')
        self.assertEqual(self.events.records()[-1]['sample']['pswpout'], 49)
        self.assertEqual(self.events.records()[-1]['guard_verdict'], 'not-evaluated')
        self.assertTrue(any('Guard verdict evidence write failed' in note for note in caught.exception.__notes__))
        self.assertEqual(len(self.accepted.records()), 1)

    def test_pass_verdict_write_failure_fails_closed(self):
        self.events.reject = lambda row: row.get('guard_verdict') == 'passed'
        with self.assertRaisesRegex(worker.StopTrial, 'Resource observation evidence write failed'):
            self.monitor()
        self.assertEqual(self.accepted.getvalue(), '')

    def test_nonfinite_sample_serialization_fails_closed_without_json_nan(self):
        monitor = self.monitor()
        self.value['temperatures_c']['amdgpu:edge'] = float('nan')
        with self.assertRaisesRegex(worker.StopTrial, 'Resource observation evidence write failed'):
            monitor.tick(None, None, force=True)
        self.assertNotIn('NaN', self.events.getvalue())
        self.assertEqual(len(self.accepted.records()), 1)

    def test_acquisition_failure_is_preserved_but_no_unobserved_counter_is_invented(self):
        monitor = self.monitor()
        before = self.events.getvalue()
        self.counter.side_effect = worker.StopTrial('pswpout unavailable')
        with self.assertRaisesRegex(worker.StopTrial, '^pswpout unavailable$'):
            monitor.tick(None, None, force=True)
        self.assertEqual(self.events.getvalue(), before)
        self.assertEqual(len(self.accepted.records()), 1)

    def test_pacing_timeout_keeps_same_abort_and_records_actual_temperature(self):
        monitor = self.monitor()
        self.value['temperatures_c']['amdgpu:edge'] = 75
        owned = Mock()
        monitor.pause_since = -21.0
        with self.assertRaisesRegex(worker.StopTrial, '^GPU thermal pacing exceeded 30 seconds$'):
            monitor.tick(owned, 123, force=True)
        owned.send.assert_called_once_with(worker.signal.SIGSTOP)
        self.assertEqual(self.events.records()[-2]['sample']['temperatures_c']['amdgpu:edge'], 75)
        self.assertEqual(self.events.records()[-1]['guard_verdict'], 'rejected')
        self.assertEqual(len(self.accepted.records()), 1)

    def test_existing_resource_boundaries_and_error_reasons_unchanged(self):
        cases = [({}, {}, 50), ({'host_mem_available_bytes': 48 * worker.GIB - 1}, {}, 'Host MemAvailable below 48 GiB'),
                 ({}, {'pswpout': 49}, 'New swapout or counter reset'),
                 ({}, {'pswpout': 0}, 'New swapout or counter reset'),
                 ({}, {'disk_free': 150 * worker.GIB - 1}, 'Disk free below 150 GiB')]
        for changes, kwargs, expected in cases:
            for module in (original, worker):
                with self.subTest(module=module.__name__, changes=changes, kwargs=kwargs):
                    args = {'bdf': 'synthetic-gpu', 'alarm_keys': ['synthetic:alarm'],
                            'disk_free': 200 * worker.GIB, 'pswpout': 48,
                            'initial_pswpout': 48, 'initial_gtt': worker.GIB, **kwargs}
                    if isinstance(expected, str):
                        with self.assertRaisesRegex(module.StopTrial, '^' + expected + '$'):
                            module.resource_check({**sample(), **changes}, **args)
                    else:
                        self.assertEqual(module.resource_check({**sample(), **changes}, **args), expected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', required=True, help='Reviewed patched private worker; imported, never executed as main')
    parser.add_argument('--baseline', required=True, help='Original private worker for unchanged guard comparison')
    args, unittest_args = parser.parse_known_args()
    worker = load('observed_worker', args.worker)
    original = load('original_worker', args.baseline)
    unittest.main(argv=[__file__, *unittest_args])
