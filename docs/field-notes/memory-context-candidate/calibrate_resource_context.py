"""Linux self-process read/parser latency calibration with an explicit cgroup-label adapter.

Reads this process and its existing cgroup only. No child discovery, service,
network, inference, or privilege operations. Does not prove production-worker overhead or
production binding. All three identity roles intentionally alias this PID.
"""
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
import types

SOURCE = Path(__file__).resolve().parent / 'resource_context.py'
SOURCE_SHA = '3f2d7cacf83111e14ea82a3ce434ffb6f777074f94070e69f59b1f15382f45e6'
LABEL = '/system.slice/aotg-0000000000000000-worker.service'
SAMPLES = 128
WARMUP = 8
TOTAL_SECONDS = 20


def main():
    if sys.argv[1:] != ['--self-readonly']:
        raise SystemExit('Explicit Linux self-read calibration only: --self-readonly')
    assert os.geteuid() != 0
    raw = SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA
    mod = types.ModuleType('context_calibration_source')
    exec(compile(raw, str(SOURCE), 'exec'), mod.__dict__)
    pid = os.getpid()
    actual = Path('/proc/self/cgroup').read_text('ascii').strip()
    assert actual.startswith('0::/') and '\n' not in actual
    group = actual[3:]
    assert group != LABEL
    started = time.monotonic()

    def identity():
        text = Path(f'/proc/{pid}/stat').read_text('ascii')
        return {'pid': pid, 'start_ticks': int(text.rpartition(')')[2].split()[19]),
                'cgroup': Path(f'/proc/{pid}/cgroup').read_text('ascii').strip()}

    before = identity()
    wanted = {'pid': pid, 'start_ticks': before['start_ticks']}

    class Adapter:
        def __init__(self):
            self.files = mod._ContextFiles('' if group == '/' else group)

        def read(self, domain, relative, cap):
            value = self.files.read(domain, relative, cap)
            if domain == 'proc' and relative.endswith('/cgroup'):
                assert relative == f'{pid}/cgroup'
                assert value.splitlines() == [actual]
                return '0::' + LABEL + '\n'
            return value

        def group_identity(self):
            return self.files.group_identity()

        def close(self):
            self.files.close()

    records = {'worker_only': [], 'three_roles_same_process': []}
    warmup_status = []
    for round_index in range(WARMUP + SAMPLES):
        names = tuple(records) if round_index % 2 == 0 else tuple(reversed(records))
        for name in names:
            if time.monotonic() - started >= TOTAL_SECONDS:
                raise RuntimeError('Calibration wall cap reached; no retry')
            wall = time.perf_counter_ns()
            cpu = time.process_time_ns()
            adapter = Adapter()
            try:
                kwargs = {} if name == 'worker_only' else dict(root_identity=wanted, native_identity=wanted)
                result = mod.collect_resource_context(LABEL, _files=adapter, **kwargs)
            finally:
                adapter.close()
            encoded = (json.dumps(result, ensure_ascii=True, sort_keys=True,
                                  allow_nan=False, separators=(',', ':')) + '\n').encode('ascii')
            elapsed_cpu = time.process_time_ns() - cpu
            elapsed_wall = time.perf_counter_ns() - wall
            entry = {'wall_ns': elapsed_wall, 'cpu_ns': elapsed_cpu,
                     'helper_seconds': result['seconds'], 'read_calls': result['read_calls'],
                     'helper_accounted_read_bytes_after_label_adapter': result['read_bytes'],
                     'context_jsonl_bytes': len(encoded), 'status_under_adapter': result['status'],
                     'errors': result['errors']}
            if round_index < WARMUP:
                warmup_status.append({'profile': name, **entry})
            else:
                records[name].append(entry)
        time.sleep(0.002)
    after = identity()
    assert after == before

    def stats(values):
        ordered = sorted(values)
        return {'count': len(values), 'min': min(values), 'p50': ordered[math.ceil(len(values)*0.50)-1],
                'p95': ordered[math.ceil(len(values)*0.95)-1], 'p99': ordered[math.ceil(len(values)*0.99)-1],
                'max': max(values), 'mean': sum(values)/len(values)}

    report = {
        'artifact': 'aotg-self-context-overhead-calibration', 'version': 1,
        'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'python': sys.version.split()[0], 'source_sha256': SOURCE_SHA,
        'scope': 'Current Linux self-process fixed-file reads plus explicit test-only cgroup label adapter',
        'production_binding_verified': False, 'production_worker_overhead_measured': False,
        'service_control': False, 'inference': False, 'remote_operations': False,
        'actual_identity_before': before, 'actual_identity_after': after,
        'identity_roles_alias_same_process': True,
        'timed_region': 'reader open + helper read/parse + reader close + compact JSONL serialization',
        'excluded': ['source import', 'identity preflight and final check', 'durable output write'],
        'warmups_per_profile': WARMUP, 'samples_per_profile': SAMPLES,
        'clock': 'perf_counter_ns; process_time_ns', 'quantile': 'nearest rank',
        'userspace_wall_cap_seconds': TOTAL_SECONDS,
        'blocking_syscall_hard_deadline_proven': False,
        'elapsed_seconds': time.monotonic() - started,
        'summary': {name: {
            'wall_ms': stats([x['wall_ns']/1e6 for x in rows]),
            'cpu_ms': stats([x['cpu_ns']/1e6 for x in rows]),
            'context_jsonl_bytes': stats([x['context_jsonl_bytes'] for x in rows]),
            'read_calls': sorted(set(x['read_calls'] for x in rows)),
            'status_counts': {status: sum(x['status_under_adapter'] == status for x in rows)
                              for status in sorted(set(x['status_under_adapter'] for x in rows))},
            'errors': sorted(set(error for x in rows for error in x['errors']))
        } for name, rows in records.items()},
        'warmup': warmup_status, 'samples': records,
        'limitations': ['Current self-process conditions only; not production worker or inference performance',
                        'One existing process is read repeatedly for three identity roles',
                        'Label adapter bypasses production-name validation only for calibration',
                        'No worker guard interval or durable writer overhead measured',
                        'Finite samples do not prove worst-case latency']
    }
    payload = json.dumps(report, sort_keys=True, allow_nan=False, separators=(',', ':'))
    assert len(payload.encode('utf-8')) <= 131072
    print(payload, flush=True)


if __name__ == '__main__':
    main()
