"""Local synthetic audit of pinned collector main serialization; no host/SSH calls.

The transport fd/select/alarm are mocked. The unmodified main/emit function
serializes every test record itself. Full-volume tests discard written bytes;
they test production wire arithmetic, not a real pipe, SSH, or storage speed.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
COL = HERE
PIN = "22a8667bd5f935403e85ebbce6a6f8dbfaeddd00137e6241448df87d074ddf5d"
raw = (COL / "collector_remote.py").read_bytes()
assert hashlib.sha256(raw).hexdigest() == PIN
R = types.ModuleType("collector_wire_audit_protocol")
R.__file__ = str(COL / "collector_remote.py")
exec(compile(raw, R.__file__, "exec"), R.__dict__)

RESULTS = {"artifact": "aotg-local-collector-wire-boundary-audit", "version": 1,
           "source_sha256": PIN, "actual_remote_actions": False,
           "actual_pipe_or_ssh_backpressure_tested": False,
           "whole_chain_qualified": False, "checks": {}}


def production_emit(rows, *, limits=None, max_write=None, block_once=False,
                    advance_after_select=False):
    """Call original main, replacing only collect's producer and OS transport."""
    state = {"wire_bytes": 0, "writes": 0, "rows_requested": 0,
             "blocked": False, "returncode": None, "error": None}
    digest = hashlib.sha256()
    now = [0.0]

    def fake_collect(config, emit):
        for row in rows:
            state["rows_requested"] += 1
            emit(row)
        return {"status": "complete"}

    def write(fd, view):
        assert fd == 123
        if block_once and not state["blocked"]:
            state["blocked"] = True
            raise BlockingIOError()
        n = min(len(view), max_write or len(view))
        digest.update(view[:n]); state["wire_bytes"] += n; state["writes"] += 1
        return n

    def select(*args):
        if advance_after_select:
            now[0] = 61.0
            return ([], [], [])
        return ([], [123], [])

    with patch.object(R, "CONFIG", {}, create=True), patch.object(R, "collect", fake_collect), \
         patch.object(R.sys, "stdout", types.SimpleNamespace(fileno=lambda: 123)), \
         patch.object(R.signal, "signal"), patch.object(R.signal, "alarm"), \
         patch.object(R.os, "set_blocking"), patch.object(R.os, "write", write), \
         patch.object(R.select, "select", select), patch.object(R.time, "monotonic", lambda: now[0]), \
         patch.dict(R.LIMITS, limits or {}):
        try:
            state["returncode"] = R.main()
        except R.CollectionError as error:
            state["error"] = str(error)
    state["wire_sha256"] = digest.hexdigest()
    return state


def row_with_bytes(size):
    value = {"s": ""}
    value["s"] = "x" * (size - len(R.canon(value)) - 1)
    assert len(R.canon(value)) + 1 == size
    return value


def maximum_stat(size, *, directory=False):
    return {"device": 2**64-1, "inode": 2**64-1, "bytes": size,
            "mtime_ns": 2**63-1, "ctime_ns": 2**63-1,
            "mode": (stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | 0o600),
            "uid": 2**32-2, "gid": 2**32-2, "links": 2**64-1 if directory else 1}


def sample_final(unattempted=0, *, after=False):
    protected = {"work": maximum_stat(2**63-1, directory=True),
                 "task": maximum_stat(2**63-1, directory=True),
                 "owner_result": maximum_stat(262144), "owner_result_sha256": "f"*64,
                 "worker_summary": maximum_stat(1048576), "worker_summary_sha256": "f"*64}
    final = {"artifact": "aotg-comparison-collection-final", "version": 1,
             "request_sha256": "f"*64, "status": "incomplete" if unattempted else "complete",
             "attempted_files": 517-unattempted, "complete_files": 517-unattempted,
             "raw_bytes": 2**28, "total_read_bytes": 2**28,
             "unattempted_indices": list(range(517-unattempted, 517)),
             "preconditions_verified": True, "protected_unchanged": after,
             "owner_reported_restoration": True, "independent_restoration_verified": False,
             "remote_written": False, "inference_invoked": False, "service_control_invoked": False,
             "errors": ["remote_collection_deadline"] if unattempted else [],
             "started_utc": "2026-11-23T12:34:56.123456+00:00",
             "finished_utc": "2026-11-23T12:35:56.123457+00:00",
             "seconds": 60.00000000000001, "protected_before": protected}
    if after:
        final["protected_after"] = copy.deepcopy(protected)
    return final


class ProductionEmitterTests(unittest.TestCase):
    def test_actual_line_boundary_and_no_oversize_write(self):
        for size in (100000, 100001):
            result = production_emit([row_with_bytes(size)])
            self.assertEqual(result["error"], None if size == 100000 else "wire_budget")
            self.assertEqual(result["wire_bytes"], size if size == 100000 else 0)
            RESULTS["checks"]["line_"+str(size)] = result

    def test_actual_record_boundary(self):
        for count in (6200, 6201):
            result = production_emit({} for _ in range(count))
            self.assertEqual(result["error"], None if count == 6200 else "wire_budget")
            self.assertEqual(result["wire_bytes"], 6200 * 3)
            RESULTS["checks"]["records_"+str(count)] = result

    def test_actual_384_mib_total_boundary(self):
        cap = R.LIMITS["wire_bytes"]
        whole, tail = divmod(cap, 100000)
        large = row_with_bytes(100000)
        def rows(extra):
            yield from (large for _ in range(whole))
            yield row_with_bytes(tail)
            if extra: yield {}
        for extra in (False, True):
            result = production_emit(rows(extra))
            self.assertEqual(result["wire_bytes"], cap)
            self.assertEqual(result["error"], "wire_budget" if extra else None)
            RESULTS["checks"]["wire_total_extra_"+str(extra)] = result

    def test_partial_writes_backpressure_and_deadline(self):
        row = row_with_bytes(100000)
        result = production_emit([row], max_write=16384, block_once=True)
        self.assertIsNone(result["error"])
        self.assertEqual(result["wire_sha256"], hashlib.sha256(R.canon(row)+b"\n").hexdigest())
        stopped = production_emit([row], advance_after_select=True)
        self.assertEqual((stopped["error"], stopped["wire_bytes"]), ("wire_deadline", 0))
        RESULTS["checks"]["partial_writes"] = result
        RESULTS["checks"]["blocked_deadline"] = stopped

    def test_conservative_metadata_shapes(self):
        shapes = {"complete_final": sample_final(after=True),
                  "early_incomplete_final": sample_final(517),
                  "last_file_close": {"artifact": "aotg-comparison-file-close", "version": 1,
                      "index": 516, "label": "task/arm-063/logs/engine-private.log", "status": "captured",
                      "reason": None, "bytes": 262144, "read_bytes": 262144,
                      "sha256": "f"*64, "partial_sha256": "f"*64, "records": None,
                      "stat_before": maximum_stat(262144), "stat_after": maximum_stat(262144)}}
        sizes = {key: len(R.canon(value))+1 for key, value in shapes.items()}
        result = production_emit(shapes.values())
        self.assertIsNone(result["error"])
        RESULTS["checks"]["metadata_shapes"] = {"serialized_bytes": sizes, "emit": result,
             "stat_assumption": "64-bit device/inode/time/size; 32-bit uid/gid; directory links64bit",
             "maximum_observed_shape_is_not_a_formal_platform_bound": True,
             "four_kib_assumption_holds_for_these_shapes": max(sizes.values()) <= 4096}


class ActualCollectBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(COL))
        spec = importlib.util.spec_from_file_location("audit_existing_collector_tests", COL/"test_collector.py")
        cls.tests = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.tests)

    def fixture(self):
        fixture = self.tests.Fixture(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        return fixture

    def test_exact_raw_total_needs_extra_eof_read_budget(self):
        fixture = self.fixture(); _, ordinary = fixture.capture()
        exact = ordinary["total_read_bytes"]
        results = {}
        for slack in (0, 1):
            with patch.dict(self.tests.R.LIMITS, {"total_raw_bytes": exact+slack}):
                _, final = fixture.capture()
            results[str(slack)] = {k: final[k] for k in ("status", "errors", "raw_bytes", "total_read_bytes")}
        self.assertEqual(results["0"]["status"], "incomplete")
        self.assertIn("aggregate_byte_limit", results["0"]["errors"])
        self.assertEqual(results["1"]["status"], "complete")
        RESULTS["checks"]["exact_raw_total"] = {"baseline_total": exact, "slack_bytes": results}

    def test_real_collect_early_terminal_shape(self):
        fixture = self.fixture(); module = self.tests.R
        original = module.metadata; timer=[0.0]; calls=[0]
        def metadata(*args, **kwargs):
            value = original(*args, **kwargs); calls[0] += 1
            if calls[0] == 2: timer[0] = 61.0
            return value
        rows=[]
        with patch.object(module, "metadata", metadata):
            final = module.collect(fixture.request, rows.append, clock=lambda:timer[0])
        self.assertEqual(final["attempted_files"], 0)
        self.assertIn("protected_before", final)
        self.assertEqual(len(final["unattempted_indices"]),517)
        RESULTS["checks"]["real_early_final"] = {"bytes": len(module.canon(final))+1,
            "status": final["status"], "errors": final["errors"], "attempted_files": 0}


if __name__ == "__main__":
    suite=unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    RESULTS["test_count"]=result.testsRun
    RESULTS["tests_passed"]=result.wasSuccessful()
    target=HERE/"collector-wire-boundary-results.json"
    with target.open("x", encoding="utf-8") as stream:
        json.dump(RESULTS,stream,sort_keys=True,indent=2,allow_nan=False);stream.write("\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
