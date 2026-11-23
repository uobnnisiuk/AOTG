"""Offline CI contracts for PR #38's unpublished diagnostic prototypes.

These tests NEVER import a private worker, access /proc, launch a model or contact a
service. They close the previous CI gap for public helpers and exercise an
isolated, synthetic stop -> evidence capture -> recovery receipt -> readback.
A passing test is NOT proof of private-worker integration or live restoration.
"""

import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest


_SOURCE = pathlib.Path(__file__).resolve().parents[1] / "docs" / "field-notes" / "memory-context-candidate"


def _load_source(name):
    """Import the fixed public source file, never a private worker or patch."""
    path = _SOURCE / (name + ".py")
    spec = importlib.util.spec_from_file_location("aotg_ci_" + name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing-public-helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses needs the registered module
    spec.loader.exec_module(module)
    return module


budget_code = _load_source("serialized_budget")
triage_code = _load_source("diagnostic_triage")


def _append_durable(path, lines, *, fail=False):
    """Synthetic artifact only; injected errors model failed persistence."""
    if fail:
        raise OSError("synthetic-observation-write-failure")
    with path.open("ab") as stream:
        for line in lines:
            stream.write(line)
        stream.flush()
        os.fsync(stream.fileno())


def _sealed(path, record):
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _append_durable(path, (raw,))
    return hashlib.sha256(raw).hexdigest()


def _trigger_event(*, same_window):
    return {
        "trigger_recorded": True,
        "fresh_anchor": True,
        "same_guard_sample": True,
        "previous_pswpout": 115,
        "trigger_pswpout": 158,
        "context_same_window": same_window,
        "psi_full_total_delta_us": None,
        "cgroup_memory_high_delta": None,
        "cgroup_memory_oom_delta": None,
        "cgroup_swap_bytes": None,
        "mem_available_bytes": None,
    }


class PublicDiagnosticContractTest(unittest.TestCase):
    def test_existing_source_self_tests_are_in_normal_ci(self):
        # These were source-only self-tests and previously absent from CI.
        for module, expected in ((budget_code, 12), (triage_code, 10)):
            with self.subTest(module=module.__name__):
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.Tests)
                self.assertEqual(suite.countTestCases(), expected)
                result = unittest.TestResult()
                suite.run(result)
                self.assertTrue(result.wasSuccessful(), repr(result.errors + result.failures))
                self.assertEqual(result.skipped, [])

    def test_synthetic_guard_stop_persists_refusal_before_recovery(self):
        # All paths are confined to a temporary isolated fixture, not a live run.
        with tempfile.TemporaryDirectory(prefix="aotg-offline-stop-") as tmp:
            root = pathlib.Path(tmp)
            observations = root / "observations.jsonl"
            restoration = root / "restoration.jsonl"
            budget = budget_code.SerializedBudget()
            reads = []
            restored = []
            try:
                _append_durable(observations, budget.initial(0, {"phase": "initial"}))
                accepted = budget.primary(0, {"sequence": 0, "pswpout": 115},
                                          {"sequence": 0, "guard": "pass"})
                _append_durable(observations, accepted)
                outcome, extra = budget.context_after_guard(
                    0, True, lambda: reads.append(0) or {"sequence": 0, "sample": "synthetic"}
                )
                self.assertEqual(outcome, "context-recorded")
                _append_durable(observations, extra)
                rejected = budget.primary(190, {"sequence": 1, "pswpout": 158},
                                          {"sequence": 1, "guard": "reject",
                                           "reason": "synthetic-swap"})
                # Ensure the rejected values are durable before stop/recovery.
                _append_durable(observations, rejected)
                decision, extra = budget.context_after_guard(
                    190, False, lambda: reads.append(190) or {"forbidden": True}
                )
                self.assertEqual((decision, extra), ("guard-rejected-no-context", ()))
            finally:
                # This is an injected *stub*, not an actual restoration command.
                restored.append(True)
                _sealed(restoration, {"synthetic_recovery_stub_called": True,
                                      "real_machine_restored": False, "status": "incomplete"})

            captured = observations.read_bytes()
            original_digest = hashlib.sha256(captured).hexdigest()
            # Independent readback: no in-memory list is used as the proof.
            lines = [json.loads(line) for line in captured.splitlines()]
            self.assertEqual(lines[-2:], [
                {"pswpout": 158, "sequence": 1},
                {"guard": "reject", "reason": "synthetic-swap", "sequence": 1},
            ])
            self.assertEqual(hashlib.sha256(observations.read_bytes()).hexdigest(), original_digest)
            self.assertEqual(reads, [0], "rejected guard must not sample context")
            self.assertEqual(restored, [True])
            receipt = json.loads(restoration.read_text())
            self.assertFalse(receipt["real_machine_restored"])
            self.assertEqual(receipt["status"], "incomplete")
            self.assertEqual(budget.summary()["status"], "incomplete-stopped")
            evidence = triage_code.triage(_trigger_event(same_window=False))
            self.assertEqual(evidence["category"], "swap-activity-unattributed")
            self.assertFalse(evidence["authorizes_retry"])
            self.assertFalse(evidence["runtime_qualified"])

    def test_synthetic_capture_failure_still_invokes_recovery_stub(self):
        with tempfile.TemporaryDirectory(prefix="aotg-offline-failure-") as tmp:
            path = pathlib.Path(tmp) / "observations.jsonl"
            budget = budget_code.SerializedBudget()
            _append_durable(path, budget.initial(0, {"phase": "initial"}))
            reads = []
            restore_calls = []
            stopped = False
            try:
                records = budget.primary(0, {"pswpout": 158, "sequence": 0},
                                         {"guard": "reject", "sequence": 0})
                _append_durable(path, records, fail=True)
                self.fail("write injection did not fail")
            except OSError:
                stopped = True
            finally:
                restore_calls.append("synthetic-restore-stub")
            self.assertTrue(stopped)
            self.assertEqual(restore_calls, ["synthetic-restore-stub"])
            self.assertEqual(reads, [])
            # Logical admission by SerializedBudget is not durable commit.
            # The failed guard record MUST NOT be treated as captured evidence.
            self.assertEqual(len(path.read_bytes().splitlines()), 1)
            self.assertEqual(triage_code.triage(
                _trigger_event(same_window=False) | {"trigger_recorded": False}
            )["category"], "trigger-evidence-missing")

    def test_capacity_refusal_is_before_sampling_and_never_a_pass(self):
        baseline = budget_code.SerializedBudget()
        baseline.initial(0, {"phase": "initial"})
        baseline.primary(0, {"sample": 0}, {"guard": "pass"})
        budget = budget_code.SerializedBudget(budget_code.Limits(max_bytes=baseline.bytes + 2))
        budget.initial(0, {"phase": "initial"})
        budget.primary(0, {"sample": 0}, {"guard": "pass"})
        reads = []
        with self.assertRaisesRegex(budget_code.BudgetStop, "no-capacity-before-context-read"):
            budget.context_after_guard(0, True, lambda: reads.append("wrong") or {})
        self.assertEqual(reads, [])
        self.assertEqual(budget.summary()["status"], "incomplete-stopped")
        self.assertFalse(budget.summary()["runtime_qualified"])


if __name__ == "__main__":
    unittest.main()
