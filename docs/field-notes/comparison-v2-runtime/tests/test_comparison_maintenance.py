"""Fake-systemd coordination tests: never invoke systemctl or stage /run files."""

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))

from aotg.artifacts import ArtifactError, digest
from aotg.field_maintenance import (
    ORIGINAL_UNIT,
    RECOVERY_SOURCE,
    _run_sequence,
    execute_maintenance,
    freeze_maintenance_plan,
    preview_maintenance,
    render_commands,
    unit_names,
    validate_maintenance_plan,
)

ACTIVE = {"LoadState": "loaded", "ActiveState": "active", "SubState": "exited",
          "Result": "success", "ExecMainStatus": "0", "ControlGroup": "/system.slice/" + ORIGINAL_UNIT}


class FakeBackend:
    simulation = True

    def __init__(self, plan, lease_store=None):
        self.plan, self.owned = plan, unit_names(plan)
        self.events, self.saved = [], {}
        self.states = {ORIGINAL_UNIT: dict(ACTIVE)}
        self.clock = 0
        self.worker_exit = 0
        self.timer_arms = True
        self.hashes_match = True
        self.candidate_empty = True
        self.recovery_passes = True
        self.receipt = False
        self.stop_fails = False
        self.fail_launch = False
        self.recovery_started = False
        self.launch_locked = False
        self.lease_store = {} if lease_store is None else lease_store

    def now(self):
        return self.clock

    def sleep(self, seconds):
        self.clock += seconds

    def show(self, unit):
        return self.states.get(unit, {"LoadState": "not-found", "ActiveState": "inactive"})

    def empty(self, unit):
        return self.candidate_empty if unit == self.owned["worker"] else self.show(unit)["ActiveState"] == "inactive"

    def baseline_matches(self, plan):
        return self.hashes_match

    def restored_receipt(self, plan):
        return self.receipt and not self.lease_active()

    def lease_active(self):
        return bool(self.lease_store)

    def acquire_lease(self, plan):
        if self.lease_store:
            raise RuntimeError("An active or stale global maintenance lease exists")
        self.lease_store["owner"] = (plan["nonce"], digest(plan))

    def lease_state(self, plan):
        if not self.lease_store:
            return "absent"
        return "matching" if self.lease_store.get("owner") == (plan["nonce"], digest(plan)) else "foreign"

    def prior_restored(self, plan):
        value = self.saved.get("restored.json", {})
        return value.get("status") == "unit-restored" and value.get("plan_sha256") == digest(plan)

    def release_lease(self, plan):
        if self.lease_state(plan) != "matching":
            raise RuntimeError("Refuse to clear another maintenance lease")
        if not self.candidate_empty or not self.hashes_match or self.states[ORIGINAL_UNIT] != ACTIVE:
            raise RuntimeError("Restoration not verified before global lease release")
        self.lease_store.clear()

    @contextmanager
    def launch_guard(self, deadline):
        if self.recovery_started:
            raise RuntimeError("Recovery already began")
        self.launch_locked = True
        try:
            yield
        finally:
            self.launch_locked = False

    def wait_worker(self, unit, deadline):
        if self.launch_locked:
            raise AssertionError("Launch lock must be released before benchmark wait")
        return self.worker_exit

    def record(self, event, **fields):
        self.events.append(event)

    def save(self, name, value):
        self.saved[name] = value

    def command(self, argv, timeout, check=True):
        self.events.append(list(argv))
        if argv[0] == "/usr/bin/systemd-run":
            if any(arg.startswith("--on-active=") for arg in argv):
                self.states[self.owned["timer"]] = {"LoadState": "loaded", "ActiveState": "active" if self.timer_arms else "failed",
                                                     "Triggers": self.owned["service"]}
                self.states[self.owned["service"]] = {"LoadState": "loaded", "ActiveState": "inactive"}
            else:
                if self.fail_launch:
                    raise RuntimeError("fake worker launch failure")
                self.states[self.owned["worker"]] = {"LoadState": "loaded", "ActiveState": "failed" if self.worker_exit else "inactive"}
                return {"returncode": self.worker_exit, "stdout": ""}
        elif argv[1] == "stop":
            if argv[2] == ORIGINAL_UNIT and self.stop_fails:
                raise RuntimeError("fake stop failure")
            self.states[argv[2]] = {"LoadState": "loaded", "ActiveState": "inactive"}
        elif argv[1] == "start":
            if argv[2] == self.owned["service"]:
                if not self.recovery_passes:
                    raise RuntimeError("fake recovery failure")
                self.receipt = True
                self.states[ORIGINAL_UNIT] = dict(ACTIVE)
                self.release_lease(self.plan)
            elif argv[2] == ORIGINAL_UNIT:
                self.states[ORIGINAL_UNIT] = dict(ACTIVE)
        return {"returncode": 0, "stdout": ""}


@unittest.skipUnless(sys.platform == "linux", "Linux-only private maintenance plan")
class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.work = root / "work"
        self.work.mkdir(mode=0o700)
        self.script, self.input, self.baseline = root / "worker.py", root / "worker.json", root / "baseline.json"
        self.script.write_text("print('simulation fixture')\n", encoding="utf-8")
        self.input.write_text(json.dumps({"artifact":"aotg-evo-worker-plan","version":2,
            "budget_policy_sha256":"96f81bfa1ea1c90e4988a0a25560156ea402493b9549ac7f17d408c53f3bf277",
            "max_seconds":5340,"maintenance_unit":"aotg-1111111111111111-worker.service",
            "task_root":str(self.work/"work"),"worker_sha256":hashlib.sha256(self.script.read_bytes()).hexdigest()}),encoding="utf-8")
        self.baseline.write_text("{}\n", encoding="utf-8")
        # CI may run as root; use a synthetic nonroot owner only for freezing
        # validation through a patched stat result, never chown host files.
        if os.getuid() == 0:
            self.skipTest("Nonroot task directory fixture required")
        self.plan = freeze_maintenance_plan(nonce="1111111111111111",uid=os.getuid(), gid=os.getgid(), worker_script=self.script,
                                            worker_plan=self.input, baseline_files=[self.baseline], work_dir=self.work)
        self.backend = FakeBackend(self.plan)

    def test_v2_budget_rejects_legacy_plan_or_policy_and_is_exact(self):
        from aotg.field_maintenance import BUDGET_POLICY_SHA256
        self.assertEqual(self.plan["version"],2)
        self.assertEqual(self.plan["work_seconds"],5400)
        self.assertEqual(self.plan["recovery_seconds"],600)
        self.assertEqual(self.plan["budget_policy_sha256"],BUDGET_POLICY_SHA256)
        for key,value in (("version",1),("work_seconds",2100),("work_seconds",5340),
                          ("work_seconds",5401),("budget_policy_sha256","0"*64)):
            changed=copy.deepcopy(self.plan);changed[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ArtifactError):
                validate_maintenance_plan(changed,check_files=False)

    def test_worker_budget_mismatch_is_rejected_even_when_outer_file_hash_rebound(self):
        worker=json.loads(self.input.read_text());worker['max_seconds']=2040
        self.input.write_text(json.dumps(worker));changed=copy.deepcopy(self.plan)
        changed['worker_plan']['sha256']=hashlib.sha256(self.input.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ArtifactError,'Staged worker budget'):
            validate_maintenance_plan(changed)

    def test_slow_stop_cannot_launch_without_full_worker_allotment(self):
        old=self.backend.command
        def slow(argv,timeout,check=True):
            result=old(argv,timeout,check)
            if argv==['/usr/bin/systemctl','stop',ORIGINAL_UNIT]:self.backend.clock+=61
            return result
        self.backend.command=slow
        result=_run_sequence(self.plan,self.backend)
        self.assertEqual(result['status'],'worker-failed-restored')
        self.assertFalse(any(isinstance(x,list) and any(y.endswith('-worker.service') for y in x)
                             for x in self.backend.events))
        self.assertIn(['/usr/bin/systemctl','start',self.backend.owned['service']],self.backend.events)

    def test_dry_run_reads_only_and_renders_exact_protection(self):
        with patch("subprocess.run", side_effect=AssertionError("real service command forbidden")):
            result = preview_maintenance(self.plan, backend=self.backend)
        self.assertTrue(result["dry_run"])
        self.assertEqual(self.backend.events, [])
        worker = result["commands"]["start_worker"]
        for value in ("--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
                      "--property=PrivateTmp=yes", "--property=NoNewPrivileges=yes",
                      "--property=KillMode=control-group", "--property=TimeoutStopSec=30s"):
            self.assertIn(value, worker)
        self.assertTrue(any("ExecStopPost=+" in value and "--cause callback" in value for value in worker))
        self.assertNotIn("--property=PrivateDevices=yes", worker)
        self.assertEqual(result["plan_sha256"], digest(self.plan))

    def test_timer_must_arm_before_stop_and_worker(self):
        result = _run_sequence(self.plan, self.backend)
        commands = [value for value in self.backend.events if isinstance(value, list)]
        self.assertTrue(any(item.startswith("--on-active=") for item in commands[0]))
        self.assertEqual(commands[1], ["/usr/bin/systemctl", "stop", ORIGINAL_UNIT])
        self.assertTrue(any(item.endswith("-worker.service") for item in commands[2]))
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["simulation"])
        self.assertFalse(result["unit_restore_verified"])
        self.assertFalse(result["rollback_demonstrated"])

    def test_unarmed_timer_never_stops_original(self):
        self.backend.timer_arms = False
        result = _run_sequence(self.plan, self.backend)
        self.assertNotIn(["/usr/bin/systemctl", "stop", ORIGINAL_UNIT], self.backend.events)
        self.assertNotEqual(result["status"], "completed")

    def test_failed_worker_and_start_gap_request_recovery(self):
        for mode in ("worker", "launch", "stop"):
            with self.subTest(mode=mode):
                backend = FakeBackend(self.plan)
                backend.worker_exit = 7 if mode == "worker" else 0
                backend.fail_launch = mode == "launch"
                backend.stop_fails = mode == "stop"
                result = _run_sequence(self.plan, backend)
                self.assertEqual(result["status"], "worker-failed-restored")
                self.assertIn(["/usr/bin/systemctl", "start", backend.owned["service"]], backend.events)

    def test_recovery_failure_is_not_masked(self):
        self.backend.recovery_passes = False
        result = _run_sequence(self.plan, self.backend)
        self.assertEqual(result["status"], "recovery-failed")
        self.assertTrue(result["failures"])

    def test_root_and_exact_hash_are_required_before_commands(self):
        with patch("subprocess.run", side_effect=AssertionError("real command forbidden")):
            with patch("os.geteuid", return_value=1000), self.assertRaisesRegex(ArtifactError, "root"):
                execute_maintenance(self.plan, execute=True, approved_plan_sha256=digest(self.plan))
            with patch("os.geteuid", return_value=0), self.assertRaisesRegex(ArtifactError, "approval"):
                execute_maintenance(self.plan, execute=True, approved_plan_sha256="0" * 64)

    def test_drift_bounds_root_worker_and_owned_names_refused(self):
        for key, value in (("work_seconds", 2101), ("work_seconds", True), ("recovery_seconds", 601),
                           ("uid", 0), ("gid", 0), ("original_unit", "unrelated.service"),
                           ("nonce", "x;stop-other")):
            with self.subTest(key=key):
                altered = copy.deepcopy(self.plan)
                altered[key] = value
                with self.assertRaises(ArtifactError):
                    validate_maintenance_plan(altered, check_files=False)
        self.baseline.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ArtifactError, "drift"):
            preview_maintenance(self.plan, backend=self.backend)

    def test_existing_transient_name_refuses_reuse(self):
        self.backend.states[self.backend.owned["worker"]] = {"LoadState": "loaded", "ActiveState": "inactive"}
        with self.assertRaisesRegex(ArtifactError, "already exists"):
            preview_maintenance(self.plan, backend=self.backend)

    def test_control_code_is_bound_into_plan_approval(self):
        for key in ("coordinator_sha256", "recovery_sha256"):
            with self.subTest(key=key):
                altered = copy.deepcopy(self.plan)
                altered[key] = "0" * 64
                with self.assertRaisesRegex(ArtifactError, "control code changed"):
                    preview_maintenance(altered, backend=self.backend)

    def test_delayed_supervisor_cannot_launch_after_recovery_starts(self):
        self.backend.recovery_started = True
        result = _run_sequence(self.plan, self.backend)
        self.assertNotEqual(result["status"], "completed")
        self.assertNotIn(["/usr/bin/systemctl", "stop", ORIGINAL_UNIT], self.backend.events)
        self.assertFalse(any(isinstance(row, list) and "--property=Type=exec" in row for row in self.backend.events))

    def test_recovery_cleans_candidate_before_start_and_is_idempotent(self):
        namespace = {"__name__": "recovery_tests"}
        exec(compile(RECOVERY_SOURCE, "standalone_recovery.py", "exec"), namespace)
        self.backend.states[self.backend.owned["worker"]] = {"LoadState": "loaded", "ActiveState": "active"}
        self.backend.states[ORIGINAL_UNIT] = {"LoadState": "loaded", "ActiveState": "inactive"}
        self.backend.acquire_lease(self.plan)
        namespace["recover"](self.plan, self.backend)
        namespace["recover"](self.plan, self.backend)
        actions = [value for value in self.backend.events if isinstance(value, list)]
        self.assertEqual(actions[0], ["/usr/bin/systemctl", "stop", self.backend.owned["worker"]])
        self.assertEqual(actions[1], ["/usr/bin/systemctl", "start", ORIGINAL_UNIT])
        self.assertIn("restored.json", self.backend.saved)
        self.assertNotIn(["/usr/bin/systemctl", "stop", ORIGINAL_UNIT], actions)

    def test_recovery_drift_and_nonempty_cgroup_never_start_original(self):
        namespace = {"__name__": "recovery_tests"}
        exec(compile(RECOVERY_SOURCE, "standalone_recovery.py", "exec"), namespace)
        for reason in ("drift", "populated"):
            with self.subTest(reason=reason):
                backend = FakeBackend(self.plan)
                backend.hashes_match = reason != "drift"
                backend.candidate_empty = reason != "populated"
                backend.acquire_lease(self.plan)
                with self.assertRaises(RuntimeError):
                    namespace["recover"](self.plan, backend)
                self.assertNotIn(["/usr/bin/systemctl", "start", ORIGINAL_UNIT], backend.events)
                self.assertTrue(any(name.startswith("failure-") for name in backend.saved))
                self.assertEqual(backend.lease_state(self.plan), "matching")

    def test_callback_only_enqueues_and_does_not_stop_or_wait(self):
        namespace = {"__name__": "recovery_tests"}
        exec(compile(RECOVERY_SOURCE, "standalone_recovery.py", "exec"), namespace)
        self.backend.acquire_lease(self.plan)
        namespace["enqueue_recovery"](self.plan, self.backend)
        self.assertEqual(self.backend.events,
                         [["/usr/bin/systemctl", "--no-block", "start", self.backend.owned["service"]]])

    def test_expired_budget_rejected_by_command_renderer(self):
        with self.assertRaises(ArtifactError):
            render_commands(self.plan, remaining_seconds=0)

    def test_two_different_plans_cannot_overlap_or_steal_owner_death_lease(self):
        shared_lease = {}
        first = FakeBackend(self.plan, shared_lease)
        first.acquire_lease(self.plan)
        # No supervisor object/process needs to remain alive for this lease.
        del first
        second_plan = copy.deepcopy(self.plan)
        second_plan["nonce"] = "0123456789abcdef" if self.plan["nonce"] != "0123456789abcdef" else "fedcba9876543210"
        other_input=json.loads(self.input.read_text())
        other_input['maintenance_unit']=unit_names(second_plan)['worker']
        other_path=self.input.with_name('second-worker.json')
        other_path.write_text(json.dumps(other_input))
        second_plan['worker_plan']={'path':str(other_path),'sha256':hashlib.sha256(other_path.read_bytes()).hexdigest()}
        second = FakeBackend(second_plan, shared_lease)
        with self.assertRaisesRegex(ArtifactError, "global maintenance lease"):
            preview_maintenance(second_plan, backend=second)
        result = _run_sequence(second_plan, second)
        self.assertEqual(result["status"], "lease-refused")
        self.assertEqual(second.events, [])
        self.assertEqual(shared_lease["owner"], (self.plan["nonce"], digest(self.plan)))

    def test_wrong_recovery_neither_acts_nor_clears_global_lease(self):
        namespace = {"__name__": "recovery_tests"}
        exec(compile(RECOVERY_SOURCE, "standalone_recovery.py", "exec"), namespace)
        self.backend.acquire_lease(self.plan)
        other_plan = copy.deepcopy(self.plan)
        other_plan["nonce"] = "0123456789abcdef" if self.plan["nonce"] != "0123456789abcdef" else "fedcba9876543210"
        wrong = FakeBackend(other_plan, self.backend.lease_store)
        for function in ("recover", "enqueue_recovery"):
            with self.subTest(function=function), self.assertRaisesRegex(RuntimeError, "lease"):
                namespace[function](other_plan, wrong)
        self.assertEqual(wrong.events, [])
        self.assertEqual(self.backend.lease_state(self.plan), "matching")
        changed_approval = copy.deepcopy(self.plan)
        changed_approval["work_seconds"] = 60
        same_nonce = FakeBackend(changed_approval, self.backend.lease_store)
        with self.assertRaisesRegex(RuntimeError, "lease"):
            namespace["recover"](changed_approval, same_nonce)
        self.assertEqual(same_nonce.events, [])
        self.assertEqual(self.backend.lease_state(self.plan), "matching")

    def test_matching_recovery_releases_lease_only_after_verified_restore(self):
        namespace = {"__name__": "recovery_tests"}
        exec(compile(RECOVERY_SOURCE, "standalone_recovery.py", "exec"), namespace)
        self.backend.acquire_lease(self.plan)
        self.backend.states[ORIGINAL_UNIT] = {"LoadState": "loaded", "ActiveState": "inactive"}
        namespace["recover"](self.plan, self.backend)
        self.assertFalse(self.backend.lease_active())
        before = list(self.backend.events)
        namespace["recover"](self.plan, self.backend)
        self.assertEqual(self.backend.events, before)  # idempotent replay performs no service actions
        new_plan = copy.deepcopy(self.plan)
        new_plan["nonce"] = "0123456789abcdef" if self.plan["nonce"] != "0123456789abcdef" else "fedcba9876543210"
        new_owner = FakeBackend(new_plan, self.backend.lease_store)
        new_owner.acquire_lease(new_plan)
        with self.assertRaises(RuntimeError):
            namespace["recover"](self.plan, self.backend)
        self.assertEqual(new_owner.lease_state(new_plan), "matching")

    def test_unowned_recovery_without_receipt_cannot_start_production(self):
        namespace = {"__name__": "recovery_tests"}
        exec(compile(RECOVERY_SOURCE, "standalone_recovery.py", "exec"), namespace)
        with self.assertRaisesRegex(RuntimeError, "lease"):
            namespace["recover"](self.plan, self.backend)
        self.assertEqual(self.backend.events, [])

    def test_matching_recovery_handles_supervisor_death_before_timer_creation(self):
        namespace = {"__name__": "recovery_tests"}
        exec(compile(RECOVERY_SOURCE, "standalone_recovery.py", "exec"), namespace)
        self.backend.acquire_lease(self.plan)
        # The lease exists, but its timer and candidate were never registered.
        namespace["recover"](self.plan, self.backend)
        self.assertFalse(self.backend.lease_active())
        self.assertNotIn(["/usr/bin/systemctl", "stop", self.backend.owned["timer"]], self.backend.events)
        self.assertNotIn(["/usr/bin/systemctl", "stop", self.backend.owned["worker"]], self.backend.events)


if __name__ == "__main__":
    unittest.main()
