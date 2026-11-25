"""Offline #29 closure staging; not a complete candidate or field run."""
import ast
import base64
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import zlib
from copy import deepcopy
from pathlib import Path

import test_comparison_v2_quality_bridge as bridge

# Exact source deltas from #29 95159f7c94840e9114a55efc52a494fde5a35be5.
# Verify both the original archive and reconstructed Git blobs; no old pin is
# modified; the assembler port retains the v2 policy, markers and I/O gates.
OVERLAYS = {
    "aotg/field_evidence.py": (
        "06bdaef9fb7276679e8aa667937704d6b790a4be",
        [
            (
                "TERMINAL = (\"passed\", \"failed\", \"stopped\", \"timed_out\", \"missing\")\n"
                "\n"
                ,
                "TERMINAL = (\"passed\", \"failed\", \"stopped\", \"timed_out\", \"missing\")\n"
                "# Explicit worker/assembler stop reasons may not be represented in RESOURCES.\n"
                "# Preserve the run-wide veto even if a scalar resource value is absent or safe.\n"
                "RESOURCE_STOP_REASONS = frozenset({\n"
                "    \"swapout_change_or_reset\", \"nvme_temperature_failed\", \"hardware_alarm_triggered\",\n"
                "    \"gpu_resource_limit\", \"swap_or_disk_limit\", \"worker_stopped\",\n"
                "    \"resource_temperature_limit\", \"resource_memory_limit\",\n"
                "})\n"
                "\n"
                ,
            ),
            (
                "    total_violation = run[\"elapsed_seconds\"] > plan[\"limits\"][\"total_seconds\"]\n"
                "    resource_stop_indices = sorted(index for index, item in rows.items()\n"
                "                                   if any(reason.startswith(\"resource_\") and reason.endswith(\"_limit\")\n"
                "                                          for reason in item[\"errors\"]))\n"
                "    baseline_rows = [row for row in plan[\"schedule\"] if row[\"candidate_id\"] == plan[\"baseline_id\"]]\n"
                ,
                "    total_violation = run[\"elapsed_seconds\"] > plan[\"limits\"][\"total_seconds\"]\n"
                "    resource_stop_indices = sorted(\n"
                "        index for index, item in rows.items()\n"
                "        if item[\"trial\"][\"reason\"] in RESOURCE_STOP_REASONS\n"
                "        or any(reason.startswith(\"resource_\") and reason.endswith(\"_limit\")\n"
                "               for reason in item[\"errors\"])\n"
                "    )\n"
                "    baseline_rows = [row for row in plan[\"schedule\"] if row[\"candidate_id\"] == plan[\"baseline_id\"]]\n"
                ,
            ),
            (
                "        missing = any(any(\"missing\" in reason or \"mismatch\" in reason\n"
                "                          or reason.endswith(\"not_independent\") for reason in reasons)\n"
                "                      for reasons in errors.values())\n"
                ,
                "        missing = any(any(\"missing\" in reason or \"mismatch\" in reason\n"
                "                          or reason.endswith((\"not_independent\", \"_undeclared\"))\n"
                "                          or reason == \"trial_stopped\" for reason in reasons)\n"
                "                      for reasons in errors.values())\n"
                ,
            ),
        ],
    ),
    "aotg/field_proxy.py": (
        "3cd5678a70b533b17f41a8348fa479e5c835cbdc",
        [
            (
                "        self.active_handlers = 0\n"
                "        self.request_records = 0\n"
                ,
                "        self.active_handlers = 0\n"
                "        self._handlers_idle = threading.Event()\n"
                "        self._handlers_idle.set()\n"
                "        self.request_records = 0\n"
                ,
            ),
            (
                "                self._emit({\"kind\": \"aotg-proxy-rejection-v2\", \"status\": \"rejected\",\n"
                "                            \"http_status\": status, \"reason\": reason,\n"
                "                            \"method\": method if method in (\"GET\", \"POST\") else \"OTHER\"})\n"
                ,
                "                self._emit({\"kind\": \"aotg-proxy-rejection-v2\", \"status\": \"rejected\",\n"
                "                            \"http_status\": int(status), \"reason\": reason,\n"
                "                            \"method\": method if method in (\"GET\", \"POST\") else \"OTHER\"})\n"
                ,
            ),
            (
                "            self.active_handlers += 1\n"
                "        try:\n"
                "            super().process_request(request, client_address)\n"
                "        except BaseException:\n"
                "            with self.audit_lock:\n"
                "                self.active_handlers -= 1\n"
                "            raise\n"
                "\n"
                ,
                "            self.active_handlers += 1\n"
                "            self._handlers_idle.clear()\n"
                "        try:\n"
                "            super().process_request(request, client_address)\n"
                "        except BaseException:\n"
                "            self._handler_finished()\n"
                "            raise\n"
                "\n"
                "    def _handler_finished(self):\n"
                "        with self.audit_lock:\n"
                "            self.active_handlers -= 1\n"
                "            if self.active_handlers == 0:\n"
                "                self._handlers_idle.set()\n"
                "\n"
                ,
            ),
            (
                "        finally:\n"
                "            with self.audit_lock:\n"
                "                self.active_handlers -= 1\n"
                "\n"
                ,
                "        finally:\n"
                "            self._handler_finished()\n"
                "\n"
                "    def wait_for_handlers(self, timeout_seconds=None):\n"
                "        \"\"\"After shutdown, wait for handlers only within the existing deadline.\n"
                "\n"
                "        This does not close or certify the capture. A shorter caller budget\n"
                "        may be supplied. No audit lock is held while waiting for a writer.\n"
                "        Always call server_close and check the closing record afterwards.\n"
                "        \"\"\"\n"
                "        remaining = self.deadline - time.monotonic()\n"
                "        if timeout_seconds is not None:\n"
                "            remaining = min(remaining, timeout_seconds)\n"
                "        return self._handlers_idle.wait(max(0, remaining))\n"
                "\n"
                ,
            ),
        ],
    ),
    "tools/assemble_field_evidence.py": (
        "a29c157c96bed3ed785a7d61251085e69e2448bb",
        [
            (
                "        try:\n"
                "            need(worker_capture_bound, \"worker_capture_not_independently_bound\")\n"
                "            er = values[\"eresult\"]\n"
                "            arm_context(er, esummary, row, profile, values[\"config\"],\n"
                "                        reader.files[str(paths[\"config\"])][\"sha256\"], expected_config)\n"
                "            if er[\"status\"] in (\"stopped\", \"cleanup-failed\"):\n"
                "                need(esummary[\"status\"] == \"stopped\" and isinstance(er.get(\"stop_reason\"), str)\n"
                "                     and 0 < len(er[\"stop_reason\"]) <= 1024, \"worker_failure_reason_missing\")\n"
                "                runtime_failures.append(\"worker_\" + er[\"status\"].replace(\"-\", \"_\"))\n"
                "                provenance[\"worker_failure\"] = {\"recorded_reason\": er[\"stop_reason\"],\n"
                "                    \"summary_sha256\": reader.files[str(eroot / \"summary.json\")][\"sha256\"],\n"
                "                    \"arm_result_sha256\": reader.files[str(paths[\"eresult\"])][\"sha256\"],\n"
                "                    \"config_sha256\": reader.files[str(paths[\"config\"])][\"sha256\"],\n"
                "                    \"worker_sha256\": identity[\"worker_sha256\"], \"profile_sha256\": profile[\"profile_sha256\"]}\n"
                "            if client_capture_bound and values[\"kresult\"] is not None and requests is not None:\n"
                "                kr = values[\"kresult\"]\n"
                "                need(all(type(kr.get(key)) is type(value) and kr[key] == value for key, value in row.items())\n"
                "                     and [arm for arm in ksummary[\"arms\"] if arm.get(\"index\") == index] == [kr], \"client_arm_binding_mismatch\")\n"
                "                need(kr[\"requests_complete\"] is True and kr[\"requests\"] == requests, \"request_capture_incomplete\")\n"
                "                attempts, rejections = request_capture(requests, client[\"max_requests\"])\n"
                "                request_failures = request_outcomes(attempts)\n"
                "                if rejections[\"rejected_total\"]:\n"
                "                    request_failures.append(\"proxy_requests_rejected\")\n"
                "                if not attempts:\n"
                "                    request_failures.append(\"no_inference_requests_observed\")\n"
                "                if request_failures:\n"
                "                    runtime_failures.extend(reason for reason in request_failures if reason not in runtime_failures)\n"
                "                    provenance[\"request_failure_capture\"] = {\"capture_sha256\": reader.files[str(ka / \"requests.jsonl\")][\"sha256\"],\n"
                "                        \"client_result_sha256\": reader.files[str(paths[\"kresult\"])][\"sha256\"],\n"
                "                        \"request_records\": len(attempts), \"rejections\": rejections}\n"
                "        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:\n"
                "            errors.append({\"reason\": str(error) if isinstance(error, EvidenceError) else type(error).__name__, \"stage\": \"failure_observation\"})\n",
                "        try:\n"
                "            need(worker_capture_bound, \"worker_capture_not_independently_bound\")\n"
                "            er = values[\"eresult\"]\n"
                "            arm_context(er, esummary, row, profile, values[\"config\"],\n"
                "                        reader.files[str(paths[\"config\"])][\"sha256\"], expected_config)\n"
                "            if er[\"status\"] in (\"stopped\", \"cleanup-failed\"):\n"
                "                need(esummary[\"status\"] in (\"stopped\", er[\"status\"]) and isinstance(er.get(\"stop_reason\"), str)\n"
                "                     and 0 < len(er[\"stop_reason\"]) <= 1024, \"worker_failure_reason_missing\")\n"
                "                runtime_failures.append(\"worker_\" + er[\"status\"].replace(\"-\", \"_\"))\n"
                "                provenance[\"worker_failure\"] = {\"recorded_reason\": er[\"stop_reason\"],\n"
                "                    \"summary_sha256\": reader.files[str(eroot / \"summary.json\")][\"sha256\"],\n"
                "                    \"arm_result_sha256\": reader.files[str(paths[\"eresult\"])][\"sha256\"],\n"
                "                    \"config_sha256\": reader.files[str(paths[\"config\"])][\"sha256\"],\n"
                "                    \"worker_sha256\": identity[\"worker_sha256\"], \"profile_sha256\": profile[\"profile_sha256\"]}\n"
                "        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:\n"
                "            errors.append({\"reason\": str(error) if isinstance(error, EvidenceError) else type(error).__name__, \"stage\": \"worker_failure_observation\"})\n"
                "        # A bound client refusal does not require a worker arm to have survived.\n"
                "        try:\n"
                "            if client_capture_bound and values[\"kresult\"] is not None and requests is not None:\n"
                "                kr = values[\"kresult\"]\n"
                "                need(all(type(kr.get(key)) is type(value) and kr[key] == value for key, value in row.items())\n"
                "                     and [arm for arm in ksummary[\"arms\"] if arm.get(\"index\") == index] == [kr], \"client_arm_binding_mismatch\")\n"
                "                need(kr[\"requests_complete\"] is True and kr[\"requests\"] == requests, \"request_capture_incomplete\")\n"
                "                attempts, rejections = request_capture(requests, client[\"max_requests\"])\n"
                "                request_failures = request_outcomes(attempts)\n"
                "                if rejections[\"rejected_total\"]:\n"
                "                    request_failures.append(\"proxy_requests_rejected\")\n"
                "                if not attempts:\n"
                "                    request_failures.append(\"no_inference_requests_observed\")\n"
                "                if request_failures:\n"
                "                    runtime_failures.extend(reason for reason in request_failures if reason not in runtime_failures)\n"
                "                    provenance[\"request_failure_capture\"] = {\"capture_sha256\": reader.files[str(ka / \"requests.jsonl\")][\"sha256\"],\n"
                "                        \"client_result_sha256\": reader.files[str(paths[\"kresult\"])][\"sha256\"],\n"
                "                        \"request_records\": len(attempts), \"rejections\": rejections}\n"
                "        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:\n"
                "            errors.append({\"reason\": str(error) if isinstance(error, EvidenceError) else type(error).__name__, \"stage\": \"client_failure_observation\"})\n",
            ),
            (
                "                need(capture_bound, \"runtime_failure_not_bound_to_independent_capture\")",
                "                need(worker_capture_bound and client_capture_bound, \"runtime_failure_not_bound_to_independent_capture\")",
            ),
            (
                "            passed = global_ok and not errors and not runtime_failures and all(v is True for v in checks.values())",
                "            # Preserve a verified failure in the ledger even when the raw\n"
                "            # elapsed value cannot be represented by the comparison schema.\n"
                "            # Never replace zero (or a sub-minimum value) with a positive time.\n"
                "            need(coding[\"seconds\"] >= 1e-9, \"wall_seconds_below_comparison_minimum\")\n"
                "            passed = global_ok and not errors and not runtime_failures and all(v is True for v in checks.values())",
            ),
            (
                "    global_ok = capture_bound = worker_capture_bound = client_capture_bound = False",
                "    global_ok = worker_capture_bound = client_capture_bound = False",
            ),
            (
                "        capture_bound = True\n",
                "",
            ),
            (
                "        \"status\": \"incomplete\" if failures or decision is None else decision[\"status\"],\n"
                "        \"selected_candidate_id\": None if failures or decision is None else decision[\"selected_candidate_id\"],",
                "        \"status\": \"incomplete\" if not global_ok or failures or decision is None else decision[\"status\"],\n"
                "        \"selected_candidate_id\": None if not global_ok or failures or decision is None else decision[\"selected_candidate_id\"],",
            ),
        ],
    ),
}


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
    "The archived assessment reader requires POSIX directory descriptors",
)
class StagedClosureTests(unittest.TestCase):
    def test_pinned_evaluator_proxy_and_ported_assembler(self):
        with tempfile.TemporaryDirectory(prefix="aotg-staged-closure-") as tmp:
            scratch = Path(tmp)
            staged = scratch / "candidate"
            for relative, pin in bridge.PINS.items():
                raw = (bridge.ARCHIVE / relative).read_bytes()
                self.assertEqual(bridge.git_blob(raw), pin, relative)
                target = staged / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if relative in OVERLAYS:
                    new_pin, edits = OVERLAYS[relative]
                    for old, new in edits:
                        before, after = old.encode(), new.encode()
                        self.assertEqual(raw.count(before), 1, relative)
                        raw = raw.replace(before, after, 1)
                    self.assertEqual(bridge.git_blob(raw), new_pin, relative)
                target.write_bytes(raw)
            for relative, pin in bridge.MAIN_INPUTS.items():
                raw = (bridge.ROOT / relative).read_bytes()
                self.assertEqual(bridge.git_blob(raw), pin, relative)
                (staged / relative).write_bytes(raw)
            old_modules = dict(sys.modules)
            try:
                spec = importlib.util.spec_from_file_location(
                    "_aotg_staged_closure_fixture", staged / "tests/test_field_assessment_assemble.py"
                )
                fixture = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(fixture)
                # The helper creates fresh identities/plan/authority before
                # trials, then checks mixed 64 positive and semantic negatives.
                bridge.ArchiveQualityBridgeTests.check_mixed_synthetic_assembly(
                    self, fixture, scratch / "mixed"
                )
                root = scratch / "failure-controls"
                root.mkdir()
                f = fixture.Fixture(root)
                positive = f.run()
                self.assertEqual(positive["global_errors"], [])
                self.assertEqual(positive["decision"]["status"], "adopt")
                self.assertFalse(positive["goal_complete"])
                api = f.api.evidence
                run = positive["run"]
                alternative = next(t["index"] for t in run["trials"]
                                   if t["candidate_id"] != f.field["baseline_id"])
                # All scalar resources remain unchanged; an explicit stop
                # alone must veto adoption of even the other alternative.
                for reason in sorted(api.RESOURCE_STOP_REASONS):
                    with self.subTest(stop=reason):
                        changed = deepcopy(run)
                        trial = next(t for t in changed["trials"] if t["index"] == alternative)
                        trial.update(status="stopped", reason=reason)
                        decision = api.compare_field_run(changed)
                        self.assertEqual(decision["status"], "incomplete")
                        self.assertIsNone(decision["selected_candidate_id"])
                        self.assertTrue(decision["global_resource_stop"])
                        self.assertEqual(decision["resource_stop_trial_indices"], [alternative])
                changed = deepcopy(run)
                trial = next(t for t in changed["trials"] if t["index"] == alternative)
                trial["metrics"]["ttft_seconds"] = 0.01
                decision = api.compare_field_run(changed)
                self.assertEqual(decision["status"], "incomplete")
                self.assertIsNone(decision["selected_candidate_id"])
                self.assertFalse(decision["global_resource_stop"])
                # Independently bound summaries remain present; deleting one
                # required job receipt must invalidate global completion.
                receipt = Path(f.authority["jobs"][0]["receipt"]["path"])
                original = receipt.read_bytes()
                summaries = [(p, p.read_bytes()) for p in (f.k / "summary.json", f.e / "summary.json")]
                receipt.unlink()
                rejected = f.run()
                self.assertTrue(rejected["global_errors"])
                self.assertEqual(rejected["decision"]["status"], "incomplete")
                self.assertIsNone(rejected["decision"]["selected_candidate_id"])
                self.assertFalse(rejected["goal_complete"])
                for path, raw in summaries:
                    self.assertEqual(path.read_bytes(), raw)
                receipt.write_bytes(original)
                restored = f.run()
                self.assertEqual(restored["global_errors"], [])
                self.assertEqual(restored["decision"]["status"], "adopt")
                self.assertFalse(restored["measurement_generated"])
                self.assertFalse(restored["goal_complete"])

                # Rebind actual historical source/catalog digests in otherwise
                # matching synthetic evidence. The frozen current identity
                # must reject them even when the external descriptor is valid.
                a = fixture.a
                index = f.failure_index
                arm_key = str(index)
                original_arm = deepcopy(f.authority["arms"][arm_key])
                receipt = json.loads(Path(original_arm["source_review"]["path"]).read_text())
                report = json.loads(Path(original_arm["quality"]["path"]).read_text())
                isolation = json.loads(Path(original_arm["isolation"]["path"]).read_text())
                for field, relative in (
                    ("grader_sha256", "aotg/quality.py"),
                    ("catalog_sha256", "tests/fixtures/benchmark/catalog.json"),
                ):
                    old_raw = (bridge.ARCHIVE / relative).read_bytes()
                    self.assertEqual(bridge.git_blob(old_raw), bridge.PINS[relative])
                    old_digest = a.sha(old_raw)
                    self.assertNotEqual(old_digest, receipt[field])
                    for kind, reason in (
                        ("receipt", "external_source_review_binding_mismatch"),
                        ("report", "native_grade_binding_mismatch"),
                    ):
                        with self.subTest(stale=field, artifact=kind):
                            altered = deepcopy(original_arm)
                            if kind == "receipt":
                                altered["source_review"] = f.trusted(
                                    f"stale/{field}-receipt.json", {**receipt, field: old_digest}
                                )
                            else:
                                stale = {**report, field: old_digest}
                                altered["quality"] = f.trusted(f"stale/{field}-report.json", stale)
                                altered["isolation"] = f.trusted(
                                    f"stale/{field}-isolation.json",
                                    {**isolation, "stdout": base64.b64encode(
                                        zlib.compress(a.canonical(stale))
                                    ).decode()},
                                )
                            f.authority["arms"][arm_key] = altered
                            rejected = f.run()
                            self.assertEqual(rejected["global_errors"], [])
                            self.assertIn(reason, [
                                e["reason"] for e in rejected["ledger"][index]["missing_or_conflicting"]
                            ])
                            self.assertEqual(rejected["decision"]["status"], "incomplete")
                            self.assertIsNone(rejected["decision"]["selected_candidate_id"])
                            self.assertEqual(rejected["observation_decision"]["status"], "incomplete")
                            self.assertIsNone(rejected["observation_decision"]["selected_candidate_id"])
                            self.assertFalse(rejected["goal_complete"])
                            f.authority["arms"][arm_key] = deepcopy(original_arm)
                            restored = f.run()
                            self.assertEqual(restored["global_errors"], [])
                            self.assertEqual(restored["decision"]["status"], "adopt")
                            self.assertFalse(restored["measurement_generated"])
                            self.assertFalse(restored["goal_complete"])

                # Capture binding is independent per side; a valid client
                # refusal must survive the loss of the worker arm/summary.
                index = f.failure_index
                original_requests = deepcopy(f.kr[index]["requests"])
                rows = deepcopy(original_requests)
                rows.insert(2, {"kind": "aotg-proxy-rejection-v2", "status": "rejected",
                                "http_status": 409, "reason": "concurrent_request_rejected",
                                "method": "POST", "event_sequence": 2})
                rows[-1].update(event_sequence=3, rejected_total=1,
                                rejections_by_reason={"concurrent_request_rejected": 1})
                f.rebind_arm(index, requests=rows)
                worker_arm = f.e / ("arm-%03d/result.json" % index)
                worker_summary = f.e / "summary.json"
                worker_raw, summary_raw = worker_arm.read_bytes(), worker_summary.read_bytes()
                worker_arm.unlink()
                worker_summary.unlink()
                f.refresh_capture()
                partial = f.run()
                entry = partial["ledger"][index]
                self.assertEqual(entry["observation_class"], "verified_runtime_failure")
                self.assertIn("proxy_requests_rejected", entry["runtime_failures"])
                self.assertIn("request_failure_capture", entry["provenance"])
                self.assertFalse(entry["normalized"])
                self.assertTrue(any(e.get("stage") == "worker_capture"
                                    for e in partial["global_errors"]))
                self.assertEqual(partial["observation_decision"]["status"], "incomplete")
                self.assertIsNone(partial["observation_decision"]["selected_candidate_id"])
                client_pin = f.authority["client_summary_sha256"]
                f.authority["client_summary_sha256"] = "0" * 64
                unbound = f.run()
                self.assertNotIn("request_failure_capture", unbound["ledger"][index]["provenance"])
                self.assertNotEqual(unbound["ledger"][index]["observation_class"],
                                    "verified_runtime_failure")
                self.assertTrue(any(e.get("stage") == "client_capture"
                                    for e in unbound["global_errors"]))
                self.assertEqual(unbound["observation_decision"]["status"], "incomplete")
                f.authority["client_summary_sha256"] = client_pin
                worker_arm.write_bytes(worker_raw)
                worker_summary.write_bytes(summary_raw)
                f.rebind_arm(index, requests=original_requests)
                self.assertEqual(f.run()["decision"]["status"], "adopt")

                # A bound zero wall time is retained in the failure ledger
                # without inventing a normalized positive elapsed value.
                coding_path = f.k / ("arm-%02d/coding/result.json" % index)
                coding = json.loads(coding_path.read_text())
                f.rebind_arm(index, coding={**coding, "seconds": 0})
                below = f.run()
                entry = below["ledger"][index]
                self.assertFalse(entry["normalized"])
                self.assertEqual(entry["observation_class"], "verified_runtime_failure")
                self.assertIn("client_bounds_failed", entry["runtime_failures"])
                self.assertTrue(any(e["reason"] == "wall_seconds_below_comparison_minimum"
                                    for e in entry["missing_or_conflicting"]))
                self.assertNotIn(index, [trial["index"] for trial in below["run"]["trials"]])
                self.assertEqual(below["observation_decision"]["status"], "incomplete")
                f.rebind_arm(index, coding=coding)
                restored = f.run()
                self.assertEqual(restored["global_errors"], [])
                self.assertEqual(restored["decision"]["status"], "adopt")
                self.assertFalse(restored["goal_complete"])

                # Symmetric partial capture: the worker's independently
                # bound cleanup failure survives loss of the client evidence.
                client_arm = f.k / ("arm-%02d/result.json" % index)
                client_summary = f.k / "summary.json"
                worker_arm = f.e / ("arm-%03d/result.json" % index)
                worker_summary = f.e / "summary.json"
                paths = (client_arm, client_summary, worker_arm, worker_summary)
                originals = {path: path.read_bytes() for path in paths}
                worker_pin = f.authority["worker_summary_sha256"]
                stopped = json.loads(originals[worker_arm])
                stopped.update(status="cleanup-failed", stop_reason="synthetic cleanup failure")
                summary = json.loads(originals[worker_summary])
                summary.update(status="cleanup-failed")
                summary["arms"] = [stopped if arm["index"] == index else arm for arm in summary["arms"]]
                f.put(worker_arm, stopped)
                f.authority["worker_summary_sha256"] = f.put(worker_summary, summary)["sha256"]
                stopped_summary = worker_summary.read_bytes()
                client_arm.unlink()
                client_summary.unlink()
                f.refresh_capture()
                partial = f.run()
                entry = partial["ledger"][index]
                self.assertEqual(entry["observation_class"], "verified_runtime_failure")
                self.assertIn("worker_cleanup_failed", entry["runtime_failures"])
                self.assertEqual(entry["provenance"]["worker_failure"]["recorded_reason"],
                                 "synthetic cleanup failure")
                self.assertFalse(entry["normalized"])
                self.assertIn("client_capture", [e.get("stage") for e in partial["global_errors"]])
                self.assertEqual(partial["observation_decision"]["status"], "incomplete")
                self.assertIsNone(partial["observation_decision"]["selected_candidate_id"])

                # Both summary files absent: no independent binding on either
                # side, no invented total elapsed or comparison decision.
                worker_summary.unlink()
                f.refresh_capture()
                missing = f.run()
                reasons = {e["reason"] for e in missing["global_errors"]}
                self.assertTrue({"worker_summary_binding_mismatch", "client_summary_binding_mismatch",
                                 "run_completion_evidence_missing", "observed_total_elapsed_missing"}
                                <= reasons, reasons)
                self.assertIsNone(missing["run"])
                self.assertIsNone(missing["decision"])
                self.assertNotIn("worker_failure", missing["ledger"][index]["provenance"])
                self.assertNotEqual(missing["ledger"][index]["observation_class"],
                                    "verified_runtime_failure")
                self.assertEqual(missing["observation_decision"]["status"], "incomplete")
                self.assertIsNone(missing["observation_decision"]["selected_candidate_id"])
                self.assertIsNone(missing["observation_decision"]["comparison_sha256"])
                self.assertFalse(missing["goal_complete"])

                # Restore the same failure witness: partial failure becomes
                # verifiable again, but never upgrades to full completion.
                worker_summary.write_bytes(stopped_summary)
                f.refresh_capture()
                recovered = f.run()
                self.assertEqual(recovered["ledger"][index]["provenance"]["worker_failure"],
                                 entry["provenance"]["worker_failure"])
                self.assertEqual(recovered["observation_decision"]["status"], "incomplete")
                for path, raw in originals.items():
                    path.write_bytes(raw)
                f.authority["worker_summary_sha256"] = worker_pin
                f.refresh_capture()
                restored = f.run()
                self.assertEqual(restored["global_errors"], [])
                self.assertEqual(restored["decision"]["status"], "adopt")
                self.assertFalse(restored["measurement_generated"])
                self.assertFalse(restored["goal_complete"])
            finally:
                for name in list(sys.modules):
                    if name.startswith("_aotg_private_assessment"):
                        if name in old_modules:
                            sys.modules[name] = old_modules[name]
                        else:
                            del sys.modules[name]


    def test_runtime_caller_closes_or_rejects_capture(self):
        """Exercise actual archived caller definitions with the ported runtime proxy.

        The listener is ephemeral loopback only; no upstream, model, SSH,
        Windows job, or execute() path is entered.
        """
        archive = bridge.ARCHIVE.parent
        runner_raw = (archive / "k8-field-runner-v2.py").read_bytes()
        self.assertEqual(bridge.git_blob(runner_raw), "848d5ca3beebca933e215e2edf50ea9dac27afa4")
        proxy_raw = (archive / "runtime/aotg/field_proxy.py").read_bytes()
        self.assertEqual(bridge.git_blob(proxy_raw), "8451357b43595b0d01f5d98b77b16ffb77fc5c0f")
        for old, new in OVERLAYS["aotg/field_proxy.py"][1]:
            before, after = old.encode(), new.encode()
            self.assertEqual(proxy_raw.count(before), 1)
            proxy_raw = proxy_raw.replace(before, after, 1)

        # The assessment proxy is not interchangeable with the richer caller
        # proxy. Preserve the actual runtime tool timing and pre-HTTP loss API.
        with tempfile.TemporaryDirectory(prefix="aotg-caller-closure-") as tmp:
            path = Path(tmp) / "field_proxy.py"
            path.write_bytes(proxy_raw)
            spec = importlib.util.spec_from_file_location("_staged_runtime_proxy", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertTrue(callable(module.MeasurementProxy.mark_capture_incomplete))
            self.assertTrue(callable(module.MeasurementProxy.wait_for_handlers))
            self.assertTrue(callable(module._ToolRoundtrips))
            names = {
                "remaining", "describe", "require", "validate_capture",
                "validate_connection_refusals", "ScopedConnections", "BoundedProxy",
                "cleanup_server",
            }
            tree = ast.parse(runner_raw)
            nodes = [node for node in tree.body
                     if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
            self.assertEqual({node.name for node in nodes}, names)
            namespace = {"MeasurementProxy": module.MeasurementProxy, "threading": threading,
                         "time": time, "socket": socket}
            exec(compile(ast.Module(body=nodes, type_ignores=[]), "<pinned-caller>", "exec"), namespace)
            proxy_class = namespace["BoundedProxy"]
            cleanup = namespace["cleanup_server"]
            validate = namespace["validate_capture"]
            validate_refusals = namespace["validate_connection_refusals"]

            for mode in ("normal", "missing-close", "pre-http-refusal", "handler-timeout"):
                with self.subTest(mode=mode):
                    records = []

                    def sink(row):
                        if mode != "missing-close" or row.get("phase") != "closed":
                            records.append(row)

                    proxy = proxy_class(
                        ("127.0.0.1", 0), upstream="http://127.0.0.1:1/v1",
                        api_key="synthetic", model="synthetic", max_requests=9,
                        max_tokens=16, total_seconds=10, request_seconds=1, record=sink,
                    )
                    self.assertTrue(hasattr(proxy, "tool_roundtrips"))
                    serving = threading.Thread(target=proxy.serve_forever,
                                               kwargs={"poll_interval": 0.01}, daemon=True)
                    release = threading.Event()
                    entered = threading.Event()
                    left = right = None
                    serving.start()
                    try:
                        if mode in ("pre-http-refusal", "handler-timeout"):
                            left, right = socket.socketpair()
                            if mode == "pre-http-refusal":
                                proxy.close_admission()
                            else:
                                def held_handler(_request, _address):
                                    entered.set()
                                    release.wait(3)

                                proxy.finish_request = held_handler
                            proxy.process_request(left, ("127.0.0.1", 1))
                            if mode == "handler-timeout":
                                self.assertTrue(entered.wait(2))
                        errors = []
                        cleanup(proxy, serving, deadline=time.monotonic() + (
                            0.1 if mode == "handler-timeout" else 2
                        ), errors=errors)
                        if mode == "normal":
                            self.assertEqual(errors, [])
                            self.assertTrue(proxy.wait_for_handlers(0))
                            validate(records)
                            validate_refusals(proxy.connection_refusal_counts)
                            self.assertEqual(records[-1]["status"], "complete")
                        else:
                            with self.assertRaises(RuntimeError):
                                validate(records)
                            if mode == "missing-close":
                                self.assertEqual(errors, [])
                                self.assertEqual([row["phase"] for row in records], ["opened"])
                            elif mode == "pre-http-refusal":
                                self.assertEqual(errors, [])
                                self.assertEqual(proxy.connection_refusal_counts["closing"], 1)
                                self.assertEqual(records[-1]["status"], "incomplete")
                                self.assertTrue(records[-1]["record_error"])
                                with self.assertRaises(RuntimeError):
                                    validate_refusals(proxy.connection_refusal_counts)
                            else:
                                self.assertTrue(any("handler drain" in error for error in errors), errors)
                                self.assertFalse(proxy.wait_for_handlers(0))
                                self.assertEqual(records[-1]["status"], "incomplete")
                                self.assertEqual(records[-1]["active_handlers"], 1)
                        self.assertTrue(proxy.audit_closed)
                        before = deepcopy(records)
                        proxy.server_close()
                        self.assertEqual(records, before)
                    finally:
                        release.set()
                        # The fake handler is always released, including on assertion failure.
                        proxy.wait_for_handlers(2)
                        serving.join(2)
                        if serving.is_alive():
                            stop = threading.Thread(target=proxy.shutdown, daemon=True)
                            stop.start()
                            stop.join(2)
                            serving.join(2)
                        proxy.server_close()
                        for connection in (left, right):
                            if connection is not None:
                                connection.close()
                        self.assertFalse(serving.is_alive(), "Synthetic listener did not exit")


if __name__ == "__main__":
    unittest.main()
