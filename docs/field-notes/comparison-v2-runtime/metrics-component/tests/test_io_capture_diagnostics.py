"""Synthetic records only. Frozen producer files are read as bytes, never run."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("io_diagnostics_under_test", HERE / "tools/io_capture_diagnostics.py")
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def stamp(seconds):
    return (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat()


class Reader:
    def __init__(self, files):
        self.files = files
        self.reads = []

    def raw(self, path, maximum):
        self.reads.append((path, maximum))
        raw = self.files[path]
        if len(raw) > maximum:
            raise D.IOCaptureError("fixture_input_exceeds_requested_bound")
        return raw


class Fixture:
    def __init__(self):
        self.raws = {}
        for role, name in {"lifecycle_source": "supplemental-io-lifecycle-v2.py",
                           "sampler_source": "supplemental-io-sampler-v2.py",
                           "wrapper_source": "windows-io-job.ps1",
                           "native_helper_source": "WindowsIoJobV2.cs"}.items():
            self.raws[role] = (HERE.parent / "io-component" / name).read_bytes()
        self.run_id = "fixture-comparison-0123456789abcdef"
        self.nonce = "0123456789abcdef"
        self.worker = {"artifact": "aotg-evo-worker-plan", "version": 2, "run_id": self.run_id}
        transport = {}
        for role, filename, digest in (
            ("wrapper", "wrapper.ps1", D.SOURCE_HASHES["wrapper_source"]),
            ("helper", "helper.cs", D.SOURCE_HASHES["native_helper_source"]),
            ("ssh", "ssh.exe", "a" * 64), ("powershell", "powershell.exe", "b" * 64)):
            path = "/mnt/c/fixture/" + filename
            transport[role] = {"path": path, "windows_path": D.winpath(path), "sha256": digest}
        self.argv = ["-T", "-o", "BatchMode=yes", "-o", "ForwardAgent=no", "-o", "StrictHostKeyChecking=yes",
                     "-o", "IdentitiesOnly=yes", "fixture.invalid"]
        self.client = {"artifact": "aotg-k8-field-plan", "version": 2, "run_id": self.run_id,
             "maintenance_nonce": self.nonce, "worker_plan_sha256": D.sha(encode(self.worker)),
             "max_seconds": 5400, "cleanup_reserve_seconds": 60, "ssh": [transport["ssh"]["path"]] + self.argv,
             "windows_transport": {role: transport[role] for role in ("ssh", "powershell")}}
        self.auth = {"artifact": "aotg-owner-authorization", "version": 1, "nonce": self.nonce,
                     "client_plan_sha256": D.canonical(self.client)}
        self.plan = {"artifact": "aotg-supplemental-io-capture-plan", "version": 2,
            "status": "PROPOSED_UNAPPROVED_NOT_EXECUTED", "run_id": self.run_id, "nonce": self.nonce,
            "authorization_sha256": D.canonical(self.auth), "client_plan_sha256": D.canonical(self.client),
            "worker_plan_sha256": self.client["worker_plan_sha256"],
            "output_root": "/mnt/c/fixture/output", "windows_output_root": "C:\\fixture\\output",
            "sampler": {"path": "/mnt/c/fixture/sampler.py", "sha256": D.SOURCE_HASHES["sampler_source"]},
            "transport": transport, "windows_job_plan": "C:\\fixture\\output\\ssh-plan.json",
            "ssh_argv": list(self.argv), "limits": dict(D.LIMITS),
            "client_plan": {"path": "/mnt/c/fixture/client.json", "sha256": D.sha(encode(self.client))},
            "coverage_gate_max_gap_seconds": 2.5, "remote_file_created": False, "coverage_claimed": False}
        self.plan["capture_binding_sha256"] = D.canonical({"artifact": "aotg-supplemental-io-invocation", "version": 2,
            **{k: self.plan[k] for k in ("run_id", "nonce", "authorization_sha256", "client_plan_sha256", "worker_plan_sha256")},
            "sampler_sha256": self.plan["sampler"]["sha256"], "limits": D.LIMITS})
        self.job = {"artifact": "aotg-windows-io-job", "version": 2,
            "wrapper_sha256": transport["wrapper"]["sha256"],
            "helper": {"path": transport["helper"]["windows_path"], "sha256": transport["helper"]["sha256"]},
            "executable": {"path": transport["ssh"]["windows_path"], "sha256": transport["ssh"]["sha256"]},
            "argv": self.argv + ["/usr/bin/python3.14", "-I", "-S", "-B", "-", "--sample", "--seconds", "6255",
                                  "--run-id", self.run_id, "--capture-binding-sha256", self.plan["capture_binding_sha256"]],
            "cwd": self.plan["windows_output_root"], "wall_seconds": 6275,
            "cancel_path": self.plan["windows_output_root"] + "\\cancel",
            "result_path": self.plan["windows_output_root"] + "\\job-result.json"}
        self.plan["job_plan"] = {"path": self.plan["output_root"] + "/ssh-plan.json", "sha256": D.sha(encode(self.job))}
        for role, value in (("worker_plan", self.worker), ("client_plan", self.client), ("authorization", self.auth),
                            ("job_plan", self.job), ("plan", self.plan)):
            self.raws[role] = encode(value)
        self.expected = {**{key: self.plan[key] for key in D.EXPECTED_KEYS - {"plan_sha256", "client_plan_raw_sha256"}},
                         "plan_sha256": D.sha(self.raws["plan"]), "client_plan_raw_sha256": D.sha(self.raws["client_plan"])}
        common = {**{k: self.plan[k] for k in ("run_id", "authorization_sha256", "client_plan_sha256", "worker_plan_sha256",
                                             "capture_binding_sha256")}, "plan_sha256": self.expected["plan_sha256"],
                  "client_plan_raw_sha256": self.expected["client_plan_raw_sha256"],
                  "job_plan_sha256": self.plan["job_plan"]["sha256"], "sampler_sha256": self.plan["sampler"]["sha256"]}
        command = [transport["powershell"]["path"], "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                   transport["wrapper"]["windows_path"], "-Plan", self.plan["windows_job_plan"]]
        self.launch = {"artifact": "aotg-supplemental-io-launch", "version": 2, **common,
                       "wrapper_pid": 100, "utc": stamp(0), "local_monotonic": 10.,
                       "remote_file_created": False, "command_sha256": D.canonical(command)}
        assoc = {"run_id": self.run_id, "capture_binding_sha256": self.plan["capture_binding_sha256"]}
        self.meta = {"artifact": "aotg-supplemental-io-plan", "version": 1, **assoc, "sample_requested": True,
            "sources": ["/sys/class/block/nvme0n1/stat", "/proc/pressure/io", "/proc/stat"],
            "interval_seconds": 1, "wall_budget_seconds": 6255, "maximum_seconds": 6255,
            "maximum_records": D.MAX_RECORDS, "maximum_output_bytes": D.MAX_OUTPUT, "maximum_line_bytes": 8192,
            "final_record_reserve_seconds": .25, "output": "stdout JSONL only", "sector_bytes": 512,
            **copy.deepcopy(D.METADATA_TEXT),
            "utc": stamp(.01), "monotonic_ns": 100010000000, "cpu_ticks_per_second": 100}
        self.samples = []
        for n in range(2):
            self.samples.append({"artifact": "aotg-supplemental-io-sample", "version": 1, **assoc,
                "index": n, "observed_baseline": n == 0, "utc_read_start": stamp(n + .02),
                "utc_read_end": stamp(n + .03), "monotonic_read_start_ns": (100 + n) * 10**9 + 20000000,
                "monotonic_read_end_ns": (100 + n) * 10**9 + 30000000,
                "block": {key: n for key in D.BLOCK_NAMES},
                "io_pressure": {scope: {"avg10": 0., "avg60": 0., "avg300": 0., "total_us": n}
                                for scope in ("some", "full")},
                "cpu": {"ticks": {key: n for key in D.CPU_NAMES}, "boot_time_unix_seconds": 1234},
                "device_identity": {"resolved_stat_path": "/sys/devices/fixture/stat", "stat_inode": 123, "stat_device": 4},
                "counter_decreases": [], "counter_reset_or_decrease_detected": False})
        self.final = {"artifact": "aotg-supplemental-io-final", "version": 1, **assoc, "reason": "deadline",
            "signal": None, "error": None, "emitted_samples": 2, "observations_with_counter_decreases": 0,
            "utc": stamp(6254.8), "monotonic_ns": 6354800000000, "elapsed_seconds": 6254.8,
            "complete_to_configured_deadline": True}
        self.receipt = {"artifact": "aotg-windows-io-job-result", "version": 2,
            "plan_sha256": self.plan["job_plan"]["sha256"], "helper_sha256": transport["helper"]["sha256"],
            "wrapper_sha256": transport["wrapper"]["sha256"],
            "result": {"ProcessId": 200, "ExecutableSha256": transport["ssh"]["sha256"], "ExitCode": 0,
                       "TimedOut": False, "Cancelled": False, "JobEmpty": True,
                       "CleanupScope": "windows-job-object", "Seconds": 6255.2}}
        self.first = {"artifact": "aotg-supplemental-io-first-observed", "version": 2,
             "plan_sha256": self.expected["plan_sha256"], "capture_binding_sha256": self.plan["capture_binding_sha256"],
             "observed_utc": stamp(.1), "metadata": self.meta, "sample": self.samples[0]}
        self.terminal = {"artifact": "aotg-supplemental-io-lifecycle-result", "version": 2, **common,
            "utc": stamp(6256), "limits": dict(D.LIMITS), "owned_windows_job_cleanup_verified": True,
            "remote_process_exit_verified": False, "cancel_requested": False, "wrapper_pid": 100, "wrapper_returncode": 0,
            "job_receipt": self.receipt, "errors": [], "first_sample_observed": True, "sample_count": 2,
            "first_utc": self.samples[0]["utc_read_start"], "last_utc": self.samples[-1]["utc_read_end"],
            "sampler_final": self.final, "capture_finished_to_deadline": True,
            "coverage_evaluated": False, "coverage_complete": None, "rates_computed": False, "files": {}}
        self.raws["stderr"] = b""
        self.refresh()

    def refresh(self):
        for role, value in (("launch", self.launch), ("job_receipt", self.receipt), ("first_sample", self.first)):
            self.raws[role] = encode(value)
        self.raws["samples"] = b"".join((json.dumps(row) + "\n").encode() for row in
                                       [self.meta, *self.samples] + ([self.final] if self.final is not None else []))
        self.inventory()

    def inventory(self):
        self.terminal["files"] = {name: D.sha(self.raws[role]) for role, name in D.FILE_ROLES.items() if role in self.raws}
        self.raws["lifecycle_result"] = encode(self.terminal)

    def run(self):
        descriptors = {role: {"path": "/collected/" + role, "sha256": D.sha(raw)} for role, raw in self.raws.items()}
        reader = Reader({descriptors[role]["path"]: raw for role, raw in self.raws.items()})
        return D.io_capture_diagnostics(reader, descriptors, self.expected)


class IOAssociationTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def incomplete(self, result):
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["capture_finished_to_deadline"])
        self.assertFalse(result["remote_process_exit_verified"])
        self.assertFalse(result["quality_accepted"])
        self.assertFalse(result["coverage_evaluated"])

    def test_associated_terminal_is_not_coverage_or_remote_exit(self):
        result = self.f.run()
        self.assertEqual(result["status"], "associated_terminal_complete")
        for key in ("producer_association_verified", "job_association_verified", "owned_windows_job_cleanup_verified"):
            self.assertTrue(result[key])
        for key in ("remote_process_exit_verified", "external_identity_authentication_proved", "coverage_evaluated",
                    "rates_computed", "quality_accepted", "adoption_evaluated"):
            self.assertFalse(result[key])
        # Only two observations in a long synthetic interval: completeness of the
        # terminal cannot fill coverage gaps; coverage is deliberately not assessed.
        self.assertEqual(result["sample_count"], 2)
        text = json.dumps(result)
        self.assertNotIn("fixture.invalid", text)
        self.assertNotIn("/mnt/c", text)

    def test_fixed_source_bytes_are_verified_without_execution(self):
        self.f.raws["sampler_source"] += b"\n"
        with self.assertRaises(D.IOCaptureError): self.f.run()

    def test_external_authority_and_raw_vs_canonical_are_required(self):
        for key, value in (("plan_sha256", "0"*64), ("client_plan_raw_sha256", D.canonical(self.f.client)),
                           ("worker_plan_sha256", D.canonical(self.f.worker)), ("authorization_sha256", D.sha(encode(self.f.auth)))):
            with self.subTest(key=key):
                saved = self.f.expected[key]; self.f.expected[key] = value
                with self.assertRaises(D.IOCaptureError): self.f.run()
                self.f.expected[key] = saved

    def test_full_route_must_match_even_when_generic_ssh_flags_remain(self):
        self.f.plan["ssh_argv"][-1] = "other.invalid"
        self.f.raws["plan"] = encode(self.f.plan)
        self.f.expected["plan_sha256"] = D.sha(self.f.raws["plan"])
        with self.assertRaises(D.IOCaptureError): self.f.run()

    def test_foreign_run_and_launch_command_rejected(self):
        for key in ("run_id", "command_sha256", "client_plan_raw_sha256", "authorization_sha256"):
            with self.subTest(key=key):
                self.setUp(); self.f.launch[key] = "0"*64; self.f.refresh()
                result = self.f.run(); self.incomplete(result)
                self.assertIn("invalid_launch", result["reasons"])

    def test_job_argv_suffix_bound_to_sampler_and_invocation(self):
        self.f.job["argv"][-1] = "0"*64
        self.f.raws["job_plan"] = encode(self.f.job)
        self.f.plan["job_plan"]["sha256"] = D.sha(self.f.raws["job_plan"])
        self.f.raws["plan"] = encode(self.f.plan)
        self.f.expected["plan_sha256"] = D.sha(self.f.raws["plan"])
        with self.assertRaises(D.IOCaptureError): self.f.run()

    def test_receipt_bindings_and_scope_cannot_be_faked_by_jobempty(self):
        for container, key, value in (("root", "plan_sha256", "0"*64), ("root", "helper_sha256", "0"*64),
                ("result", "ExecutableSha256", "0"*64), ("result", "CleanupScope", "remote-process"),
                ("result", "ProcessId", True), ("result", "JobEmpty", 1)):
            with self.subTest(key=key):
                self.setUp(); target = self.f.receipt if container == "root" else self.f.receipt["result"]
                target[key] = value; self.f.refresh(); result = self.f.run(); self.incomplete(result)
                self.assertFalse(result["job_association_verified"])
                self.assertFalse(result["owned_windows_job_cleanup_verified"])

    def test_missing_receipt_or_terminal_does_not_prove_cleanup(self):
        for role in ("job_receipt", "lifecycle_result"):
            with self.subTest(role=role):
                self.setUp(); del self.f.raws[role]
                result = self.f.run(); self.incomplete(result)
                self.assertFalse(result["owned_windows_job_cleanup_verified"])

    def test_missing_final_preserves_association_but_never_completes(self):
        self.f.final = None; self.f.terminal["sampler_final"] = None
        self.f.terminal["capture_finished_to_deadline"] = False; self.f.refresh()
        result = self.f.run(); self.incomplete(result)
        self.assertTrue(result["producer_association_verified"])
        self.assertTrue(result["owned_windows_job_cleanup_verified"])
        self.assertIn("missing_sampler_final", result["reasons"])

    def test_cancel_can_only_prove_owned_windows_cleanup(self):
        self.f.raws["cancel"] = b""
        self.f.terminal["cancel_requested"] = True
        self.f.terminal["capture_finished_to_deadline"] = False
        self.f.terminal["wrapper_returncode"] = 124
        self.f.receipt["result"]["Cancelled"] = True
        self.f.final.update(reason="signal", signal=15, complete_to_configured_deadline=False, elapsed_seconds=2.,
                            monotonic_ns=102000000000, utc=stamp(2.))
        self.f.refresh(); result = self.f.run(); self.incomplete(result)
        self.assertTrue(result["owned_windows_job_cleanup_verified"])
        self.assertTrue(result["cancel_observed"])

    def test_cancel_marker_alone_overrides_success_claim(self):
        self.f.raws["cancel"] = b""; self.f.inventory()
        result = self.f.run(); self.incomplete(result)
        self.assertIn("cancellation_observed", result["reasons"])

    def test_caller_cancel_after_job_exit_is_still_incomplete(self):
        self.f.terminal["cancel_requested"] = True
        self.f.terminal["capture_finished_to_deadline"] = False
        self.f.inventory()
        result = self.f.run(); self.incomplete(result)
        self.assertTrue(result["owned_windows_job_cleanup_verified"])
        self.assertTrue(result["cancel_observed"])

    def test_late_errors_and_nonzero_wrapper_never_complete(self):
        self.f.terminal["errors"] = ["output-hash-failed-stderr.log"]
        self.f.terminal["capture_finished_to_deadline"] = False
        self.f.inventory()
        result = self.f.run(); self.incomplete(result)
        self.assertIn("lifecycle_reported_errors", result["reasons"])
        self.setUp()
        self.f.terminal["wrapper_returncode"] = 5
        self.f.receipt["result"]["ExitCode"] = 5
        self.f.terminal["capture_finished_to_deadline"] = False
        self.f.refresh(); result = self.f.run(); self.incomplete(result)
        self.assertTrue(result["owned_windows_job_cleanup_verified"])

    def test_fixed_metadata_and_terminal_monotonic_consistency(self):
        self.f.meta["sector_bytes"] = 4096
        self.f.refresh(); result = self.f.run(); self.incomplete(result)
        self.assertIn("invalid_samples", result["reasons"])
        self.setUp()
        self.f.final["monotonic_ns"] += 10**10
        self.f.refresh(); result = self.f.run(); self.incomplete(result)
        self.assertIn("invalid_samples", result["reasons"])

    def test_false_cleanup_and_remote_exit_claims_rejected(self):
        for key, value in (("remote_process_exit_verified", True), ("wrapper_pid", 999), ("wrapper_returncode", None),
                           ("coverage_evaluated", True), ("capture_finished_to_deadline", False)):
            with self.subTest(key=key):
                self.setUp(); self.f.terminal[key] = value; self.f.inventory()
                result = self.f.run(); self.incomplete(result)
                self.assertIn("invalid_lifecycle_result", result["reasons"])

    def test_terminal_inventory_requires_all_supplied_raw_files(self):
        self.f.terminal["files"]["samples.jsonl"] = "0"*64
        self.f.raws["lifecycle_result"] = encode(self.f.terminal)
        result = self.f.run(); self.incomplete(result)
        self.assertIn("invalid_lifecycle_result", result["reasons"])

    def test_first_sample_exact_copy_required(self):
        self.f.first = copy.deepcopy(self.f.first); self.f.first["sample"]["index"] = 99
        self.f.refresh(); result = self.f.run(); self.incomplete(result)
        self.assertIn("invalid_first_sample", result["reasons"])

    def test_stream_foreign_duplicate_final_sequence_and_boolean_index(self):
        for mutation in ("foreign", "duplicate-final", "sequence", "boolean-index", "backwards", "boot"):
            with self.subTest(mutation=mutation):
                self.setUp()
                if mutation == "foreign": self.f.samples[1]["capture_binding_sha256"] = "0"*64
                if mutation == "sequence": self.f.samples[1]["index"] = 4
                if mutation == "boolean-index": self.f.samples[1]["index"] = True
                if mutation == "backwards": self.f.samples[1]["monotonic_read_end_ns"] = 0
                if mutation == "boot": self.f.samples[1]["cpu"]["boot_time_unix_seconds"] += 1
                self.f.refresh()
                if mutation == "duplicate-final":
                    self.f.raws["samples"] += (json.dumps(self.f.final) + "\n").encode(); self.f.inventory()
                result = self.f.run(); self.incomplete(result)
                self.assertIn("invalid_samples", result["reasons"])

    def test_invalid_final_reason_count_and_early_deadline(self):
        for key, value in (("reason", "unknown"), ("emitted_samples", 3), ("elapsed_seconds", 1.),
                           ("signal", 15), ("complete_to_configured_deadline", 1)):
            with self.subTest(key=key):
                self.setUp(); self.f.final[key] = value; self.f.refresh()
                result = self.f.run(); self.incomplete(result)
                self.assertIn("invalid_samples", result["reasons"])

    def test_partial_oversized_line_and_record_count_bounds(self):
        for mutation in ("partial", "line", "count"):
            with self.subTest(mutation=mutation):
                self.setUp()
                if mutation == "partial": self.f.raws["samples"] = self.f.raws["samples"][:-1]
                elif mutation == "line": self.f.raws["samples"] = b"x"*8192 + b"\n{}\n"
                else: self.f.raws["samples"] = b"{}\n"*(D.MAX_RECORDS+1)
                self.f.inventory(); result = self.f.run(); self.incomplete(result)
                self.assertIn("invalid_samples", result["reasons"])

    def test_reader_gets_output_cap_and_descriptor_hash_checked(self):
        descriptors = {role: {"path": "/collected/" + role, "sha256": D.sha(raw)} for role, raw in self.f.raws.items()}
        reader = Reader({descriptors[role]["path"]: raw for role, raw in self.f.raws.items()})
        D.io_capture_diagnostics(reader, descriptors, self.f.expected)
        self.assertIn(("/collected/samples", 32*1024*1024), reader.reads)
        descriptors["samples"]["sha256"] = "0"*64
        with self.assertRaises(D.IOCaptureError): D.io_capture_diagnostics(reader, descriptors, self.f.expected)

    def test_duplicate_json_keys_and_nan_rejected(self):
        for raw in (b'{"artifact":"a","artifact":"b"}', b'{"value":NaN}'):
            self.f.raws["job_receipt"] = raw; self.f.inventory()
            result = self.f.run(); self.incomplete(result)
            self.assertIn("invalid_job_receipt", result["reasons"])

    def test_no_emitted_evidence_is_incomplete_not_success(self):
        self.f.raws = {role: raw for role, raw in self.f.raws.items() if role in D.BASE_ROLES}
        result = self.f.run(); self.incomplete(result)
        self.assertFalse(result["producer_association_verified"])
        self.assertFalse(result["job_association_verified"])


if __name__ == "__main__":
    unittest.main()
