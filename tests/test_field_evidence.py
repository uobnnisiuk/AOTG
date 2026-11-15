"""Measured evidence gates: completed failures differ from missing evidence."""

import copy
import tempfile
import unittest
from pathlib import Path

from aotg.artifacts import ArtifactError, digest
from aotg.field_evidence import (
    build_field_kit,
    compare_field_run,
    freeze_plan,
    quality_record,
    validate_field_plan,
    verify_field_kit,
)


def example_run():
    plan = freeze_plan(
        identity_sha256=digest({"model": "fixed", "quant": "fixed", "sampling": 4242}),
        verifier_sha256=digest("verifier"),
        candidates=[{"id": name, "profile_sha256": digest(name)}
                    for name in ("baseline", "threads", "batch")],
        workloads=[{"id": name, "input_sha256": digest(name),
                    "tests_sha256": digest(name + "-independent"), "cache_cohort": "cold"}
                   for name in ("cpp", "csharp")],
        limits={"trial_seconds": 120, "total_seconds": 3600,
                "max_temperature_c": 75, "min_mem_available_bytes": 1024,
                "max_swapout_bytes": 0},
    )
    profiles = {value["id"]: value for value in plan["candidates"]}
    workloads = {value["id"]: value for value in plan["workloads"]}
    trials = []
    for row in plan["schedule"]:
        workload = workloads[row["workload_id"]]
        trials.append({
            "index": row["index"], "candidate_id": row["candidate_id"],
            "workload_id": row["workload_id"], "identity_sha256": plan["identity_sha256"],
            "profile_sha256": profiles[row["candidate_id"]]["profile_sha256"],
            "source_sha256": digest("result-source"),
            "cache_cohort": "cold", "status": "passed", "reason": "completed",
            "metrics": {"wall_seconds": 8 if row["candidate_id"] == "threads" else 10},
            "resources": {"peak_temperature_c": 65, "min_mem_available_bytes": 4096,
                          "swapout_delta_bytes": 0, "gpu_errors": 0, "io_errors": 0},
            "quality": quality_record(
                input_sha256=workload["input_sha256"], tests_sha256=workload["tests_sha256"],
                verifier_sha256=digest("verifier"), source_sha256=digest("result-source"),
                independent=True, checks={"correctness": True, "tool_compatibility": True,
                                          "completed": True, "stability": True},
                source_review={"artifact": "aotg-source-review", "version": 1,
                               "source_sha256": digest("result-source"),
                               "grader_sha256": digest("verifier"),
                               "catalog_sha256": workload["tests_sha256"],
                               "independent": True, "reviewer": "independent-reviewer",
                               "verdict": "accepted", "evidence_reference": "review-record"}),
        })
    return {"artifact": "aotg-field-run", "version": 1, "plan": plan,
            "plan_sha256": digest(plan), "elapsed_seconds": 200, "trials": trials}


class FieldEvidenceTests(unittest.TestCase):
    def test_frozen_abba_and_repeated_improvement(self):
        run = example_run()
        self.assertEqual([row["candidate_id"] for row in run["plan"]["schedule"][:4]],
                         ["baseline", "threads", "threads", "baseline"])
        result = compare_field_run(run)
        self.assertEqual(result["status"], "adopt")
        self.assertEqual(result["selected_candidate_id"], "threads")
        self.assertEqual(result["comparisons"][0]["paired_improvement_fractions"], [0.2] * 4)
        self.assertFalse(result["deployment_verified"])

    def test_no_reproduced_improvement_retains_baseline(self):
        run = example_run()
        for trial in run["trials"]:
            trial["metrics"]["wall_seconds"] = 10
        result = compare_field_run(run)
        self.assertEqual(result["status"], "retain_baseline")
        self.assertEqual(result["selected_candidate_id"], "baseline")

    def test_median_improvement_cannot_hide_one_regression(self):
        run = example_run()
        run["trials"][2]["metrics"]["wall_seconds"] = 11
        result = compare_field_run(run)
        self.assertEqual(result["status"], "retain_baseline")
        self.assertEqual(result["comparisons"][0]["status"], "hold")

    def test_explicit_bad_candidate_is_rejected(self):
        run = example_run()
        for trial in run["trials"]:
            if trial["candidate_id"] == "threads":
                trial["status"] = "failed"
                trial["reason"] = "independent_test_failure"
                quality = trial["quality"]
                quality["checks"]["correctness"] = False
                quality["result_sha256"] = digest({key: value for key, value in quality.items()
                                                   if key != "result_sha256"})
        result = compare_field_run(run)
        self.assertEqual(result["status"], "retain_baseline")
        self.assertEqual(result["comparisons"][0]["status"], "reject")
        self.assertIn("quality_correctness_failed", result["comparisons"][0]["trial_errors"]["1"])

    def test_missing_observation_is_not_no_improvement(self):
        run = example_run()
        run["trials"].pop()
        result = compare_field_run(run)
        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["selected_candidate_id"])

    def test_missing_metrics_and_resources_block_completion(self):
        for section, key in (("metrics", "wall_seconds"), ("resources", "gpu_errors")):
            with self.subTest(section=section):
                run = example_run()
                run["trials"][1][section][key] = None
                self.assertEqual(compare_field_run(run)["status"], "incomplete")

    def test_quality_and_condition_changes_cannot_pass(self):
        for section, key, value in (
            (None, "cache_cohort", "warm"),
            (None, "identity_sha256", digest("changed-quant")),
            (None, "profile_sha256", digest("wrong-profile")),
            ("resources", "peak_temperature_c", 76),
            ("resources", "swapout_delta_bytes", 1),
            ("resources", "min_mem_available_bytes", 100),
        ):
            with self.subTest(key=key):
                run = example_run()
                target = run["trials"][1] if section is None else run["trials"][1][section]
                target[key] = value
                expected = "incomplete" if section is None else "reject"
                self.assertEqual(compare_field_run(run)["comparisons"][0]["status"], expected)

    def test_non_independent_quality_cannot_pass(self):
        run = example_run()
        quality = run["trials"][1]["quality"]
        quality["independent"] = False
        quality["result_sha256"] = digest({key: value for key, value in quality.items()
                                           if key != "result_sha256"})
        self.assertEqual(compare_field_run(run)["comparisons"][0]["status"], "incomplete")

    def test_failed_baseline_cannot_certify_search(self):
        run = example_run()
        run["trials"][0]["resources"]["io_errors"] = 1
        self.assertEqual(compare_field_run(run)["status"], "incomplete")

    def test_total_bound_prevents_adoption(self):
        run = example_run()
        run["elapsed_seconds"] = 3601
        result = compare_field_run(run)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["total_time_limit_exceeded"])

    def test_total_cannot_understate_sequential_measured_time(self):
        run = example_run()
        run["elapsed_seconds"] = 1
        with self.assertRaisesRegex(ArtifactError, "shorter than sequential"):
            compare_field_run(run)

    def test_forged_quality_hash_rejected(self):
        run = example_run()
        run["trials"][1]["quality"]["checks"]["correctness"] = False
        with self.assertRaisesRegex(ArtifactError, "hash mismatch"):
            compare_field_run(run)

    def test_wrong_source_grader_catalog_or_missing_review_cannot_adopt(self):
        cases = ("trial-source", "quality-source", "quality-grader", "review-grader",
                 "review-catalog", "missing-review", "not-independent-review")
        for case in cases:
            with self.subTest(case=case):
                run = example_run()
                trial = run["trials"][1]
                quality = trial["quality"]
                if case == "trial-source":
                    trial["source_sha256"] = digest("different-artifact")
                elif case == "quality-source":
                    quality["source_sha256"] = digest("different-artifact")
                    quality["source_review"]["source_sha256"] = quality["source_sha256"]
                elif case == "quality-grader":
                    quality["verifier_sha256"] = digest("weaker-grader")
                    quality["source_review"]["grader_sha256"] = quality["verifier_sha256"]
                elif case == "review-grader":
                    quality["source_review"]["grader_sha256"] = digest("weaker-grader")
                elif case == "review-catalog":
                    quality["source_review"]["catalog_sha256"] = digest("different-tests")
                elif case == "missing-review":
                    quality["source_review"] = None
                else:
                    quality["source_review"]["independent"] = False
                quality["source_review_sha256"] = (digest(quality["source_review"])
                                                    if quality["source_review"] is not None else None)
                quality["result_sha256"] = digest({key: value for key, value in quality.items()
                                                   if key != "result_sha256"})
                decision = compare_field_run(run)
                self.assertEqual(decision["status"], "incomplete")
                self.assertIsNone(decision["selected_candidate_id"])

    def test_source_review_rejection_overrides_behavioral_pass(self):
        run = example_run()
        quality = run["trials"][1]["quality"]
        quality["source_review"]["verdict"] = "rejected"
        quality["source_review_sha256"] = digest(quality["source_review"])
        quality["result_sha256"] = digest({key: value for key, value in quality.items()
                                           if key != "result_sha256"})
        result = compare_field_run(run)
        self.assertEqual(result["status"], "retain_baseline")
        self.assertEqual(result["comparisons"][0]["status"], "reject")
        self.assertIn("quality_source_review_rejected", result["comparisons"][0]["trial_errors"]["1"])

    def test_missing_frozen_grader_or_dropped_review_field_rejected(self):
        for section, key in (("plan", "verifier_sha256"), ("quality", "source_review")):
            with self.subTest(section=section):
                run = example_run()
                target = run["plan"] if section == "plan" else run["trials"][1]["quality"]
                target.pop(key)
                with self.assertRaises(ArtifactError):
                    compare_field_run(run)

    def test_unbounded_altered_duplicate_and_unscheduled_inputs_rejected(self):
        run = example_run()
        mutations = [
            lambda x: x["plan"]["limits"].update(total_seconds=float("inf")),
            lambda x: x["plan"]["schedule"][1].update(candidate_id="baseline"),
            lambda x: x["trials"].append(copy.deepcopy(x["trials"][0])),
            lambda x: x["trials"].reverse(),
            lambda x: x["trials"][1]["metrics"].update(wall_seconds=True),
            lambda x: x["trials"][1].update(reason="/private/source/path"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(run)
                mutation(changed)
                with self.assertRaises(ArtifactError):
                    compare_field_run(changed)

    def test_plan_requires_two_distinct_alternatives(self):
        plan = example_run()["plan"]
        plan["candidates"].pop()
        with self.assertRaises(ArtifactError):
            validate_field_plan(plan)

    def test_kit_integrity_does_not_claim_live_verification(self):
        run = example_run()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run.py").write_text("print('dry run only')\n", encoding="utf-8")
            kit = build_field_kit(run, root=root, paths=["run.py"],
                                  operations=dict.fromkeys(("build", "start", "verify", "rollback"), "run.py"),
                                  private_configuration_sha256=digest("private-config"))
            result = verify_field_kit(kit, run, root=root)
            self.assertTrue(result["integrity_verified"])
            self.assertFalse(result["rollback_demonstrated"])
            self.assertFalse(result["independent_rebuild_verified"])
            (root / "run.py").write_text("modified\n", encoding="utf-8")
            with self.assertRaisesRegex(ArtifactError, "integrity mismatch"):
                verify_field_kit(kit, run, root=root)

    def test_incomplete_run_cannot_make_a_selected_kit(self):
        run = example_run()
        run["trials"] = []
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ArtifactError):
            build_field_kit(run, root=directory, paths=["run.py"], operations={},
                            private_configuration_sha256=digest("private"))

    def test_kit_refuses_escape_and_symlink(self):
        run = example_run()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "run.py"
            target.write_text("pass\n", encoding="utf-8")
            for name in ("../run.py", str(target), "C:/private/key", "a/../run.py"):
                with self.subTest(name=name), self.assertRaises(ArtifactError):
                    build_field_kit(run, root=root, paths=[name],
                                    operations=dict.fromkeys(("build", "start", "verify", "rollback"), name),
                                    private_configuration_sha256=digest("private"))
            try:
                (root / "link.py").symlink_to(target)
            except OSError:
                return
            with self.assertRaises(ArtifactError):
                build_field_kit(run, root=root, paths=["link.py"],
                                operations=dict.fromkeys(("build", "start", "verify", "rollback"), "link.py"),
                                private_configuration_sha256=digest("private"))


if __name__ == "__main__":
    unittest.main()
