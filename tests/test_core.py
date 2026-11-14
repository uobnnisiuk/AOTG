import json
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aotg.artifacts import ArtifactError, publish_artifact, read_artifact
from aotg.core import MAX_SECONDS, MAX_TRIALS, plan_experiment, run_experiment
from aotg.judge import _gates, compare_run
from aotg.kit import build_kit, verify_kit
from aotg.manifest import load_manifest

EVO = Path(__file__).parent / "fixtures" / "evo-linux.json"


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.manifest = load_manifest(EVO)
        self.plan = plan_experiment(self.manifest)

    def test_plan_is_deterministic_and_bounded(self):
        self.assertEqual(self.plan, plan_experiment(self.manifest))
        self.assertNotEqual(
            self.plan["plan_id"], plan_experiment(self.manifest, seed=2)["plan_id"]
        )
        schedule = self.plan["schedule"]
        self.assertEqual(MAX_TRIALS, len({entry["id"] for entry in schedule}))
        for repeat in (1, 2, 3):
            self.assertEqual(
                {"baseline", "same-settings", "mock-batch"},
                {
                    entry["candidate_id"]
                    for entry in schedule
                    if entry["repeat"] == repeat
                },
            )
        self.assertNotIn("hardware", self.plan)

    def test_runner_rejects_modified_schedule_or_candidate(self):
        plan = deepcopy(self.plan)
        plan["schedule"].append(plan["schedule"][0])
        with self.assertRaisesRegex(ArtifactError, "bounded mock schedule"):
            run_experiment(plan)
        plan = deepcopy(self.plan)
        plan["candidates"][-1]["delta"][0]["after"] = 100
        with self.assertRaisesRegex(ArtifactError, "bounded mock schedule"):
            run_experiment(plan)

    def test_runner_rejects_invalid_budget_and_seed(self):
        with self.assertRaisesRegex(ArtifactError, "Trial budget"):
            run_experiment(self.plan, trial_budget=MAX_TRIALS + 1)
        with self.assertRaisesRegex(ArtifactError, "Seed"):
            plan_experiment(self.manifest, seed=-1)

    def test_resume_uses_validated_prefix(self):
        partial = run_experiment(self.plan, trial_budget=2)
        self.assertEqual("trial-budget", partial["stop_reason"])
        self.assertEqual(2, len(partial["trials"]))
        with self.assertRaisesRegex(ArtifactError, "Complete the mock run"):
            compare_run(partial)
        self.assertEqual(
            run_experiment(self.plan), run_experiment(self.plan, resume=partial)
        )
        with self.assertRaisesRegex(ArtifactError, "different plan"):
            run_experiment(plan_experiment(self.manifest, seed=2), resume=partial)
        partial["trials"][0]["metrics"]["ttft_ms"] = 10
        with self.assertRaisesRegex(ArtifactError, "recorded mock schedule"):
            run_experiment(self.plan, resume=partial)

    def test_wall_clock_limit_yields_resumable_artifact(self):
        with patch("aotg.core.monotonic", side_effect=[0, MAX_SECONDS]) as monotonic:
            partial = run_experiment(self.plan)
        self.assertEqual("wall-clock", partial["stop_reason"])
        self.assertEqual([], partial["trials"])
        self.assertEqual(2, monotonic.call_count)
        self.assertEqual(
            run_experiment(self.plan), run_experiment(self.plan, resume=partial)
        )

    def test_comparison_and_verified_rollback(self):
        run = run_experiment(self.plan)
        decision = compare_run(run)
        self.assertEqual("mock-batch", decision["selected_candidate_id"])
        comparisons = {
            candidate["candidate_id"]: candidate
            for candidate in decision["comparisons"]
        }
        self.assertEqual("hold", comparisons["same-settings"]["status"])
        self.assertEqual(
            0, comparisons["same-settings"]["end_to_end_improvement_fraction"]
        )
        self.assertEqual("pass", comparisons["mock-batch"]["status"])
        kit = build_kit(run, decision)
        self.assertFalse(kit["applicable_to_production"])
        self.assertEqual(
            [{"setting": "batch_size", "before": 16, "after": 8}], kit["rollback"]
        )
        self.assertTrue(verify_kit(kit, run)["verified"])
        kit["rollback"][0]["after"] = 0
        with self.assertRaisesRegex(ArtifactError, "Kit does not match"):
            verify_kit(kit, run)
        decision["selected_candidate_id"] = "same-settings"
        with self.assertRaisesRegex(ArtifactError, "Decision does not match"):
            build_kit(run, decision)

    def test_quality_and_resources_can_each_reject_a_faster_candidate(self):
        decision = compare_run(run_experiment(self.plan))
        baseline = decision["baseline"]
        faster = decision["comparisons"][1]
        self.assertEqual("pass", _gates(baseline, faster)["status"])

        for name, changed in (
            ("failed quality", {"quality": {**faster["quality"], "tests_pass": False}}),
            ("peak temperature", {"max_temperature_c": 86}),
            ("swap", {"medians": {**faster["medians"], "swap_delta_bytes": 4096}}),
            (
                "tool latency",
                {"medians": {**faster["medians"], "tool_roundtrip_ms": 900}},
            ),
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    "reject", _gates(baseline, {**faster, **changed})["status"]
                )


class ArtifactTests(unittest.TestCase):
    def test_file_is_published_once(self):
        with TemporaryDirectory() as name:
            directory = Path(name)
            path = directory / "report.json"
            publish_artifact(path, {"complete": True})
            with self.assertRaises(FileExistsError):
                publish_artifact(path, {"complete": False})
            self.assertEqual({"complete": True}, read_artifact(path))
            self.assertEqual([path], list(directory.iterdir()))

    def test_artifact_parser_rejects_ambiguous_or_non_object_json(self):
        with TemporaryDirectory() as name:
            path = Path(name) / "report.json"
            for invalid in ('{"a":1,"a":2}', '{"a":NaN}', "[]"):
                with self.subTest(invalid=invalid):
                    path.write_text(invalid, encoding="utf-8")
                    with self.assertRaises((ArtifactError, json.JSONDecodeError)):
                        read_artifact(path)
