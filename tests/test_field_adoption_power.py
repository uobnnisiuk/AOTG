"""ADV-13 fixed synthetic power replay; no hardware or real quality claims."""

import hashlib
import json
import math
import random
import time
import unittest
from collections import Counter
from pathlib import Path

from test_field_evidence import example_run

from aotg.field_evidence import compare_field_run

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/field-notes/adoption-power-plan.json"
PLAN_BLOB = "5c8741dcd4ce1a95427b1349d8914dd11fd7b3ad"
FIXTURE_BLOB = "367f3893f6976755fbdec48808ff8cdc9b453a6a"


def pinned_bytes(path, expected_blob):
    # Normalize checkout line endings to the original Git text blob.
    raw = path.read_text(encoding="utf-8").encode("utf-8")
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if blob != expected_blob:
        raise ValueError(f"Frozen source changed: {path.name}")
    return raw


def run_power():
    raw = pinned_bytes(PLAN, PLAN_BLOB)
    plan = json.loads(raw)
    evaluator = pinned_bytes(ROOT / "aotg/field_evidence.py", plan["evaluator_git_blob"])
    artifacts = pinned_bytes(ROOT / "aotg/artifacts.py", plan["artifacts_git_blob"])
    fixture = pinned_bytes(ROOT / "tests/test_field_evidence.py", FIXTURE_BLOB)
    run = example_run()
    field = run["plan"]
    if (len(run["trials"]) != plan["trials_per_run"]
            or len(field["workloads"]) != plan["workloads"]
            or len(field["candidates"]) != plan["alternatives"] + 1
            or [c["id"] for c in field["candidates"]] != ["baseline", "threads", "batch"]
            or field["blocks"] != plan["blocks"]
            or field["metric_gates"] != plan["metric_gates"]
            or field["minimum_improvement"] != plan["minimum_improvement"]
            or field["adoption_policy"]["block_order"] != plan["block_order"]):
        raise ValueError("Frozen fixture shape changed")
    if (len(plan["log_sigma"]) * len(plan["effect_percent"])
            * plan["repetitions_per_case"] + 1 != plan["maximum_evaluator_calls"]):
        raise ValueError("Unexpected replay size")

    started = time.monotonic()
    calls = 0

    def evaluate(effect, sigma, rng):
        nonlocal calls
        if calls >= plan["maximum_evaluator_calls"]:
            raise RuntimeError("Synthetic call limit")
        if time.monotonic() - started >= plan["maximum_wall_seconds"]:
            raise TimeoutError("Synthetic replay time limit")
        for trial in run["trials"]:
            multiplier = 1.0 - effect if trial["candidate_id"] == "threads" else 1.0
            trial["metrics"]["wall_seconds"] = (
                plan["wall_median_seconds"] * multiplier * math.exp(rng.gauss(0, sigma))
            )
        run["elapsed_seconds"] = 1 + sum(t["metrics"]["wall_seconds"] for t in run["trials"])
        calls += 1
        decision = compare_field_run(run)
        if time.monotonic() - started >= plan["maximum_wall_seconds"]:
            raise TimeoutError("Synthetic replay time limit")
        if decision["status"] == "adopt":
            return "threads_adoptions" if decision["selected_candidate_id"] == "threads" else "other_adoptions"
        if decision["status"] in ("retain_baseline", "incomplete"):
            return decision["status"]
        return "other"

    rows = []
    minimum = []
    for si, sigma in enumerate(plan["log_sigma"]):
        reaching = []
        for ei, effect_percent in enumerate(plan["effect_percent"]):
            seed = plan["seed_base"] + 100 * si + ei
            rng = random.Random(seed)
            counts = Counter(dict.fromkeys(
                ("threads_adoptions", "other_adoptions", "retain_baseline", "incomplete", "other"), 0
            ))
            for _ in range(plan["repetitions_per_case"]):
                counts[evaluate(effect_percent / 100, sigma, rng)] += 1
            fraction = counts["threads_adoptions"] / plan["repetitions_per_case"]
            if effect_percent > 0 and fraction >= plan["minimum_detected_fraction"]:
                reaching.append(effect_percent)
            rows.append({
                "log_sigma": sigma, "effect_percent": effect_percent, "seed": seed,
                "repetitions": plan["repetitions_per_case"], "counts": dict(counts),
                "threads_adoption_fraction": fraction,
            })
        minimum.append({"log_sigma": sigma, "minimum_tested_effect_percent_at_80": min(reaching, default=None)})
    positive = evaluate(0.5, 0.05, random.Random(20261125001999))
    return {
        "artifact": "aotg-adoption-power-simulation-result", "version": 1,
        "parameters_sha256": hashlib.sha256(raw).hexdigest(),
        "evaluator_sha256": hashlib.sha256(evaluator).hexdigest(),
        "artifacts_sha256": hashlib.sha256(artifacts).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "replay_sha256": hashlib.sha256(Path(__file__).read_text(encoding="utf-8").encode()).hexdigest(),
        "field_plan_sha256": run["plan_sha256"], "calls": calls,
        "trials_per_run": len(run["trials"]), "results": rows,
        "minimum_tested_effects": minimum, "positive_control": positive,
        "synthetic_only": True, "real_host_independence_verified": False,
        "real_host_variance_estimated": False,
        "thresholds_or_seeds_tuned_after_results": False,
    }


class AdoptionPowerTests(unittest.TestCase):
    def test_preregistered_power_grid_and_noisy_positive_control(self):
        report = run_power()
        payload = json.dumps(report, sort_keys=True, separators=(",", ":"))
        print("ADV13_RESULT " + payload, flush=True)
        print("ADV13_RESULT_SHA256 " + hashlib.sha256(payload.encode()).hexdigest(), flush=True)
        self.assertEqual(report["calls"], 8401)
        self.assertEqual(report["trials_per_run"], 64)
        self.assertEqual(len(report["results"]), 28)
        for row in report["results"]:
            self.assertEqual(sum(row["counts"].values()), row["repetitions"])
            self.assertEqual(row["counts"]["incomplete"], 0)
            self.assertEqual(row["counts"]["other"], 0)
        self.assertEqual(report["positive_control"], "threads_adoptions")
