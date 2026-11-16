"""Replay a preregistered synthetic experiment through the public evidence API.

Every quality attestation here is a synthetic fixture, never real review evidence.
Uses only Python stdlib and the repository module; no machine or network access.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aotg.artifacts import digest  # noqa: E402
from aotg.field_evidence import compare_field_run, freeze_plan, quality_record  # noqa: E402


def fixture(alternatives, parameters):
    source = digest("synthetic-source-only")
    verifier = digest("synthetic-verifier-only")
    tests = digest("synthetic-tests-only")
    task = digest("synthetic-workload-only")
    plan = freeze_plan(
        identity_sha256=digest("synthetic-machine-only"), verifier_sha256=verifier,
        candidates=[{"id": name, "profile_sha256": digest(name)} for name in
                    ("baseline", *("alternative" + str(i) for i in range(alternatives)))],
        workloads=[{"id": "synthetic", "input_sha256": task, "tests_sha256": tests, "cache_cohort": "fixed"}],
        blocks=parameters["blocks"], metric_gates=parameters["metric_gates"],
        minimum_improvement=parameters["minimum_improvement"],
        limits={"trial_seconds": 3600, "total_seconds": 86400, "max_temperature_c": 75,
                "min_mem_available_bytes": 1024, "max_swapout_bytes": 0})
    quality = quality_record(input_sha256=task, tests_sha256=tests, verifier_sha256=verifier,
        source_sha256=source, independent=True,
        checks=dict.fromkeys(("correctness", "tool_compatibility", "completed", "stability"), True),
        source_review={"artifact": "aotg-source-review", "version": 1, "source_sha256": source,
                       "grader_sha256": verifier, "catalog_sha256": tests, "independent": True,
                       "reviewer": "synthetic-review-fixture", "verdict": "accepted",
                       "evidence_reference": "synthetic-no-real-attestation"})
    profiles = {row["id"]: row["profile_sha256"] for row in plan["candidates"]}
    trials = [{"index": row["index"], "candidate_id": row["candidate_id"], "workload_id": "synthetic",
               "identity_sha256": plan["identity_sha256"], "profile_sha256": profiles[row["candidate_id"]],
               "source_sha256": source, "cache_cohort": "fixed", "status": "passed", "reason": "synthetic",
               "metrics": {"wall_seconds": 10}, "quality": quality,
               "resources": {"peak_temperature_c": 65, "min_mem_available_bytes": 4096,
                             "swapout_delta_bytes": 0, "gpu_errors": 0, "io_errors": 0}}
              for row in plan["schedule"]]
    return {"artifact": "aotg-field-run", "version": 2, "plan": plan,
            "plan_sha256": digest(plan), "elapsed_seconds": 1, "trials": trials}


def simulate(parameters, case, repetitions, iid):
    rng = random.Random(case["seed"])
    run = fixture(case["alternatives"], parameters)
    counts = Counter()
    for _ in range(repetitions):
        block_offset = 0.0
        for trial in run["trials"]:
            if iid:
                offset = rng.gauss(0.0, case["log_sigma"])
            else:
                if case["model"] == "shared-block-drift":
                    if trial["index"] % 4 == 0:
                        block_offset = rng.gauss(0.0, case["block_log_sigma"])
                    offset = block_offset
                else:
                    offset = (case["outer_position_log_offset"] if trial["index"] % 4 in (0, 3)
                              else case["inner_position_log_offset"])
                offset += rng.gauss(0.0, case["observation_log_sigma"])
            trial["metrics"]["wall_seconds"] = parameters["wall_median_seconds"] * math.exp(offset)
        run["elapsed_seconds"] = 1 + sum(trial["metrics"]["wall_seconds"] for trial in run["trials"])
        counts[compare_field_run(run)["status"]] += 1
    fraction = counts["adopt"] / repetitions
    return {"case": case, "repetitions": repetitions, "decision_counts": dict(counts),
            "false_adoption_fraction": fraction, "iid": iid,
            "iid_bound_passed": fraction <= parameters["iid_max_false_adoption_fraction"] if iid else None,
            "analytic_exchangeable_union_bound": case["alternatives"] / math.comb(16, 8) if iid else None,
            "field_plan_sha256": run["plan_sha256"], "trials_per_run": len(run["trials"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parameters", required=True)
    parser.add_argument("--parameters-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    raw = Path(args.parameters).read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.parameters_sha256:
        raise ValueError("Predeclared parameter hash mismatch")
    plan = json.loads(raw)
    if (plan["artifact"] != "aotg-adoption-null-simulation-plan" or plan["version"] != 2
            or plan["blocks"] != 4 or plan["workloads"] != 1 or plan["metric_gates"] != {}
            or len(plan["iid_cases"]) != 6 or len(plan["non_iid_cases"]) != 2
            or plan["iid_repetitions_per_case"] != 4000 or plan["non_iid_repetitions_per_case"] != 500):
        raise ValueError("Unexpected preregistered bounded experiment")
    output = Path(args.output)
    if output.exists():
        raise FileExistsError("Never overwrite a previous simulation result")
    started = time.monotonic()
    rows = []
    for iid, cases, count in ((True, plan["iid_cases"], plan["iid_repetitions_per_case"]),
                              (False, plan["non_iid_cases"], plan["non_iid_repetitions_per_case"])):
        for case in cases:
            result = simulate(plan, case, count, iid)
            rows.append(result)
            print(json.dumps(result, sort_keys=True), flush=True)
    report = {"artifact": "aotg-adoption-null-simulation-result", "version": 2,
              "parameters_sha256": args.parameters_sha256,
              "simulator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "evaluator_sha256": hashlib.sha256((ROOT / "aotg/field_evidence.py").read_bytes()).hexdigest(),
              "python_version": sys.version.split()[0], "seconds": time.monotonic() - started,
              "results": rows, "all_iid_cases_within_predeclared_cap": all(row["iid_bound_passed"] for row in rows if row["iid"]),
              "synthetic_only": True, "real_host_independence_verified": False,
              "non_iid_excluded_from_calibrated_bound": True,
              "mechanism_revision": "balance-ABBA-and-BAAB-after-preserved-failed-order-stress",
              "thresholds_or_seeds_tuned_after_results": False}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return 0 if report["all_iid_cases_within_predeclared_cap"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
