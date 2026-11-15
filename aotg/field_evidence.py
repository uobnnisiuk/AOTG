"""Offline, fail-closed comparison of bounded real-machine evidence.

This module neither generates measurements nor runs services. Hashes bind the
submitted evidence; they do not prove that its independent-review attestations
are true. Private machine details belong in the owner's evidence store.
"""

import hashlib
import json
import math
import re
from pathlib import Path
from statistics import median

from .artifacts import ArtifactError, canonical_json, digest

_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
METRICS = (
    "wall_seconds", "ttft_seconds", "prefill_tokens_per_second",
    "decode_tokens_per_second", "draft_accepted", "draft_proposed",
    "tool_roundtrip_seconds",
)
CHECKS = ("correctness", "tool_compatibility", "completed", "stability")
RESOURCES = (
    "peak_temperature_c", "min_mem_available_bytes", "swapout_delta_bytes",
    "gpu_errors", "io_errors",
)
TERMINAL = ("passed", "failed", "stopped", "timed_out", "missing")


def _require(condition, message):
    if not condition:
        raise ArtifactError(message)


def _exact(value, fields, name):
    _require(isinstance(value, dict) and set(value) == set(fields),
             f"Invalid {name} fields")


def _sha(value, name):
    _require(isinstance(value, str) and _SHA.fullmatch(value), f"Invalid {name}")


def _id(value):
    _require(isinstance(value, str) and _ID.fullmatch(value), "Invalid identifier")


def _number(value, name, minimum=0, maximum=None):
    _require(type(value) in (int, float) and math.isfinite(value)
             and value >= minimum and (maximum is None or value <= maximum),
             f"Invalid {name}")


def _schedule(candidates, workloads, baseline_id, blocks):
    rows = []
    for workload in workloads:
        for candidate in candidates:
            if candidate["id"] == baseline_id:
                continue
            for block in range(blocks):
                for arm in (baseline_id, candidate["id"], candidate["id"], baseline_id):
                    rows.append({
                        "index": len(rows), "candidate_id": arm,
                        "comparison_id": candidate["id"],
                        "workload_id": workload["id"], "block": block,
                    })
    return rows


def freeze_plan(*, identity_sha256, verifier_sha256, candidates, workloads, baseline_id="baseline",
                blocks=1, limits, minimum_improvement=0.05,
                required_metrics=("wall_seconds",)):
    """Freeze an ABBA plan. Identity binds model, quantization and sampling.

    Workload input hashes must include the complete task and initial workspace;
    tests_sha256 is the exact independently held grader catalog hash. Freeze the
    expected verifier code hash before execution. Cache cohorts remain explicit.
    At least two alternative profiles and two observations per arm are required.
    No configuration values or local paths are needed in this public structure.
    """
    # Bound allocation before constructing the derived schedule.
    _require(type(blocks) is int and 1 <= blocks <= 3, "Invalid block count")
    _require(isinstance(candidates, list) and 3 <= len(candidates) <= 9,
             "Require baseline and two to eight alternatives")
    _require(isinstance(workloads, list) and 1 <= len(workloads) <= 16,
             "Require one to sixteen workloads")
    for candidate in candidates:
        _exact(candidate, ("id", "profile_sha256"), "candidate")
    for workload in workloads:
        _exact(workload, ("id", "input_sha256", "tests_sha256", "cache_cohort"), "workload")
    plan = {
        "artifact": "aotg-field-plan", "version": 1,
        "identity_sha256": identity_sha256, "verifier_sha256": verifier_sha256,
        "baseline_id": baseline_id,
        "candidates": candidates, "workloads": workloads, "blocks": blocks,
        "limits": limits, "minimum_improvement": minimum_improvement,
        "required_metrics": list(required_metrics),
        "schedule": _schedule(candidates, workloads, baseline_id, blocks),
    }
    validate_field_plan(plan)
    # Detach from mutable caller-owned inputs; callers publish before execution.
    return json.loads(canonical_json(plan))


def validate_field_plan(plan):
    _exact(plan, ("artifact", "version", "identity_sha256", "verifier_sha256", "baseline_id",
                  "candidates", "workloads", "blocks", "limits",
                  "minimum_improvement", "required_metrics", "schedule"), "plan")
    _require(plan["artifact"] == "aotg-field-plan" and type(plan["version"]) is int
             and plan["version"] == 1, "Unsupported field plan")
    _sha(plan["identity_sha256"], "identity hash")
    _sha(plan["verifier_sha256"], "frozen verifier hash")
    _id(plan["baseline_id"])
    _require(type(plan["blocks"]) is int and 1 <= plan["blocks"] <= 3,
             "Blocks must be between one and three")
    _require(isinstance(plan["candidates"], list) and 3 <= len(plan["candidates"]) <= 9,
             "Require baseline and two to eight alternatives")
    ids, profiles = [], []
    for candidate in plan["candidates"]:
        _exact(candidate, ("id", "profile_sha256"), "candidate")
        _id(candidate["id"])
        _sha(candidate["profile_sha256"], "profile hash")
        ids.append(candidate["id"])
        profiles.append(candidate["profile_sha256"])
    _require(len(set(ids)) == len(ids) and plan["baseline_id"] in ids,
             "Duplicate candidate or absent baseline")
    _require(len(set(profiles)) == len(profiles), "Candidate profiles must differ")
    _require(isinstance(plan["workloads"], list) and 1 <= len(plan["workloads"]) <= 16,
             "Require one to sixteen workloads")
    workload_ids = []
    for workload in plan["workloads"]:
        _exact(workload, ("id", "input_sha256", "tests_sha256", "cache_cohort"),
               "workload")
        _id(workload["id"])
        _id(workload["cache_cohort"])
        _sha(workload["input_sha256"], "input hash")
        _sha(workload["tests_sha256"], "tests hash")
        workload_ids.append(workload["id"])
    _require(len(set(workload_ids)) == len(workload_ids), "Duplicate workload")
    limits = plan["limits"]
    _exact(limits, ("trial_seconds", "total_seconds", "max_temperature_c",
                    "min_mem_available_bytes", "max_swapout_bytes"), "limits")
    _number(limits["trial_seconds"], "trial limit", 0.001, 3600)
    _number(limits["total_seconds"], "total limit", limits["trial_seconds"], 86400)
    _number(limits["max_temperature_c"], "temperature limit", 1, 90)
    _number(limits["min_mem_available_bytes"], "memory floor", 1)
    _number(limits["max_swapout_bytes"], "swapout limit")
    _number(plan["minimum_improvement"], "improvement threshold", 0.000001, 0.9)
    required = plan["required_metrics"]
    _require(isinstance(required, list) and "wall_seconds" in required
             and all(item in METRICS for item in required)
             and len(set(required)) == len(required), "Invalid required metrics")
    _require(plan["schedule"] == _schedule(plan["candidates"], plan["workloads"],
                                          plan["baseline_id"], plan["blocks"]),
             "Schedule differs from the frozen ABBA order")
    return plan


def quality_record(*, input_sha256, tests_sha256, verifier_sha256,
                   source_sha256, independent, checks, source_review=None):
    """Bind behavioral gates and a separate source-review receipt.

    Obtain the receipt from the independent reviewer, never the candidate. A
    missing receipt cannot pass even when all four behavioral checks are true.
    The receipt format matches aotg.quality's aotg-source-review version 1.
    """
    value = {
        "input_sha256": input_sha256, "tests_sha256": tests_sha256,
        "verifier_sha256": verifier_sha256, "source_sha256": source_sha256,
        "independent": independent, "checks": checks, "source_review": source_review,
        "source_review_sha256": digest(source_review) if source_review is not None else None,
    }
    return {**value, "result_sha256": digest(value)}


def _source_review_errors(receipt, source_sha256, verifier_sha256, tests_sha256):
    if receipt is None:
        return ["quality_source_review_missing"]
    _exact(receipt, ("artifact", "version", "source_sha256", "grader_sha256", "catalog_sha256",
                     "independent", "reviewer", "verdict", "evidence_reference"), "source review")
    _require(receipt["artifact"] == "aotg-source-review" and type(receipt["version"]) is int
             and receipt["version"] == 1 and type(receipt["independent"]) is bool
             and receipt["verdict"] in ("accepted", "rejected"), "Invalid source review")
    for key in ("reviewer", "evidence_reference"):
        _require(isinstance(receipt[key], str) and receipt[key].strip() and len(receipt[key]) <= 512,
                 "Source review requires reviewer and evidence references")
    errors = []
    for key, expected in (("source_sha256", source_sha256), ("grader_sha256", verifier_sha256),
                          ("catalog_sha256", tests_sha256)):
        _sha(receipt[key], key)
        if receipt[key] != expected:
            errors.append(f"quality_source_review_{key}_mismatch")
    if not receipt["independent"]:
        errors.append("quality_source_review_not_independent")
    if receipt["verdict"] != "accepted":
        errors.append("quality_source_review_rejected")
    return errors


def _quality_errors(value, workload, source_sha256, verifier_sha256):
    if value is None:
        return ["quality_missing"]
    _exact(value, ("input_sha256", "tests_sha256", "verifier_sha256",
                   "source_sha256", "independent", "checks", "result_sha256",
                   "source_review", "source_review_sha256"),
           "quality evidence")
    for key in ("input_sha256", "tests_sha256", "verifier_sha256",
                "source_sha256", "result_sha256"):
        _sha(value[key], key)
    _require(type(value["independent"]) is bool, "Invalid independent attestation")
    _exact(value["checks"], CHECKS, "quality checks")
    _require(all(type(item) is bool or item is None for item in value["checks"].values()),
             "Quality checks must be boolean or missing")
    _require(value["result_sha256"] == digest({k: v for k, v in value.items()
                                               if k != "result_sha256"}),
             "Quality result hash mismatch")
    errors = []
    if not value["independent"]:
        errors.append("quality_not_independent")
    for key in ("input_sha256", "tests_sha256"):
        if value[key] != workload[key]:
            errors.append(f"quality_{key}_mismatch")
    if value["source_sha256"] != source_sha256:
        errors.append("quality_source_sha256_mismatch")
    if value["verifier_sha256"] != verifier_sha256:
        errors.append("quality_verifier_sha256_mismatch")
    expected_receipt_hash = digest(value["source_review"]) if value["source_review"] is not None else None
    _require(value["source_review_sha256"] == expected_receipt_hash, "Source review hash mismatch")
    errors.extend(_source_review_errors(value["source_review"], source_sha256, verifier_sha256,
                                        workload["tests_sha256"]))
    errors.extend(f"quality_{key}_missing" if item is None else f"quality_{key}_failed"
                  for key, item in value["checks"].items() if item is not True)
    return errors


def _trial_errors(trial, row, plan, workload, profile):
    _exact(trial, ("index", "candidate_id", "workload_id", "identity_sha256",
                   "profile_sha256", "source_sha256", "cache_cohort", "status", "reason",
                   "metrics", "resources", "quality"), "trial")
    _require(type(trial["index"]) is int and trial["index"] == row["index"]
             and trial["candidate_id"] == row["candidate_id"]
             and trial["workload_id"] == row["workload_id"],
             "Trial does not match scheduled observation")
    _require(trial["status"] in TERMINAL, "Invalid trial status")
    # Reasons are fixed machine-readable codes, never raw logs or local paths.
    _id(trial["reason"])
    _sha(trial["source_sha256"], "trial source artifact hash")
    errors = []
    for key, expected in (("identity_sha256", plan["identity_sha256"]),
                          ("profile_sha256", profile["profile_sha256"]),
                          ("cache_cohort", workload["cache_cohort"])):
        if trial[key] != expected:
            errors.append(f"{key}_mismatch")
    if trial["status"] != "passed":
        errors.append(f"trial_{trial['status']}")
    metrics = trial["metrics"]
    _require(isinstance(metrics, dict) and set(metrics) <= set(METRICS),
             "Unknown measured metric")
    for key, value in metrics.items():
        if value is not None:
            _number(value, key, 0.000000001 if key == "wall_seconds" else 0)
    errors.extend(f"metric_{key}_missing" for key in plan["required_metrics"]
                  if metrics.get(key) is None)
    if metrics.get("wall_seconds", 0) is not None and metrics.get("wall_seconds", 0) > plan["limits"]["trial_seconds"]:
        errors.append("trial_time_limit_exceeded")
    accepted, proposed = metrics.get("draft_accepted"), metrics.get("draft_proposed")
    if accepted is not None and proposed is not None:
        _require(type(accepted) is int and type(proposed) is int and accepted <= proposed,
                 "Invalid draft acceptance counts")
    resources = trial["resources"]
    _exact(resources, RESOURCES, "resources")
    for key, value in resources.items():
        if value is None:
            errors.append(f"resource_{key}_missing")
        else:
            _number(value, key)
    for key, limit, compare in (
        ("peak_temperature_c", plan["limits"]["max_temperature_c"], lambda a, b: a > b),
        ("min_mem_available_bytes", plan["limits"]["min_mem_available_bytes"], lambda a, b: a < b),
        ("swapout_delta_bytes", plan["limits"]["max_swapout_bytes"], lambda a, b: a > b),
        ("gpu_errors", 0, lambda a, b: a > b),
        ("io_errors", 0, lambda a, b: a > b),
    ):
        if resources[key] is not None and compare(resources[key], limit):
            errors.append(f"resource_{key}_limit")
    errors.extend(_quality_errors(trial["quality"], workload, trial["source_sha256"], plan["verifier_sha256"]))
    return errors


def compare_field_run(run):
    """Return adopt, retain_baseline, or incomplete without inventing trials.

    Every workload and ABBA block must meet the declared wall-time threshold in
    both adjacent A/B pairs. A faster median alone is not reproduction evidence.
    Absent evidence differs from a completed, failed or slower candidate.
    """
    _exact(run, ("artifact", "version", "plan", "plan_sha256", "elapsed_seconds",
                 "trials"), "run")
    _require(run["artifact"] == "aotg-field-run" and type(run["version"]) is int
             and run["version"] == 1, "Unsupported measured run")
    plan = validate_field_plan(run["plan"])
    _require(run["plan_sha256"] == digest(plan), "Frozen plan hash mismatch")
    _number(run["elapsed_seconds"], "elapsed time")
    _require(isinstance(run["trials"], list), "Invalid trials")
    _require(len(run["trials"]) <= len(plan["schedule"]), "Too many trials")
    profiles = {item["id"]: item for item in plan["candidates"]}
    workloads = {item["id"]: item for item in plan["workloads"]}
    rows = {}
    for trial in run["trials"]:
        _require(isinstance(trial, dict) and type(trial.get("index")) is int,
                 "Invalid trial index")
        index = trial["index"]
        _require(0 <= index < len(plan["schedule"]) and index not in rows,
                 "Duplicate or out-of-range trial")
        row = plan["schedule"][index]
        rows[index] = {"trial": trial, "errors": _trial_errors(
            trial, row, plan, workloads[row["workload_id"]], profiles[row["candidate_id"]])}
    _require([item["index"] for item in run["trials"]] == sorted(rows),
             "Observed trial order differs from frozen schedule")
    measured_seconds = sum(item["metrics"].get("wall_seconds") or 0 for item in run["trials"])
    _require(run["elapsed_seconds"] + 0.000001 >= measured_seconds,
             "Elapsed time is shorter than sequential measured trials")
    total_violation = run["elapsed_seconds"] > plan["limits"]["total_seconds"]
    baseline_rows = [row for row in plan["schedule"] if row["candidate_id"] == plan["baseline_id"]]
    baseline_valid = all(row["index"] in rows and not rows[row["index"]]["errors"]
                         for row in baseline_rows)
    comparisons = []
    for candidate in plan["candidates"]:
        if candidate["id"] == plan["baseline_id"]:
            continue
        selected = [row for row in plan["schedule"] if row["comparison_id"] == candidate["id"]]
        errors = {str(row["index"]): rows[row["index"]]["errors"]
                  if row["index"] in rows else ["trial_missing"] for row in selected}
        missing = any(any("missing" in reason or "mismatch" in reason
                          or reason.endswith("not_independent") for reason in reasons)
                      for reasons in errors.values())
        failed = any(errors.values()) or total_violation
        pairs = []
        for offset in range(0, len(selected), 4):
            block = selected[offset:offset + 4]
            if all(row["index"] in rows and not rows[row["index"]]["errors"] for row in block):
                values = [rows[row["index"]]["trial"]["metrics"]["wall_seconds"] for row in block]
                pairs.extend(((values[0] - values[1]) / values[0],
                              (values[3] - values[2]) / values[3]))
        repeated_win = bool(pairs) and all(value >= plan["minimum_improvement"] for value in pairs)
        status = "incomplete" if missing else "reject" if failed else "pass" if repeated_win else "hold"
        comparisons.append({
            "candidate_id": candidate["id"], "status": status,
            "trial_indices": [row["index"] for row in selected],
            "trial_errors": errors, "paired_improvement_fractions": pairs,
            "median_paired_improvement_fraction": median(pairs) if pairs else None,
        })
    complete = baseline_valid and not total_violation and all(item["status"] != "incomplete" for item in comparisons)
    passing = [item for item in comparisons if item["status"] == "pass"] if complete else []
    best = max(passing, key=lambda item: item["median_paired_improvement_fraction"], default=None)
    return {
        "artifact": "aotg-field-decision", "version": 1, "run_sha256": digest(run),
        "plan_sha256": digest(plan), "status": "incomplete" if not complete else "adopt" if best else "retain_baseline",
        "selected_candidate_id": best["candidate_id"] if best else plan["baseline_id"] if complete else None,
        "baseline_valid": baseline_valid, "total_time_limit_exceeded": total_violation,
        "comparisons": comparisons,
        "deployment_verified": False, "rollback_demonstrated": False,
    }


def _bundle_files(root, paths):
    root = Path(root).resolve(strict=True)
    _require(isinstance(paths, list) and paths, "Bundle requires explicit files")
    _require(len(set(paths)) == len(paths), "Duplicate bundle path")
    files = []
    for name in sorted(paths):
        _require(isinstance(name, str) and name and "\\" not in name,
                 "Bundle paths must use relative POSIX names")
        relative = Path(name)
        _require(not relative.is_absolute() and all(part not in ("..", ".") for part in name.split("/"))
                 and ":" not in name, "Unsafe bundle path")
        path = root / relative
        for parent in [path, *path.parents]:
            if parent == root:
                break
            _require(not parent.is_symlink(), "Symlink in bundle")
        _require(path.resolve(strict=True).is_relative_to(root) and path.is_file(),
                 "Bundle file escaped root")
        with path.open("rb") as stream:
            sha = hashlib.file_digest(stream, "sha256").hexdigest()
        files.append({"path": name, "sha256": sha, "size_bytes": path.stat().st_size})
    return files


def build_field_kit(run, *, root, paths, operations, private_configuration_sha256):
    """Inventory an already staged, owner-private kit; never copy or execute it.

    Callers must review file contents before any publication. Filename/hash
    inventory is not a secret scanner. Every operation is an explicit artifact
    in the bundle; invocation, machine rebuild and rollback remain unverified.
    """
    decision = compare_field_run(run)
    _require(decision["status"] != "incomplete", "Incomplete evidence cannot select a kit")
    _sha(private_configuration_sha256, "private configuration hash")
    _exact(operations, ("build", "start", "verify", "rollback"), "kit operations")
    _require(all(isinstance(path, str) and path in paths for path in operations.values()),
             "Operations must reference bundled files")
    return {
        "artifact": "aotg-field-kit", "version": 1, "default_dry_run": True,
        "selected_candidate_id": decision["selected_candidate_id"],
        "selected_profile_sha256": next(item["profile_sha256"] for item in run["plan"]["candidates"]
                                        if item["id"] == decision["selected_candidate_id"]),
        "run_sha256": digest(run), "decision_sha256": digest(decision),
        "private_configuration_sha256": private_configuration_sha256,
        "files": _bundle_files(root, paths), "operations": dict(operations),
        "independent_rebuild_verified": False,
        "deployment_verified": False, "rollback_demonstrated": False,
    }


def verify_field_kit(kit, run, *, root):
    """Verify file/decision integrity only, without claiming a machine test."""
    _require(isinstance(kit, dict) and isinstance(kit.get("files"), list), "Invalid kit")
    expected = build_field_kit(
        run, root=root, paths=[item["path"] for item in kit["files"]],
        operations=kit["operations"], private_configuration_sha256=kit["private_configuration_sha256"])
    _require(canonical_json(kit) == canonical_json(expected), "Kit integrity mismatch")
    return {"artifact": "aotg-field-kit-integrity", "version": 1,
            "integrity_verified": True, "kit_sha256": digest(kit),
            "independent_rebuild_verified": False, "deployment_verified": False,
            "rollback_demonstrated": False}
