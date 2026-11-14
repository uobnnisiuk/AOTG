"""Bounded mock candidate planning and trial execution."""

import hashlib
import re
from time import monotonic

from .artifacts import ArtifactError, canonical_json, digest
from .manifest import validate_manifest

SEED_DEFAULT = 42
REPEATS = 3
MAX_TRIALS = REPEATS * 3
MAX_SECONDS = 5
RUNNER_VERSION = "mock-v1"


def _candidates():
    # Future source-level proposals need their own isolated runner and rollback contract.
    return [
        {"id": "baseline", "kind": "baseline", "delta": []},
        {"id": "same-settings", "kind": "config", "delta": []},
        {
            "id": "mock-batch",
            "kind": "config",
            "delta": [{"setting": "batch_size", "before": 8, "after": 16}],
        },
    ]


def _plan(manifest_sha256, adapter, seed):
    candidates = _candidates()
    # Interleave candidates and rotate the order across repetitions.
    ids = [candidate["id"] for candidate in candidates]
    schedule = [
        {
            "id": f"{candidate_id}-{repeat + 1}",
            "candidate_id": candidate_id,
            "repeat": repeat + 1,
        }
        for repeat in range(REPEATS)
        for candidate_id in ids[repeat:] + ids[:repeat]
    ]
    document = {
        "artifact": "aotg-plan",
        "version": 1,
        "mode": "mock-dry-run",
        "runner": RUNNER_VERSION,
        "adapter": adapter,
        "manifest_sha256": manifest_sha256,
        "seed": seed,
        "limits": {
            "max_trials": MAX_TRIALS,
            "max_wall_seconds_per_invocation": MAX_SECONDS,
        },
        "candidates": candidates,
        "schedule": schedule,
    }
    return {**document, "plan_id": digest(document)}


def plan_experiment(manifest, seed=SEED_DEFAULT):
    validate_manifest(manifest)
    _validate_seed(seed)
    return _plan(digest(manifest), manifest["adapter"], seed)


def _validate_seed(seed):
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ArtifactError("Seed must be an unsigned 32-bit integer")


def validate_plan(plan):
    if not isinstance(plan, dict):
        raise ArtifactError("Expected a plan object")
    manifest_sha256 = plan.get("manifest_sha256")
    adapter = plan.get("adapter")
    seed = plan.get("seed")
    _validate_seed(seed)
    if not isinstance(manifest_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", manifest_sha256
    ):
        raise ArtifactError("Invalid manifest SHA-256 in plan")
    if not isinstance(adapter, str) or not re.fullmatch(
        r"[a-z][a-z0-9-]{0,31}", adapter
    ):
        raise ArtifactError("Invalid adapter in plan")
    if canonical_json(plan) != canonical_json(_plan(manifest_sha256, adapter, seed)):
        raise ArtifactError("Plan does not match the bounded mock schedule")


def _mock_trial(plan, entry):
    candidate = entry["candidate_id"]
    salt = f"{plan['seed']}:{entry['repeat']}".encode("ascii")
    jitter = int.from_bytes(hashlib.sha256(salt).digest()[:2], "big") % 31
    mock_batch = candidate == "mock-batch"
    metrics = {
        "opencode_end_to_end_ms": (876 if mock_batch else 1000) + jitter,
        "ttft_ms": (137 if mock_batch else 148) + jitter,
        "prefill_tokens_per_second": (493 if mock_batch else 480) + jitter,
        "decode_tokens_per_second": (37 if mock_batch else 32) + jitter / 10,
        "tool_roundtrip_ms": 120 + jitter,
        "draft_acceptance_ratio": 0.72,
        "peak_ram_mib": 4096 + jitter,
        "peak_vram_mib": 3072 + jitter,
        "ssd_read_bytes": 4194304,
        "ssd_write_bytes": 524288,
        "peak_temperature_c": 64 + jitter / 10,
        "swap_delta_bytes": 0,
    }
    return {
        **entry,
        "metrics": metrics,
        "quality": {"output_match": True, "tool_calls_valid": True, "tests_pass": True},
    }


def _run_document(plan, trials, stop_reason):
    return {
        "artifact": "aotg-run",
        "version": 1,
        "mode": "mock-dry-run",
        "plan": plan,
        "stop_reason": stop_reason,
        "trials": trials,
    }


def validate_run(run, *, complete=False):
    if not isinstance(run, dict):
        raise ArtifactError("Expected a run object")
    plan = run.get("plan")
    validate_plan(plan)
    trials = run.get("trials")
    if not isinstance(trials, list) or len(trials) > MAX_TRIALS:
        raise ArtifactError("Invalid mock trial count")
    expected_trials = [
        _mock_trial(plan, entry) for entry in plan["schedule"][: len(trials)]
    ]
    stop_reason = run.get("stop_reason")
    if len(trials) == MAX_TRIALS:
        allowed = ("completed",)
    elif trials:
        allowed = ("trial-budget", "wall-clock")
    else:
        allowed = ("wall-clock",)
    if stop_reason not in allowed or canonical_json(run) != canonical_json(
        _run_document(plan, expected_trials, stop_reason)
    ):
        raise ArtifactError("Run does not match the recorded mock schedule and results")
    if complete and stop_reason != "completed":
        raise ArtifactError("Complete the mock run before comparing results")


def run_experiment(plan, *, resume=None, trial_budget=MAX_TRIALS):
    started = monotonic()
    validate_plan(plan)
    if type(trial_budget) is not int or not 1 <= trial_budget <= MAX_TRIALS:
        raise ArtifactError(f"Trial budget must be between 1 and {MAX_TRIALS}")
    trials = []
    if resume is not None:
        validate_run(resume)
        if resume["plan"]["plan_id"] != plan["plan_id"]:
            raise ArtifactError("Resume artifact belongs to a different plan")
        trials = list(resume["trials"])
    remaining = plan["schedule"][len(trials) :]
    for entry in remaining[:trial_budget]:
        if monotonic() - started >= MAX_SECONDS:
            return _run_document(plan, trials, "wall-clock")
        trials.append(_mock_trial(plan, entry))
    stop_reason = "completed" if len(trials) == MAX_TRIALS else "trial-budget"
    return _run_document(plan, trials, stop_reason)
