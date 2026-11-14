"""Deterministic comparison and quality gates for synthetic trials."""

from statistics import median

from .artifacts import digest
from .core import validate_run

MIN_END_TO_END_IMPROVEMENT = 0.05
MAX_RELATIVE_REGRESSION = 0.05
MAX_TEMPERATURE_C = 85
MAX_TEMPERATURE_INCREASE_C = 2
QUALITY_CHECKS = ("output_match", "tool_calls_valid", "tests_pass")

LOWER_IS_BETTER = (
    "ttft_ms",
    "tool_roundtrip_ms",
    "peak_ram_mib",
    "peak_vram_mib",
    "ssd_read_bytes",
    "ssd_write_bytes",
    "swap_delta_bytes",
)
HIGHER_IS_BETTER = (
    "prefill_tokens_per_second",
    "decode_tokens_per_second",
    "draft_acceptance_ratio",
)


def _summarize(trials):
    return {
        "trial_ids": [trial["id"] for trial in trials],
        "medians": {
            metric: median(trial["metrics"][metric] for trial in trials)
            for metric in trials[0]["metrics"]
        },
        "max_temperature_c": max(
            trial["metrics"]["peak_temperature_c"] for trial in trials
        ),
        "quality": {
            check: all(trial["quality"][check] is True for trial in trials)
            for check in QUALITY_CHECKS
        },
    }


def _gates(baseline, candidate):
    baseline_metrics = baseline["medians"]
    candidate_metrics = candidate["medians"]
    quality = all(candidate["quality"].values()) and all(baseline["quality"].values())
    regressions = [
        metric
        for metric in LOWER_IS_BETTER
        if candidate_metrics[metric]
        > baseline_metrics[metric] * (1 + MAX_RELATIVE_REGRESSION)
    ]
    regressions.extend(
        metric
        for metric in HIGHER_IS_BETTER
        if candidate_metrics[metric]
        < baseline_metrics[metric] * (1 - MAX_RELATIVE_REGRESSION)
    )
    temperature_ok = (
        candidate["max_temperature_c"] <= MAX_TEMPERATURE_C
        and baseline["max_temperature_c"] <= MAX_TEMPERATURE_C
        and candidate["max_temperature_c"]
        <= baseline["max_temperature_c"] + MAX_TEMPERATURE_INCREASE_C
    )
    improvement = (
        baseline_metrics["opencode_end_to_end_ms"]
        - candidate_metrics["opencode_end_to_end_ms"]
    ) / baseline_metrics["opencode_end_to_end_ms"]
    if not quality or regressions or not temperature_ok:
        status = "reject"
    elif improvement < MIN_END_TO_END_IMPROVEMENT:
        status = "hold"
    else:
        status = "pass"
    return {
        "status": status,
        "end_to_end_improvement_fraction": improvement,
        "gates": {
            "quality": quality,
            "regressions": regressions,
            "temperature": temperature_ok,
            "minimum_improvement": improvement >= MIN_END_TO_END_IMPROVEMENT,
        },
    }


def compare_run(run):
    validate_run(run, complete=True)
    candidates = run["plan"]["candidates"]
    grouped = {candidate["id"]: [] for candidate in candidates}
    for trial in run["trials"]:
        grouped[trial["candidate_id"]].append(trial)

    baseline = _summarize(grouped["baseline"])
    comparisons = []
    for candidate in candidates:
        candidate_id = candidate["id"]
        if candidate_id == "baseline":
            continue
        summary = _summarize(grouped[candidate_id])
        comparisons.append(
            {"candidate_id": candidate_id, **summary, **_gates(baseline, summary)}
        )

    passing = [item for item in comparisons if item["status"] == "pass"]
    selected = max(
        passing, key=lambda item: item["end_to_end_improvement_fraction"], default=None
    )
    return {
        "artifact": "aotg-decision",
        "version": 1,
        "mode": "mock-dry-run",
        "run_sha256": digest(run),
        "policy": {
            "minimum_end_to_end_improvement_fraction": MIN_END_TO_END_IMPROVEMENT,
            "maximum_relative_regression_fraction": MAX_RELATIVE_REGRESSION,
            "max_temperature_c": MAX_TEMPERATURE_C,
            "max_temperature_increase_c": MAX_TEMPERATURE_INCREASE_C,
            "aggregation": "median-except-temperature-cap",
        },
        "baseline": baseline,
        "comparisons": comparisons,
        "selected_candidate_id": selected["candidate_id"] if selected else None,
    }
