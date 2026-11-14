"""Build and independently re-check the metadata of a mock kit."""

from .artifacts import ArtifactError, canonical_json, digest
from .judge import compare_run


def _expected_kit(run, decision):
    selection = decision["selected_candidate_id"]
    if selection is None:
        raise ArtifactError("No mock candidate passed the quality gates")
    plan = run["plan"]
    candidate = next(item for item in plan["candidates"] if item["id"] == selection)
    rollback = [
        {
            "setting": entry["setting"],
            "before": entry["after"],
            "after": entry["before"],
        }
        for entry in reversed(candidate["delta"])
    ]
    return {
        "artifact": "aotg-kit",
        "version": 1,
        "mode": "mock-dry-run",
        "applicable_to_production": False,
        "adapter": plan["adapter"],
        "manifest_sha256": plan["manifest_sha256"],
        "plan_id": plan["plan_id"],
        "runner_version": plan["runner"],
        "run_sha256": decision["run_sha256"],
        "decision_sha256": digest(decision),
        "candidate": candidate,
        "rollback": rollback,
    }


def build_kit(run, decision):
    expected = compare_run(run)
    if canonical_json(decision) != canonical_json(expected):
        raise ArtifactError("Decision does not match the run")
    return _expected_kit(run, expected)


def verify_kit(kit, run):
    expected_decision = compare_run(run)
    expected_kit = _expected_kit(run, expected_decision)
    if canonical_json(kit) != canonical_json(expected_kit):
        raise ArtifactError("Kit does not match the run or recorded decision")
    return {
        "mode": "mock-dry-run",
        "verified": True,
        "kit_sha256": digest(kit),
        "run_sha256": expected_decision["run_sha256"],
    }
