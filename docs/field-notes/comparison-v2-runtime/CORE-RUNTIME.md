# Isolated comparison v2 runtime proposal

This archived candidate is source-only, unapproved and not deployed. No new real run ID, service window, authentication, staging, model call or quality receipt was created here. Existing frozen worker, client, coordinator, plans and consumed IDs remain unchanged. Neither the previous 35-minute comparison approval nor the later startup-only approval authorizes this proposal.

## Schedule and identity

The exact full field v2 validator is pinned at `3965ae8ead3e8c11fa513ba84a83105e1f5811d8a51b65c046b75b0ed6a888ac`. The worker verifies the artifacts and validator bytes before executing either. Both worker and client require two workloads, baseline prefill 512, alternatives 256 and 1024, and four blocks per alternative/workload in ABBA / BAAB / BAAB / ABBA order: 64 independent starts, primers and coding tasks. Baseline rows are not shared (32 baseline, 16 for each alternative). Old v1 plans, 16/32-row schedules, wrong order, comparison, block, profile, quality pair or budget are rejected.

Worker, client and maintenance *plans* are version 2. The result artifacts `aotg-evo-worker-result` and `aotg-k8-field-run` remain version 1. Ready/done artifact versions remain 1 with strict added bindings: run ID, raw worker-plan SHA, raw field-plan SHA, canonical schedule SHA, index, candidate ID, comparison ID, workload ID, block and profile SHA. Every scalar has the expected type; booleans do not stand in for integer indices. Future assemblers must require these v2-plan and marker joins. Old markers are insufficient.

The client uses the new metrics proxy at `41ed09f04e168b96a24906fbf63e250ab553ea0d4cfee90cc592dc4606bc1657`. Its pre-HTTP closing/concurrency/deadline/thread-start refusals invalidate capture; they do not invent an HTTP request or response. Closure after a sealed record raises instead of silently changing the sealed result. Missing, incomplete or rejected capture prevents the completion marker and leaves arm/final failure evidence. Request diagnostics are not task quality. The actual OpenCode tool-call join remains unqualified until a future permitted run.

## Separate finite budget proposal

`budget-policy.proposed.json` freezes canonical policy `96f81bfa1ea1c90e4988a0a25560156ea402493b9549ac7f17d408c53f3bf277`. Its status is expressly unapproved. The initial copy lineage retained legacy caps; this separate subsequent policy supersedes that preparation choice only in these new source copies, not in any historical plan.

| Scope | Seconds | Boundary |
|---|---:|---|
| Client total | 5400 | From its own monotonic start |
| Client work | 5340 | Last 60 seconds reserved for shared cleanup |
| Coordinator worker runtime | 5400 | systemd RuntimeMaxSec / local coordinator budget |
| Worker / field total | 5340 | Worker has its own later monotonic origin |
| Recovery | 600 | Existing independent recovery reserve |
| Coding / primer / request | 130 / 20 / 35 | Unchanged per-operation maxima |
| Trial field limit | 180 | Unchanged field validity bound |

Eight model steps and nine admitted requests per arm remain unchanged. No guard threshold, resource cap or retry policy was relaxed. Coordinator arming/stopping that consumes more than the 60-second margin prevents worker launch; recovery is still requested. Client starts before worker: neither epoch metadata nor a later worker start extends the client cutoff. No new arm begins without the existing complete wait/work/cleanup reserve.

The coordinator retains an extra 45-second worker wait grace and a recovery-call allowance of 600 + 15 seconds. The arithmetic wait envelope is 5400 + 45 + 600 + 15 = 6060 seconds after its sequence starts, excluding prior validation and other bounded readbacks. This is not a hard whole-workflow wall-clock guarantee. A future orchestration and owner approval must state the complete envelope, independent watchdog behavior and any post-restoration checks. The separate I/O component proposes 6255-second sampling and a 6275-second dedicated job; its actual coverage must still pass the fixed coverage gate.

The prior observed approximately 11.63-second startup and 35.4-second coding times suggest roughly 50 minutes for 64 tasks before primers, control and cleanup. A 90-minute cap is a finite conservative proposal, not a completion guarantee or calibrated prediction. Timeout or missing rows remain incomplete; there is no automatic retry or fallback adoption.

## Trust and preservation

The client retains top-level runtime imports before its own preflight. A reviewed external launcher MUST verify the runner and the complete pinned runtime module closure before importing or executing it. The client's later hash checks are not a substitute for that boundary. No launcher or actual input bundle for this candidate is qualified here. The future owner-entry bundle must likewise pin the new coordinator closure and source before root imports. New explicit nonce and matching staged worker-unit binding are required; no consumed nonce is reusable.

The paired grader is `f8797a3a6ab7bad05995572e7bed306f372eb5cd8a356396bc8f0f4ac8f42e9c`, and the catalog is `277abb01f995890be289b2c3d2e679f8a3283a12040b54218991fc005c19c268` (reviewed PR23 candidate, not a claim of merge). The C++ catalog now contains 15 assertions. Old nine-case results and source-review receipts cannot qualify a new run. Both workloads need new catalog-bound descriptors, independent source-review receipts and isolated native grader provenance. Public selftests do not satisfy this gate.

The worker preserves the reviewed pre-guard observation/anchor behavior. Resource checks, Monitor, OwnedProcesses, clean-cgroup barrier and final-kernel scan are AST-identical to the reviewed comparison base. Independent cleanup finalizers now all run when another fails; the original guard error remains primary. Embedded root recovery source is byte-identical to the earlier coordinator. None of these source checks proves actual restoration.

## Offline validation

Run only these synthetic tests with the existing interpreter:

```sh
python3 -B tests/test_comparison_runtime.py -v
python3 -B tests/test_comparison_maintenance.py -v
```

Latest results: 21 runtime tests and 22 coordinator tests pass. They include full 64-arm fake worker execution, enriched marker interchange, malformed schedule rejection, guard/cleanup failures, full fake client execution with incomplete capture and missing JobEmpty receipts, and three local socket/MRO checks with no upstream call. Coordinator tests use a fake command backend and never invoke real systemd. A separate independent reviewer also exercised readiness timeout, pre-start budget, outer monitor close and final-kernel failure cases. These are implementation checks, not hardware measurements, model quality, deployment, or rollback proof.

`source-index.json` records the archived source hashes and documentation-only deltas. Private validation and copy-lineage receipts are retained outside this archive. The public integration fixture pins its own exact module closure. Metrics, I/O and assessment components have their own review and integration boundaries. No live comparison package or execution is authorized by this directory.
