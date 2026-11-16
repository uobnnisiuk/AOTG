# Field adoption gates v2

V2 addresses [ADV-8/9](https://github.com/uobnnisiuk/AOTG/issues/24) with a frozen,
conservative rule for repeatability and explicit limits on metric regressions.
It changes offline evidence comparison only. It does not alter an engine, deploy
a configuration, authorize maintenance or certify independence on a real host.

## Frozen contract

`freeze_plan` now creates plan version 2 and requires an explicit `metric_gates`
mapping. Runs, decisions and newly generated kit inventories are also version 2.
The evaluator explicitly refuses v1 plans/runs for new adoption. Preserve older
artifacts and their pinned evaluator; do not edit their versions, hashes or past
decisions to migrate them. New observations require a newly frozen v2 plan.

The frozen `adoption_policy` requires four blocks per alternative and workload,
in the order ABBA, BAAB, BAAB, ABBA: eight observations per configuration and
exactly two of each orientation. It allows at most eight alternatives.
Every adjacent A/B and B/A pair must exceed the plan's `minimum_improvement`.
For each workload, the slowest candidate observation must also be at least that
fraction faster than the fastest baseline observation. For the usual 5% margin:

`max(candidate wall times) <= 0.95 * min(baseline wall times)`.

The decision records each configuration's observed range and the worst-case
improvement. A faster median is insufficient. The ADV-8 sequence
`[10.0, 9.4, 7.4, 8.0]`, repeated with the matching baseline/candidate roles across
all required blocks, is held because its
ranges overlap even though each adjacent pair exceeds 5%.
The complete frozen schedule is checked exactly; altering BAAB to ABBA is
rejected. Paired mapping follows the actual baseline role in both orientations.

No non-wall tolerance is implicit. For example, a **synthetic test** supplies
`{"ttft_seconds": {"direction": "minimize", "max_regression_fraction": 0.1}}`.
This is not a recommended or approved live tolerance. Each future real plan must
give its own rationale and receive the applicable approval before measurement.
TTFT/tool roundtrip must minimize; prefill/decode throughput must maximize. The
validator rejects reversed meanings. Each gated metric is required in every
trial, and its paired observations must stay within its frozen regression limit.
TTFT ten times slower or throughput one hundred times slower is rejected by the
synthetic 10% test gate. Missing required observations remain incomplete.

An explicitly empty gate mapping assesses wall time only. The decision lists
unassessed performance metrics. Supplying a non-wall performance observation
without its policy cannot silently pass; raw `draft_accepted`/`draft_proposed`
counts are explicitly diagnostic and do not have a monotonic performance gate.
All prior quality, identity, source-review, resource and finite-bound checks
remain required. Fixed observed terminal reasons are retained in `trial_reasons`
so missing evidence is distinguishable from a recorded failed attempt.
A resource-limit violation in any observed trial also sets
`global_resource_stop` and records `resource_stop_trial_indices`. The whole
decision remains incomplete, including when another candidate otherwise passes.
An independently incorrect code submission remains a candidate rejection rather
than a global resource stop.

## Preserved failed stress finding

The initial ABBA-only [parameters](adoption-null-plan.json) were saved before execution with SHA-256
`5df8b6973c56e7a580b3ac62e44ccc72a0de275b5c4dd4d017198ae06c20682e`.
The initial [result](adoption-null-result.json) pins those bytes and the original
evaluator/simulator. It is a retained failed stress finding, not the acceptance
record for the revised mechanism.
The initial result remains the unchanged outcome of its predeclared ABBA-only
rule. The mechanism was revised only for the separately preregistered balanced
experiment; seeds, margins, noise distributions and the false-adoption cap
remained unchanged.
The script uses `freeze_plan`, `quality_record` and `compare_field_run`; all
quality attestations are explicitly synthetic fixtures, not real review evidence.

Every IID case uses the smallest allowed workload count (one), three blocks,
identical lognormal wall distributions for all configurations, median 10 seconds,
and 4,000 repetitions. The predeclared false-adoption cap is 1% per case.

| Alternatives | Log sigma | False adoptions | Fraction |
| --- | --- | --- | --- |
| 2 | 0.05 | 0 / 4,000 | 0% |
| 2 | 0.10 | 0 / 4,000 | 0% |
| 2 | 0.20 | 1 / 4,000 | 0.025% |
| 8 | 0.05 | 0 / 4,000 | 0% |
| 8 | 0.10 | 2 / 4,000 | 0.05% |
| 8 | 0.20 | 7 / 4,000 | 0.175% |

All six initial IID cases met the cap, but that alone was insufficient.

Separate non-IID stress cases used 500 repetitions each and were excluded from
the calibrated cap. Shared block drift produced 0/500 adoptions. An arm-position
confound that makes baseline positions systematically slower produced **500/500
adoptions**, despite no causal configuration effect. This was treated as a
remaining adoption blocker, not just a limitation in prose. The ABBA-only source
and both original experiment records were retained before changing the mechanism.

## Balanced-order preregistered check

The revised [parameters](adoption-balanced-null-plan.json) were saved before the
new execution with SHA-256
`417f0f2683552b04aacb01652e57d5bc2b18edfa8916b5d3c7a5debeaf6ee957`.
The [balanced result](adoption-balanced-null-result.json) pins the revised
evaluator and [replay script](../../tools/check_field_adoption_null.py).
That recorded evaluator is the version before the subsequent global resource-stop
guard; its exact source hash remains in the unchanged result. The later guard
only prohibits adoption after observed resource violations. The simulator gives
every synthetic trial clear resources, so the added guard does not change its
decision rule on those inputs. Focused regressions separately check all five
resource dimensions and distinguish ordinary incorrect submissions. The stored
simulation is not presented as a rerun of the later evaluator bytes.
The change is the balanced ABBA/BAAB mechanism, not a change to the seed, noise,
5% effect margin, 1% IID cap or repetition counts. The same physical order
effect remains: positions 0/3 have log offset +0.1 and positions 1/2 have -0.1.
This is equivalent to the original simulator's role-based assignment when every
block was ABBA; in BAAB it correctly stays with position rather than following
the candidate label.

The revised run observed **0/4,000 false adoptions in each of the six IID
conditions** (24,000 total). Both separate stress conditions also produced
0/500 adoptions, including the unchanged physical order effect that defeated the
initial ABBA-only rule. These results satisfy the predeclared 1% IID cap and the
specific order-confound regression; they do not establish general drift immunity.

Under independent, exchangeable continuous null observations, complete
separation of eight candidate and eight baseline values has probability
`1 / choose(16, 8)`. The union bound for eight alternatives is `8 / 12870`, about
0.0622%; a positive margin and the paired gate only reduce that event. This is a
conditional mathematical bound, not a real-host confidence interval. A finite
experiment does not guarantee behavior across all drift processes or repeated
searches. The decision retains `real_host_independence_verified: false`.

Replay locally with existing Python; no downloads or machine inference:

```sh
python -I -S -B tools/check_field_adoption_null.py \
  --parameters docs/field-notes/adoption-balanced-null-plan.json \
  --parameters-sha256 417f0f2683552b04aacb01652e57d5bc2b18edfa8916b5d3c7a5debeaf6ee957 \
  --output /absolute/new-synthetic-result.json
```

## Integration boundaries

Two workloads and two alternatives now require 64 trials. The previous private
worker's 32-row bound and K8 runner's fixed 16-row contract cannot execute this
plan. Their 35-minute window is not enlarged by this change. New runtime design,
budgets, independent integration verification and explicit authorization are
necessary before a real v2 comparison. A one-startup diagnostic remains a
separate non-adoption task. No old evidence fills the new repetition requirement.

The accompanying assembler changes for
[ADV-10/11](https://github.com/uobnnisiuk/AOTG/issues/25) emit run version 2 with
the exact frozen plan and require new proxy completeness evidence. Their 26
synthetic integration tests pass with the balanced v2 evaluator. These tests
exercise evidence joins and failure handling, not a private K8/EVO runtime.
The pinned v1 runtime remains unchanged. Real runtime integration is still
required before applying an adoption decision.

Kit integrity still proves file/decision hash consistency only. It does not
establish that a bundled configuration implements the selected profile or that
the supplied private-configuration hash belongs to that profile. Rebuild,
deployment and rollback remain unverified.
