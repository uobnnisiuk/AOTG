# One-attempt baseline startup diagnostic

This source archive preserves the reviewed, isolated startup-only worker change.
It is not deployed, and it does not authorize maintenance or complete the AOTG
first-machine Goal. It follows the missing guard-observation repair archived in
[PR #27](https://github.com/uobnnisiuk/AOTG/pull/27); the original failed comparison
and its unknown triggering counter value remain unchanged.

## Scope and fixed limits

The new plan schema permits one unchanged prefill-512 baseline profile. It rejects
the old comparison schedule and field-plan fields. A permitted execution starts
one server, waits at most 120 seconds for verified native readiness, observes it
for 10 seconds, then cleans up and finalizes the resource/kernel evidence. The
worker limit is exactly 240 seconds. The proposed coordinator work budget is
360 seconds, with a separate 600-second recovery budget. These are bounded stages,
not a guarantee that restoration succeeds within a wall-clock maintenance window.

The worker sends no inference API request and does not wait for an OpenCode task
or publish a benchmark-ready endpoint. Its `inference_invoked: false` and
`startup-observed-no-inference` labels mean no workload/API invocation by this
worker. An authorized real execution would still load model weights, initialize
the GPU/runtime and may perform engine-internal warmup. This is not a claim of no
GPU computation or no internal model execution.

Result fields keep `benchmark_trials: 0`, `comparison_complete: false` and
`quality_accepted: false`. A successful diagnostic would establish only the
observed startup/idle interval, not coding quality, optimization, general
stability, independent kit reconstruction or restoration. The external reviewed
maintenance coordinator owns restoration; it is not included here.

## Failure finding and repair

Review found that one exception from journal-process shutdown could skip the
owned-engine cleanup and cgroup check in the old shared cleanup block. The new
copy attempts journal close, owned-process cleanup and cgroup verification
separately, preserving each failure and refusing success. A failure in the outer
journal close also no longer skips the final kernel scan and summary write.
The independent coordinator remains the cleanup backstop. Attempting every
finalizer is not evidence that every finalizer succeeds on a real host.

The resource thresholds, `Monitor`, native identity checks, process ownership,
cgroup barrier, HIP preflight helper, dependency/import isolation and configuration
copy helper are unchanged from the supplied baseline. Tests compare their ASTs.
Only plan/input validation, the one-startup execution flow and CLI result semantics
change. No production configuration, private plan, credential or model is bundled.

## Reproduce the source and synthetic tests

The full worker remains private. Obtain the already-reviewed baseline through its
existing private channel and verify its SHA-256 before using it. This archive
cannot reconstruct the worker from public files alone. The standalone test runner
imports the explicit `--worker` path; supply only the trusted files whose hashes
match below. It does not authenticate an arbitrary file supplied by a caller.

| Artifact | SHA-256 |
| --- | --- |
| Required baseline worker | `cdac8769878976a784bc0008543e376133a86914653b4f0594d2338e3aef653e` |
| Patched startup worker | `69edcd28bb1e6859501fb1ef3523b8befa4fe62061b82f6bb35cc3046fbd1550` |
| Complete unified patch | `761f47807d6ba3824f4ee2c8ce0456443c7b4b89999cf21224c86f9f272bafa6` |
| Standalone test runner | `383e5fe744512143d1377316dfc2eb9d4b2fef987eb18308fd0c1b703a9a86f2` |
| Preserved local test stderr | `3797ee7d3678e1d497c41577f74d0af1a1e6e315051cab58136bc8ce26502db0` |

Use an existing Python/Git installation on Linux or WSL, in a new isolated local
scratch directory. Set the archive path explicitly; these commands do not install
anything or run the actual worker entrypoint.

```sh
ARCHIVE=/absolute/path/to/docs/field-notes/diagnostics/startup-diagnostic
BASELINE=/absolute/trusted/field-worker.before.py
sha256sum "$BASELINE"
cp "$BASELINE" field-startup-diagnostic.py
git apply --no-index "$ARCHIVE/startup-diagnostic.patch"
sha256sum field-startup-diagnostic.py
python3 -I -S -B "$ARCHIVE/test_startup_diagnostic.py" \
  --worker "$PWD/field-startup-diagnostic.py" --baseline "$BASELINE" -v
```

The preserved local report records **21 synthetic tests passed in 0.496 seconds**.
All host/GPU/process actions in those fixtures are replaced; they exercise the
real validation, execution control flow and local temporary result writes.
Negative cases cover startup/idle guards, readiness timeout, process replacement,
launch/ownership failures, independent cleanup failures, final kernel failure,
wrong unit, unchanged protected helpers and read-only CLI preflight.

The report is the original local test output, not a fresh run or a host result.
Normal repository CI does not execute this standalone runner because the private
worker/baseline are absent and the runner is outside `tests/`. A green repository
CI therefore does not prove these 21 tests ran there. New private plans, transport
integration, independent review and explicit operational authorization are still
required before any real startup. This archive changes none of those approvals.
