# Preserve rejected resource observations

This is a proposed patch for an existing private field worker. The worker is not
part of the public repository; this directory does not add a production module.
Nothing has been deployed or rerun on an inference host. The original worker,
frozen plans, runtime files and collected evidence remain unchanged.

The patch requires the reviewed private base with SHA-256
`aa75b284c9b365f2c37cc4f4946ca17ebcdfde8420b006909041db4693f976cf`.
The resulting patched worker has SHA-256
`cdac8769878976a784bc0008543e376133a86914653b4f0594d2338e3aef653e`.
`resource-observation.patch` contains only changed lines, without identifying
unchanged context. Obtain the base from its authorized private location and apply
the patch only to a new isolated copy. Do not upload the private base or a complete
patched worker. Future use still requires source review, a newly pinned execution
plan and the applicable operational authorization.

From the isolated directory containing the copied `field-worker.py`, apply the
zero-context patch with `git apply --no-index --unidiff-zero /absolute/path/resource-observation.patch`.
Check both the base and resulting file hashes. Local application was verified to
produce the exact patched hash above.

## Behavior

The worker keeps `resources.jsonl` as accepted-only telemetry. A separate
`resource-observations.jsonl` records:

- The fresh startup counter and GTT anchors, with timestamps bracketing their
  sequential reads. This is not an atomic hardware snapshot or a passed guard.
- Each collected sample and sequence before resource checks, explicitly marked
  `guard_verdict: not-evaluated`.
- A result linked to that sequence: `passed` or `rejected`, retaining a rejected
  check's reason and exception type.

The result covers resource checks and thermal pacing within that block. It does
not certify the later kernel-journal check, the complete monitor tick, model
readiness, a completed task or a safe deployment. All resource thresholds, startup
anchor semantics, thermal decisions and their order are unchanged.

Startup/observation/result-write failures stop execution. If recording a rejection
also fails, the original guard exception remains primary and receives an evidence
failure note. Successful observations are never inferred from an absent verdict.
Records are flushed for a normal process stop; no fsync or power-loss durability
claim is made.

The change addresses a fully acquired sample rejected by a guard. If telemetry or
counter acquisition raises before a complete sample exists, its original exception
is preserved and no counter value or observation is invented. Non-finite values
that cannot be serialized as strict JSON stop with an evidence-write error; they
are not written as JSON `NaN` or treated as passed. A partial write is not a valid
complete record and must remain incomplete during later assessment.

## Focused verification

The standalone runner imports **trusted, explicitly supplied** original and
patched worker files. It never invokes the worker entry point. It substitutes
telemetry, counters, clocks, storage and process operations; it is not a sandbox
for importing arbitrary Python. No actual telemetry, GPU, SSH, systemd or model
execution is used.

```sh
/usr/bin/python3 -I -S -B test_resource_observation.py \
  --worker /absolute/new-copy/field-worker.py \
  --baseline /absolute/private-base/field-worker.py -v
```

The 12 tests cover observation-before-validation, increment/reset triggers,
invalid/missing data, unchanged rejection boundaries, thermal timeout, startup,
observation and flush failures, rejection-write failure preserving its primary
exception, and incomplete acquisition without fabricated values. These are
synthetic regression results, not a successful hardware trial or optimization.
All 12 passed in the local offline check. Public CI does not have the private
worker and does not execute this standalone runner.

The main repository currently has no private field worker to patch. This artifact
preserves the scoped fix and its verification method without claiming integration
into the public runtime.
