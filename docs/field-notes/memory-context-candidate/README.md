# Bounded observation integration candidate

Source-only, unapproved and not deployed. No model/service/SSH operation or field
measurement is performed by these sources or the synthetic tests. Original
runtime, plans and execution evidence remain unchanged.

This reuses PR38 head `31a5f0f5a63b4e9a4ec98a4d27e5e30c249dd967`:
`serialized_budget.py` and `diagnostic_triage.py` are byte-identical; the capacity
calculator adds optional force ticks, a hard sample quota and a separate guard
line cap. Its original defaults and eight original tests remain unchanged.
`resource_context.py` is the previously reviewed bounded reader, byte-identical.
The helper test copy removes only its obsolete optional private integration suite;
the new private runner tests the current adapter explicitly.

`ObservationJournal` reserves the next guard line before flushing the raw observed
sample. The original guard then runs unchanged. A rejected guard performs zero
context reads; its original exception remains primary even if verdict recording
fails. Accepted resource lines remain accepted-only. After the passed guard and
resource line are flushed, an optional context may be read. No fsync or power-loss
durability is claimed. A blocking kernel syscall cannot be preempted by these
userspace clock checks.

Expected missing/invalid diagnostic values remain `null` with reasons and may
continue after the unchanged guard passed. Unexpected sampler exceptions, clock
rollback/nonfinite/deadline, serialization, quota or write errors latch a stop.
The selected attempt is consumed before the reader; no retry resets quota or
clock state. A failure witness is attempted within its reserved line. Failed
writes cannot be reported as completed capture. The adapter summary retains
`rows`/`bytes` as admission charges (also named `admitted_rows`/`admitted_bytes`).
`flush_confirmed_rows`/`flush_confirmed_bytes` advance only after a full write
and successful flush; `unconfirmed_admitted_*` is their difference, not a
physical file-size measurement. Failed or partial writes remain charged;
visible bytes after a failed flush are not confirmation. This is not fsync,
collector verification, or proof that the private worker persists this summary.
Post-call actual monotonic time
is checked, including the shared worker deadline. Passed ticks also check the
shared worker deadline after accepted-resource flush when context is skipped,
and after a selected context is serialized and flushed. The 50 ms reader budget
is not a bound on the writer; late completed records can be retained but the
tick must stop. No additional clock or sampler call is required on guard refusal. Skip reasons/counts occupy the
existing guard row, not an extra row per skipped tick.

Context reads are separated by at least two seconds between actual start times;
force ticks do not reset that clock. The compact guard record preserves verdict,
reason and sequence and references the exact pre-guard JSONL bytes (including
newline) by SHA256 instead of repeating the full sample/anchor. Context uses the
same sequence/hash. The old offline triage accepts explicit evidence fields, not
raw journal rows, so it is unchanged. A separately qualified raw-journal join and
adversarial duplicate/missing/tampered-record reader is **not implemented** here;
these references alone are not independent authenticity or quality evidence.

## Fixed capacity

All limits apply to the fully escaped, encoded JSONL bytes **including newline**.
No field is truncated and no absent counter becomes zero. Oversize records stop.

| Item | Hard upper bound |
| --- | ---: |
| Worker window | 5,340 seconds |
| Normal primary cadence | at least 190 ms |
| Forced guard samples | 65 (initial + at most 64 arms) |
| Total primary samples, including forced | 28,200 |
| Context attempts | 2,671 |
| Startup / observed / guard / context line | 2,048 / 2,048 / 1,024 / 16,384 bytes |
| Observations | 59,072 rows; 130,394,112 bytes |
| Accepted resources | 28,200 rows; 57,753,600 bytes |

The conservative cadence bound is `ceil(5340000/190)+1+65 = 28172`.
The hard quota of 28,200 includes forced samples and does not delay or skip them.
The observation calculation is `1 + 2*28200 + 2671` rows and
`2048 + 28200*(2048+1024) + 2671*16384` bytes. Initial discussion assumed a
1 KiB anchor (130,393,088 bytes); the serialized boundary test found that the
implementation uses a 2 KiB anchor, and the upper bound above follows the source.

This is below the existing 60,001-row/128 MiB observation and 30,000-row/64 MiB
resource caps. With the calculator's conservative 128 MiB of **other** raw data,
raw total is 264,611,840 bytes, strictly below 256 MiB (the actual collector's EOF
probe is conservative at an exactly exhausted raw cap). Other files must still
satisfy their own caps. The current producer server log can exceed the collector's
individual log caps; this candidate does not fix that separate condition.
The reused wire calculation remains conditional on bounded metadata and other
files. Passing this local arithmetic does not qualify a complete capture chain.

## Reproduce offline checks

Linux/WSL, stdlib only, no downloads. From any working directory:

```sh
python3 -I -S -B /path/to/candidate/test_observation_journal.py
```

This suite previously ran 64 tests with no skips on Linux: 20 adapter/boundary
tests, the original 30 pure prototype tests and 14 helper tests. Three additional
worker-deadline regression tests and three write-accounting tests are included
(70 expected total); the historical 64- and 67-test results are not evidence for
the new revision. It includes a complete
synthetic 5,340-second clock window with 64 forced arm checks, exact serialized
line boundaries, maximum uint64/PSI/role fixtures, missing values, identity drift,
clock discontinuity, full-cap reservation before reads and no-retry failures.
It uses no live proc/cgroup reads. The POSIX no-follow test uses temporary files.

The full private worker is deliberately excluded from publication. With explicitly
trusted private source and core-test files available:

```sh
python3 -I -S -B /path/to/candidate/test_private_integration.py \
  --base-worker /private/field-worker-v2.py \
  --candidate-worker /private/field-worker-integrated-candidate.py \
  --candidate-sha256 "$TRUSTED_REBUILT_CANDIDATE_SHA256" \
  --core-tests /private/tests/test_comparison_runtime.py
```

Before running, the private fixture holder must apply the pinned patch to the
exact base in an isolated, single-writer copy and independently record the
new candidate SHA-256. The old candidate digest is invalid for this revision;
the source index intentionally leaves the new digest null. Do not derive the
trusted argument from the untrusted input at invocation. The runner verifies
base, candidate and core-test bytes before private imports, rejects stale,
malformed, missing or mismatched inputs, and executes the checked snapshots
rather than re-reading import paths. This does not sandbox untrusted Python:
only previously trusted private fixtures and an isolated fake-only environment
are permitted. The private inputs and new rebuild digest are not published here.

The historical six private synthetic tests cover actual Monitor ordering, owned PID/start
bindings, zero extra reads after rejection, preserved original rejection on write
failure, and original execute cleanup/barrier/kernel/summary behavior after an
actual journal or context failure using fake children. All original top-level
functions/classes except Monitor, its original guard try-body, and kernel/close
methods are AST-identical to the frozen base. This is not a real systemd restore
or an end-to-end automatic collection test. Coordinator restore followed by one
collection after a new journal failure remains separately unqualified.

The earlier per-pass `memory-context.patch` remains a separate unchanged historical candidate; `memory-context-integration.patch` is this bounded replacement against the exact original base.

The n=0 patch requires `git apply --unidiff-zero` against the exact private base
hash in `source-index.json`. It embeds reviewed helper definitions into the
private standalone worker, so root imports do not gain an unpinned dependency.
No patch application, source pin update, plan generation, approval, enrollment or
runtime launch is performed here. The new adapter adds measurable work to accepted
ticks; no zero-overhead, same-performance-condition or causal attribution claim
is made. Self-only reader calibration does not measure this worker, flushes or
production guard intervals.
