# Startup diagnostics: offline integration findings

These are source-only findings and synthetic checks. No new field run, service
stop, model request or operational authorization is established by this note.
The proposed driver and parent connection still require final integration review.

A coupled test found a deadline mismatch that separate component tests missed:
the parent allowed exactly 45 seconds for a read phase, while the read wrapper
required a full 45 seconds remaining after local preparation. Even a small clock
advance therefore prevented the first transport from starting. The owned
transport retains its 45-second bound. Each read envelope is now 50 seconds,
including at most five seconds of local preparation/validation margin. Consuming
that margin refuses a new read job rather than extending a deadline.

The proposed post phase is **235 seconds**: preparation 30, baseline read 50,
read-only API idle check 50, collection 90 and final cleanup 15. The proposed
parent bound is **1,420 seconds** from its drive start: 1,185 seconds for the
existing startup/watch/recovery path plus the post phase. Interactive
authentication and preceding validation are outside that clock. These are source
budgets, not permission for another stop or a guarantee of task completion.

Two further clock cases were fixed. A rollback or nonfinite clock previously
could raise again during finalization and bypass result persistence; the failure
is now latched and saved as incomplete with an unknown wall time. A valid final
clock beyond the shared deadline previously retained a completed status; it now
records incomplete with a deadline reason. Failed persistence propagates to the
parent, and a retained parent watchdog remains necessary for blocked calls.

Independent library review passed 30 synthetic tests: 11 read-wrapper tests,
10 flow tests and nine additional coupled tests. They exercised advancing clocks,
preparation exceeding the five-second margin, unknown transport cleanup, baseline
mismatch, busy API slots, transport exceptions and final persistence failures.
Unknown cleanup prevents subsequent remote phases. A baseline mismatch with
known cleanup can still permit bounded diagnostic collection without claiming
restoration. These tests use fake exchanges and do not prove a real restore or
the complete parent/driver/collector chain.

## Historical telemetry size check

Saved records from one successful startup and one stopped comparison were
hash-verified and encoded using the new writer's exact compact JSONL convention.
The raw files were not modified and no host was contacted. Sizes include escaping
and newline. The guard maximum below includes every fixed scheduling reason and
maximum bounded counters; it is a derived size envelope, not another measurement.

| Saved window | Observed rows: maximum / cap | Accepted resources: maximum / cap | Compact guard envelope: maximum / cap |
| --- | --- | --- | --- |
| Successful startup | 111 rows: 1,484 / 2,048 bytes | 111 rows: 1,083 / 2,048 bytes | 456 / 1,024 bytes |
| Stopped comparison | 29 rows: 1,482 / 2,048 bytes | 28 rows: 1,078 / 2,048 bytes | 525 / 1,024 bytes |

All saved payloads fit. The largest anchor was 309 bytes. Neither historical
worker log contained the new context records, so this check supplies no actual
worker evidence for the 16 KiB context cap. It does not guarantee future sensor,
label or PCIe error-field sizes, and it does not measure added sampling/flush
cost. Oversized records remain a stop condition; resource guard thresholds are
unchanged.

## Compact journal verification

This is a separate strict-schema candidate; it does not replace or remove the
reader already present in public PR38. It checks bounded canonical JSONL, duplicate keys and
nonfinite numbers, phase order, run/sequence identity and SHA256 references to
the exact observed line. Missing initial measurements remain explicit incomplete
evidence rather than becoming zero. Guard rejection, a missing selected context,
partial EOF and invalid references have distinct outcomes.

There is no successful-runtime result. A structurally consistent EOF is still
incomplete because the journal has no authenticated execution-completion marker.
A coherent rewrite also requires an externally trusted digest to detect; internal
hashes alone do not authenticate custody. The reader never promotes a context to
same-window triage, quality acceptance, causal attribution or retry authority.

The reader passed 28 synthetic tests both directly and after relocation; an
independent reviewer passed those 28 plus four additional boundary checks. The
fixture was generated from the fixed writer with fake files, identities and
clocks. No private worker, execution payload or historical telemetry is included.
