# Proposed single-capture I/O v2

Isolated, unapproved source preparation. No SSH, service, inference or live
kernel-counter operation has been performed by this component. Earlier frozen
inputs are unchanged. A future controller must validate new owner authorization
and all source/plan hashes before the explicit execution API.

## Bound

6255 sampler seconds = 120 prearm/ready + 5400 proposed coordinator work +
45 existing worker-wait grace + 600 recovery + 15 recovery-request grace +
15 result collection + 60 local cleanup. Dedicated Windows job: 6275 seconds
(20 seconds slack). Lifecycle waits until job-start + 6275 + 5, then requests
cancellation and waits at most 10 more seconds. The controller must include
these verification deadlines in its own bound.

These are configured limits, not a promise of exact wall-clock completion.
The native job clock starts inside the helper after wrapper initialization.
This budget does not include a separate post-restoration two-task coding check;
that requires its own fixed capture/scope. Cancellation, including after a child
has already exited, and any output-inventory error prohibit deadline completion.
No prior 35-minute authorization applies. The original generic 2100-second
control/relay transport remains unchanged.

## Contract

The lifecycle CLI is local preview only:
    python3 -I -S -B supplemental-io-lifecycle-v2.py --plan PATH --plan-sha256 RAW

Python API: Capture(path, raw_sha).preview(); then, only under separately
validated authorization, start(execution_authorized=True, deadline=MONOTONIC).
Start returns the first actual sample; publish client readiness only afterward.
The first sample must arrive within 5 seconds and the owner handshake deadline.
Always call finish(cancel=False) in a finally block after successful start.
Start failure performs cancellation/finalization internally. Do not retry a
consumed plan or ambiguous launch.

PLAN_FIELDS, LIMITS, capture_binding(), and constructor validation are the
schema. Plan artifact: aotg-supplemental-io-capture-plan, version 2.
Dedicated job/receipt: aotg-windows-io-job / aotg-windows-io-job-result,
version 2. Legacy jobs, extra fields and altered limits are refused.

client_plan is an explicit path/raw-SHA descriptor. Its canonical digest must
equal client_plan_sha256. Its run_id, maintenance_nonce, raw worker_plan_sha256,
5400/60 limits and complete ssh argv must agree. SSH and PowerShell descriptors
must exactly equal the client's windows_transport descriptors. Only wrapper and
native helper differ for dedicated I/O. Extra ProxyCommand, forwarding or a
different host cannot be smuggled in by retaining safe tokens.

Hash semantics:
- authorization_sha256: canonical digest of the separate owner authorization;
- client_plan_sha256: canonical digest of the exact pinned v2 client plan;
- client_plan.sha256 / emitted client_plan_raw_sha256: raw client file hash;
- worker_plan_sha256: raw worker-plan file hash, same as the client field;
- job_plan.sha256 and lifecycle plan_sha256: raw bytes;
- capture_binding_sha256: canonical digest of the aotg-supplemental-io-invocation
  version 2 object containing run_id, nonce, the three authorization/client/worker
  hashes, sampler_sha256 and exact LIMITS.

The sampler receives run_id and capture_binding_sha256 as explicit argv and
echoes them in every metadata/sample/final record. Raw sample artifacts remain
version 1 with additive fields. This is invocation association, not independent
cryptographic authentication or proof of human identity.

Plan/source/helper/wrapper/executable bytes are pinned before launch.
Sampler stdin is an anonymous temporary snapshot of the verified bytes; a source
path replacement after the final hash check cannot change streamed code. Output
root must be owned, canonical, unused except its ssh-plan.json, and on the
explicitly mapped C drive. Files are created exclusively. Hardlinks are
permitted only on individually pinned SSH/PowerShell executable descriptors.

Launch/result records include raw plan/job/source hashes, binding, wrapper PID
and return code, the complete native job receipt, and all generated file hashes.
The original suspended-create -> assign-to-job -> resume, kill-on-close,
cancel marker and JobEmpty checks are preserved.

## Output and assessment

Nominal sampling is 1 Hz. Maximum line: 8192 bytes; total: 32 MiB;
maximum records: 6257 (6255 samples plus header/final). Output size monitoring
requests owned cancellation on overflow. The 200 ms monitor cannot prevent
transient overshoot or guarantee progress of an OS-stalled writer; an oversized
capture is incomplete, never silently truncated into an accepted result.

The fixed read-only sources remain block statistics, I/O PSI and aggregate CPU
kernel text. No SMART queries, remote files, shell commands or device writes.
512-byte sector interpretation, read-start/end UTC and monotonic brackets,
device/boot identity and counter decreases remain explicit.

The separately owned adapter must accept exactly this dedicated v2 contract,
raise its I/O row cap from 4000 to 6257, retain bounded input and 2.5-second
observed-gap policy, and verify source/launch/job/receipt/run association through
the trusted capture inventory. First/last brackets and actual gaps, reset
flags and final record remain necessary. Generic control/relay v1 job policy
does not change. No rates, io_errors=0, causal bottleneck or continuous resource
proof are asserted here.

Windows JobEmpty proves local Windows child cleanup only. Remote process exit
is explicitly unverified; the sampler has its own finite clock and termination/
hangup handling. Missing final output means incomplete evidence.

## Validation

24 synthetic tests passed (0.170 seconds): preview without execution, strict
limits/schemas, source/route drift, raw/canonical client binding, first-sample
association/timeout, cancellation/JobEmpty refusal, output bounds, finite
simulated sampling, missing counters, resets, and exact native/wrapper delta.

Three harmless native Windows fixture checks also passed: 200 ms child timeout
with JobEmpty; immediate child exit under a configured budget just above the old
cap; refusal above the new cap. No long sleep completed. No SSH or counters were
used. The original fixture receipt is retained privately (raw SHA256 `f76a4a06c6cbae957a696fa87074950a03b1f6c17db24ca6d9b4c41f9145afb2`); process identifiers are excluded from this archive. Native cleanup code exactly matches the
old helper after reversing the class-name and cap substitutions.

The UNC test-script path was refused by existing signing policy. Exact test and
helper bytes were copied into a new private C-drive fixture directory and run
there; no execution policy was changed. These fixtures do not demonstrate a
6255-second capture or remote behavior.
