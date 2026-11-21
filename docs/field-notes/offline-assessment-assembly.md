# Offline field evidence assembly

`tools/assemble_field_evidence.py` preserves the reviewed first-machine evidence
adapter. It joins existing worker, client, resource and independent assessment
records into `aotg.field_evidence.compare_field_run`. It does not run OpenCode,
native submissions, SSH, services, downloads or benchmarks. Its fixed producer
contracts and assessment thresholds are specific to this initial experiment.

Use existing Python 3.12 on Linux or WSL. File validation relies on POSIX
`dir_fd`, `O_NOFOLLOW` and regular single-link files, including parent-directory
checks. Windows execution is unsupported; the corresponding synthetic tests
are skipped there. This archive adds no platform support.

## Invocation and inputs

```sh
python3 -I -B tools/assemble_field_evidence.py \
  --inputs /absolute/private/inputs.json --inputs-sha256 RAW_INPUT_SHA256 \
  --authority /absolute/trusted/authority.json --authority-sha256 RAW_AUTHORITY_SHA256 \
  --output /absolute/private/new-assessment.json
```

Supply the actual SHA-256 of each manifest separately through a trusted channel.
The authority options may be omitted to collect an incomplete ledger. An existing
output is refused, and output cannot overwrite original evidence. Exit code zero
means assembly finished; it does not mean the comparison passed. The CLI's
`output_sha256` is the canonical JSON digest, excluding the output file's newline.

The input manifest pins the original field/client/worker plans, runtime identity,
reviewed client-runner source, source repository, catalog, baseline configuration,
assessment policy and exact replay-driver guide. It identifies separate client,
worker and trusted assessment roots. Original files stay private. The adapter
loads only pinned repository library bytes for parsing and comparison; the
manifest and those library pins must themselves be independently trusted. The
synthetic tests demonstrate field names and hash conventions without supplying
owner configurations or real receipts.

## Independent evidence requirements

The authority root must be separate from generated client and worker output
roots. It contains the actual reviewer/operator records and byte-identical copies
of their referenced evidence. Caller-provided hashes bind bytes; they do not
authenticate the reviewer or prove that a reported execution happened.

- Bind every captured file to the actual run through an independently pinned
  inventory and collection record. Preserve original successes, failures and
  missing files; never select a favorable retry.
- Bind source review to the exact submitted source, grader and catalog. Rejected
  source need not be executed. A native test pass alone cannot accept quality.
- Supply the actual outer isolation result, native quality report, staged-input
  inventory and replay execution record. Decoded bounded outer stdout must match
  the quality report. An isolation-reference string alone is insufficient.
- Associate the complete Windows owned-job directory delta with observed client
  launch and exit records. Preserve real job plans and cleanup receipts. Do not
  infer per-arm ownership from random filenames.
- Retain the final kernel scan and its independent coverage review. Require the
  actual final public-selftest report after the last edit, bound to the frozen
  helper, source and public test. Unknown OpenCode output layouts stay incomplete.

Resources must bracket the observed EVO ready-to-finished interval, including
cleanup, with at most 2 seconds between actual samples in both UTC and monotonic
elapsed time. No synthetic endpoint is added. Optional I/O coverage uses a
2.5-second gap rule and remains `coverage_only_unverified_producer`; it neither
establishes producer authenticity nor proves an I/O bottleneck. Task wall time
is separate from request TTFT, usage and server timings. Missing decode or
speculation counters are not inferred.

## Incomplete results and validation limits

In the historical local absence check using the original frozen v1 evaluator
against the prepared first-machine inputs, assembly
retained all 16 scheduled ledger entries, produced zero normalized trials and
left the comparison unavailable (`decision: null`): no run evidence or worker
elapsed measurement existed. This checks missing-data handling only.

A missing source has no invented hash and therefore stays in the ledger without
a normalized trial. Missing elapsed time is not replaced with a sum of task
times. Where the comparator can run, incomplete evidence remains `incomplete`,
not a claim that optimization produced no improvement. Post-restoration checks
are separate from the frozen comparison schedule.

Run the synthetic adapter tests with:

```sh
python3 -B -m unittest discover -s tests -p test_field_assessment_assemble.py
```

The fixture driver text is only parsed and hashed by these tests. All successful
reports in the fixtures are manufactured test data, never native execution,
measurements or accepted owner receipts. Assembly always records
`measurement_generated`, `deployment_verified` and `goal_complete` as false.
This source archive does not establish a real baseline, independent native
quality, a reproducible deployed kit, restoration or Goal completion.


## Observation contract v2 (ADV-10 / ADV-11)

The new assembler accepts `aotg-field-assessment-inputs` version 2 only. A version-1
input requires its original frozen evaluator; existing plans, reports, hashes and
historical observations are not rewritten. The new frozen client plan must state
`proxy_capture_version: 2`, and the identity must pin `aotg/field_proxy.py` to the
exact supplied source. These are new execution inputs, not inferred defaults.

A v2 proxy capture starts with an opened event and ends with a closed event.
Every emitted record has one monotonically increasing `event_sequence`. Ordinary
inference attempt records retain their request `index`, timings, sampling and
content hashes. Admitted attempts, including malformed payloads, consume the
finite request budget. Concurrent requests, exhausted limits, authentication,
route/protocol, and HTTP parser rejections have fixed reason codes and status
numbers; paths, bodies, headers and credentials are not included.

Callbacks and sequence allocation are serialized. The first 128 rejections have
individual records; further rejections use one overflow marker and bounded
per-reason counters in the closing summary. Missing sequence numbers, inconsistent
counters, absent closure, active handlers at closure, or a callback write failure
cannot certify complete capture. Once closed, no late event is appended. The
caller must stop accepting requests and drain handlers before freezing evidence;
`server_close()` records incomplete capture if handlers remain. This is not a
claim that an arbitrary callback is bounded or crash-durable.

The assembler checks the entire capture and requires zero refusals for a passing
arm. A client that retries a 409 and eventually completes cannot hide that refusal
behind a list of successful requests. Request-only historical logs cannot prove
that zero rejections occurred and are not accepted by this contract.

For ADV-10, identity, scheduling and capture inventory bindings remain mandatory.
When a real source and the remaining required artifacts exist, a well-formed,
independently bound runtime failure is normalized with
its actual source hash, terminal status and fixed reason, and classified as
`verified_runtime_failure`. Client completion failures, timeouts, proxy refusals,
and observed resource guard violations are distinct from `missing_or_conflicting`.
The report preserves the scheduled denominator and counts each classification.
The v2 comparison dependency also retains each observed trial's reason in
`comparisons[].trial_reasons`.

This narrow change intentionally keeps the whole comparison incomplete after a
runtime failure: the fixed operational stop policy has not certified a continued
experiment. In particular, a swap/NVMe/GPU stop never permits adopting a different
candidate merely because that candidate's observed arms look good. Missing
stability is explicit. Unknown metrics remain null, and a pswpout mismatch is not
converted into invented swap bytes. Resource observations compare pswpout against
the first saved sample, preserving that anchor and the observed range; this is not
a recovered value for a previously unsaved trigger.

A worker stop before readiness can be independently observed without a source,
client result, resources or kernel scan: the captured worker summary and source,
unique exact schedule row, arm result, frozen profile and recomputed configuration
must all bind. Its original stop reason is retained. A closed, independently bound
request failure before payload validation may have no request hash or fixed
sampling; only a failed/timed-out result with no response bytes and an empty
response hash can use that form. Completed requests still require every exact
sampling field and content hash.

Such observations remain outside `run.trials` when source or required metrics are
absent. `observation_decision` preserves the scheduled denominator, verified
failure count and per-index reasons, bound to the ledger and canonical comparison
digests. Consumers must display it alongside the canonical `decision`, whose
missing-source trial remains missing. It cannot adopt after any verified runtime
failure. Corruption, duplicate schedule rows, profile/config conflicts or absent
authority cannot certify the failure; missing data is not guessed successful.
The assembler never invents a source hash to force a row into `run.trials`. A bound
failure means its recorded bytes and execution identity were checked; the program
still does not authenticate the external reviewer's identity or guarantee their
attestation is truthful.

Verification uses synthetic fixtures and local loopback HTTP stubs only. The
private K8 runner must be adapted to retain the new capture events and closing
summary, and new plans/source hashes must be frozen before use. This source change
has not been applied to the private runtime or an inference host. ADV-8/9 adoption
policy is integrated in the same change; ADV-4 grading remains a separate dependency. New plan,
quality and timing contracts require combined review and testing. No existing
real trial has been made successful or retried by this implementation.
