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

In the local absence check against the prepared first-machine inputs, assembly
retained all 16 scheduled ledger entries, produced zero normalized trials and
left the comparison unavailable (`decision: null`): no run evidence or worker
elapsed measurement existed. This checks missing-data handling only.

A missing source has no invented hash and therefore stays in the ledger without
a normalized trial. Missing elapsed time is not replaced with a sum of task
times. Where the comparator can run, incomplete evidence remains `incomplete`,
not a claim that optimization produced no improvement. Post-restoration checks
are separate from the frozen comparison schedule.

Run the 14 synthetic adapter tests with:

```sh
python3 -B -m unittest discover -s tests -p test_field_assessment_assemble.py
```

The fixture driver text is only parsed and hashed by these tests. All successful
reports in the fixtures are manufactured test data, never native execution,
measurements or accepted owner receipts. Assembly always records
`measurement_generated`, `deployment_verified` and `goal_complete` as false.
This source archive does not establish a real baseline, independent native
quality, a reproducible deployed kit, restoration or Goal completion.
