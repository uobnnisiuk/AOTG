# Offline comparison v2 assessment candidate

This source-only adapter does not start a service, run a candidate, authenticate
an owner, or create a native quality receipt. Its synthetic fixtures are not
real measurements. It accepts v2 worker/client plans with the enriched schedule
markers. Earlier plans and their original evaluators remain unchanged.

Only client coding invocation `wall_seconds` is the primary task metric.
Request TTFT, server prefill/decode timings, speculative acceptance counters,
and proxy-observable tool intervals remain separate diagnostics. Missing values
are not zeros and no task aggregate or tolerance is invented. Independent
source review, isolated native quality, compatibility, resource coverage,
runtime failures and owned process cleanup retain their original gates.

The tool interval helper is pinned before execution. Its boundary is successful
response DONE flush through receipt of the next admitted request body. This
includes client processing and local transport; it is not isolated tool runtime.
Missing IDs produce incomplete diagnostics. Contradictory joins prevent the arm
from being normalized. Diagnostic completeness does not grant quality acceptance.

## Supplemental I/O

The v2 policy fixes one optional capture, at most 32 MiB, 6257 records and 8192
bytes per record. The adapter reads a finite capture once and reuses that
immutable snapshot for per-arm coverage. It does not reread the entire long
capture for every arm or multiply its input budget by 64.

`supplemental_io` in the input specification contains at most one raw
`{path, sha256}` capture descriptor. This alone establishes observed coverage,
not producer identity. The independent authority may additionally contain one
`supplemental_io_captures` entry with exactly these fields:

- `descriptors`: the fixed role inventory defined by `io_capture_diagnostics`;
- `authorization_sha256`: the independently asserted canonical owner record hash;
- `review_record`: a nonempty, pinned external inventory review descriptor.

Every copied role must reside under the separate trusted root. The adapter
derives run ID, nonce, canonical client hash, raw client hash and raw worker hash
from its already bound plans. The helper verifies actual copied authorization,
plan, producer source, invocation, samples and terminal records against those
values. Paths inside plans describe the original invocation; copied descriptor
paths may differ. This is consistency under an external trusted inventory, not
cryptographic authentication of an owner or reviewer.

Association and per-arm coverage are joined by the exact raw sample hash.
`verified_capture_coverage` requires observed brackets and gaps, stable counters,
the producer/job association, owned Windows cleanup and a complete uncancelled
terminal record. A Windows JobEmpty receipt never proves remote process exit.
No I/O rates, causal bottleneck diagnosis or quality/adoption score is computed.
Supplemental diagnostic failures do not silently become resource successes;
their availability and the primary comparison decision remain separate fields.

## Validation scope

The 37 adapter tests use explicitly synthetic plans, native reports and captures.
Their legacy grader/catalog bytes are preserved solely as fixtures; actual v2
runtime uses the separately pinned newer grader/catalog and needs fresh real
quality receipts. Seven additional cross-component tests use the real I/O helper
with synthetic trusted copies, covering identity derivation, untrusted paths,
code hash checks and snapshot reuse. These tests do not demonstrate hardware
performance, deployed configuration, successful rollback or Goal completion.

Run the focused adapter suite from this directory with the existing Python:

```sh
python3 -B -m unittest discover -s tests -p test_field_assessment_assemble.py
```

Run the I/O integration suite from the enclosing candidate directory:

```sh
python3 -I -B integration-tests/test_assessment_io_integration.py
```
