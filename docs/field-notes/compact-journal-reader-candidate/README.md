# Compact observation journal reader candidate

Read-only source proposal. This is not deployed, not connected to an assessment
adoption gate, and does not authorize a field run. It never opens files or starts
a process. No private or historical runtime data is published with it.

`verify_journal(bytes_or_chunks, expected_run_id=None, expected_sha256=None)`
accepts a bytes object or an iterator yielding nonempty byte chunks of at most
65,536 bytes. Caller-controlled file IO/deadlines remain the caller's job; this
API cannot interrupt a blocked or hostile iterator. Internal buffering is bounded
by one admitted chunk and one partial line. It retains only current sample state,
not the full journal. Output contains fixed reason codes, counts and hashes, not
raw payloads, private exception strings or the run identifier.

Limits are fixed to the reviewed writer/collector contract: 128 MiB input,
60,001 rows, 16,384 bytes per JSONL line; startup/observed 2,048 bytes, compact guard
1,024 bytes, 28,200 primary samples and 2,671 selected context attempts. All line
limits include the newline. `admitted_bytes` and `admitted_prefix_sha256` describe
only the bounded prefix admitted to parsing; `input_sha256` is supplied only when
the iterator reaches EOF. A rejected oversize chunk is not part of that prefix.

The parser rejects duplicate JSON fields at any depth, NaN/infinity (including
float overflow), malformed/non-object JSON, excessive nesting and noncanonical
encoding. The required canonical bytes are the writer's sorted compact JSON,
ASCII escapes and one LF. Legacy pretty/noncompact records are refused rather
than silently rewritten. Each observed line's exact raw bytes, including LF,
are hashed and bound to its guard and selected context. It checks one startup
anchor, unchanged anchor, run identity, consecutive sequence, sample/guard time
labels, phase order and context selection/skip counters. It distinguishes duplicate,
gap, wrong hash, wrong phase, context after rejection, unexpected/unselected context,
missing final guard, missing selected context and partial-line EOF.

Missing/invalid initial anchor measurements are retained as explicit issues: the writer can save a null initial GTT before the guard rejects it. Values are never converted to zero, and an anomalous anchor cannot establish safety.

Helper context may contain expected diagnostic missing values. Its guard/causality
flags must remain null/false and `diagnostic_only` true. The reviewed adapter's
small failure-witness shape is also accepted only as an incomplete terminal record.
A passed guard is a recorded claim: this reader does not rerun resource checks,
validate every metric's scientific meaning or attest process ownership. It does
not establish monotonic sample cadence or temporal overlap from UTC labels.

There is deliberately no `completed` result. Consistent EOF returns
`status=incomplete, record_chain_consistent=true` and
`reason=runtime-completion-not-proven`; a terminal guard rejection, budget stop or
context failure has its own incomplete reason. Missing evidence stays incomplete.
Contradictory/malformed evidence is `refused`. Runtime completion, quality,
authenticated custody, causal attribution, triage same-window qualification and
retry authority remain false for every result. Internal hashes cannot detect a
coherently rewritten journal without an externally trusted digest; the optional
expected input hash can detect a mismatch but does not authenticate its provider.

Example using a caller-owned stream:

```python
result = verify_journal(iter(lambda: stream.read(65536), b""),
                        expected_run_id=expected_run,
                        expected_sha256=externally_pinned_raw_sha256)
```

## Synthetic verification

```sh
python3 -I -S -B /path/to/test_verify_compact_journal.py
```

28 adversarial tests use a public synthetic fixture made by the exact reviewed
writer and fixed helper with fake files, PID identities and clocks. Its UTC labels
are fixed to year 2000. No actual worker results are represented. Provenance is
in `fixture-provenance.json`. Tests cover arbitrary chunk boundaries, byte/row/line
bounds, multi-sample selection state, duplicate keys/sequences, nonfinite values,
missing and tampered references, malformed order, rejected-guard context, expected
missing values and a coherent-rewrite counterexample requiring external authority.
The test script loads only its explicit sibling module and fixture and works
under isolated Python from another directory. Existing writer and original raw
records are unchanged. Integration with trusted collection receipts, evaluator
adoption policy and a real stop/restore/one-collection chain remains separate work.
