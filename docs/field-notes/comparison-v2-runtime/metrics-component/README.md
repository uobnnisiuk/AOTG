# Proxy-observed tool-result return interval (isolated source candidate)

This component extends the reviewed PR29 proxy. It has not been installed in a
runtime, invoked against an inference service or measured on a model task.

## Exact observable boundary

A source event is a completed streaming response with `finish_reason=tool_calls`,
valid bounded tool-call IDs, `[DONE]` and a successful final proxy write/flush.
The start timestamp is taken after that flush. The end timestamp is taken after
the **next admitted request body** has been read completely, before JSON parsing
and forwarding. Matching `role=tool` messages must contain the source call's
`tool_call_id` exactly once. Both timestamps use the same proxy monotonic clock,
relative to proxy construction. The interval includes client processing,
serialization and local transport after the response completes. It may exclude
tool execution which started before the final response flush. It is neither
pure tool execution time nor tool-result-to-model-answer latency.

Each match records its source request index, source response hash, domain-separated
ID digest, start/end and seconds. IDs, function names, arguments, prompt text,
result content and credentials are not retained by this observer. It preserves
raw per-request observations only: no average, task-wide scalar, tolerance or
performance adoption rule is supplied.

## Missing and ambiguous observations

Stream fragments are combined by numeric call index; at most32 calls per response
and256 UTF-8 bytes per ID are observed. Excess, missing or malformed IDs and
reused IDs are unavailable, never silently truncated into a match. The next
request consumes the pending source exactly once, including malformed/truncated
requests; a later request cannot retroactively fill the missing interval.
Duplicate matching result messages are ambiguous. Full-history results for older
calls are not counted again. Concurrent pre-admission requests remain existing
proxy refusals, not fabricated task metrics. The final response's calls without a
following request remain unmatched in the closed capture. The separate offline
`tools/tool_roundtrip_diagnostics.py` helper reconciles all source calls against
adjacent requests, rather than counting only successful matches.

The nested `tool_roundtrip` artifact version1 does not change the PR29 v2
opened/closed sequence or rejection contract. Original TTFT, usage, server timings,
response hashes and request counters are preserved. A transport wrapper can call
`mark_capture_incomplete()` for a pre-HTTP refusal; this sets the existing closing
record's incomplete/error state without fabricating an HTTP status or request.
Calls after capture closure raise instead of mutating a sealed success. The
wrapper must surface that failure and retain its own fixed refusal reason separately.

## Validation and limits

34 local tests passed: the unchanged12 PR29 proxy cases plus9 deterministic
observer cases,3 local synthetic HTTP/lifecycle cases and10 offline diagnostic
validation cases. The loopback case feeds real proxy records through the helper. They cover fragmented
IDs, parallel result batches, history, duplicates/reuse, malformed/missing IDs,
missing requests, failed streams, monotonic inversion, privacy and refusal closure.
No GPU, model, authenticated remote route or production service was contacted.

The preserved actual OpenCode offline fixture includes streamed call IDs and tool
result roles, but its request summary did not retain the incoming `tool_call_id`
fields. That fixture alone does not establish this new matching boundary on the
actual client. If a future approved request lacks matching IDs, this observer
reports unavailable data; it does not substitute event tool duration. The new
observer is therefore source/synthetic-qualified, not a real measured tool result.

Source baseline SHA256:30367863bdb50f83cbdd89e8a442c7c1e204490cfddc7ad60c10e30b43298952.

## Offline interpretation API

`tool_roundtrip_diagnostics(requests)` accepts the request rows returned by the
existing closed v2 capture validator. It independently reconstructs each expected
previous-response call from that response's index/hash and emitted ID digests,
checks exact nested schemas, adjacent partitions and same-clock elapsed arithmetic,
and returns all intervals plus missing/unavailable reasons. Conflicting bindings
raise `ToolMetricError`; missing records and final unanswered calls are incomplete.
No calls produces `not_observed`, not a measured zero. It is bounded to128 requests
and32 calls per response. Even a complete result sets external capture identity,
quality acceptance, task scalar and performance-adoption claims to false; its
caller must separately verify the enclosing source/transport/evidence chain.
