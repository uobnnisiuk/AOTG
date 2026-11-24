# Startup entry repair and guard-stopped unattended diagnostic — 2026-11-23

This addendum records a local failure after owner authentication. It follows the preparation snapshot in [the unattended preparation note](evo-x3-unattended-preparation-20261123.md); that note's pre-approval cutoff remains historical evidence. The public source reviewed for this addendum was PR38 head `503a13e4db2310fe81911a57838e6f55e9de90c3`.

The detached supervisor exited with a saved `KeyError` refusal before creating its output directory. Its `main()` accessed `watch["limits"]["total_seconds"]`, but the validated startup watch plan contains four fields: prearm 120 seconds, maintenance 360 seconds, recovery 600 seconds and cleanup 60 seconds. They sum to 1,140 seconds; the separate `total_seconds` field does not exist. This is a schema mismatch in local admission, not evidence of a measurement timeout or a host resource failure.

The failing expression precedes output creation, watcher child creation and the remote release path. This supports the local pre-release failure classification. It does not by itself establish the state or remaining lifetime of the separately authenticated remote gate; that requires its own read-only verification. The initial failure did not trigger an automatic retry or another authentication request.

Earlier previews and synthetic tests missed this boundary. The launcher preview called the supervisor's nested helper and release-preview functions, without entering the supervisor's `main()`. The coupled post-processing tests began at the post phase. Their recorded passes remain valid for those paths; they did not establish that the complete production-shaped CLI entry was executable.

The required regression is a default-preview invocation of the actual supervisor `main()` using the exact four-field startup budget shape. It must pass argument parsing and local admission, return the expected preview, and leave the output absent while forbidding child creation, remote transport and writes. The old source should reproduce the `KeyError`. A repaired launcher must use this same entry boundary during its default preview. Any approved execution-prefix test must stop before the first output-directory mutation.

Source provenance: failed supervisor SHA-256 `058ab9cf10d17c4b4976788b8be1d31fe3ebe0b443b05eef062806c621254ce0`; saved refusal stderr SHA-256 `bc1092b2c4f5a17202daf938a55257a2839ea8d1f9985f3e9d793a3be082ba39`. This note claims no completed startup diagnostic, comparison, quality result or independent restoration check from this failed local entry. A source repair and offline validation alone do not authorize or prove another execution.

## Repair and the first release of the approved operation

The repaired supervisor checks the exact four keys, integer types, expected values and sum. Its other AST nodes are unchanged. The launcher changes its supervisor pin and calls the actual supervisor default `main()` instead of only the nested release preview; detach, environment, deadlines and approval logic are unchanged. Three focused tests passed, including six invalid budget shapes. Separate read-only checks reproduced the old `KeyError`, passed the repaired actual default entry, and reached the first-directory sentinel after approval validation without creating a directory or child. The exact continuation plan changed only the local launcher, supervisor and launcher output directory.

The narrow budget admission now uses the actual schema:

```python
expected_limits = {"prearm_seconds": 120, "maintenance_seconds": 360,
                   "recovery_seconds": 600, "cleanup_seconds": 60}
require(set(watch["limits"]) == set(expected_limits)
        and all(type(watch["limits"][key]) is int
                and watch["limits"][key] == value
                for key, value in expected_limits.items())
        and sum(watch["limits"].values()) == HANDOFF_SECONDS,
        "Startup watcher budget differs")
```

`HANDOFF_SECONDS` remains 1,140. The launcher default preview then invokes the
actual supervisor `main()` and requires its non-executing, no-output result; a
helper-only preview is insufficient to cover this boundary.


Before continuation, the failed local process was confirmed absent and its exact saved refusal was bound to the original launch. An independently reviewed read-only observation at 14:40:45 UTC found the authenticated gate unconsumed, no release marker, empty task work and the same 19 protected content hashes, native baseline identity and original unit state. This was point-in-time evidence; the release still performed its own live checks. An exclusive durable continuation intent prevented duplicate admission. It preserved the same owner approval and remote operation and did not enroll another gate.

The corrected local supervisor started at approximately 14:43:45 UTC. The first atomic release followed at approximately 14:43:50 UTC, and the watcher confirmed readiness for the controlled operation at approximately 14:43:53 UTC. This readiness is the controller handshake, not model readiness. No second authentication or agent-to-owner handoff was required after the local continuation.

## Actual startup and automatic post-observation results

The worker reported `stopped`, with **3.605844966 seconds** of worker time and zero benchmark trials or inference API workload. The first arm ran from 14:43:55.029526 to 14:43:58.048633 UTC. Unlike the older missing-trigger record, this journal retained the rejected observation: the fresh global `pswpout` anchor was **203**, and a sample at elapsed **3.421083680 seconds** contained **207**, followed by the unchanged `New swapout or counter reset` rejection. The cause of those four global counter increments is not identified by this observation; it is not proof of OOM, a particular process, or a performance bottleneck. No guard was loosened and the diagnostic was not rerun.

The adjacent samples show the reported GPU memory-used counter rising from 6,869,450,752 to 57,748,824,064 bytes, while the rejected sample still reported 62,441,480,192 bytes of host available memory and zero native-process VmSwap. SwapFree fell by 16,384 bytes. The last separate memory context ended **1.215746 seconds before** the rejected sample; its clean PSI/event counters cannot establish the state at rejection or identify the source of global swapout. The engine log reports automatic expert-cache sizing from 50.17 GiB to 19,705 slots. This supports investigating a bounded cache-size candidate, but its option units, supported bounds and causal effect remain unverified; no numeric configuration or new run is proposed by this note.

The owner reported the original unit restored at 14:44:25.196225 UTC. The separate automatic post path recorded matching protected baseline/native/unit checks, an idle result from the read-only inference API check, and completed bounded collection. Its `post-observations-complete` status explicitly leaves startup success, comparison completion, new quality acceptance and Goal completion false. The startup supervisor's `incomplete-or-failed` status therefore remains appropriate for the stopped diagnostic. The baseline observation was at 14:44:27.749 UTC and the read-only API returned HTTP 200 with one idle slot at 14:44:28.689 UTC. The baseline scan encountered 454 permission-denied process entries. These checks establish the visible native baseline and owned transport results, not absence of every host process or every remote descendant. The supervisor's 38.890527-second record precedes the post phase; neither it nor the separate 3.609947-second post-driver duration is a measured API outage.

Collection attempted all 12 fixed paths and captured ten files totaling **69,166 bytes**. The missing startup-ready record was classified as ungenerated for this stopped terminal state, while the absent transient server-ready record was optional. All required failure evidence was obtained; this is diagnostic evidence coverage, not successful startup. The retained stream contains 17 passing resource rows and 39 observation-journal rows, including the rejected sample and verdict. The independent memory audit verified the 39-row chain as 18 observations, 18 guard verdicts, two contexts and one anchor. Its strict reader correctly reports incomplete because the guard rejected the run; record consistency is not runtime completion. The separate final transport/restoration readback passed 151 independent checks: one release and one readiness publication, all 20 owned Windows jobs exited zero and were empty, direct child reaping and log hashes matched, and all captured bytes were reconstructed from the bounded stream.

The existing restored-service C++/C# results from [the November 16 fixed evidence commit](https://github.com/uobnnisiuk/AOTG/blob/d743ea89783c23b52006f5d85bff4bb8b6244baa/docs/field-notes/evidence/2026-11-16-guard-stop-window.json) remain separate historical results: about 35.454/35.337 seconds, then independent 9/9 and 16/16 fixed-catalog checks and rejected negative controls. No new quality evaluation occurred in this startup diagnostic. Multiple-candidate comparison, causal attribution, sustained stability and reproducible kit completion remain outstanding.
