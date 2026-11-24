# Bounded post-restoration comparison collection (source candidate)

This component is an **unapproved source-only proposal**, not a deployed collector.
It has no real run plan, nonce, authentication or captured host data. Default
execution of the remote/receiver source prints a local preview. The transport
source has no CLI entry point; its explicit library adapter can use the existing
verified SSH implementation only when connected by the controller. No SSH has
been executed for this component. No inference, service control, package download
or remote write is implemented here. The current
production configuration and earlier evidence are untouched; old approvals do not
authorize a new comparison or this proposed longer collection phase.

The short controller exchange (512 KiB) cannot retrieve all 64 arms and global
resource logs. This separate, read-only phase starts **after a hash-bound owner
result reports restoration**. That report is not independent proof of restoration.
This collector does not invent an independent check or certify model quality.

## Fixed inventory and limits

The inventory contains 517 files, derived without listing a remote directory:

| Role | Count | Per-file maximum |
|---|---:|---:|
| Owner result | 1 | 256 KiB |
| Worker summary / final kernel record | 1 / 1 | 1 MiB / 128 KiB |
| Global resources / resource observations | 1 / 1 | 64 MiB, 30,000 lines / 128 MiB, 60,001 lines |
| Each arm: result, settings, ready, server-ready, done | 64 × 5 | 64 KiB |
| Each arm: config | 64 | 128 KiB |
| Each arm: server and engine private logs | 64 × 2 | 256 KiB each |

The resource JSONL line cap is 16 KiB. Every complete line must be an object on
receipt; partial tails and invalid JSON do not pass. The sender transfers at most
256 MiB of total file reads **including owner/summary pre/post rereads**. The wire
cap is 384 MiB / 6,200 records / 100,000 bytes per line, with raw chunks of at most
64 KiB. Stderr is capped at 256 KiB. A file exceeding its cap is refused, never
reported as a successfully truncated capture. Missing transient server-ready files
remain explicit missing records; earlier readiness is not inferred from absence.
The pinned worker removes global `task/ready.json`, which is not in this inventory,
but does not itself remove arm `server-ready.json`. Removal by its server child is
not established by this source. A missing arm marker currently makes overall
collection incomplete, even if other evidence remains useful. A future policy that
separates optional transient coverage must be reviewed explicitly; collection
status is never quality/adoption status.

Remote collection has a 60-second alarm and monotonic checks. The one Windows SSH
Job is limited to 70 seconds; the local phase is 90 seconds including at most
20 seconds of owned cleanup and local validation. **This 90-second phase is not
automatically included in the 6,410-second handoff or revised 6,455-second
supervisor budget** (the earlier supervisor proposal was 6,425 seconds).
The integrating launcher must permit these bounded files: an inherited 64 MiB
hard file limit cannot save a 128 MiB raw file or 384 MiB wire file. The proposed
512 MiB inherited hard ceiling is compatible only while narrower producer limits
and the supervisor's own 8 MiB stdout/stderr bounds remain enforced.

These are limits, not a claim that the capture finishes in time. Kernel-blocked
filesystem operations are not preempted by ordinary Python deadline checks.
The enclosing launcher/transport must qualify cancellation and the whole process
deadline before real use. Any exhausted deadline or absent terminal evidence is
incomplete. There is no automatic retry.

## Existing sizing evidence (not a capacity guarantee)

The saved 23.089-second startup diagnostic used 118,633 resource bytes / 111 lines
and 209,184 observation bytes / 223 lines. The largest observed resource line was
1,082 bytes, observation line 1,483 bytes. Its two private logs were 1,387 and
7,549 bytes; summary 1,134 bytes. Roughly 0.19-second sampling over 5,340 seconds
suggests about 28,200 resource and 56,400 observation rows. This extrapolation
motivates the bounds but does not prove future size, cadence, network throughput,
complete outage coverage, or stable behavior. The worker's larger log limit is
unchanged; a log above the collector's 256 KiB bound makes collection incomplete.

The old read-only startup payload (SHA-256
`96d494f450706b2edf995ab5036feb3d39e3553122156c912962a0c3ca31b6dc`)
provided the component-wise directory-fd/no-follow and before/after identity
pattern. Its 17-file stdout receipt has SHA-256
`1203e08e44c80c2fae81ed92f29494442fe40553f19141e8e169d2c142df02fa`.
Neither private payload/configuration nor raw data is included here.

## Integration API (not yet connected)

The controller first verifies local source bytes before importing
`collect_comparison.py`; it then loads the exact pinned companion source in
memory, bypassing bytecode caches. It must supply a newly reviewed run context:

- exact run/nonce, UID/GID and canonical remote work root;
- earlier work-directory device/inode observation;
- exact canonical authorization and client-plan digests, raw worker-plan digest;
- the exact 64-row projection of the already validated v2 schedule, including
  index, candidate, comparison, workload, block and profile hash;
- saved owner-result bytes and their raw SHA-256, obtained through the already
  validated controller, with matching authorization/nonce and restoration true;
- the previously validated existing SSH route and fixed transport source hashes.

Call `run_collection(request, seed, owner_result_bytes, exclusive_output_dir,
transport, remote_source=bytes, remote_source_sha256=expected)` once. The callback
receives `payload`, bounded `stdout`/`stderr` sinks, `remote_seconds=60`,
`wall_seconds=70`, `cleanup_seconds=20`, one absolute monotonic `deadline`, and
byte limits. It must pump pipes into the sinks, finish or fail by the deadline,
and perform owned Job cancellation/cleanup even when a sink rejects data. It
must use one existing `OwnedSSH`, not the small control exchange. The callback
is a trusted integration boundary; this module cannot make an arbitrary Python
callback preemptible or prove an assertion came from a real SSH process.

Return exactly these fields:

```text
job_plan_bytes, receipt_bytes, wrapper_returncode,
stdout_sha256, stderr_sha256, payload_sha256
callback_error
```

`callback_error` is null or a bounded operation/type reason. A successful process
exit and `JobEmpty` cannot override a pump/cleanup/deadline failure.
The raw Job plan and receipt must use the existing version-1 Windows SSH schemas.
The receiver checks complete SSH argv including the fixed isolated Python stdin
command, Job directory/files, source/executable pins, raw plan hash, stdout/stderr
and payload hashes, timeout/cancel/exit status and `JobEmpty`.
`JobEmpty` proves the owned Windows Job is empty; **it does not independently
prove remote process exit**. Exit 2 is a valid remote incomplete report, never a
complete capture. Invalid receipts are retained as raw evidence when bounded.

`collector_transport.collect_after_owner_result(receiver, ..., verified_runner=...)`
connects this API without changing the handoff/supervisor. The caller supplies the
receiver and runner modules only after the existing full source-closure verifier
has completed; this adapter imports neither runtime nor source paths. It checks
the owner report through `run_collection` before the first job. The single-use
callback starts one `runner.OwnedSSH`, pumps verified stdin and both output pipes
nonblockingly, reserves cleanup time, and always calls the existing owned Job
close/cancel path after a pump failure. No retry occurs, and missing cleanup
receipt remains incomplete. Exact raw Job plan/receipt bytes are read with
no-follow/regular-file/identity checks and supplied to the independent receiver
validator. No process-group-by-number kill or new transport route is introduced.

The callback tests exercise real **local pipes** with a fake OwnedSSH class and
synthetic Windows Job receipts. They do not start PowerShell, SSH, a Windows Job,
or remote code. Actual inherited-runtime, native transport and whole-chain
qualification remain required. The separately proposed total is the revised
6,455-second controller phase **plus a distinct 90-second collection phase**;
neither an old approval nor this source archive authorizes it.

### Phase driver and parent connection

`collection_phase.py` provides `prepare(plan_path, expected_raw_sha256)` and
`collect_once(prepared, plan_sha256=...)`. The parent binds the driver raw hash,
collection-plan raw/canonical hashes and helper source closure in its new launch
packet/GUI pins. `prepare` is local only and does not require future owner results.
It returns `canonical_sha256` (also `plan_sha256`), `plan_raw_sha256`, the verified
plan/source references, and private prepared runtime data. It creates no output.

The collection plan has artifact `aotg-comparison-collection-plan`, version 1,
and exact fields from `collection_phase.FIELDS`: driver/handoff source and plan,
authorization, raw worker/client plans, three collector source descriptors,
run/nonce/UID/GID/work-root identity, canonical auth/client hashes, separate
output/job roots and `local_seconds: 90`. It is separate from the stop/release
approval schema. No real instance of this plan has been created by these tests.

On collection, the driver rechecks those bytes and the existing runtime closure.
It binds the handoff input-bindings and summary to the exact reviewed controller,
then reads only the referenced `control-NNN/stdout.json` and `association.json`.
Their raw hashes, run, operation, canonical watch/auth identities, work-directory
identity and decoded owner-result bytes must agree with the saved owner result.
The prior control association inherits the reviewed handoff's native receipt
validation; it does not rediscover or independently re-audit all old Job files.
The new collection Job has its own raw native receipt validation.

A failed comparison with a true, matching owner-restoration report can still be
collected for diagnosis. A missing/false report, changed source, path, owner bytes
or consumed output fails before a job is created. The driver creates one exclusive
phase root containing `claim.json`, `phase-result.json` and a `capture/` subdirectory
for the receiver; ordinal raw names are associated with their original labels in
the manifest, not silently materialized into an apparent successful trial tree.

Default and explicit CLI forms are:

```text
python3 -I -S -B /absolute/collector-component/collection_phase.py --plan /absolute/collection.json --plan-raw-sha256 RAW
python3 -I -S -B /absolute/collector-component/collection_phase.py --plan /absolute/collection.json --plan-raw-sha256 RAW --execute-approved-plan-sha256 CANONICAL
```

Default output is `aotg-comparison-collection-phase-preview`, `dry_run:true`,
`remote_actions:false`. The execute flag is a fixed-plan opt-in, not a new grant
of service-control authority. Phase output is `aotg-comparison-collection-phase-result`;
status `complete` still means evidence capture only. The parent separately allows
30 seconds for preparation/spawn, the shared 90-second phase and 15 seconds of
owned-child cleanup: **135 seconds after the existing 6,455-second controller
phase, for 6,590 seconds total**. Authentication and earlier validation are outside
that origin. These are unapproved source budgets, not observed real runtimes.
The driver uses a fresh, independently verified runtime import entrance because
the original handoff loader correctly refuses consumed handoff output.
The optional `--parent-deadline-monotonic` argument is the same local monotonic
clock used by the supervising child controller. It can only shorten the phase:
`collect_once(..., deadline=...)` uses the earlier of that cutoff and its own
entry plus 90 seconds, then forwards the same cutoff to receiver and transport.
An expired or nonfinite parent cutoff refuses before any new Job.

Pinned source/plan files may live on the existing Windows filesystem, where
emulated POSIX mode bits do not prove an ACL. They still require exact hashes,
current UID, regular/single-link/no-follow files and before/after identity. Private
handoff evidence under Linux retains the stricter non-group/world-writable check.
The new dedicated Windows Job directory is checked by path/UID/no-follow and
exclusive creation; no claim about changing or proving Windows ACLs is made.

The sender uses only planned paths opened component-by-component with directory
fds and `O_NOFOLLOW`; files must be regular, single-link, expected UID/GID and
not group/world writable. It verifies the run-root device/inode and owner/worker
identity before capture, file metadata before/after each read, and protected
root/task/owner/summary metadata and content hashes afterward. `remote_written`
means no explicit remote writes; ordinary read-atime/cache effects are not denied.

The local receiver uses a new exclusive 0700 directory, 0600 files and ordinal
names. Partial files stay `.partial`; only verified complete files become `.raw`.
Missing/unattempted indices, partial hashes, before/after metadata and reasons are
retained. Overall `complete` means bounded collection and transport association
only. `independent_restoration_verified`, `remote_process_exit_verified`,
`quality_accepted` and `adoption_accepted` remain false. Config/log bodies may
contain private paths and must remain private; never copy this output to GitHub.

## Local validation

Run the standalone synthetic suite with an explicitly supplied checkout path:

```text
python3 -I -S -B /absolute/collector-component/test_collector.py -v
python3 -I -S -B /absolute/collector-component/test_collector_transport.py -v
python3 -I -S -B /absolute/collector-component/test_collection_phase.py -v
python3 -I -S -B /absolute/collector-component/collect_comparison.py
python3 -I -S -B /absolute/collector-component/collector_remote.py
```

The suite uses temporary local files, mocked streaming transport and synthetic
Job receipts. It covers fixed inventory, missing files, no-follow links/FIFO,
ownership/mode, changing files/directories, row/byte budgets, incomplete tails,
protected records, malformed wire/JSON, spoofed hashes/routes, absent cleanup,
deadlines, exclusive output and no retry after callback failure. It does not
execute the remote payload through SSH or qualify the future callback, full
controller chain, physical resources, inference or restoration. Source review,
integration qualification, concrete budgets/plans and appropriate owner approval
remain prerequisites for real collection.

Phase-driver unit fixtures substitute a synthetic handoff verifier and runner,
while exercising the real collection-plan/hash/control-record joins. They do not
replace the existing handoff's own closure tests or claim actual whole-chain
qualification. No live callback, concrete approved plan, owner report or physical
resource data was fabricated as part of this source work.
