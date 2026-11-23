# Observed startup diagnostic and restoration, 2026-11-16

One explicitly authorized, unchanged-baseline startup diagnostic completed on the
EVO-X3, followed by restoration of the original service. This is a real host
observation, separate from the 21 synthetic tests in the original source archive.
The four original archive files remain unchanged: their deployment wording
records the earlier, pre-execution snapshot. The machine-readable
[observed evidence](observed-outcome.json) retains measurement scope and source
hashes; it omits private paths, identifiers and authorization data.

## What actually ran

After one successful authentication, the prepared automatic chain started its
watcher, observed durable readiness, and released the already-approved diagnostic
without another manual handoff. The
[Windows child-environment repair](../../powershell-child-environment.md)
describes the earlier GUI failure and its separate no-execution checks.

The diagnostic used the unchanged prefill-512 baseline profile and worker
`69edcd28bb1e6859501fb1ef3523b8befa4fe62061b82f6bb35cc3046fbd1550`.
It observed native startup readiness and approximately 10 seconds of idle time,
then cleaned up. It made no inference API workload request. Loading the model,
initializing the GPU/runtime and engine-internal warmup remain possible; this is
not a claim of no GPU computation or internal model execution.

| Observed interval | Seconds | Meaning |
| --- | ---: | --- |
| Startup wait | 11.631659 | Launch toward verified native readiness; not pure model-weight I/O time |
| Idle observation | 10.014912 | The short post-readiness interval |
| Worker total | 23.089064 | Worker execution, including cleanup and finalization |
| Local supervisor total | 60.395673 | Watch/release/owner-result observation; excludes authentication |

The supervisor interval is **not measured production outage duration**. The
worker, release child and watcher returned exit code 0. The supervisor recorded
one verified release, no retry and no errors. The owner reported completed
maintenance and verified unit restoration at 04:17:56 UTC; the supervisor finished
at 04:17:58 UTC. That supervisor result deliberately did not claim independent
restoration verification.

## Preserved resource evidence

The worker saved 111 resource samples and 223 observation rows: one fresh startup
anchor, 111 acquired observations before evaluation, and 111 matching passed guard
results. The startup anchor and all preserved samples reported `pswpout = 108`.
No rejected guard result or thermal pause was recorded in this diagnostic. The
largest sample elapsed-time gap was approximately 0.888103 seconds. An independent
review matched all 111 observation/verdict pairs and recomputed their numeric
guard limits successfully. No actual rejected sample occurred, so preservation
of rejected observations remains verified by synthetic tests only.

Observed available host memory ranged from 61,333,704,704 to 63,270,277,120 bytes.
The selected GPU's reported edge temperature ranged from 31 to 38 degrees Celsius.
GPU memory counter ranges are preserved in the JSON; they span startup, the idle
interval and cleanup and are not an isolated steady-state usage measurement.
These samples do not measure CPU temperature or SSD I/O rate. The final worker
kernel-error pattern scan reported `clear`, which does not mean there were no
kernel events or prove long-term stability.

The older pre-diagnostic snapshot at 03:30:17 UTC reported `pswpout = 106`; the
post snapshot at 04:18:59 UTC reported 108. That 48-minute 42-second interval cannot
attribute the difference to this diagnostic. The diagnostic's own fresh anchor
and preserved samples are the relevant evidence for its guard outcome. This
successful run does not recover the missing triggering value from the earlier
failed comparison.

## Restoration and evidence limits

A separate read-only post-operation capture at 04:18:59 UTC confirmed all 19
protected content hashes, the original unit's `active/exited/success` state, and
the original native baseline arguments and executable metadata. The native PID
and process-start identity changed, as expected after restart. The active
configuration's content was identical, while its inode and modification time
changed; this is not a claim that every file's metadata was preserved.

A later unprivileged collection at 04:21:51 UTC found the temporary auth, worker
and recovery units absent/inactive, no temporary measurement listeners, and no
owned-work-path match among 464 visible process command lines. This is a scoped
process search, not proof about every possible descendant. The collector obtained
17 fixed files, including the diagnostic startup-ready record. The transient
server-ready marker was absent at post-collection; the retained startup-ready
record and pinned worker path record the earlier readiness observation. Its
removal timing was not captured.

Four privileged coordinator records and the consumed-gate record could not be
read because of permissions. They remain explicitly unavailable. The owner
restoration report and independently captured post-state therefore support
separate, bounded claims; missing coordinator records are not treated as read.
Neither file/process capture sent an inference API request or tested a generated
answer. A separate read-only `GET` to the existing backend slots endpoint returned
HTTP 200 and one idle slot at 04:24:07 UTC. This was a point-in-time API observation;
it sent no inference `POST`, changed no service and recorded no credential. It is
not a generated-answer or workload test.

## Goal status and next use

This observation demonstrates the approved single-authentication automatic path,
one baseline startup/idle interval and independently observed return to the
original unit/process/configuration state. It does **not** establish optimization,
new coding-task quality, a reproducible full kit, general stability or Goal
completion. `benchmark_trials` remains 0; `comparison_complete`,
`quality_accepted` and `goal_completed` remain false.

A later comparison still requires its own frozen compatible plan, complete
measurements and independent quality assessment. This note neither authorizes a
new maintenance window nor changes the preserved evidence from previous failures.
