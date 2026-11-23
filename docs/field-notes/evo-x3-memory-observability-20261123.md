# EVO-X3: comparison-stop investigation and bounded memory context

The approved comparison on 2026-11-23 stopped during its first baseline load
after the global swapout counter increased. No coding arm completed. Production
restoration was independently verified as recorded in
[the comparison field note](evo-x3-comparison-20261123.md). That one-use approval
is consumed. The work below does not authorize another production stop.

## Question and evidence

The immediate question is whether startup arguments or explicit environment
settings explain why an earlier startup diagnostic succeeded and the comparison
stopped. The saved plans, generated baseline configuration, worker source and
engine logs were compared independently.

The baseline profile and pinned engine/Python/dependency inputs match. After
normalizing only the task-specific expert-profile path, the actual engine argv
matches. The generated baseline configuration differs only in three task paths.
Both workers construct an explicit environment rather than inheriting a caller
environment. The environment-building and guard/monitor code matches. Neither
sets `STRATA_FILL_AHEAD`; both engine logs report 256 pairs ahead.

This excludes a detected difference in those saved inputs. It does not establish
identical executions or identify the source of swapout. The worker version,
control/cgroup arrangement, work budget, auxiliary I/O sampling and host state
differ. The actual process environment was not dumped. Engine cache-size messages
are engine estimates, not independent physical-memory measurements. The earlier
successful startup has not been reproduced under the newer conditions.

## Supplemental observation design

The original swapout, temperature, memory and process guards remain the decision
makers. Optional context supplies fixed cgroup memory/swap counters, memory PSI
and selected global reclaim counters. It must follow a flushed passed guard and
accepted primary sample. A rejected guard triggers no optional read.

The initial offline arithmetic assumed every primary sample was spaced by
190 ms. The real worker additionally forces samples at startup and before each
of 64 arms. An independent review identified that omission and also the need to
preserve the existing order: save the observation, evaluate the guard, then save
its verdict. A two-record admission method cannot by itself prove that order.

The runtime adapter therefore uses separate phases, whole-line byte admission,
a hard primary-sample quota and a separate two-second context schedule that is
not reset by forced samples. The intended hard envelope is:

| Item | Limit, including JSON escaping and newline |
|---|---:|
| Primary samples | 28,200 |
| Forced primary samples | 65 |
| Context attempts | 2,671 |
| Initial row | 2,048 bytes |
| Observed row / guard row | 2,048 / 1,024 bytes |
| Context link row | 16,384 bytes |
| Accepted resource row | 2,048 bytes |
| Observation journal total | 59,072 rows / 130,394,112 bytes |
| Accepted resource journal total | 28,200 rows / 57,753,600 bytes |

These are enforced ceilings for the candidate, not predictions of actual file
sizes or permission to run a 64-arm comparison. A line that cannot fit is rejected
rather than truncated or replaced with zero. The full serialized context row is
reserved before optional reads. The larger context cap avoids assuming that a
normal approximately 3 KB context remains that small with unusual counters or
identity errors. A serialized-boundary test found that the initial estimate used
a 1 KiB initial row while the implementation admits 2 KiB. The final total above
includes that extra 1,024 bytes; the earlier conditional estimate is preserved
as history rather than treated as the implemented limit.

## Read-cost calibration on the actual machines

The unchanged context helper was calibrated using real fixed-file reads on K8
WSL and through the existing noninteractive SSH route on EVO. No sudo,
authentication gate, service control, inference request or remote file write was
used. The SSH job exited and its owned Windows job was verified empty.

Each profile used eight warmups followed by 128 timed samples. The two profiles
alternated order each round. The timed region includes reader open, reads and
parsing, reader close and compact JSONL serialization. It excludes import,
pre/post identity checks, durable writes, the worker guard loop and network time.

| Host / read profile | Reads | Median | p95 | Maximum |
|---|---:|---:|---:|---:|
| K8 WSL / worker identity only | 12 | 0.860 ms | 1.004 ms | 1.100 ms |
| K8 WSL / three identity roles | 20 | 1.096 ms | 1.307 ms | 1.371 ms |
| EVO / worker identity only | 12 | 0.467 ms | 1.208 ms | 1.377 ms |
| EVO / three identity roles | 20 | 0.567 ms | 1.306 ms | 1.506 ms |

All 512 timed contexts had no helper errors. The largest standalone context JSONL
was 2,879 bytes on K8 and 2,939 bytes on EVO. Python versions were 3.12.3 and
3.14.4 respectively. Quantiles use nearest rank. Exact values and evidence hashes
are in [the sanitized calibration record](evo-x3-context-overhead-20261123.json).

The three roles intentionally reread the same actual calibration process; they
are not three model processes. An explicit test adapter checks the actual
self-cgroup and substitutes the expected worker label for the helper's binding
check. Accordingly these measurements do **not** verify production worker/cgroup
binding, inference performance or guard-loop delay. They are not a controlled
comparison between the machines and cannot prove worst-case latency. The
helper's userspace checks cannot interrupt a blocking kernel syscall.

For a fresh unprivileged Linux self-read calibration, place
[`calibrate_resource_context.py`](memory-context-candidate/calibrate_resource_context.py)
beside the pinned `resource_context.py` and run:

```sh
python3 -I -S -B calibrate_resource_context.py --self-readonly > private-calibration.json
```

The raw output contains process/cgroup identity and should remain private. The
script itself opens no SSH connection and controls no service. Its userspace
budget is 20 seconds. The actual EVO capture used the same timed loop with a
10-second userspace budget, a 15-second self-alarm, and the existing 30-second
SSH / 45-second local transport-and-cleanup limits.

## Remaining qualification and generalization

The [integration candidate](memory-context-candidate/README.md) passed 64 public
synthetic checks and six private worker-integration checks, independently rerun
with no skips. The tests cover forced samples, a full synthetic work window,
serialization limits, optional-read rejection and the original worker cleanup
path with fake children. They do not prove real systemd restoration or an
unattended restore-and-collection chain for this new candidate. The compact
sequence/hash references also still need a separately qualified reader for
duplicate, missing and tampered records before they can serve as independent
evidence joins.

Seven additional synthetic tests execute the unchanged collector's actual wire
serializer and check exact line/record/byte boundaries, partial writes, simulated
backpressure and deadline rejection. They also exercise a real local-file
collection fixture. Four inventory-shaped serializer cases include the final
130,394,112-byte journal envelope: it produces 350,054,356 wire bytes in 5,032
records, with 264,480,768 total raw bytes including protected metadata rereads.
That leaves 3,954,688 bytes below the existing raw limit. File bodies in the
inventory cases are synthetic zero patterns; these are not valid-model-evidence,
decoder, storage-speed or SSH-throughput tests.

The raw-reader boundary test also found that exactly exhausting the read budget
before the final EOF check yields an incomplete result. One extra budget byte
permits EOF verification. The unchanged collector therefore requires positive
slack for completeness. No safety limit was weakened to avoid that result.

The new tests and reproduction harness are in
[`comparison-collector/test_wire_boundary.py`](comparison-collector/test_wire_boundary.py)
and [`check_inventory_wire.py`](comparison-collector/check_inventory_wire.py),
with [the four-case results](comparison-collector/inventory-serialization-results.json).

The collector has independent raw, wire, line, row and time limits. Passing the
observation arithmetic does not prove every other producer stays below its own
capture limit. In particular, the worker's server-log limit and the collector's
per-log acceptance limit differ. Complete future capture still needs that
producer/collector contract to agree or a documented incomplete result.

The next operational diagnostic must be a separately reviewed and approved
operation, with its own fresh source binding and rollback. Startup, guard timing,
actual worker binding and collection must be checked together before attempting
another optimization comparison. No guard relaxation is justified by the small
calibration timings.

For future environments, the reusable findings are the need to count forced
samples, distinguish pre-guard and post-guard evidence, reserve serialized output
before optional I/O, retain incomplete observations without treating them as
quality evidence, and measure read overhead separately from inference speed.
The existing UOB-50 scope covers this work; no duplicate generalization issue is
needed. Multiple-candidate real measurements, independent model quality,
reproducible kit and application verification remain outstanding.
