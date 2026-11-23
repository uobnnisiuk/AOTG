# Startup diagnostics: preparing unattended restoration and collection

Record cutoff: **2026-11-23 14:06:59 UTC**, before any new production-stop approval
request. Preparation is reviewed; execution remains unapproved.

This follows the startup integration findings with concrete preparation results
from 2026-11-23. A new packet was materialized locally as **PROPOSED_UNAPPROVED**.
The actual release, post-observation and detached-launch default previews all
returned successfully without activation. One isolated input-staging operation
also reported success. No new gate enrollment, production stop, startup trial,
comparison workload or quality evaluation was performed by this preparation.
No new production-stop approval has been requested or granted at this cutoff.

The new route is intended to finish startup observation, restoration, independent
read-only restoration checks and evidence collection after one authentication.
The source, local previews and staging results do not yet prove that complete
unattended route on the host. Existing performance/quality evidence and the
unfinished first-machine completion conditions are unchanged.

## A real filesystem boundary that synthetic paths missed

The actual Windows-mounted preparation files appeared as mode `0777` from WSL,
including files originally created with a `0600` request. The private readers
correctly reject group/other-writable input. A successful temporary-file test on
the WSL filesystem therefore did not establish compatibility with the concrete
Windows-mounted packet.

The fix retains the existing reader checks and mount settings. The original
Windows-side staging packet and its index remain byte-for-byte unchanged. A new
WSL-only directory contains exact authorization and baseline byte copies plus
the collection and post contexts and their index. Its directory mode is `0700`
and all five files are `0600`. Both release and collection reference the same
authorization copy; the launch plan references the private post context, which
references the private collection context and baseline copy. Raw and canonical
hash bindings are preserved across the copies.

Independent readback confirmed the actual two-root packet, private modes and
copy/descriptor bindings. The actual release/post/launch default previews then
passed. This is a narrow storage compatibility fix, not a relaxation of private
input policy or evidence that every Windows mount behaves the same way.

## Acquiring process ownership before executing a preview

Source review found a gap in the older startup stager: a preview child could run
before its parent acquired a pidfd, and the pidfd-acquisition failure path did not
reliably clean up that child. This was a source-level failure path, not an observed
production orphan or a measured service incident.

The new stager uses the already reviewed bounded execution gate from the
comparison stager. A child waits for a private release byte before executing the
preview; the parent obtains its pidfd first. Acquisition failure closes/refuses
the gate and reaps its own child. Unknown numeric process IDs are not treated as
authority to kill another process. The transplanted gate's AST matched the
reviewed donor and 15 independent offline tests passed. The change is confined to
the new stager source; previous sources and saved evidence remain available.

## Reusing the correct schema version

The concrete GUI packet integration exposed another mismatch: the reused
comparison renderer required a version-2 client seed, whereas the existing
startup control transport uses a version-1 seed. Its refusal was a compatibility
finding before activation, not an authentication failure or a reason to replace
the established SSH connection.

A startup-specific, version-1-only renderer now binds the existing startup seed
explicitly. Its change is limited to the required version and rejection label;
the template and route protections are unchanged. Eleven independent offline
tests passed. The actual rendered packet's Windows PowerShell 5 default preview
also exited successfully without approval, an execute switch, SSH or a visible
window. Final independent GUI packet readback verified all 74 bound files, the
exact rendered script and saved default-preview result. This does not silently
accept arbitrary seed versions or exercise the version-2 comparison runtime.

## What was observed, and what remains unproved

At **2026-11-23 13:34:00 UTC**, a bounded unprivileged baseline capture matched
all 19 protected content hashes, the expected native engine executable/argv,
and the original unit state before/after the read. One matching engine was found
among visible executable identities. There were **414 permission-denied process
entries**; this is not a complete inventory of every process. The result describes
that short read interval and does not guarantee state at a later run.

Independent source/integration checks passed 109 offline tests: 75 parent tests,
27 driver tests and seven additional tests joining the actual pinned parent,
driver, flow and read-validator components with fake operations. The bundle
assembler separately passed ten narrow offline tests, including actual WSL
private-file modes and exclusive creation. These counts are not host benchmark
trials. Late persistence requires a failing child result even if a previously
written file says complete; consumers must require the expected bindings, a
timely successful child exit and verified owned-process cleanup together.

The isolated staging operation copied only the fixed new task inputs and ran
read-only default previews. Its saved result reports `staged-readonly-previews-passed`,
owned-job cleanup confirmed, enrollment/release false, and no production change
or inference call. Independent final staging readback passed 31 checks, binding
the exact eight input files plus separate gate source, three previews and one
successful owned job. Remote permission statements come from the fixed producer's
passed assertions; separate stat rows were not emitted. Existing writable-input
warnings were retained, and future execution still requires its frozen inputs to
be read-only. Staging writes new task files; it is distinct from the read-only
checks performed afterward and does not authorize a production stop.

The proposed bounds remain: worker 240 seconds, coordinator work 360, recovery
600, parent drive 1,185, post-observation phase 235, and parent total 1,420.
The post phase reserves 30 seconds for preparation, 50 for each of two read
phases, 90 for collection and 15 for final cleanup. These nested budgets are not
additive outage measurements or a promise of success. Authentication wait is
outside the parent drive clock. Actual startup may perform internal engine
warmup even though this diagnostic contains no inference API workload.

The next completion evidence must come from an explicitly approved new run,
including independent restoration confirmation and preserved collection results.
At this cutoff, this packet has **zero new startup trials, zero comparisons and
zero new quality evaluations**. No prior approval or consumed attempt is reused.
