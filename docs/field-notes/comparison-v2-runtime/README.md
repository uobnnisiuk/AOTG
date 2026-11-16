# Comparison v2: source archive candidate

This directory preserves an isolated implementation for the EVO/K8 first-machine comparison. It is not an approved execution kit. No live v2 plan has been created, no v2 comparison has run on the host, and the existing production configuration has not been changed by these components. Previous authentication, startup-diagnostic approval, and shorter maintenance approvals cannot authorize this proposed comparison. There is no activation workflow or automatic deployment here. The new execution controller is still being prepared and is deliberately excluded from this archive.

The original first-machine Goal remains incomplete. Earlier observed startup and restoration results are recorded separately in [the startup diagnostic outcome](https://github.com/uobnnisiuk/AOTG/pull/30). They do not validate this larger comparison.

## Components and layout

The relative layout is deliberate. `k8-field-runner-v2.py` loads only its adjacent `runtime` package. The worker and client validate the v2 field schedule and bound every trial to its plan/profile identity. The worker requires a separately approved maintenance coordinator and read-only runtime mounts; it is not itself an isolation or recovery boundary. The client does not control the production service.

`runtime` contains the exact dependency snapshot, including the paired PR23 quality source and 15-case C++ catalog. New quality review and execution receipts are required; earlier nine-case receipts cannot be reused. `tests` uses fake worker/transport/service backends for schedule, budget, cleanup and maintenance behavior.

`io-component` contains the bounded sampler, its lifecycle, and the dedicated Windows job helper. Its proposed 6,255-second sampler/6,275-second job budget is documented in its README. It preserves invocation/source/transport associations; Windows JobEmpty does not establish remote process exit.

`metrics-component` records proxy-observed tool-result return intervals and validates their adjacent-request bindings offline. The interval is not pure tool execution duration. Its separate I/O association helper validates independently trusted captured copies; actual coverage and rates remain separate. No task-wide latency or throughput aggregate or new adoption tolerance is invented.

`assessment-component` assembles evidence, preserving observed failure versus missing evidence and conservative v2 adoption gates. Its existing synthetic adapter fixture deliberately retains its earlier quality/catalog identity. Those manufactured fixture reports test the adapter, not the new runtime grader or actual native correctness. The metrics component also retains an earlier assembler solely as a test dependency for the unchanged proxy-capture contract.

## Proposed budget and acceptance boundary

The source proposal uses four balanced blocks (ABBA/BAAB/BAAB/ABBA), two alternatives and two workloads: 64 scheduled tasks. The 5,400-second coordinator/client total, 5,340-second worker bound, and 600-second recovery bound are finite limits, not a guarantee that all 64 tasks finish. The budget JSON is explicitly unapproved and is not a runtime plan or execution authority.

Adoption uses the coding task's wall time with explicit `metric_gates={}`. Per-request TTFT, native prefill/decode, draft counts and cache observations remain diagnostics with their original meanings. No unapproved numerical tolerance is supplied for them. A global resource stop, incomplete schedule, missing independent quality, failed cleanup or insufficient evidence cannot be treated as a completed successful comparison.

## Validation and reproduction limits

The sources were checked with component-specific offline tests. The core has 21 runtime tests, 22 fake coordinator tests and seven cross-runtime tests; see `CORE-RUNTIME.md` and `integration-tests/README.md`. The metrics component has 34 existing proxy/interpretation tests, including synthetic local HTTP; the I/O association helper adds 23 pure record-validation tests. The I/O producer has 24 synthetic tests and three separately observed harmless Windows job fixtures. These counts do not mean that a full real comparison, long-duration capture, authentication chain or recovery was executed. Component test source and exact dependency bytes are included; detailed private records are excluded.

Run each suite separately from its component directory so intentionally different package snapshots cannot shadow each other. The worker/client tests require Linux/WSL semantics. The native Windows fixture script is explicit opt-in and is not part of these Python tests. No public CI execution claim is made by this archive; an enclosing PR's general checks are a separate result.

`source-index.json` records copied source hashes and any relocation or documentation-only delta. Concrete host plans, addresses, owner paths, credentials, nonces, release records and private assessment receipts are absent. This archive supplies code and reproducible offline checks; future use still needs a fresh reviewed plan, explicit maintenance approval, current host preflight and independently checked results.

The original guard-equivalence test read a private sibling baseline file. The public copy instead compares five reviewed definition fingerprints from raw baseline `cdac8769878976a784bc0008543e376133a86914653b4f0594d2338e3aef653e`. The fixture records the extraction recipe, and the test omits only empty AST `type_params` fields to keep Python 3.11/3.12 structural compatibility. The production worker is unchanged. The public integration pin is updated only for this adapted test; both deltas are listed in the source index.

Relocated verification completed with 175 offline test cases: core 43, cross-runtime seven, metrics and I/O association 57, I/O producer 24, assessment 37, and assessment/I/O integration seven. This includes synthetic loopback and fake service tests, not new inference or host control. The first relocated core run exposed the private-baseline dependency described above; the corrected run passed, and the initial failure is retained privately.
