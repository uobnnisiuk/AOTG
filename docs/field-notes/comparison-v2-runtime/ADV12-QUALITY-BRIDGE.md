# ADV-12 quality bridge: limited offline candidate (2026-11-25)

This additive test does not edit any historical source-index entry, archived
runtime, fixture, plan, or approved/consumed reservation. It is not an execution
kit or authorization. The candidate is staged only in a temporary directory.

Inputs:
- Archive PR #31 head `69014fd957639a151303594bb26db6859ecb23ba`.
- Main `3a5d85c08c230c6c123da87abc61d21f21dcd2e0`: paired quality.py/catalog;
  artifacts.py is byte-identical to the archived assessment dependency.
- PR #29 head `95159f7c94840e9114a55efc52a494fde5a35be5`: the complete
  quality_gate function text equals the archived assessment function (4,271
  characters). This is a source comparison, not a proof of complete #29
  integration. Both assemblers still require stable toolchain identity.

The separate root test `tests/test_comparison_v2_quality_bridge.py` checks the
exact Git blob identities before staging the finite assessment inventory.
It uses the archive's 32-arm synthetic C++ fixture and separately calls the
current grader for every arm with the trusted reference implementation.
Only UBSan is accepted in this fixture; -ftrapv fallback alone is not a
qualification for ADV-4. Distinct measured preflight timings are required.
The synthetic outer stdout is rebound to each report; the authority's
toolchain remains fixed. Negative controls change compiler hash, flags,
detector mode, probe hash, old grader hash, and the report without rebinding
outer stdout. These must be rejected. The fixture's adoption is synthetic
only; no actual source-review authority or isolation is asserted.

Run on a Linux merge checkout containing the pinned main inputs and archive:
`python -m unittest discover -s tests -p test_comparison_v2_quality_bridge.py -v`.
Uses installed g++ only; Windows does not support the archived reader.
No model, SSH, service, host maintenance, or new dependencies are involved.

Remaining: independent execution/review of this test; C# and the complete
64-arm dual-workload fixture; exact new runtime/metrics/assessment closure
including #29 evaluator, assembler and proxy, fresh source pins and authority
bindings; reject prior receipts at all joins; ADV-4 fallback applicability;
#38 private diagnostic and independent recovery. Existing adoption and resource
thresholds are unchanged. Actual comparison remains 0/64 and Goal incomplete.

## 2026-11-25: current #29 closure compatibility check

The independently accepted mixed 64-arm **synthetic** fixture at #31
`70a46df8f9ef575e768ca55671770b70d11c72a0` is a positive control for
the archived assessment closure only (CI 45489091440, four successful jobs,
Linux bridge test executed). It is not a positive control for current #29.

Source comparison against #29 `95159f7c94840e9114a55efc52a494fde5a35be5`
used the complete three source texts (Git blob identities below; not raw
SHA-256 pins). The archived files are under `assessment-component/`.

| File | Archive blob | #29 blob |
| --- | --- | --- |
| aotg/field_evidence.py | 1d547a18c5ec45080c2a1bb4d2b835d295792b37 | 06bdaef9fb7276679e8aa667937704d6b790a4be |
| aotg/field_proxy.py | b0ccb8bcee3ae6ac2e731aed40db78f7249962de | 3cd5678a70b533b17f41a8348fa479e5c835cbdc |
| tools/assemble_field_evidence.py | dab6787e24e0014fb1cc3a886eb62a3a67b8b676 | 73013ed3161cb9509032f9cf1250a596d1a18e19 |

**Direct substitution is incompatible.** The archived Fixture writes
assessment-policy version 2 with `io_max_records: 6257`. The #29 assembler
(lines 586–590) uses exact dictionary equality against version 1 with
no io_max_records field; even if source identity pins were regenerated,
this input must raise `unreviewed_assessment_policy` before the arm loop.
This is a deterministic source-level counterexample, not a Python execution
result. Changing the fixture to version 1 simply to pass would discard
the later archive contract and is not a valid integration.

Other non-equivalent contracts found by line comparison:

- #29 comparison adds explicit run-wide resource-stop reasons (including
  swapout_change_or_reset and worker_stopped), undeclared evidence and
  trial_stopped uncertainty. Do not regress these by using the archive
  evaluator.
- #29 proxy introduces the idle-handler event, bounded wait_for_handlers,
  shared handler completion and integer refusal status. The wait is not
  capture certification; server_close and the closing record remain
  necessary. Caller behavior and source identity still require validation.
- The archive assembler verifies runtime-v2 plan types, source hashes of
  tool and I/O diagnostics, type-sensitive arm schedule joins including
  comparison_id/block, complete plan and schedule hashes on markers, and
  done profile hash. Its bounded I/O snapshot is parsed once (32 MiB,
  6257 records, 8192 bytes per line), with independently supplied capture
  association and coverage. The #29 assembler lacks these specific checks,
  uses a 4000-record per-call I/O reader, and lacks the two diagnostic
  source pins. Do not remove the archive checks to enable replacement.
- #29 separates worker and client failure observation, permits bound
  client refusal without a surviving worker arm, accepts matching stopped
  or failed worker summary status, and preserves below-minimum elapsed
  failure in the observation ledger without inventing a positive duration.
  Its failure classification requires worker and client capture bindings
  rather than the archive's capture_bound. Preserve both independently
  verified binding obligations; test partial/missing/conflicting evidence.

### Narrow next offline candidate (not implemented or accepted)

Keep all archive files and pins immutable. Stage a separate finite candidate
in a temporary directory, retaining the archived assessment-v2 policy,
diagnostic and marker checks and one-pass I/O association. Use #29's
comparison and proxy source as pinned inputs and port only the identified
failure-observation/binding/elapsed changes into a separate assembler
candidate. Recompute the candidate source identity and all dependent plan,
runner, schedule, authority and fixture bindings before constructing any
synthetic trials; do not re-label old receipts. Do not change resource,
adoption, measurement or execution budgets.

Required controls for that candidate:

1. Exact unmodified #29 assembler + archived policy fails closed (with
   source bindings otherwise valid); the original archive remains a
   separate positive control. No policy downgrade.
2. Fresh 32+32 synthetic arms pass the existing quality and plan joins;
   cross-language receipt and corrupted final C# observation still reject.
   Rebind hashes before each negative case to test semantics, not only
   stale digests. Old identities/receipts reject.
3. Explicit stop with otherwise safe scalar resource values vetoes adoption
   across candidates; undeclared evidence, missing worker arm with bound
   refusal, mismatched independent capture, and zero/sub-minimum elapsed
   preserve the correct incomplete/failure ledger without fabricated trials.
4. Reject wrong marker block/comparison/plan/schedule/profile and unpinned
   diagnostics; retain bounded I/O record/line/byte and association tests.
5. Exercise #29 proxy close with both drained and outstanding handlers,
   bounded timeout, refusal audit and incomplete capture rejection. Check
   the actual staged caller, not a replacement fake that skips closing.
6. Record new source manifest, full changed paths, old and new controls,
   and independent CI/review. Native C# and independent real receipts are
   separate remaining requirements.

This run established only the static incompatibility and finite repair
scope. No new candidate or native execution, no private worker substitution,
no operational permission, and no new comparison measurement. #38 still
requires the original field owner's authorized isolated integration evidence;
0/64 actual comparison arms, root cause undetermined and Goal incomplete.
