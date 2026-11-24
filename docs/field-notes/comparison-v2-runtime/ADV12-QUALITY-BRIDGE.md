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
