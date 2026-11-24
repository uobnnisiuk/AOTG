"""Offline-only, conditional upper-bound arithmetic for PR #38 memory context.

No sampling, file access, network, worker imports, system changes, or permissions.
A passing calculation NEVER authorizes a runtime integration or a new field run.
Run: python3 -I -S -B capacity_envelope.py --self-test
"""
import json
import sys
import unittest
from dataclasses import dataclass

MIB = 1024 * 1024


def ceil_div(numerator, denominator):
    if type(numerator) is not int or numerator < 0 or type(denominator) is not int or denominator <= 0:
        raise ValueError("invalid nonnegative integer ratio")
    return (numerator + denominator - 1) // denominator


@dataclass(frozen=True)
class Envelope:
    # 5,340 s is the reviewed work-window assumption, NOT the full 6,590 s
    # field authorization including restoration/collection. Other phases need
    # their own assessment; extension is NOT implicitly covered here.
    window_ms: int = 5_340_000
    primary_min_period_ms: int = 190
    context_min_period_ms: int = 2_000
    primary_rows_per_tick: int = 2
    primary_fixed_rows: int = 1
    primary_forced_ticks: int = 0
    primary_hard_tick_quota: int = 0
    primary_guard_max_line_bytes: int = 0
    primary_max_line_bytes: int = 2_048
    context_max_line_bytes: int = 4_096
    other_raw_max_bytes: int = 128 * MIB
    other_file_count: int = 516  # 517 total inventory, one observations file
    metadata_wire_max_per_message: int = 4_096
    observations_row_cap: int = 60_001
    observations_byte_cap: int = 128 * MIB
    total_raw_byte_cap: int = 256 * MIB
    wire_record_cap: int = 6_200
    wire_byte_cap: int = 384 * MIB
    wire_chunk_bytes: int = 65_536
    helper_max_reads: int = 24
    helper_max_raw_bytes: int = 256 * 1024
    helper_userspace_ms: int = 50


def calculate(e=Envelope()):
    """Upper bounds on event counts. Conditional per-line caps MUST be enforced.

    ceil(window/period)+1 deliberately budgets both starting and trailing ticks.
    Even with a within-cap result, any unenforced assumption means INCOMPLETE.
    """
    fields = vars(e)
    if any(type(v) is not int or v < 0 for v in fields.values()):
        raise ValueError("invalid-envelope-field")
    if not all((e.primary_min_period_ms, e.context_min_period_ms,
                e.wire_chunk_bytes, e.primary_rows_per_tick)):
        raise ValueError("invalid-envelope-period-or-rows")
    primary_ticks = ceil_div(e.window_ms, e.primary_min_period_ms) + 1
    primary_ticks += e.primary_forced_ticks
    if e.primary_hard_tick_quota:
        if e.primary_hard_tick_quota < primary_ticks:
            raise ValueError("hard-quota-below-cadence-bound")
        primary_ticks = e.primary_hard_tick_quota
    context_ticks = ceil_div(e.window_ms, e.context_min_period_ms) + 1
    primary_rows = primary_ticks * e.primary_rows_per_tick + e.primary_fixed_rows
    observation_rows = primary_rows + context_ticks
    observations_bytes = (primary_rows * e.primary_max_line_bytes
                          + context_ticks * e.context_max_line_bytes)
    if e.primary_guard_max_line_bytes:
        if e.primary_rows_per_tick != 2:
            raise ValueError("split-line-caps-require-two-primary-rows")
        observations_bytes = (e.primary_fixed_rows * e.primary_max_line_bytes
            + primary_ticks * (e.primary_max_line_bytes + e.primary_guard_max_line_bytes)
            + context_ticks * e.context_max_line_bytes)
    total_raw_bytes = observations_bytes + e.other_raw_max_bytes
    inventory_files = e.other_file_count + 1
    # Each present file adds at most one rounding chunk above the aggregate.
    max_chunks = ceil_div(total_raw_bytes, e.wire_chunk_bytes) + inventory_files
    # open + close per file, one open event and one final result.
    max_wire_records = max_chunks + 2 * inventory_files + 2
    # Base64 of many chunks: <=4*ceil(all raw/3) + 3 per chunk.
    max_wire_bytes = (4 * ceil_div(total_raw_bytes, 3) + 3 * max_chunks
                      + e.metadata_wire_max_per_message * max_wire_records)
    breaches = []
    for name, used, cap in (
        ("observations_rows", observation_rows, e.observations_row_cap),
        ("observations_bytes", observations_bytes, e.observations_byte_cap),
        ("total_raw_bytes", total_raw_bytes, e.total_raw_byte_cap),
        ("wire_records", max_wire_records, e.wire_record_cap),
        ("wire_bytes", max_wire_bytes, e.wire_byte_cap),
    ):
        if used > cap:
            breaches.append(name)
    return {
        "artifact": "aotg-memory-context-capacity-envelope", "version": 1,
        "basis": "conditional-source-only-not-runtime-qualified",
        "primary_ticks": primary_ticks, "context_ticks": context_ticks,
        "primary_rows": primary_rows, "observations_rows": observation_rows,
        "observations_bytes": observations_bytes,
        "total_raw_bytes": total_raw_bytes,
        "wire_records_upper": max_wire_records,
        "wire_bytes_upper": max_wire_bytes,
        "context_raw_read_bytes_upper": context_ticks * e.helper_max_raw_bytes,
        "context_read_calls_upper": context_ticks * e.helper_max_reads,
        "context_userspace_budget_ms_sum": context_ticks * e.helper_userspace_ms,
        "breaches": breaches,
        # False even on arithmetic PASS: the live producer does not currently
        # enforce these tighter producer-line/interval/other-raw/wire-overhead
        # assumptions, the private integration is not independently verified,
        # and blocked syscalls are not bounded by the userspace timer.
        "runtime_qualified": False,
        "status": "capacity-exceeded" if breaches else "incomplete-unverified-assumptions",
        "required_evidence": [
            "enforce_minimum_primary_and_context_sampling_periods_in_private_worker",
            "fail_closed_on_primary_or_context_serialized_line_cap_excess",
            "enforce_other_file_raw_total_and_wire_metadata_overhead_caps",
            "measure_guard_interval_and_context_read_overhead_in_isolated_worker",
            "independently_verify_guard_reject_zero_context_reads_and_cleanup",
            "recompute_for_every_additional_phase_outside_5340_second_window",
        ],
    }


class EnvelopeTests(unittest.TestCase):
    def test_prior_1hz_counterexample_exceeds_rows(self):
        from dataclasses import replace
        result = calculate(replace(Envelope(), context_min_period_ms=1000))
        self.assertEqual((result["primary_ticks"], result["context_ticks"]), (28107, 5341))
        self.assertEqual(result["observations_rows"], 61556)
        self.assertIn("observations_rows", result["breaches"])
        self.assertEqual(result["status"], "capacity-exceeded")

    def test_two_second_candidate_is_conditional_not_approved(self):
        result = calculate()
        self.assertEqual(result["observations_rows"], 58886)
        self.assertEqual(result["observations_bytes"], 126068736)
        self.assertFalse(result["breaches"])
        self.assertEqual(result["status"], "incomplete-unverified-assumptions")
        self.assertIs(result["runtime_qualified"], False)
        self.assertEqual(result["context_userspace_budget_ms_sum"], 133550)

    def test_faster_original_interval_exceeds_rows(self):
        from dataclasses import replace
        result = calculate(replace(Envelope(), primary_min_period_ms=150))
        self.assertIn("observations_rows", result["breaches"])

    def test_actual_collector_16k_line_cap_cannot_prove_byte_fit(self):
        from dataclasses import replace
        result = calculate(replace(Envelope(), primary_max_line_bytes=16384))
        self.assertIn("observations_bytes", result["breaches"])

    def test_context_line_and_other_files_must_be_bounded(self):
        from dataclasses import replace
        self.assertIn("observations_bytes", calculate(replace(Envelope(), context_max_line_bytes=16384))["breaches"])
        self.assertIn("total_raw_bytes", calculate(replace(Envelope(), other_raw_max_bytes=160 * MIB))["breaches"])

    def test_wire_overhead_and_record_budget_fail_closed(self):
        from dataclasses import replace
        self.assertIn("wire_bytes", calculate(replace(Envelope(), metadata_wire_max_per_message=16384))["breaches"])
        self.assertIn("wire_records", calculate(replace(Envelope(), wire_record_cap=5200))["breaches"])

    def test_invalid_parameters_rejected(self):
        from dataclasses import replace
        for e in (replace(Envelope(), primary_min_period_ms=0),
                  replace(Envelope(), window_ms=-1),
                  replace(Envelope(), context_min_period_ms=True)):
            with self.assertRaises(ValueError):
                calculate(e)

    def test_no_runtime_success_possible_from_arithmetic(self):
        from dataclasses import replace
        for e in (Envelope(), replace(Envelope(), context_min_period_ms=1000)):
            result = calculate(e)
            self.assertFalse(result["runtime_qualified"])
            self.assertNotEqual(result["status"], "passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    elif not sys.argv[1:]:
        print(json.dumps(calculate(), sort_keys=True, indent=2))
    else:
        raise SystemExit("usage: capacity_envelope.py [--self-test]")
