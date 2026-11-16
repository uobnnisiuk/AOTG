"""Offline validation of recorded proxy boundaries; no service or model."""
import copy
import unittest

from aotg.field_proxy import _ToolCallIds, _ToolRoundtrips
from tools.tool_roundtrip_diagnostics import ToolMetricError, tool_roundtrip_diagnostics


def records(tool_result_ids=("private-id",), *, final_calls=False):
    tracker = _ToolRoundtrips(100)
    first = {"index": 0, "status": "completed", "finish_reason": "tool_calls", "sse_done": True,
             "response_sha256": "a" * 64}
    first["tool_roundtrip"] = tracker.begin()
    tracker.received(first["tool_roundtrip"], {"messages": [{"role": "user"}]}, 100.5)
    calls = _ToolCallIds()
    calls.observe([{"index": 0, "id": "private-id"}])
    tracker.finished(first["tool_roundtrip"], first, calls, 101)
    second = {"index": 1, "status": "completed", "finish_reason": "tool_calls" if final_calls else "stop",
              "sse_done": True, "response_sha256": "b" * 64}
    second["tool_roundtrip"] = tracker.begin()
    tracker.received(second["tool_roundtrip"], {"messages": [{"role": "tool", "tool_call_id": item}
                                                           for item in tool_result_ids]}, 103.5)
    calls = _ToolCallIds()
    if final_calls:
        calls.observe([{"index": 0, "id": "another-private-id"}])
    tracker.finished(second["tool_roundtrip"], second, calls, 104)
    return [first, second]


class DiagnosticTests(unittest.TestCase):
    def test_exact_join_keeps_interval_without_task_scalar_or_authority(self):
        result = tool_roundtrip_diagnostics(records())
        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["measurement_complete"])
        self.assertEqual(result["matched_call_count"], 1)
        self.assertEqual(result["intervals"][0]["seconds"], 2.5)
        self.assertFalse(result["external_capture_identity_verified"])
        self.assertFalse(result["quality_accepted"])
        self.assertFalse(result["task_scalar_computed"])

    def test_unreturned_final_call_is_explicitly_incomplete(self):
        result = tool_roundtrip_diagnostics(records(final_calls=True))
        self.assertEqual(result["source_call_count"], 2)
        self.assertEqual(result["matched_call_count"], 1)
        self.assertEqual(result["unmatched_call_count"], 1)
        self.assertEqual(result["unmatched_calls"][0]["reason"], "final_response_without_next_request")
        self.assertFalse(result["measurement_complete"])

    def test_missing_and_duplicate_result_preserve_no_interval(self):
        for ids, reason in [((), "tool_result_missing"), (("private-id", "private-id"), "tool_result_ambiguous")]:
            result = tool_roundtrip_diagnostics(records(ids))
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["intervals"], [])
            self.assertEqual(result["unmatched_calls"][0]["reason"], reason)

    def test_absent_metric_does_not_invent_success_or_zero(self):
        request = records()
        del request[1]["tool_roundtrip"]
        result = tool_roundtrip_diagnostics(request)
        self.assertEqual(result["unmatched_call_count"], 1)
        self.assertEqual(result["matched_call_count"], 0)
        self.assertFalse(result["measurement_complete"])

    def test_source_index_hash_id_boundary_clock_and_interval_tamper_rejected(self):
        mutations = [("source_request_index", 7), ("source_request_index", False),
                     ("source_response_sha256", "c" * 64), ("tool_call_id_sha256", "d" * 64),
                     ("response_completed_seconds", .9), ("seconds", 2.4),
                     ("tool_result_received_seconds", 3.4)]
        for key, value in mutations:
            rows = records()
            rows[1]["tool_roundtrip"]["matches"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ToolMetricError):
                tool_roundtrip_diagnostics(rows)
        for key in ("clock", "boundary"):
            rows = records()
            rows[1]["tool_roundtrip"][key] = "different"
            with self.assertRaises(ToolMetricError):
                tool_roundtrip_diagnostics(rows)

    def test_partition_or_adjacency_cannot_drop_missing_call(self):
        rows = records()
        rows[1]["tool_roundtrip"]["matches"] = []
        with self.assertRaisesRegex(ToolMetricError, "partition"):
            tool_roundtrip_diagnostics(rows)
        rows = records()
        rows[1]["tool_roundtrip"]["expected_calls"] = []
        with self.assertRaisesRegex(ToolMetricError, "adjacent"):
            tool_roundtrip_diagnostics(rows)

    def test_incomplete_stream_and_boolean_index_cannot_support_match(self):
        rows = records()
        rows[0]["status"] = "failed"
        with self.assertRaisesRegex(ToolMetricError, "not_complete"):
            tool_roundtrip_diagnostics(rows)
        rows = records()
        rows[0]["index"] = False
        with self.assertRaises(ToolMetricError):
            tool_roundtrip_diagnostics(rows)

    def test_request_bound_and_unknown_fields_fail_closed(self):
        with self.assertRaisesRegex(ToolMetricError, "request_limit"):
            tool_roundtrip_diagnostics([{}] * 129)
        rows = records()
        rows[1]["tool_roundtrip"]["untrusted_field"] = True
        with self.assertRaisesRegex(ToolMetricError, "schema"):
            tool_roundtrip_diagnostics(rows)

    def test_duplicate_matches_or_impossible_count_rejected(self):
        rows = records()
        rows[1]["tool_roundtrip"]["matches"] *= 2
        with self.assertRaises(ToolMetricError):
            tool_roundtrip_diagnostics(rows)
        rows = records()
        rows[1]["tool_roundtrip"]["tool_result_message_count"] = 0
        with self.assertRaises(ToolMetricError):
            tool_roundtrip_diagnostics(rows)

    def test_no_calls_is_not_a_measured_zero(self):
        self.assertEqual(tool_roundtrip_diagnostics([])["status"], "not_observed")
        rows = records()
        only = copy.deepcopy(rows[1])
        only["index"] = 0
        only["tool_roundtrip"]["expected_calls"] = []
        only["tool_roundtrip"]["matches"] = []
        value = tool_roundtrip_diagnostics([only])
        self.assertEqual(value["status"], "not_observed")
        self.assertFalse(value["measurement_complete"])


if __name__ == "__main__":
    unittest.main()
