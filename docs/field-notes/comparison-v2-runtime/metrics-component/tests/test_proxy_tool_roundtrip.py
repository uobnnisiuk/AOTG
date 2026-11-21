"""Synthetic transport-only metric tests; no inference service or model is used."""
import hashlib
import json
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aotg.field_proxy import MeasurementProxy, _ToolCallIds, _ToolRoundtrips
from tools.assemble_field_evidence import EvidenceError, request_capture
from tools.tool_roundtrip_diagnostics import tool_roundtrip_diagnostics


class MetricTests(unittest.TestCase):
    def setUp(self):
        self.tracker = _ToolRoundtrips(100)

    def response(self, identities=("call-a",), *, index=0, status="completed", finish="tool_calls", at=101):
        metric = self.tracker.begin()
        self.tracker.received(metric, {"messages": [{"role": "user", "content": "private"}]}, 100.5)
        calls = _ToolCallIds()
        calls.observe([{"index": i, "id": identity, "function": {"name": "secret-name", "arguments": "private-argument"}}
                       for i, identity in enumerate(identities)])
        result = {"index": index, "status": status, "finish_reason": finish, "response_sha256": "a" * 64}
        self.tracker.finished(metric, result, calls, at)
        return metric

    def receive(self, identities, at=103.5):
        metric = self.tracker.begin()
        self.tracker.received(metric, {"messages": [{"role": "tool", "tool_call_id": identity,
                                                    "content": "private-result"} for identity in identities]}, at)
        return metric

    def test_exact_monotonic_boundary_and_hash_binding(self):
        source = self.response()
        metric = self.receive(["call-a"])
        self.assertEqual(metric["matches"][0]["seconds"], 2.5)
        self.assertEqual(metric["matches"][0]["source_request_index"], 0)
        self.assertEqual(metric["matches"][0]["source_response_sha256"], "a" * 64)
        self.assertEqual(metric["matches"][0]["tool_call_id_sha256"], source["response_calls"][0]["tool_call_id_sha256"])
        self.assertEqual(metric["unmatched_calls"], [])
        stored = json.dumps([source, metric])
        for secret in ("call-a", "private", "secret-name"):
            self.assertNotIn(secret, stored)

    def test_fragmented_stream_ids_and_parallel_batch(self):
        metric = self.tracker.begin()
        calls = _ToolCallIds()
        calls.observe([{"index": 0, "id": "call-"}, {"index": 1, "id": "other"}])
        calls.observe([{"index": 0, "id": "a"}, {"index": 1, "function": {"arguments": "ignored"}}])
        self.tracker.finished(metric, {"index": 0, "status": "completed", "finish_reason": "tool_calls", "response_sha256": "b" * 64}, calls, 101)
        observed = self.receive(["call-a", "other"])
        self.assertEqual([x["seconds"] for x in observed["matches"]], [2.5, 2.5])
        self.assertEqual(observed["unmatched_calls"], [])

    def test_historical_results_are_not_recounted(self):
        self.response()
        first = self.receive(["call-a"])
        calls = _ToolCallIds()
        calls.observe([{"index": 0, "id": "call-b"}])
        self.tracker.finished(first, {"index": 1, "status": "completed", "finish_reason": "tool_calls", "response_sha256": "b" * 64}, calls, 104)
        second = self.receive(["call-a", "call-b"], 106)
        self.assertEqual(len(second["matches"]), 1)
        self.assertEqual(second["matches"][0]["source_request_index"], 1)
        self.assertEqual(second["matches"][0]["seconds"], 2)

    def test_missing_result_not_joined_to_later_request(self):
        self.response()
        absent = self.receive([])
        self.assertEqual(absent["unmatched_calls"][0]["reason"], "tool_result_missing")
        later = self.receive(["call-a"], 108)
        self.assertEqual(later["matches"], [])
        self.assertEqual(later["expected_calls"], [])

    def test_duplicated_result_or_reused_call_is_unavailable(self):
        self.response()
        duplicate = self.receive(["call-a", "call-a"])
        self.assertEqual(duplicate["matches"], [])
        self.assertEqual(duplicate["unmatched_calls"][0]["reason"], "tool_result_ambiguous")
        reused = self.response(index=2, at=104)
        self.assertIn("tool_call_id_reused", reused["errors"])
        self.assertEqual(self.tracker.pending, [])

    def test_missing_invalid_oversized_or_ambiguous_outbound_ids(self):
        examples = [[{"index": 0}], [{"index": 0, "id": 123}], [{"index": True, "id": "x"}],
                    [{"index": 0, "id": "x" * 257}], [{"index": 0, "id": "x"}, {"index": 1, "id": "x"}],
                    [{"index": i, "id": str(i)} for i in range(33)]]
        for items in examples:
            tracker = _ToolRoundtrips(100)
            metric, calls = tracker.begin(), _ToolCallIds()
            calls.observe(items)
            tracker.finished(metric, {"index": 0, "status": "completed", "finish_reason": "tool_calls", "response_sha256": "a" * 64}, calls, 101)
            self.assertEqual(metric["response_status"], "incomplete")
            self.assertTrue(metric["errors"])
            self.assertEqual(tracker.pending, [])

    def test_failed_response_or_missing_next_body_never_creates_duration(self):
        self.response(status="timeout")
        self.assertEqual(self.receive(["call-a"])["matches"], [])
        self.response(("call-b",), index=2)
        metric = self.tracker.begin()
        self.tracker.finished(metric, {"index": 3, "status": "failed", "finish_reason": None, "response_sha256": "c" * 64}, _ToolCallIds(), None)
        self.assertEqual(metric["matches"], [])
        self.assertEqual(metric["unmatched_calls"][0]["reason"], "request_body_unavailable")

    def test_unknown_protocol_tool_id_is_missing_not_tool_duration(self):
        self.response()
        metric = self.tracker.begin()
        self.tracker.received(metric, {"messages": [{"role": "tool", "callID": "call-a", "content": "private"}]}, 103)
        self.assertEqual(metric["matches"], [])
        self.assertIn("tool_result_id_missing_or_invalid", metric["errors"])

    def test_monotonic_inversion_cannot_be_accepted(self):
        self.response()
        metric = self.receive(["call-a"], 100.9)
        self.assertEqual(metric["matches"], [])
        self.assertEqual(metric["unmatched_calls"][0]["reason"], "monotonic_order_invalid")


class HTTPMetricTests(unittest.TestCase):
    def test_real_loopback_stream_and_full_history_join_preserve_capture_v2(self):
        requests, records = [], []
        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                if len(requests) == 1:
                    events = [{"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "private-call-",
                        "function": {"name": "secret-tool", "arguments": "private-input"}}]}, "finish_reason": None}]},
                        {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "identifier"}]}, "finish_reason": "tool_calls"}]}]
                else:
                    events = [{"choices": [{"delta": {"content": "42"}, "finish_reason": "stop"}]}]
                for value in [*events, "[DONE]"]:
                    data = value if isinstance(value, str) else json.dumps(value)
                    self.wfile.write(("data: " + data + "\n\n").encode())
                    self.wfile.flush()
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        proxy = MeasurementProxy(("127.0.0.1", 0), upstream=f"http://127.0.0.1:{upstream.server_port}/v1",
            api_key="synthetic-key", model="synthetic-model", max_requests=3, max_tokens=32,
            total_seconds=5, request_seconds=2, record=records.append)
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, proxy)]
        for thread in threads:
            thread.start()
        try:
            for messages in ([{"role": "user", "content": "private-question"}],
                [{"role": "tool", "tool_call_id": "private-call-identifier", "content": "private-answer"}]):
                body = json.dumps({"model": "synthetic-model", "stream": True, "messages": messages}).encode()
                request = urllib.request.Request(f"http://127.0.0.1:{proxy.server_port}/v1/chat/completions", data=body,
                    headers={"Authorization": "Bearer synthetic-key"})
                with urllib.request.urlopen(request, timeout=3) as response:
                    self.assertIn(b"[DONE]", response.read())
        finally:
            for server in (proxy, upstream):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(2)
        attempts, refusals = request_capture(records, 3)
        self.assertEqual(len(attempts), 2)
        diagnostic = tool_roundtrip_diagnostics(attempts)
        self.assertTrue(diagnostic["measurement_complete"])
        self.assertEqual(diagnostic["matched_call_count"], 1)
        self.assertEqual(refusals["rejected_total"], 0)
        metric = attempts[1]["tool_roundtrip"]
        self.assertEqual(len(metric["matches"]), 1)
        self.assertGreaterEqual(metric["matches"][0]["seconds"], 0)
        self.assertEqual(metric["matches"][0]["source_response_sha256"], attempts[0]["response_sha256"])
        self.assertEqual(metric["matches"][0]["tool_call_id_sha256"],
            hashlib.sha256(b"aotg-proxy-tool-call-id-v1\0private-call-identifier").hexdigest())
        for secret in ("private-question", "private-answer", "private-call-identifier", "secret-tool", "synthetic-key"):
            self.assertNotIn(secret, json.dumps(records))

    def test_transport_refusal_after_sealed_capture_raises(self):
        records = []
        proxy = MeasurementProxy(("127.0.0.1", 0), upstream="http://127.0.0.1:9/v1",
            api_key="synthetic", model="synthetic", max_requests=1, max_tokens=1,
            total_seconds=1, request_seconds=1, record=records.append)
        proxy.server_close()
        before = json.dumps(records)
        with self.assertRaisesRegex(OSError, "already closed"):
            proxy.mark_capture_incomplete()
        self.assertEqual(json.dumps(records), before)

    def test_pre_http_refusal_marks_capture_incomplete_without_fake_request(self):
        records = []
        proxy = MeasurementProxy(("127.0.0.1", 0), upstream="http://127.0.0.1:9/v1",
            api_key="synthetic", model="synthetic", max_requests=1, max_tokens=1,
            total_seconds=1, request_seconds=1, record=records.append)
        proxy.mark_capture_incomplete()
        proxy.server_close()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[-1]["status"], "incomplete")
        self.assertTrue(records[-1]["record_error"])
        self.assertEqual(records[-1]["request_records"], 0)
        with self.assertRaisesRegex(EvidenceError, "capture_or_cleanup"):
            request_capture(records, 1)


if __name__ == "__main__":
    unittest.main()
