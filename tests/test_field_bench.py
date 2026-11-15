import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from aotg.field_bench import measure_chat


class FieldBenchTest(unittest.TestCase):
    def request(self, events, *, status=200, delay=0, timeout=2, raw=None, limit=4096):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(status)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                try:
                    if raw is not None:
                        for part in raw:
                            self.wfile.write(part)
                            self.wfile.flush()
                            time.sleep(delay)
                    else:
                        for event in events:
                            time.sleep(delay)
                            data = event if isinstance(event, str) else json.dumps(event)
                            self.wfile.write(("data: " + data + "\n\n").encode())
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            return measure_chat(f"http://127.0.0.1:{server.server_port}/v1",
                                {"model": "test", "messages": [{"role": "user", "content": "fixture"}], "max_tokens": 16},
                                api_key="synthetic-test-only", timeout_seconds=timeout,
                                max_response_bytes=limit)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_real_stream_and_usage(self):
        result = self.request([
            {"choices": [{"delta": {"role": "assistant"}}]},
            {"choices": [{"delta": {"content": "42"}}]},
            {"choices": [{"delta": {}, "finish_reason": "stop"}], "usage": {"completion_tokens": 1}},
            "[DONE]",
        ], delay=.01)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["content"], "42")
        self.assertGreater(result["ttft_seconds"], .015)
        self.assertGreater(result["wall_seconds"], result["ttft_seconds"])
        self.assertIsNone(result["timings"])
        self.assertEqual(result["usage"], {"completion_tokens": 1})
        self.assertNotIn("synthetic-test-only", json.dumps(result))

    def test_tool_fragments(self):
        result = self.request([
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call1", "function": {"name": "lookup", "arguments": '{"x":'}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "1}"}}]}, "finish_reason": "tool_calls"}]},
            "[DONE]",
        ])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["tool_calls"][0]["function"], {"name": "lookup", "arguments": '{"x":1}'})

    def test_missing_done_and_length_are_failures(self):
        for reason in ("stop", "length"):
            result = self.request([{"choices": [{"delta": {"content": "42"}, "finish_reason": reason}]}])
            self.assertEqual(result["status"], "failed")

    def test_unauthorized_is_observed(self):
        result = self.request([], status=401)
        self.assertEqual(result["http_status"], 401)
        self.assertEqual(result["status"], "failed")

    def test_response_limit_and_malformed_json(self):
        for events, limit in [(["x" * 500], 100), (["{bad"], 4096)]:
            result = self.request(events, limit=limit)
            self.assertEqual(result["status"], "failed")

    def test_trickle_deadline(self):
        result = self.request([], raw=[b"d"] * 50, delay=.01, timeout=.08)
        self.assertEqual(result["status"], "timeout")
        self.assertLess(result["wall_seconds"], .5)

    def test_nonloopback_rejected_before_connection(self):
        with self.assertRaises(ValueError):
            measure_chat("http://example.com/v1", {}, api_key="x", timeout_seconds=1)

    def test_guard_blocks_request(self):
        def stopped():
            raise ValueError("resource-stop")

        result = measure_chat("http://127.0.0.1:1/v1",
                              {"model": "test", "messages": [{}], "max_tokens": 1},
                              api_key="x", timeout_seconds=1, guard=stopped)
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["http_status"])

    def test_slow_guard_cannot_start_inference_after_deadline(self):
        with patch("aotg.field_bench.http.client.HTTPConnection") as connection:
            result = measure_chat("http://127.0.0.1:1/v1",
                                  {"model": "test", "messages": [{}], "max_tokens": 1},
                                  api_key="x", timeout_seconds=.02,
                                  guard=lambda: time.sleep(.04))
        self.assertEqual(result["status"], "timeout")
        connection.return_value.connect.assert_not_called()
        connection.return_value.request.assert_not_called()
