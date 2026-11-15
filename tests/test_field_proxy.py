import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aotg.field_proxy import MeasurementProxy


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.forwarded = []
        forwarded = self.forwarded

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                forwarded.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for event in [{"choices": [{"delta": {"content": "42"}, "finish_reason": "stop"}],
                               "usage": {"completion_tokens": 1}, "timings": {"draft_n": 1}}, "[DONE]"]:
                    data = event if isinstance(event, str) else json.dumps(event)
                    self.wfile.write(("data: " + data + "\n\n").encode())

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.records = []
        self.proxy = MeasurementProxy(("127.0.0.1", 0),
                                      upstream=f"http://127.0.0.1:{self.upstream.server_port}/v1",
                                      api_key="test-only", model="fixed-model", max_requests=1,
                                      max_tokens=128, total_seconds=5, request_seconds=2,
                                      record=self.records.append)
        self.threads = []
        for server in (self.upstream, self.proxy):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)

    def tearDown(self):
        for server in (self.proxy, self.upstream):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(2)

    def send(self, *, key="test-only", model="fixed-model", extra=None):
        body = json.dumps({"model": model, "messages": [{"role": "user", "content": "42"}],
                           "stream": True, "temperature": 1, "max_tokens": 9999, **(extra or {})}).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{self.proxy.server_port}/v1/chat/completions",
                                         data=body, headers={"Authorization": "Bearer " + key})
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.read()

    def test_fixed_sampling_streaming_metrics_and_request_cap(self):
        self.assertIn(b"[DONE]", self.send())
        self.assertEqual(len(self.forwarded), 1)
        self.assertEqual(self.forwarded[0]["seed"], 4242)
        self.assertEqual(self.forwarded[0]["temperature"], 0)
        self.assertEqual(self.forwarded[0]["max_tokens"], 128)
        self.assertFalse(self.forwarded[0]["cache_prompt"])
        self.assertEqual(self.records[0]["status"], "completed")
        self.assertEqual(self.records[0]["usage"], {"completion_tokens": 1})
        self.assertEqual(self.records[0]["timings"], {"draft_n": 1})
        self.assertIsNotNone(self.records[0]["ttft_seconds"])
        self.assertNotIn("test-only", json.dumps(self.records))
        self.assertNotIn("messages", json.dumps(self.records))
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.send()
        self.assertEqual(error.exception.code, 429)
        self.assertEqual(len(self.forwarded), 1)

    def test_wrong_credential_or_model_never_reaches_inference(self):
        for kwargs, status in (({"key": "wrong"}, 401), ({"model": "wrong"}, 400)):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.send(**kwargs)
            self.assertEqual(error.exception.code, status)
        self.assertEqual(self.forwarded, [])

    def test_nonlocal_endpoint_rejected(self):
        with self.assertRaises(ValueError):
            MeasurementProxy(("127.0.0.1", 0), upstream="http://192.0.2.1/v1", api_key="x", model="x",
                             max_requests=1, max_tokens=1, total_seconds=1,
                             request_seconds=1, record=lambda _: None)

    def test_competing_token_limits_and_multiple_choices_rejected_before_send(self):
        for extra in ({"n": 2}, {"n": True}, {"max_completion_tokens": 99999}, {"max_output_tokens": 99999}):
            with self.subTest(extra=extra), self.assertRaises(urllib.error.HTTPError) as error:
                self.send(extra=extra)
            self.assertEqual(error.exception.code, 400)
        self.assertEqual(self.forwarded, [])
