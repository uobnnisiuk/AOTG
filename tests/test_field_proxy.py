import json
import socket
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

from aotg.field_proxy import MeasurementProxy
from tools.assemble_field_evidence import EvidenceError, request_capture


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.forwarded = []
        forwarded = self.forwarded
        self.upstream_entered, self.upstream_release = threading.Event(), threading.Event()
        self.upstream_release.set()
        entered, release = self.upstream_entered, self.upstream_release

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                forwarded.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                entered.set()
                release.wait(2)
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
                                      api_key="test-only", model="fixed-model", max_requests=4,
                                      max_tokens=128, total_seconds=5, request_seconds=2,
                                      record=self.records.append)
        self.threads = []
        for server in (self.upstream, self.proxy):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)

    def tearDown(self):
        self.upstream_release.set()
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

    def test_malformed_json_and_contract_are_closed_pre_sampling_failures(self):
        for body in (b"{", json.dumps({"model": "wrong", "stream": True, "messages": []}).encode()):
            request = urllib.request.Request(f"http://127.0.0.1:{self.proxy.server_port}/v1/chat/completions",
                data=body, headers={"Authorization": "Bearer test-only"})
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(error.exception.code, 400)
            self.assertTrue(self.proxy.wait_for_handlers())
        self.close_capture()
        attempts, rejections = request_capture(self.records, 4)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(rejections["rejected_total"], 0)
        self.assertEqual(self.forwarded, [])
        for attempt in attempts:
            self.assertEqual(attempt["status"], "failed")
            self.assertIsNone(attempt["request_sha256"])
            self.assertNotIn("fixed_sampling", attempt)
            self.assertFalse(attempt["sse_done"])
            self.assertEqual(attempt["response_bytes"], 0)
            self.assertGreaterEqual(attempt["wall_seconds"], 0)

    def test_fixed_sampling_streaming_metrics_and_request_cap(self):
        self.assertIn(b"[DONE]", self.send())
        self.assertTrue(self.proxy.wait_for_handlers())
        self.assertEqual(len(self.forwarded), 1)
        self.assertEqual(self.forwarded[0]["seed"], 4242)
        self.assertEqual(self.forwarded[0]["temperature"], 0)
        self.assertEqual(self.forwarded[0]["max_tokens"], 128)
        self.assertFalse(self.forwarded[0]["cache_prompt"])
        self.assertEqual(self.records[1]["status"], "completed")
        self.assertEqual(self.records[1]["usage"], {"completion_tokens": 1})
        self.assertEqual(self.records[1]["timings"], {"draft_n": 1})
        self.assertIsNotNone(self.records[1]["ttft_seconds"])
        self.assertNotIn("test-only", json.dumps(self.records))
        self.assertNotIn("messages", json.dumps(self.records))
        for _ in range(3):
            self.send()
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.send()
        self.assertEqual(error.exception.code, 429)
        self.assertEqual(len(self.forwarded), 4)
        self.assertEqual(self.records[-1]["reason"], "request_limit_rejected")

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
            self.assertTrue(self.proxy.wait_for_handlers())
        self.assertEqual(self.forwarded, [])

    def close_capture(self):
        self.proxy.shutdown()
        self.assertTrue(self.proxy.wait_for_handlers())
        self.proxy.server_close()
        self.assertEqual([r["event_sequence"] for r in self.records], list(range(len(self.records))))
        self.assertEqual(self.records[-1]["phase"], "closed")
        self.assertEqual(self.records[-1]["status"], "complete")
        return self.records[-1]

    def test_real_concurrent_rejection_survives_success_and_cap(self):
        self.upstream_release.clear()
        result = []
        thread = threading.Thread(target=lambda: result.append(self.send()))
        thread.start()
        self.assertTrue(self.upstream_entered.wait(2))
        try:
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.send()
            self.assertEqual(error.exception.code, 409)
        finally:
            self.upstream_release.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertIn(b"[DONE]", result[0])
        for _ in range(3):
            self.send()
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.send()
        self.assertEqual(error.exception.code, 429)
        final = self.close_capture()
        self.assertEqual(final["rejected_total"], 2)
        self.assertEqual(final["rejections_by_reason"], {"concurrent_request_rejected": 1, "request_limit_rejected": 1})
        requests = [r for r in self.records if r["kind"] == "aotg-proxy-request-v1"]
        self.assertEqual([r["index"] for r in requests], [0, 1, 2, 3])
        self.assertTrue(all(r["status"] == "completed" for r in requests))
        self.assertEqual(final["request_records"], 4)
        parsed, rejected = request_capture(self.records, 4)
        self.assertEqual(len(parsed), 4)
        self.assertEqual(rejected["rejected_total"], 2)

    def test_auth_route_refusals_and_bounded_overflow_never_log_input(self):
        for i in range(130):
            request = urllib.request.Request(f"http://127.0.0.1:{self.proxy.server_port}/private-secret-{i}",
                                             headers={"Authorization": "Bearer private-secret"})
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=2)
            self.assertEqual(error.exception.code, 401)
        request = urllib.request.Request(f"http://127.0.0.1:{self.proxy.server_port}/private-secret",
                                         headers={"Authorization": "Bearer test-only"})
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        self.assertEqual(error.exception.code, 403)
        final = self.close_capture()
        self.assertEqual(final["rejected_total"], 131)
        self.assertEqual(final["rejections_by_reason"], {"authorization_rejected": 130, "route_or_protocol_rejected": 1})
        self.assertEqual(final["rejection_events_dropped"], 3)
        parsed, rejected = request_capture(self.records, 4)
        self.assertEqual(parsed, [])
        self.assertEqual(rejected["rejected_total"], 131)
        self.assertEqual(sum(r["kind"] == "aotg-proxy-rejection-v2" for r in self.records), 128)
        self.assertEqual(sum(r["kind"] == "aotg-proxy-rejection-overflow-v2" for r in self.records), 1)
        self.assertNotIn("private-secret", json.dumps(self.records))
        self.assertNotIn("test-only", json.dumps(self.records))
        self.assertEqual(self.forwarded, [])

    def test_malformed_admitted_attempts_are_bounded_and_recorded(self):
        for _ in range(4):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.send(model="wrong")
            self.assertEqual(error.exception.code, 400)
            self.assertTrue(self.proxy.wait_for_handlers())
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.send()
        self.assertEqual(error.exception.code, 429)
        final = self.close_capture()
        self.assertEqual(final["request_records"], 4)
        self.assertEqual(final["rejected_total"], 1)
        self.assertEqual(self.forwarded, [])

    def test_callback_failure_prevents_future_upstream_admission(self):
        self.proxy._record_sink = Mock(side_effect=OSError("synthetic storage failure"))
        self.proxy.handle_error = Mock()
        with self.assertRaises((OSError, urllib.error.URLError)):
            self.send(key="wrong")
        with self.assertRaises((OSError, urllib.error.URLError)):
            self.send()
        self.assertEqual(self.forwarded, [])
        self.assertTrue(self.proxy.audit_failed)
        self.proxy._record_sink = self.records.append
        self.proxy.shutdown()
        self.proxy.server_close()
        self.assertEqual(self.records[-1]["status"], "incomplete")
        self.assertTrue(self.records[-1]["record_error"])

    def test_protocol_refusal_is_counted_without_raw_request(self):
        with socket.create_connection(self.proxy.server_address, timeout=2) as sock:
            sock.sendall(b"PUT /private-secret HTTP/1.0\r\n\r\n")
            self.assertIn(b"501", sock.recv(1024))
        final = self.close_capture()
        self.assertEqual(final["rejections_by_reason"], {"http_protocol_rejected": 1})
        self.assertNotIn("private-secret", json.dumps(self.records))

    def test_response_can_precede_record_and_bounded_drain_completes_capture(self):
        entered, release = threading.Event(), threading.Event()
        original_record = self.proxy.record

        def delayed_record(row):
            entered.set()
            if not release.wait(3):
                raise OSError("synthetic record did not release")
            original_record(row)

        self.proxy.record = delayed_record
        try:
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.send(model="wrong")
            self.assertEqual(error.exception.code, 400)
            self.assertTrue(entered.wait(2))
            self.proxy.shutdown()
            self.assertFalse(self.proxy.wait_for_handlers(0))
            self.assertEqual(len(self.records), 1)
            original_wait = self.proxy._handlers_idle.wait

            def release_on_wait(timeout):
                self.assertFalse(self.proxy._handlers_idle.is_set())
                release.set()
                return original_wait(timeout)

            self.proxy._handlers_idle.wait = Mock(side_effect=release_on_wait)
            self.assertTrue(self.proxy.wait_for_handlers())
            self.proxy._handlers_idle.wait.assert_called_once()
            self.proxy.server_close()
            attempts, rejected = request_capture(self.records, 4)
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["status"], "failed")
            self.assertEqual(rejected["rejected_total"], 0)
            self.assertEqual(self.records[-1]["active_handlers"], 0)
            self.assertEqual(self.records[-1]["status"], "complete")
            self.assertEqual(self.forwarded, [])
        finally:
            release.set()

    def test_active_handler_closure_cannot_certify_complete_or_emit_late_success(self):
        self.upstream_release.clear()
        self.proxy.handle_error = Mock()
        outcomes = []

        def invoke():
            try:
                outcomes.append(self.send())
            except (OSError, urllib.error.URLError) as error:
                outcomes.append(type(error).__name__)

        thread = threading.Thread(target=invoke)
        thread.start()
        self.assertTrue(self.upstream_entered.wait(2))
        self.proxy.shutdown()
        self.assertFalse(self.proxy.wait_for_handlers(0))
        self.proxy.server_close()
        before = list(self.records)
        self.assertEqual(before[-1]["status"], "incomplete")
        self.assertGreater(before[-1]["active_handlers"], 0)
        with self.assertRaisesRegex(EvidenceError, "request_capture_or_cleanup_incomplete"):
            request_capture(before, 4)
        self.upstream_release.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.records, before)

    def test_closing_record_write_failure_is_not_silently_accepted(self):
        self.send()
        sink = self.records.append

        def fail_final(row):
            if row.get("phase") == "closed":
                raise OSError("synthetic final write failure")
            sink(row)

        self.proxy._record_sink = fail_final
        self.proxy.shutdown()
        with self.assertRaisesRegex(OSError, "proxy capture write failed"):
            self.proxy.server_close()
        self.assertTrue(self.proxy.audit_closed)
        with self.assertRaises(EvidenceError):
            request_capture(self.records, 4)
