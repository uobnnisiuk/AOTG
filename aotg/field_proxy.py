"""Finite local OpenCode measurement proxy; never starts an inference service.

The owner supplies an existing loopback route and key in memory. Requests are
serialized, sampled with fixed parameters and capped. Records contain hashes
and counters rather than prompts or credentials. This is not a GPU monitor.
"""

import hashlib
import hmac
import http.client
import ipaddress
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class MeasurementProxy(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, *, upstream, api_key, model, max_requests,
                 max_tokens, total_seconds, request_seconds, record):
        target = urlsplit(upstream)
        if (target.scheme != "http" or target.path.rstrip("/") != "/v1"
                or target.username or target.password or target.query or target.fragment
                or not ipaddress.ip_address(target.hostname).is_loopback
                or not ipaddress.ip_address(address[0]).is_loopback):
            raise ValueError("explicit loopback endpoints required")
        if (type(max_requests) is not int or not 1 <= max_requests <= 128
                or type(max_tokens) is not int or not 1 <= max_tokens <= 2048
                or type(total_seconds) not in (int, float) or not 0 < total_seconds <= 2100
                or type(request_seconds) not in (int, float) or not 0 < request_seconds <= total_seconds
                or not callable(record) or not isinstance(model, str) or not model
                or not isinstance(api_key, str) or not api_key or "\n" in api_key or "\r" in api_key):
            raise ValueError("invalid fixed limits or credentials")
        self.upstream = target
        self.api_key = api_key
        self.model = model
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        self.deadline = time.monotonic() + total_seconds
        self.request_seconds = request_seconds
        self.record = record
        self.requests = 0
        self.serial = threading.Lock()
        super().__init__(address, _Handler)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def reject(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def authorized(self):
        return hmac.compare_digest(self.headers.get("Authorization", ""),
                                   "Bearer " + self.server.api_key)

    def do_GET(self):
        if not self.authorized():
            self.reject(401)
            return
        if self.path != "/v1/models" or time.monotonic() >= self.server.deadline:
            self.reject(403)
            return
        # Only the fixed candidate is advertised. No upstream discovery calls.
        body = json.dumps({"object": "list", "data": [{"id": self.server.model, "object": "model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.authorized():
            self.reject(401)
            return
        if self.path != "/v1/chat/completions" or self.headers.get("Transfer-Encoding"):
            self.reject(403)
            return
        if not self.server.serial.acquire(blocking=False):
            self.reject(409)
            return
        try:
            self.forward()
        finally:
            self.server.serial.release()

    def forward(self):
        server = self.server
        started = time.monotonic()
        deadline = min(server.deadline, started + server.request_seconds)
        if server.requests >= server.max_requests or started >= deadline:
            self.reject(429)
            return
        connection = None
        timer = None
        active_socket = [None]
        expired = threading.Event()
        result = {"kind": "aotg-proxy-request-v1", "index": server.requests,
                  "status": "failed", "wall_seconds": None, "ttft_seconds": None,
                  "usage": None, "timings": None, "finish_reason": None,
                  "sse_done": False, "request_sha256": None, "response_sha256": None,
                  "response_bytes": 0, "error": None}
        response_hash = hashlib.sha256()
        sent_headers = False

        def cancel():
            expired.set()
            for sock in (active_socket[0], self.connection):
                if sock is not None:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        try:
            timer = threading.Timer(deadline - time.monotonic(), cancel)
            timer.daemon = True
            timer.start()
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024 * 1024:
                raise ValueError("request-size")
            self.connection.settimeout(min(5, deadline - time.monotonic()))
            payload = json.loads(self.rfile.read(length))
            permitted = {"model", "messages", "stream", "stream_options", "temperature", "top_p",
                         "top_k", "min_p", "seed", "presence_penalty", "frequency_penalty",
                         "repeat_penalty", "cache_prompt", "max_tokens", "tools", "tool_choice",
                         "parallel_tool_calls", "stop", "response_format", "chat_template_kwargs", "n"}
            if (not isinstance(payload, dict) or payload.get("model") != server.model
                    or set(payload) - permitted or payload.get("stream") is not True
                    or not isinstance(payload.get("messages"), list) or not payload["messages"]
                    or type(payload.get("n", 1)) is not int or payload.get("n", 1) != 1):
                raise ValueError("request-contract")
            payload.update(temperature=0, top_p=1, top_k=20, min_p=0, seed=4242,
                           presence_penalty=0, frequency_penalty=0, repeat_penalty=1,
                           cache_prompt=False, max_tokens=server.max_tokens,
                           stream_options={"include_usage": True},
                           chat_template_kwargs={"enable_thinking": False})
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            result["request_sha256"] = hashlib.sha256(body).hexdigest()
            result["fixed_sampling"] = {key: payload[key] for key in (
                "temperature", "top_p", "top_k", "min_p", "seed", "presence_penalty",
                "frequency_penalty", "repeat_penalty", "cache_prompt", "max_tokens")}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            server.requests += 1
            connection = http.client.HTTPConnection(server.upstream.hostname, server.upstream.port, timeout=remaining)
            connection.auto_open = 0
            connection.connect()
            active_socket[0] = connection.sock
            if expired.is_set() or time.monotonic() >= deadline:
                raise TimeoutError()
            connection.request("POST", "/v1/chat/completions", body=body,
                               headers={"Authorization": "Bearer " + server.api_key, "Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != 200 or not response.getheader("Content-Type", "").startswith("text/event-stream"):
                result["error"] = "upstream-status-or-type"
                self.reject(502)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            sent_headers = True
            event_lines = []
            while not result["sse_done"]:
                if expired.is_set() or time.monotonic() >= deadline:
                    raise TimeoutError()
                line = response.readline(65537)
                if not line:
                    break
                result["response_bytes"] += len(line)
                if len(line) > 65536 or result["response_bytes"] > 4 * 1024 * 1024:
                    raise ValueError("response-size")
                response_hash.update(line)
                value = line.decode("utf-8").rstrip("\r\n")
                if value.startswith("data:"):
                    event_lines.append(value[5:].lstrip(" "))
                elif not value and event_lines:
                    data = "\n".join(event_lines)
                    event_lines.clear()
                    if data == "[DONE]":
                        result["sse_done"] = True
                    else:
                        event = json.loads(data)
                        if event.get("error"):
                            raise ValueError("upstream-error")
                        result["usage"] = event.get("usage") or result["usage"]
                        result["timings"] = event.get("timings") or result["timings"]
                        choices = event.get("choices", [])
                        if not isinstance(choices, list) or len(choices) > 1:
                            raise ValueError("multiple-choices")
                        for choice in choices:
                            delta = choice.get("delta", {})
                            if (delta.get("content") or delta.get("tool_calls")) and result["ttft_seconds"] is None:
                                result["ttft_seconds"] = time.monotonic() - started
                            result["finish_reason"] = choice.get("finish_reason") or result["finish_reason"]
                self.wfile.write(line)
                self.wfile.flush()
            if result["sse_done"] and result["finish_reason"] in ("stop", "tool_calls") and result["ttft_seconds"] is not None:
                result["status"] = "completed"
            else:
                result["error"] = "incomplete-generation"
        except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException) as error:
            result["error"] = type(error).__name__
            if not sent_headers:
                try:
                    self.reject(400)
                except OSError:
                    pass
        finally:
            if timer:
                timer.cancel()
            if connection:
                connection.close()
            result["wall_seconds"] = time.monotonic() - started
            result["response_sha256"] = response_hash.hexdigest()
            if expired.is_set() or time.monotonic() >= deadline:
                result.update(status="timeout", error="deadline")
            server.record(result)
