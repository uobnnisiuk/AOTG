"""Bounded measurements for an explicitly selected local inference endpoint.

No service discovery, startup, credential copying, retry, or model download is
performed here. The caller must establish an isolated maintenance session and
retain raw results privately. This module is separate from the mock pipeline.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import math
import socket
import threading
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit


def _positive(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and positive")
    return float(value)


def measure_chat(
    base_url: str,
    request: dict,
    *,
    api_key: str,
    timeout_seconds: float,
    max_response_bytes: int = 4 * 1024 * 1024,
    guard: Callable[[], None] | None = None,
) -> dict:
    """Measure one SSE request; return failures as observations without retries.

    TTFT ends at the first nonempty content or tool-call delta, not an empty
    role/reasoning chunk. Engine timings and cached tokens are nullable: wall
    time is never misrepresented as decode time. Output is private evidence.
    The optional guard runs between reads, not continuously. Hardware trials
    require a separate protective monitor even while a response line blocks.
    """
    timeout_seconds = _positive(timeout_seconds, "timeout_seconds")
    if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 1 <= max_response_bytes <= 16 * 1024 * 1024:
        raise ValueError("invalid response limit")
    url = urlsplit(base_url)
    if url.scheme != "http" or url.username or url.password or url.query or url.fragment:
        raise ValueError("explicit loopback HTTP endpoint required")
    try:
        loopback = ipaddress.ip_address(url.hostname or "").is_loopback
    except ValueError:
        loopback = False
    if not loopback or url.path.rstrip("/") != "/v1":
        raise ValueError("explicit loopback /v1 endpoint required")
    if not isinstance(request, dict) or not isinstance(request.get("model"), str) or not request.get("model"):
        raise ValueError("model required")
    if not isinstance(request.get("messages"), list) or not request["messages"]:
        raise ValueError("messages required")
    output_cap = request.get("max_tokens")
    if isinstance(output_cap, bool) or not isinstance(output_cap, int) or not 1 <= output_cap <= 16384:
        raise ValueError("explicit bounded max_tokens required")
    body = json.dumps({**request, "stream": True, "stream_options": {"include_usage": True}},
                      sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(body) > 1024 * 1024:
        raise ValueError("request too large")
    if not api_key or "\r" in api_key or "\n" in api_key:
        raise ValueError("invalid credential")
    result = {"kind": "aotg-http-measurement-v1", "request_sha256": hashlib.sha256(body).hexdigest(),
              "status": "failed", "http_status": None, "ttft_seconds": None,
              "wall_seconds": None, "usage": None, "timings": None,
              "sse_done": False, "finish_reason": None, "content": "", "tool_calls": [],
              "response_bytes": 0, "error": None}
    started = time.monotonic()
    deadline = started + timeout_seconds
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=timeout_seconds)
    # The deadline watchdog may close a connected socket before request().
    # Never let HTTPConnection silently open a new one after that cancellation.
    connection.auto_open = 0
    expired = threading.Event()
    active_socket: list[socket.socket | None] = [None]

    def expire() -> None:
        expired.set()
        sock = active_socket[0] or connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()

    timer = threading.Timer(timeout_seconds, expire)
    timer.daemon = True
    chunks: list[str] = []
    calls: dict[int, dict] = {}
    event_lines: list[str] = []

    def consume_event() -> None:
        data = "\n".join(event_lines)
        event_lines.clear()
        if not data:
            return
        if data == "[DONE]":
            result["sse_done"] = True
            return
        event = json.loads(data)
        if not isinstance(event, dict) or event.get("error"):
            raise ValueError("invalid SSE event")
        if event.get("usage") is not None:
            if not isinstance(event["usage"], dict):
                raise ValueError("invalid usage")
            result["usage"] = event["usage"]
        if event.get("timings") is not None:
            if not isinstance(event["timings"], dict):
                raise ValueError("invalid timings")
            result["timings"] = event["timings"]
        choices = event.get("choices", [])
        if not isinstance(choices, list) or len(choices) > 1:
            raise ValueError("expected one choice")
        for choice in choices:
            delta = choice.get("delta", {})
            content = delta.get("content")
            tool_deltas = delta.get("tool_calls", [])
            if content is not None and not isinstance(content, str):
                raise ValueError("invalid content")
            if not isinstance(tool_deltas, list):
                raise ValueError("invalid tool delta")
            if (content or tool_deltas) and result["ttft_seconds"] is None:
                result["ttft_seconds"] = time.monotonic() - started
            if content:
                chunks.append(content)
            for part in tool_deltas:
                index = part.get("index")
                if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < 32:
                    raise ValueError("invalid tool index")
                call = calls.setdefault(index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                if part.get("id"):
                    call["id"] += part["id"]
                for name in ("name", "arguments"):
                    value = part.get("function", {}).get(name, "")
                    if not isinstance(value, str):
                        raise ValueError("invalid function delta")
                    call["function"][name] += value
            if choice.get("finish_reason") is not None:
                result["finish_reason"] = choice["finish_reason"]

    try:
        timer.start()
        if guard:
            guard()
        remaining = deadline - time.monotonic()
        if expired.is_set() or remaining <= 0:
            raise TimeoutError("request deadline before connect")
        connection.timeout = remaining
        connection.connect()
        active_socket[0] = connection.sock
        remaining = deadline - time.monotonic()
        if expired.is_set() or remaining <= 0:
            raise TimeoutError("request deadline before send")
        active_socket[0].settimeout(remaining)
        connection.request("POST", "/v1/chat/completions", body=body,
                           headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"})
        response = connection.getresponse()
        result["http_status"] = response.status
        if response.status != 200:
            result["error"] = "http-status"
            return result
        if response.getheader("Content-Type", "").split(";")[0].strip() != "text/event-stream":
            raise ValueError("expected SSE content type")
        while not result["sse_done"]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("request deadline")
            if guard:
                guard()
            # Bound a blocked line read by the total request deadline.
            if active_socket[0] is not None:
                active_socket[0].settimeout(remaining)
            line = response.readline(65537)
            result["response_bytes"] += len(line)
            if len(line) > 65536 or result["response_bytes"] > max_response_bytes:
                raise ValueError("response limit")
            if not line:
                break
            text = line.decode("utf-8").rstrip("\r\n")
            if not text:
                consume_event()
            elif text.startswith("data:"):
                event_lines.append(text[5:].lstrip(" "))
        if guard:
            guard()
        if result["sse_done"] and result["finish_reason"] in ("stop", "tool_calls") and result["ttft_seconds"] is not None:
            result["status"] = "completed"
        else:
            result["error"] = "incomplete-generation"
    except TimeoutError:
        result.update(status="timeout", error="request-deadline")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, http.client.HTTPException) as exc:
        # Do not echo exception text: endpoints or credentials can occur in it.
        result["error"] = type(exc).__name__
    finally:
        result["wall_seconds"] = time.monotonic() - started
        result["content"] = "".join(chunks)
        result["tool_calls"] = [calls[i] for i in sorted(calls)]
        timer.cancel()
        connection.close()
        if expired.is_set() or result["wall_seconds"] > timeout_seconds:
            result.update(status="timeout", error="request-deadline")
    return result


def resource_snapshot(proc: Path = Path("/proc"), sys: Path = Path("/sys")) -> dict:
    """Read Linux counters without touching model files or clearing caches.

    GPU reserved memory and host MemTotal are separate fields, never summed.
    Missing sensors remain absent. Device names and paths are not exported.
    """
    start = time.monotonic()
    memory = {line.split()[0].rstrip(":"): int(line.split()[1]) * 1024
              for line in (proc / "meminfo").read_text().splitlines()
              if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"))}
    vmstat = dict(line.split() for line in (proc / "vmstat").read_text().splitlines())
    gpu = []
    for card in sorted((sys / "class/drm").glob("card[0-9]*/device")):
        row = {}
        for name in ("mem_info_vram_total", "mem_info_vram_used", "mem_info_gtt_used"):
            path = card / name
            if path.exists():
                row[name] = int(path.read_text())
        if row:
            gpu.append(row)
    temperatures = []
    for sensor in sorted((sys / "class/hwmon").glob("hwmon*")):
        name = (sensor / "name").read_text().strip()
        for path in sensor.glob("temp*_input"):
            label = path.with_name(path.name.replace("_input", "_label"))
            label_text = label.read_text().strip() if label.exists() else "unlabelled"
            if (name == "amdgpu" and label_text == "edge") or (name == "nvme" and label_text == "Composite"):
                temperatures.append({"kind": name + ":" + label_text, "celsius": int(path.read_text()) / 1000})
    disks = []
    for line in (proc / "diskstats").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 14 and fields[2].startswith("nvme") and "p" not in fields[2].split("n", 1)[-1]:
            disks.append({"read_bytes": int(fields[5]) * 512, "written_bytes": int(fields[9]) * 512,
                          "io_milliseconds": int(fields[12])})
    return {"memory": memory, "swapout_pages": int(vmstat["pswpout"]), "gpu": gpu,
            "temperatures": temperatures, "disks": disks, "sampling_seconds": time.monotonic() - start}
