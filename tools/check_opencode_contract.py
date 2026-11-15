"""Finite actual-client/fake-provider integration; never real model quality.

Requires existing Linux tools and OpenCode 1.1.53. The parent creates a fresh
user/mount/network/IPC/PID namespace, enabling only its own loopback. All profile
and token bytes are synthetic; no owner profile, cache or credential is copied.
The deterministic source and verification script are trusted test fixtures.
Default performs local preparation only. --execute opts into this offline test.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
import time

NAMESPACES = ("user", "mnt", "net", "ipc", "pid")
SOURCE = "int synthetic_value() { return 0; }\n"
INTERMEDIATE = "int synthetic_value() { return 1; }\n"
REPLACEMENT = "int synthetic_value() { return 2; }\n"
PROMPT = "Synthetic offline transport check: read synthetic.cpp, write its return value as 1, edit that value to 2, then run ./verify.sh. Report only the observed transport-test result; no real model or native compilation is involved."
EXPECTED_REQUESTS = 8
MODEL = "synthetic-offline-overlay"
TOKEN = "synthetic-test-only-not-an-owner-secret"


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n"); stream.flush(); os.fsync(stream.fileno())


def namespaces():
    return {name: os.readlink("/proc/self/ns/" + name) for name in NAMESPACES}


def verify_namespaces(config):
    observed = namespaces()
    need(all(observed[n] != config["parent_namespaces"][n] for n in NAMESPACES), "A required namespace was not isolated")
    need(sorted(name for _, name in socket.if_nameindex()) == ["lo"], "External network interface exists")
    need(os.getpid() == 1, "Outer driver must be namespace PID 1")
    return observed


def setup(config_path):
    config = json.loads(Path(config_path).read_text())
    verify_namespaces(config)
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True, timeout=3,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin"})
    routes = subprocess.run(["/usr/sbin/ip", "-j", "route", "show"], check=True, timeout=3,
                            capture_output=True, env={"PATH": "/usr/bin:/bin"})
    need(json.loads(routes.stdout) == [], "Unexpected nonlocal route")
    os.execve("/usr/bin/setpriv", ["/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
              "--no-new-privs", "/usr/bin/python3", "-I", "-S", "-B", str(Path(__file__).resolve()),
              "--child", config_path], {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})


def child(config_path):
    config = json.loads(Path(config_path).read_text())
    isolated = verify_namespaces(config)
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    need(status["NoNewPrivs"].strip() == "1" and all(int(status[key].strip(), 16) == 0
         for key in ("CapInh", "CapEff", "CapPrm", "CapBnd", "CapAmb")), "Capabilities were not dropped")
    root, repo = Path(config["output"]), Path(config["repo"])
    for name, expected in config["module_sha256"].items():
        need(sha(repo / name) == expected, "Module changed before import")
    need(sha(config["binary"]) == config["binary_sha256"], "Installed binary changed")
    sys.path.insert(0, str(repo))
    from aotg.field_client import run_opencode, client_command, _configuration
    inputs = root / "synthetic-inputs"
    inputs.mkdir(mode=0o700)
    contents = {"synthetic.cpp": SOURCE,
        "README.txt": "Synthetic deterministic transport test only. No model quality or native compiler is tested.\n",
        "verify.sh": "#!/bin/sh\nset -eu\nexec /usr/bin/python3 -I -S -B -c " +
            "'from pathlib import Path; import json; actual=Path(\"synthetic.cpp\").read_text(); " +
            "expected=\"int synthetic_value() { return 2; }\\n\"; ok=actual==expected; " +
            "print(json.dumps({\"artifact\":\"synthetic-byte-verification\",\"matched\":ok,\"native_compilation\":False,\"quality_accepted\":False})); raise SystemExit(0 if ok else 1)'\n"}
    for name, text in contents.items():
        (inputs / name).write_text(text)
    (inputs / "prompt.txt").write_text(PROMPT)
    (inputs / "synthetic-token.txt").write_text(TOKEN)
    workload = {"id": "synthetic-offline-overlay", "source": {"name": "synthetic.cpp", "path": str(inputs / "synthetic.cpp"), "sha256": sha(inputs / "synthetic.cpp")},
        "public_files": [{"name": name, "path": str(inputs / name), "sha256": sha(inputs / name)} for name in ("verify.sh", "README.txt")],
        "prompt": {"path": str(inputs / "prompt.txt"), "sha256": sha(inputs / "prompt.txt")}}
    output = root / "client"
    workspace = output / "work"
    ordered_files = {item["name"]: contents[item["name"]] for item in [workload["source"], *workload["public_files"]]}
    expected_overlay = _configuration(workspace, "synthetic.cpp", ordered_files, MODEL, 45, 10)
    expected_prompt = expected_overlay["agent"]["aotg-field"]["prompt"]
    (root / "outside-sentinel.txt").write_text("Synthetic outside-work sentinel; must remain unchanged.\n")
    outside_sha256 = sha(root / "outside-sentinel.txt")
    records, failures = [], []
    serial = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_):
            pass

        def do_GET(self):
            failures.append("Unexpected discovery GET")
            self.send_error(400)

        def do_POST(self):
            self.connection.settimeout(3)
            if not serial.acquire(blocking=False):
                failures.append("Concurrent request")
                self.send_error(409)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                need(self.path == "/v1/chat/completions" and 0 < length <= 1024**2, "Unexpected request path/size")
                need(self.headers.get("Authorization") == "Bearer " + TOKEN, "Unexpected synthetic authentication")
                payload = json.loads(self.rfile.read(length))
                tools = [item["function"]["name"] for item in payload.get("tools", [])]
                messages = payload["messages"]
                system = "\n".join(m["content"] for m in messages if m["role"] == "system")
                index = len(records)
                records.append({"index": index, "request_sha256": digest(payload), "tool_names": tools,
                    "message_roles": [m["role"] for m in messages], "system_sha256": hashlib.sha256(system.encode()).hexdigest(),
                    "custom_primary_prompt_present": expected_prompt in system,
                    "default_provider_prompt_present": "You are opencode, an interactive CLI tool" in system,
                    "tool_result_count": sum(m["role"] == "tool" for m in messages), "stream": payload.get("stream")})
                need(index < EXPECTED_REQUESTS, "Unexpected additional/title request")
                need(set(tools) == {"bash", "read", "edit", "write"} and len(tools) == 4, "Unexpected tool set/title request")
                need(expected_prompt in system and "You are opencode, an interactive CLI tool" not in system, "Custom system prompt not honored")
                need(payload.get("stream") is True and payload.get("model") == MODEL, "Unexpected model/stream contract")
                need(sum(m["role"] == "tool" for m in messages) == index, "Tool sequence skipped or duplicated")
                if index == 0:
                    name, arguments = "read", {"filePath": str(workspace / "synthetic.cpp")}
                elif index == 1:
                    name, arguments = "read", {"filePath": str(workspace / "README.txt")}
                elif index == 2:
                    name, arguments = "edit", {"filePath": str(workspace / "README.txt"), "oldString": contents["README.txt"], "newString": "SYNTHETIC forbidden public overwrite\n"}
                elif index == 3:
                    name, arguments = "write", {"filePath": str(root / "outside-sentinel.txt"), "content": "SYNTHETIC forbidden outside overwrite\n"}
                elif index == 4:
                    name, arguments = "write", {"filePath": str(workspace / "synthetic.cpp"), "content": INTERMEDIATE}
                elif index == 5:
                    name, arguments = "edit", {"filePath": str(workspace / "synthetic.cpp"), "oldString": INTERMEDIATE, "newString": REPLACEMENT}
                elif index == 6:
                    name, arguments = "bash", {"command": "./verify.sh", "description": "Check synthetic bytes; no compiler or model-quality claim"}
                else:
                    name, arguments = None, None
                records[-1]["response_tool"] = name
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                base = {"id": "synthetic-completion-" + str(index), "object": "chat.completion.chunk", "created": 1, "model": MODEL}
                delta = {"role": "assistant"}
                if name:
                    delta["tool_calls"] = [{"index": 0, "id": "synthetic-call-" + str(index), "type": "function",
                                            "function": {"name": name, "arguments": json.dumps(arguments)}}]
                else:
                    def verified(value):
                        if isinstance(value, dict):
                            return (value.get("artifact") == "synthetic-byte-verification" and value.get("matched") is True) or any(verified(v) for v in value.values())
                        if isinstance(value, list):
                            return any(verified(v) for v in value)
                        if isinstance(value, str):
                            try:
                                parsed = json.loads(value)
                            except ValueError:
                                return False
                            return parsed != value and verified(parsed)
                        return False
                    checked = verified(messages[-1].get("content"))
                    records[-1]["actual_verify_report_passed"] = checked
                    delta["content"] = ("Synthetic source bytes changed and the observed byte verification passed. " if checked else
                                        "Synthetic byte verification did not report a pass. ") + "No real model inference or native compilation was performed."
                chunks = [{**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                          {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls" if name else "stop"}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}]
                for chunk in chunks:
                    self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode())
                self.wfile.write(b"data: [DONE]\n\n"); self.wfile.flush()
            except BaseException as error:
                failures.append(type(error).__name__ + ": " + str(error))
                try:
                    self.send_error(400)
                except OSError:
                    pass
            finally:
                serial.release()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
    thread.start()
    endpoint = "http://127.0.0.1:" + str(server.server_port) + "/v1"
    profile = {"$schema": "https://opencode.ai/config.json", "autoupdate": False, "share": "disabled",
        "model": "evo/" + MODEL, "small_model": "evo/" + MODEL, "enabled_providers": ["evo"],
        "plugin": [], "mcp": {}, "instructions": [], "agent": {}, "permission": {},
        "provider": {"evo": {"npm": "@ai-sdk/openai-compatible", "name": "Synthetic offline provider",
            "options": {"baseURL": endpoint, "apiKey": "{file:" + str(inputs / "synthetic-token.txt") + "}"},
            "models": {MODEL: {"name": "Synthetic offline provider", "limit": {"context": 32768, "output": 1024}, "tool_call": True}}}}}
    save(inputs / "profile.json", profile)
    result, error = None, None
    started = time.monotonic()
    try:
        result = run_opencode(executable=config["binary"], profile=inputs / "profile.json",
            command=client_command(config["binary"], MODEL), workload=workload, endpoint=endpoint,
            model=MODEL, output_dir=output, tool_path=["/usr/bin", "/bin"], max_seconds=45,
            max_steps=10, max_output_bytes=1024**2, namespace_tools={"unshare": "/usr/bin/unshare", "setpriv": "/usr/bin/setpriv", "python": "/usr/bin/python3"},
            execution_authorized=True)
        time.sleep(.5)  # bounded observation after actual client exits
    except BaseException as caught:
        error = type(caught).__name__ + ": " + str(caught)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
    title_lines = 0
    public_denials = outside_denials = 0
    for log in (output / "private/data/opencode/log").glob("*.log"):
        need(log.stat().st_size <= 2 * 1024**2, "Unexpected client log size")
        for line in log.read_text().splitlines():
            title_lines += int("service=llm" in line and "agent=title " in line)
            if "service=permission" in line and " evaluated" in line and '"action":"deny"' in line:
                public_denials += int("permission=edit " in line and "README.txt" in line)
                outside_denials += int("permission=external_directory " in line)
    outside_unchanged = sha(root / "outside-sentinel.txt") == outside_sha256
    source_ok = (workspace / "synthetic.cpp").is_file() and (workspace / "synthetic.cpp").read_text() == REPLACEMENT
    module_unchanged = all(sha(repo / n) == h for n, h in config["module_sha256"].items())
    passed = bool(result and result["status"] == "completed-awaiting-independent-quality" and not failures and not error
        and len(records) == EXPECTED_REQUESTS and title_lines == 0 and source_ok and module_unchanged
        and public_denials >= 1 and outside_denials >= 1 and outside_unchanged
        and records[-1].get("actual_verify_report_passed") is True
        and result["public_selftests_unchanged"] and result["selftest_after_last_edit"]
        and [x["tool"] for x in result["tool_calls"]] == ["read", "read", "write", "edit", "bash"]
        and result["overlay_sha256"] == digest(expected_overlay))
    summary = {"artifact": "aotg-synthetic-offline-client-overlay-check", "version": 1,
        "status": "passed-transport-only" if passed else "failed", "actual_client_version": "1.1.53",
        "client_sha256": config["binary_sha256"], "module_sha256": config["module_sha256"],
        "module_bytes_unchanged": module_unchanged, "namespace_isolation_verified": isolated != config["parent_namespaces"],
        "network_interfaces": ["lo"], "external_routes": [], "capabilities_dropped": True,
        "requests": records, "title_agent_log_lines": title_lines, "expected_requests": EXPECTED_REQUESTS,
        "public_edit_denials": public_denials, "outside_directory_denials": outside_denials,
        "outside_sentinel_unchanged": outside_unchanged,
        "actual_source_changed_to_fixture": source_ok, "client_status": result["status"] if result else None,
        "client_result_sha256": digest(result) if result else None,
        "overlay_sha256": digest(expected_overlay), "prompt_sha256": workload["prompt"]["sha256"],
        "seconds": time.monotonic() - started, "error": error, "failures": failures,
        "real_model_inference": False, "native_compilation": False, "independent_quality_accepted": False,
        "production_access": False, "owner_credentials_copied": False, "new_software_downloaded": False}
    save(root / "summary.json", summary)
    print(json.dumps({k: summary[k] for k in ("status", "client_status", "title_agent_log_lines", "actual_source_changed_to_fixture", "seconds", "error", "failures")}))
    return 0 if passed else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo")
    parser.add_argument("--binary")
    parser.add_argument("--output")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--setup")
    parser.add_argument("--child")
    args = parser.parse_args()
    if args.setup:
        return setup(args.setup)
    if args.child:
        return child(args.child)
    need(sys.platform == "linux", "Existing Linux/WSL tools required")
    repo, binary, output = Path(args.repo), Path(args.binary), Path(args.output)
    need(repo.is_absolute() and binary.is_absolute() and output.is_absolute() and not output.exists(), "New absolute private output required")
    config = {"repo": str(repo), "binary": str(binary), "output": str(output), "parent_namespaces": namespaces(),
        "module_sha256": {name: sha(repo / name) for name in ("aotg/__init__.py", "aotg/artifacts.py", "aotg/field_client.py")},
        "binary_sha256": sha(binary), "wall_seconds": 90, "script_sha256": sha(__file__)}
    if not args.execute:
        print(json.dumps({"execute": False, "binary_sha256": config["binary_sha256"], "module_sha256": config["module_sha256"]}))
        return 0
    output.mkdir(mode=0o700)
    save(output / "input.json", config)
    (output / "probe-source.py").write_bytes(Path(__file__).read_bytes())
    command = ["/usr/bin/unshare", "--user", "--map-current-user", "--keep-caps", "--mount", "--net", "--ipc", "--pid",
        "--fork", "--kill-child=KILL", "--mount-proc", "--propagation", "private", "/usr/bin/python3", "-I", "-S", "-B",
        str(Path(__file__).resolve()), "--setup", str(output / "input.json")]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=5)
    (output / "driver.stdout").write_bytes(stdout[:65536])
    (output / "driver.stderr").write_bytes(stderr[:65536])
    save(output / "supervisor.json", {"timed_out": timed_out, "exit_code": process.returncode,
         "stdout_bytes": len(stdout), "stderr_bytes": len(stderr), "namespace_parent_exited": process.poll() is not None,
         "original_namespace_unchanged": namespaces() == config["parent_namespaces"]})
    print(stdout[:65536].decode(errors="replace"))
    if stderr:
        print(stderr[:4000].decode(errors="replace"), file=sys.stderr)
    return 2 if timed_out else process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
