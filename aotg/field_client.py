"""Bounded OpenCode 1.1.53 work in a private, explicitly configured workspace.

This provides workspace/configuration separation, an OpenCode tool policy and
a PID namespace for complete descendant cleanup. It does NOT isolate the host
filesystem or network. Native code needs separate filesystem/OS isolation.
Client-reported tests never constitute independent quality proof.
The caller supplies a dedicated profile, existing executable, exact command and
hashed public workload. Credentials remain references in the owner's profile.
"""

import hashlib
import ipaddress
import json
import math
import os
import re
import select
import signal
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from .artifacts import ArtifactError, digest, publish_artifact, read_artifact

VERSION = "1.1.53"
AGENT = "aotg-field"
MAX_FILE = 1024 * 1024

# Runs as PID 1 only after unshare and setpriv. The private acknowledgment pipe
# is closed before spawning any client code; client output cannot forge it.
_NAMESPACE_INIT = r"""
import json, os, subprocess, sys
fd = int(sys.argv[1])
old_namespace = sys.argv[2]
expected_uid, expected_gid = int(sys.argv[3]), int(sys.argv[4])
current_namespace = os.readlink('/proc/self/ns/pid')
status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
if (os.getpid() != 1 or current_namespace == old_namespace
        or os.getuid() != expected_uid or os.geteuid() != expected_uid
        or os.getgid() != expected_gid or os.getegid() != expected_gid
        or status['NoNewPrivs'].strip() != '1'
        or any(int(status[key].strip(), 16) != 0 for key in ('CapInh', 'CapEff', 'CapPrm', 'CapBnd', 'CapAmb'))):
    raise SystemExit(125)
record = {'protocol': 'aotg-pid-namespace-v1', 'pid': 1,
          'uid': os.getuid(), 'gid': os.getgid(),
          'namespace': current_namespace, 'no_new_privs': True, 'capabilities_dropped': True}
os.write(fd, (json.dumps(record) + '\n').encode())
os.close(fd)
child = subprocess.Popen(sys.argv[5:], close_fds=True)
code = child.wait()
# Exiting namespace PID 1 makes the kernel kill every remaining descendant,
# even double-forked or setsid children, before the unshare parent returns.
raise SystemExit(code if code >= 0 else 128 - code)
"""


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _plain_file(path, limit=MAX_FILE):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ArtifactError("Expected an absolute regular file, not a symlink")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ArtifactError("Input exceeds its fixed size limit")
    return data


def _file_hash(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        return None
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _endpoint(value):
    try:
        url = urlsplit(value)
        local = ipaddress.ip_address(url.hostname or "").is_loopback
        valid = (url.scheme == "http" and local and url.port is not None
                 and 0 < url.port < 65536 and url.path == "/v1"
                 and not url.query and not url.fragment and not url.username and not url.password)
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ArtifactError("Use an explicit numeric loopback HTTP endpoint ending in /v1")


def validate_profile(profile_path, endpoint, model):
    """Validate without copying or reading the referenced credential file."""
    _endpoint(endpoint)
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", model):
        raise ArtifactError("Invalid explicit EVO model identifier")
    raw = _plain_file(profile_path)
    profile = read_artifact(profile_path)
    allowed = {"$schema", "provider", "model", "small_model", "enabled_providers",
               "autoupdate", "share", "plugin", "mcp", "instructions", "agent", "permission"}
    if set(profile) - allowed:
        raise ArtifactError("The dedicated profile contains unsupported discovery or behavior settings")
    if profile.get("$schema") != "https://opencode.ai/config.json":
        raise ArtifactError("Pin the profile schema to avoid OpenCode's implicit profile migration")
    for key, empty in (("plugin", []), ("mcp", {}), ("instructions", []), ("agent", {}), ("permission", {})):
        if profile.get(key, empty) != empty:
            raise ArtifactError("The dedicated profile must not add plugins, agents, instructions, MCP or permissions")
    if profile.get("autoupdate", False) is not False or profile.get("share", "disabled") != "disabled":
        raise ArtifactError("Updates and sharing must be disabled")
    for key in ("model", "small_model"):
        if key in profile and profile[key] != "evo/" + model:
            raise ArtifactError("The dedicated profile selects another model")
    if profile.get("enabled_providers", ["evo"]) != ["evo"] or set(profile.get("provider", {})) != {"evo"}:
        raise ArtifactError("The dedicated profile must contain only provider evo")
    provider = profile["provider"]["evo"]
    if not isinstance(provider, dict) or set(provider) - {"npm", "name", "options", "models"}:
        raise ArtifactError("Unsupported provider configuration")
    if provider.get("npm") != "@ai-sdk/openai-compatible":
        raise ArtifactError("Only the bundled OpenAI-compatible provider is allowed; no package installation")
    options = provider.get("options", {})
    if not isinstance(options, dict) or set(options) - {"baseURL", "apiKey", "timeout"} or options.get("baseURL") != endpoint:
        raise ArtifactError("Provider endpoint or options differ from the frozen run")
    reference = options.get("apiKey")
    if not isinstance(reference, str) or not re.fullmatch(r"\{file:/[^{}\r\n]+\}", reference):
        raise ArtifactError("Use an existing owner-supplied {file:/absolute/path} credential reference")
    models = provider.get("models", {})
    if not isinstance(models, dict) or set(models) != {model}:
        raise ArtifactError("The profile must contain exactly the explicit model")
    settings = models[model]
    if not isinstance(settings, dict) or set(settings) - {"name", "limit", "tool_call", "temperature", "attachment", "reasoning", "modalities"}:
        raise ArtifactError("Unsupported model overrides")
    limits = settings.get("limit", {})
    if (not isinstance(limits, dict) or set(limits) != {"context", "output"}
            or type(limits["context"]) is not int or not 1 <= limits["context"] <= 131072
            or type(limits["output"]) is not int or not 1 <= limits["output"] <= 4096
            or limits["output"] > limits["context"] or settings.get("tool_call") is not True):
        raise ArtifactError("Freeze context/output limits and enable tool calls explicitly")
    return {"sha256": _sha(raw), "model_limits": limits}


def _workload(workload):
    if not isinstance(workload, dict) or set(workload) != {"id", "source", "public_files", "prompt"}:
        raise ArtifactError("Expected a frozen public workload with source, public_files and prompt")
    if not isinstance(workload["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", workload["id"]):
        raise ArtifactError("Invalid workload identifier")
    public = workload["public_files"]
    if not isinstance(public, list) or not 1 <= len(public) <= 8:
        raise ArtifactError("Expected one to eight explicit public selftest files")
    files = {}
    for entry in [workload["source"], *public]:
        if not isinstance(entry, dict) or set(entry) != {"name", "path", "sha256"}:
            raise ArtifactError("Each staged file requires name, absolute path and SHA-256")
        name = entry["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", name) or name in files:
            raise ArtifactError("Staged filenames must be unique simple names")
        data = _plain_file(entry["path"])
        if _sha(data) != entry["sha256"]:
            raise ArtifactError("Frozen workload input hash changed")
        files[name] = data
    source = workload["source"]["name"]
    if "verify.sh" not in files or source == "verify.sh":
        raise ArtifactError("The immutable public files must include verify.sh")
    prompt_entry = workload["prompt"]
    if not isinstance(prompt_entry, dict) or set(prompt_entry) != {"path", "sha256"}:
        raise ArtifactError("Prompt requires an explicit path and SHA-256")
    prompt = _plain_file(prompt_entry["path"], 32768)
    if _sha(prompt) != prompt_entry["sha256"] or not prompt.decode("utf-8").strip():
        raise ArtifactError("Frozen prompt differs or is empty")
    return source, files, prompt.decode("utf-8")


def client_command(executable, model):
    """The only supported invocation; caller passes this explicit argv back to run."""
    return [str(executable), "run", "--format", "json", "--agent", AGENT, "-m", "evo/" + model]


def _require_global_project(root):
    """Pin OpenCode 1.1.53's non-Git project boundary to / without discovery.

    Its read permission uses an absolute path; edit/write use a path relative
    to the project boundary. An ancestor .git would change that interpretation.
    This is a tool-policy guard, not protection against a hostile host process.
    """
    if (not root.is_absolute() or ".." in root.parts or root.resolve() != root
            or any(character in str(root) for character in "*?")):
        raise ArtifactError("Use a canonical workspace without permission wildcards")
    for parent in (root, *root.parents):
        marker = parent / ".git"
        if parent.is_symlink() or marker.exists() or marker.is_symlink():
            raise ArtifactError("Use a symlink-free workspace outside every Git project")


def _configuration(root, source, files, model, seconds, steps):
    _require_global_project(root)
    paths = [str(root / name) for name in files]
    reads = {"*": "deny", **{path: "allow" for path in paths}}
    edits = {"*": "deny", (root / source).relative_to("/").as_posix(): "allow"}
    permissions = {"*": "deny", "read": reads, "list": {"*": "deny", str(root): "allow"},
                   "edit": edits, "bash": {"*": "deny", "./verify.sh": "allow"},
                   "external_directory": "deny", "webfetch": "deny", "websearch": "deny",
                   "codesearch": "deny", "task": "deny", "question": "deny", "skill": "deny"}
    public_paths = [str(root / name) for name in files if name != source]
    # In OpenCode 1.1.53 agent.prompt replaces the provider's generic prompt.
    # That generic prompt suggests discovery tools which this workload denies.
    prompt = (
        "You are completing one bounded coding task in the supplied workspace. "
        "Read the task and supplied files, repair the source, and verify the result.\n"
        "Editable source: " + str(root / source) + "\n"
        "Read-only public files:\n" + "\n".join(public_paths) + "\n"
        "These are all the files needed for this task; no file discovery is needed. "
        "Use read to inspect them, and edit or write only the editable source. "
        "Use the provided structured tool interface for every tool call. "
        "Do not print XML or other tool-call markup as response text. "
        "The only allowed bash command is exactly ./verify.sh. It builds the source "
        "and runs the public tests. Do not invoke ls, glob, other shell commands, "
        "subagents, or network tools. Do not modify public files or tests. "
        "After the final edit, run ./verify.sh and inspect its result. "
        "If verification fails, fix the source within the task limits. "
        "Finish with a concise, truthful result; do not claim unrun tests passed."
    )
    return {"model": "evo/" + model, "small_model": "evo/" + model, "enabled_providers": ["evo"],
            "provider": {"evo": {"options": {"timeout": int(seconds * 1000)}}},
            # Both session naming and message-summary naming call agent title.
            # Disable it so background requests cannot contend for the serial
            # measurement proxy or consume the finite workload request budget.
            "agent": {"title": {"disable": True},
                      AGENT: {"mode": "primary", "model": "evo/" + model,
                              "prompt": prompt, "temperature": 0, "top_p": 1, "steps": steps,
                              "permission": permissions}},
            "default_agent": AGENT, "permission": permissions, "plugin": [], "mcp": {},
            "instructions": [], "autoupdate": False, "share": "disabled", "lsp": False,
            "formatter": False, "compaction": {"auto": False, "prune": False},
            "experimental": {"batch_tool": False}}


def _environment(private, profile, overlay, tool_path):
    if not isinstance(tool_path, (list, tuple)) or not tool_path:
        raise ArtifactError("Supply the exact existing compiler/tool PATH directories")
    for path in tool_path:
        if not Path(path).is_absolute() or not Path(path).is_dir():
            raise ArtifactError("Tool PATH entries must be absolute existing directories")
    env = {"PATH": os.pathsep.join(str(p) for p in tool_path), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for name in ("home", "config", "data", "state", "cache", "tmp", "managed"):
        (private / name).mkdir(mode=0o700)
    env.update(HOME=str(private / "home"), OPENCODE_TEST_HOME=str(private / "home"),
               OPENCODE_TEST_MANAGED_CONFIG_DIR=str(private / "managed"),
               TMPDIR=str(private / "tmp"), TMP=str(private / "tmp"), TEMP=str(private / "tmp"),
               OPENCODE_CONFIG=str(profile), OPENCODE_CONFIG_CONTENT=json.dumps(overlay),
               DOTNET_CLI_HOME=str(private / "home"), DOTNET_CLI_TELEMETRY_OPTOUT="1",
               DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1", DOTNET_MULTILEVEL_LOOKUP="0")
    for kind in ("CONFIG", "DATA", "STATE", "CACHE"):
        env["XDG_" + kind + "_HOME"] = str(private / kind.lower())
    for flag in ("PROJECT_CONFIG", "AUTOUPDATE", "DEFAULT_PLUGINS", "CLAUDE_CODE", "EXTERNAL_SKILLS",
                 "LSP_DOWNLOAD", "MODELS_FETCH", "AUTOCOMPACT", "PRUNE"):
        env["OPENCODE_DISABLE_" + flag] = "true"
    env["OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER"] = "true"
    # v1.1.53 config.needsInstall checks only these two prerequisites when no
    # plugins are configured. The provider is bundled. No cache/credential copy.
    config = private / "config/opencode"
    (config / "node_modules").mkdir(parents=True, mode=0o700)
    (config / "package.json").write_text(json.dumps({"dependencies": {"@opencode-ai/plugin": VERSION}}), encoding="utf-8")
    return env


def _stop_group(process):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    process.wait(timeout=5)


def _namespace_tools(value):
    if not isinstance(value, dict) or set(value) != {"unshare", "setpriv", "python"}:
        raise ArtifactError("Supply explicit existing unshare, setpriv and Python executable paths")
    paths, hashes = {}, {}
    for name, raw in value.items():
        path = Path(raw)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise ArtifactError("Namespace executables must be absolute existing executable files")
        path = path.resolve()
        paths[name], hashes[name] = str(path), _file_hash(path)
    return paths, hashes


def _supervise(command, cwd, env, seconds, output_limit, max_steps, stdout_path, stderr_path, namespace_tools):
    started = time.monotonic()
    reason = "exited"
    read_fd, write_fd = os.pipe()
    previous_namespace = os.readlink("/proc/self/ns/pid")
    # Preserve the caller's nonroot UID so the public selftest can create its
    # own user namespace after we drop all capabilities. Mapping parent UID 0
    # again can require CAP_SETFCAP. keep-caps lasts only until setpriv below.
    wrapped = [namespace_tools["unshare"], "--user", "--map-current-user", "--keep-caps", "--mount", "--pid",
               "--fork", "--kill-child=KILL", "--mount-proc", "--propagation", "private",
               namespace_tools["setpriv"], "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
               "--no-new-privs", namespace_tools["python"], "-I", "-S", "-B", "-c", _NAMESPACE_INIT,
               str(write_fd), previous_namespace, str(os.getuid()), str(os.getgid()), *command]
    with stdout_path.open("xb+") as stdout, stderr_path.open("xb+") as stderr:
        try:
            process = subprocess.Popen(wrapped, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True,
                                       pass_fds=(write_fd,))
        except BaseException:
            os.close(read_fd)
            raise
        finally:
            os.close(write_fd)
        offset, tail, starts = 0, b"", 0
        acknowledged = None
        try:
            # Fail closed if namespaces or capability removal are unavailable.
            # This happens before the explicit client is ever started.
            ack = b""
            ack_deadline = started + min(seconds, 5)
            while b"\n" not in ack:
                if time.monotonic() >= ack_deadline:
                    raise ArtifactError("PID namespace startup acknowledgment missing; no fallback is allowed")
                if select.select([read_fd], [], [], 0.02)[0]:
                    chunk = os.read(read_fd, 4097 - len(ack))
                    if not chunk or len(ack) + len(chunk) > 4096:
                        raise ArtifactError("Invalid PID namespace startup acknowledgment")
                    ack += chunk
                elif process.poll() is not None:
                    raise ArtifactError("PID namespace startup acknowledgment missing; no fallback is allowed")
            try:
                acknowledged = json.loads(ack)
            except (ValueError, UnicodeError) as exc:
                raise ArtifactError("Invalid namespace startup record") from exc
            if (acknowledged.get("protocol") != "aotg-pid-namespace-v1"
                    or acknowledged.get("pid") != 1 or acknowledged.get("namespace") == previous_namespace
                    or acknowledged.get("uid") != os.getuid() or acknowledged.get("gid") != os.getgid()
                    or acknowledged.get("no_new_privs") is not True
                    or acknowledged.get("capabilities_dropped") is not True):
                raise ArtifactError("PID namespace security properties not acknowledged")
            while True:
                size = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
                if size > output_limit:
                    reason = "output-limit"
                    break
                chunk = os.pread(stdout.fileno(), output_limit - offset, offset)
                offset += len(chunk)
                tail += chunk
                lines = tail.split(b"\n")
                tail = lines.pop()
                for line in lines:
                    try:
                        event = json.loads(line)
                        starts += isinstance(event, dict) and event.get("type") == "step_start"
                    except (ValueError, UnicodeError):
                        pass
                if max_steps is not None and starts > max_steps:
                    reason = "step-limit"
                    break
                if process.poll() is not None:
                    break
                if time.monotonic() - started >= seconds:
                    reason = "wall-time"
                    break
                time.sleep(0.02)
        finally:
            os.close(read_fd)
            # unshare --kill-child kills namespace PID 1 when the wrapper dies;
            # exiting PID 1 also kills descendants after normal client exit.
            _stop_group(process)
        total = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
        if total > output_limit:
            reason = "output-limit"
        stdout.seek(0)
        out = stdout.read(output_limit)
        stderr.seek(0)
        err = stderr.read(max(0, output_limit - len(out)))
        if total > output_limit:
            # Persist exactly the bounded evidence represented by the hashes.
            stdout.truncate(len(out))
            stderr.truncate(len(err))
        return {"stop_reason": reason, "seconds": time.monotonic() - started,
                "exit_code": process.returncode, "stdout": out, "stderr": err,
                "output_truncated": total > output_limit, "observed_output_bytes": total,
                "namespace": acknowledged}


def summarize_events(raw, workspace, source, allowed_files):
    """Summarize client claims, not independently attested tests or correctness."""
    tools, selftests, errors, invalid, steps = [], [], 0, 0, 0
    texts, final, last_edit = {}, None, -1
    tokens = {"input": 0, "output": 0, "reasoning": 0, "cache_read": 0, "cache_write": 0}
    observed_tokens, violations = False, []
    allowed_paths = {str(workspace / name) for name in allowed_files}
    lines = raw.splitlines()
    for index, line in enumerate(lines):
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("event is not an object")
        except (ValueError, UnicodeError):
            invalid += 1
            continue
        kind, part = event.get("type"), event.get("part", {})
        if not isinstance(part, dict):
            invalid += 1
            continue
        if kind == "error":
            errors += 1
        if kind == "text" and isinstance(part.get("text"), str) and part.get("messageID"):
            texts[part["messageID"]] = part["text"]
        if kind == "step_finish":
            steps += 1
            if part.get("reason") == "stop" and part.get("messageID") in texts:
                final = texts[part["messageID"]]
            usage = part.get("tokens")
            if isinstance(usage, dict):
                cache = usage.get("cache", {})
                if not isinstance(cache, dict):
                    cache = {}
                values = {**{key: usage.get(key) for key in ("input", "output", "reasoning")},
                          "cache_read": cache.get("read"), "cache_write": cache.get("write")}
                for key, value in values.items():
                    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
                        tokens[key] += value
                        observed_tokens = True
        if kind != "tool_use":
            continue
        state = part.get("state", {})
        if not isinstance(state, dict) or not isinstance(state.get("input", {}), dict):
            invalid += 1
            continue
        name, parameters = part.get("tool"), state.get("input", {})
        metadata = state.get("metadata", {})
        metadata = metadata if isinstance(metadata, dict) else {}
        row = {"tool": name, "status": state.get("status"), "event_index": index,
               "exit": metadata.get("exit")}
        tools.append(row)
        if state.get("status") != "completed":
            continue
        if name == "bash":
            if parameters.get("command") != "./verify.sh":
                violations.append("unexpected-bash-command")
            else:
                selftests.append(row)
        elif name in ("edit", "write", "apply_patch", "patch", "multiedit"):
            last_edit = index
            filename = parameters.get("filePath", parameters.get("path"))
            if name in ("edit", "write") and filename not in (source, "./" + source, str(workspace / source)):
                violations.append("unexpected-edit-path")
        elif name == "read":
            filename = parameters.get("filePath", parameters.get("path"))
            if filename not in allowed_paths and filename not in allowed_files and filename not in {"./" + n for n in allowed_files}:
                violations.append("unexpected-read-path")
        elif name == "list":
            if parameters.get("path", str(workspace)) not in (".", str(workspace)):
                violations.append("unexpected-list-path")
        else:
            violations.append("unexpected-tool")
    if raw and not raw.endswith(b"\n"):
        invalid += 1
    last = selftests[-1] if selftests else None
    selftest_pass = bool(last and type(last["exit"]) is int and last["exit"] == 0 and last["event_index"] > last_edit)
    return {"steps": steps, "tool_calls": tools, "selftest_attempts": len(selftests),
            "selftest_pass_reported": selftest_pass, "selftest_after_last_edit": bool(last and last["event_index"] > last_edit),
            "final_response_present": bool(final and final.strip()), "final_response": final,
            "step_limit_summary": bool(final and "maximum number of steps" in final.lower()),
            "tokens": tokens if observed_tokens else None, "invalid_event_lines": invalid,
            "client_errors": errors, "tool_policy_violations": violations}


def run_opencode(*, executable, profile, command, workload, endpoint, model, output_dir,
                 tool_path, max_seconds, max_steps, max_output_bytes,
                 namespace_tools, execution_authorized=False):
    """Run only the explicit pinned client; caller handles independent patch review.

    The supplied verify.sh is trusted PUBLIC test code, but candidate source is
    untrusted. Use an external OS sandbox when executing untrusted native code.
    """
    if execution_authorized is not True:
        raise ArtifactError("OpenCode execution requires explicit opt-in")
    if os.name != "posix" or not Path("/proc/self/ns/pid").exists():
        raise ArtifactError("This first-machine runner requires K8 WSL/Linux PID namespaces")
    namespace_paths, namespace_hashes = _namespace_tools(namespace_tools)
    if type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or not 0 < max_seconds <= 1800:
        raise ArtifactError("Wall-clock limit must be finite and at most 1800 seconds")
    if type(max_steps) is not int or not 1 <= max_steps <= 20:
        raise ArtifactError("Step limit must be between 1 and 20")
    if type(max_output_bytes) is not int or not 4096 <= max_output_bytes <= 16 * MAX_FILE:
        raise ArtifactError("Output limit must be between 4096 bytes and 16 MiB")
    executable, profile = Path(executable), Path(profile)
    if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ArtifactError("Supply the absolute existing OpenCode executable")
    if command != client_command(executable, model):
        raise ArtifactError("Command differs from the explicit bounded OpenCode invocation")
    profile_info = validate_profile(profile, endpoint, model)
    executable_hash = _file_hash(executable)
    source, files, prompt = _workload(workload)
    output = Path(output_dir)
    if not output.is_absolute() or output.exists() or not output.parent.is_dir():
        raise ArtifactError("Use a new absolute results directory beneath an existing parent")
    workspace, private = output / "work", output / "private"
    _require_global_project(workspace)
    output.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    for name, data in files.items():
        target = workspace / name
        target.write_bytes(data)
        target.chmod(0o600 if name == source else 0o500 if name == "verify.sh" else 0o400)
    overlay = _configuration(workspace, source, files, model, max_seconds, max_steps)
    env = _environment(private, profile, overlay, tool_path)
    version = _supervise([str(executable), "--version"], workspace, env, 10, 65536, None,
                         private / "version.stdout", private / "version.stderr", namespace_paths)
    if version["exit_code"] != 0 or version["stop_reason"] != "exited" or version["stdout"].decode("utf-8", errors="replace").strip() != VERSION:
        raise ArtifactError("The existing executable is not verified OpenCode 1.1.53")
    fixed_hashes = {name: _sha(data) for name, data in files.items() if name != source}
    before = {name: _file_hash(workspace / name) for name in files}
    if any(before[name] != _sha(data) for name, data in files.items()):
        raise ArtifactError("Staged workload changed before client execution")
    invocation = [*command, prompt]
    _require_global_project(workspace)
    observed = _supervise(invocation, workspace, env, max_seconds, max_output_bytes, max_steps,
                          private / "events.jsonl", private / "stderr.log", namespace_paths)
    summary = summarize_events(observed["stdout"], workspace, source, files)
    after = {name: _file_hash(workspace / name) for name in files}
    unchanged = all(after[name] == expected for name, expected in fixed_hashes.items())
    status = observed["stop_reason"]
    if status == "exited":
        if (not unchanged or _file_hash(profile) != profile_info["sha256"] or _file_hash(executable) != executable_hash
                or any(_file_hash(namespace_paths[name]) != expected for name, expected in namespace_hashes.items())):
            status = "protected-input-changed"
        elif after[source] is None:
            status = "source-missing-or-symlink"
        elif summary["invalid_event_lines"] or summary["tool_policy_violations"]:
            status = "invalid-client-evidence"
        elif observed["exit_code"] != 0 or summary["client_errors"]:
            status = "client-error"
        elif summary["steps"] > max_steps or summary["step_limit_summary"]:
            status = "step-limit"
        elif not summary["final_response_present"] or not summary["selftest_pass_reported"]:
            status = "incomplete"
        else:
            status = "completed-awaiting-independent-quality"
    result = {"artifact": "aotg-opencode-work", "version": 1, "workload_id": workload["id"],
              "status": status, "quality_accepted": False, "client_version": VERSION,
              "client_sha256": executable_hash, "profile_sha256": profile_info["sha256"],
              "overlay_sha256": digest(overlay), "prompt_sha256": _sha(prompt.encode("utf-8")),
              "source_name": source, "source_sha256_before": before[source], "source_sha256_after": after[source],
              "source_changed": before[source] != after[source], "public_selftests_unchanged": unchanged,
              "public_selftest_sha256": fixed_hashes, "seconds": observed["seconds"],
              "exit_code": observed["exit_code"], "limits": {"seconds": max_seconds, "steps": max_steps,
              "output_bytes": max_output_bytes, **profile_info["model_limits"]},
              "sampling": {"temperature": 0, "top_p": 1, "seed_verified": False},
              "isolation": {"workspace_and_tool_policy": True, "os_sandbox_verified": False,
                            "filesystem_sandbox_verified": False, "network_sandbox_verified": False,
                            "pid_namespace_verified": True, "cleanup_scope": "dedicated-pid-namespace",
                            "namespace_tool_sha256": namespace_hashes, "namespace": observed["namespace"]},
              "private_events_sha256": _sha(observed["stdout"]), "output_truncated": observed["output_truncated"],
              "observed_output_bytes": observed["observed_output_bytes"],
              **summary}
    publish_artifact(output / "result.json", result)
    return result
