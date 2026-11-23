"""Render a private one-authentication PS5 window; never run it or generate scope.

Rendering gives no approval. The script defaults to local preview; execution
requires separate exact owner approval checked by the pinned launch chain.
"""
import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{64}\Z")
SAFE_LINUX = re.compile(r"/[A-Za-z0-9_./-]+\Z")
FIELDS = {"files", "launch_plan", "launch_plan_canonical_sha256", "launcher",
          "python", "release_plan_canonical_sha256", "wsl", "client_plan",
          "client_plan_file", "gate"}


def need(value, message):
    if not value:
        raise ValueError(message)


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, "Nonfinite JSON"))


def fingerprint(value):
    need(isinstance(value, str) and SHA.fullmatch(value), "Exact lowercase SHA256 required")
    return value


def linux_path(value):
    need(isinstance(value, str) and SAFE_LINUX.fullmatch(value)
         and "//" not in value and all(x not in (".", "..") for x in value.split("/")[1:]),
         "Safe canonical Linux path required")
    return value


def windows_path(value):
    need(isinstance(value, str) and re.fullmatch(r"(?:C:\\|\\\\wsl\.localhost\\Ubuntu\\)[A-Za-z0-9_.+\\-]+", value),
         "Explicit safe C or Ubuntu UNC path required")
    tail = value[3:] if value.startswith("C:\\") else value[len("\\\\wsl.localhost\\Ubuntu\\"):]
    need(all(x and x not in (".", "..") for x in tail.split("\\")), "Noncanonical Windows path")
    return value


def to_windows(value):
    linux_path(value)
    if value.startswith("/mnt/c/"):
        return "C:\\" + value[len("/mnt/c/"):].replace("/", "\\")
    return "\\\\wsl.localhost\\Ubuntu" + value.replace("/", "\\")


def descriptor(value):
    need(isinstance(value, dict) and set(value) == {"path", "sha256"}, "Exact file descriptor required")
    return {"path": windows_path(value["path"]), "sha256": fingerprint(value["sha256"])}


def read_regular(path, limit):
    """Bounded local inputs; no FIFO, final link, or changing file accepted."""
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts, "Absolute nontraversing input required")
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
             "Input link or reparse point refused")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
         "Bounded regular input required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_nlink)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        need(signature(opened) == signature(before), "Input changed before opening")
        raw = stream.read(limit+1)
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and len(raw) <= limit
         and signature(before) == signature(after) == signature(path.lstat()), "Input changed during reading")
    return raw


def interactive_route(client):
    need(isinstance(client, dict) and client.get("artifact") == "aotg-k8-field-plan"
         and type(client.get("version")) is int and client["version"] == 2, "Client v2 required")
    route = client["ssh"]
    need(isinstance(route, list) and 12 <= len(route) <= 40
         and all(isinstance(x, str) for x in route), "Existing SSH route required")
    need(route[0] == client["windows_transport"]["ssh"]["path"], "SSH executable binding differs")
    exe = to_windows(route[0])
    need(exe == "C:\\Windows\\System32\\OpenSSH\\ssh.exe", "Existing Windows system SSH required")
    need(route[1:4] == ["-F", "none", "-T"], "Expected existing control SSH route")
    need(re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+", route[-1]), "Single literal SSH target required")
    options = {}
    identities = []
    i = 4
    while i < len(route)-1:
        need(i+1 < len(route)-1 and route[i] in ("-o", "-i"), "Unknown SSH option")
        value = route[i+1]
        need(re.fullmatch(r"[A-Za-z0-9_./:=\\-]+", value), "Unsafe SSH argument")
        if route[i] == "-i":
            identities.append(value)
        else:
            key, sep, val = value.partition("=")
            need(sep and key not in options, "Duplicate or invalid SSH option")
            options[key] = val
        i += 2
    required = {"BatchMode": "yes", "StrictHostKeyChecking": "yes", "IdentitiesOnly": "yes",
                "ForwardAgent": "no", "ConnectTimeout": "10"}
    need(all(options.get(k) == v for k, v in required.items()), "Required SSH protections differ")
    need(set(options) <= set(required) | {"UserKnownHostsFile", "ServerAliveInterval", "ServerAliveCountMax"}
         and "UserKnownHostsFile" in options and len(identities) == 1, "Unexpected connection route")
    for path in (options["UserKnownHostsFile"], identities[0]):
        need(re.fullmatch(r"C:[/\\][A-Za-z0-9_./\\-]+", path)
             and ".." not in path.replace("\\", "/").split("/"), "Existing absolute Windows SSH file required")
    for key in ("ServerAliveInterval", "ServerAliveCountMax"):
        if key in options:
            need(options[key].isdigit() and 0 < int(options[key]) <= 60, "Bounded SSH keepalive required")
    args = list(route[1:])
    args[2] = "-tt"
    return exe, args


def bootstrap(gate):
    need(isinstance(gate, dict) and set(gate) == {"remote_path", "sha256"}, "Exact gate descriptor required")
    path = linux_path(gate["remote_path"])
    need(re.fullmatch(r"/home/[A-Za-z0-9_.-]+/\.local/state/aotg-field/auth-gate-[0-9a-f]{16}/auth_gate\.py", path),
         "Fresh gate path format required")
    pin = fingerprint(gate["sha256"])
    raw = ("import os,sys,stat,hashlib; p='"+path+"'; h='"+pin+"'; "
           "fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); st=os.fstat(fd); "
           "assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<65536; "
           "raw=os.read(fd,65536); os.close(fd); assert hashlib.sha256(raw).hexdigest()==h; "
           "os.environ['AOTG_EXPECTED_GATE_SHA']=h; sys.argv=[p,'--enroll']; "
           "exec(compile(raw,p,'exec'),{'__name__':'__main__','__file__':p})").encode("ascii")
    compile(raw, "<numeric-bootstrap>", "exec")
    return raw


def render(spec, *, client_raw):
    need(isinstance(spec, dict) and set(spec) == FIELDS, "Exact window specification required")
    files = spec["files"]
    need(isinstance(files, list) and 8 <= len(files) <= 160, "Finite pinned inventory required")
    files = [descriptor(x) for x in files]
    pins = {x["path"].casefold(): x["sha256"] for x in files}
    need(len(pins) == len(files), "Duplicate pinned path")
    client_file = descriptor(spec["client_plan_file"])
    need(pins.get(client_file["path"].casefold()) == client_file["sha256"], "Client file must be pinned")
    need(isinstance(client_raw, bytes) and len(client_raw) <= 262144
         and hashlib.sha256(client_raw).hexdigest() == client_file["sha256"]
         and parse(client_raw) == spec["client_plan"], "Client object is not the pinned raw file")
    ssh, ssh_args = interactive_route(spec["client_plan"])
    need(pins.get(ssh.casefold()) == spec["client_plan"]["windows_transport"]["ssh"]["sha256"],
         "SSH binary must match client and file inventory")
    for key in ("launch_plan", "launcher", "python"):
        need(to_windows(spec[key]).casefold() in pins, "Launcher input missing from frozen inventory: "+key)
    wsl = windows_path(spec["wsl"])
    need(wsl == "C:\\Windows\\System32\\wsl.exe" and wsl.casefold() in pins, "Pinned system WSL required")
    for key in ("launch_plan_canonical_sha256", "release_plan_canonical_sha256"):
        fingerprint(spec[key])
    raw = bootstrap(spec["gate"])
    command = ("sudo /usr/bin/python3.14 -I -S -B -c exec\\(\\(0x"+raw.hex()
               +"\\).to_bytes\\("+str(len(raw))+"\\)\\)")
    pinned = {k: spec[k] for k in ("launch_plan", "launch_plan_canonical_sha256", "launcher", "python",
                                  "release_plan_canonical_sha256", "wsl")}
    pinned.update(files=files, ssh=ssh, ssh_args=ssh_args, command=command)
    template = Path(__file__).with_name("approved-comparison-window.ps1.in").read_text(encoding="ascii")
    need(template.count("__PINNED_JSON__") == 1, "Template marker differs")
    return template.replace("__PINNED_JSON__", json.dumps(pinned, sort_keys=True, indent=2, ensure_ascii=True)).encode("ascii")


def validate_client_file(spec):
    d = descriptor(spec["client_plan_file"])
    return read_regular(d["path"], 262144)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--spec-sha256", required=True)
    ap.add_argument("--write-source")
    args = ap.parse_args()
    raw = read_regular(args.spec, 262144)
    need(hashlib.sha256(raw).hexdigest() == fingerprint(args.spec_sha256), "Spec drift")
    spec = parse(raw)
    source = render(spec, client_raw=validate_client_file(spec))
    if args.write_source:
        with Path(args.write_source).open("xb") as stream:
            stream.write(source)
    print(json.dumps({"artifact": "aotg-comparison-window-source", "version": 2,
                      "sha256": hashlib.sha256(source).hexdigest(), "bytes": len(source),
                      "source_written": bool(args.write_source), "process_started": False,
                      "remote_actions_executed": False, "approval_granted": False}, sort_keys=True))


if __name__ == "__main__":
    main()
