"""Bounded public C++/C# self-tests in the existing offline namespace sandbox.

Only the caller's explicit source and public test are copied into the read-only
workspace. No benchmark catalog, hidden assertions, review receipts, repository
checkout or credentials are exposed. Passing a public self-test is never an
independent quality acceptance. No package restore or download is performed.
"""

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

from .artifacts import ArtifactError, digest
from .field_sandbox import run_isolated

MAX_SOURCE_BYTES = 1024 * 1024
PHASE_OUTPUT_BYTES = 8192
AS_BYTES = 8 * 1024**3
FILE_BYTES = 64 * 1024**2
GC_BYTES = 512 * 1024**2

_DRIVER = r'''"""Trusted public-selftest driver; runs only inside namespace containment."""
import json, os, pathlib, selectors, signal, subprocess, sys, time


def run(argv, timeout, dotnet):
    started = time.monotonic()
    result = {"status": "ok", "exit_code": None, "seconds": 0.0,
              "stdout": "", "stderr": "", "output_truncated": False}
    environment = dict(os.environ)
    environment["DOTNET_MULTILEVEL_LOOKUP"] = "0"
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    process = None
    try:
        process = subprocess.Popen(argv, cwd="/tmp", env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                   restore_signals=not dotnet)
        # CoreCLR's sparse memfd reservation needs EFBIG fallback under FSIZE;
        # only dotnet inherits Python's ignored SIGXFSZ. Native C++ keeps default.
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            if time.monotonic() - started >= timeout:
                result["status"] = "timeout"
                break
            for key, _ in selector.select(0.02):
                data = os.read(key.fd, 4096)
                if data:
                    streams[key.data].extend(data)
                else:
                    selector.unregister(key.fileobj)
            if sum(map(len, streams.values())) > 8192:
                result["status"] = "output-limit"
                result["output_truncated"] = True
                break
        if result["status"] == "ok":
            process.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
    except OSError:
        result["status"] = "launch-error"
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            result["exit_code"] = process.returncode
            process.stdout.close()
            process.stderr.close()
        selector.close()
    remaining = 8192
    for name in ("stdout", "stderr"):
        data = bytes(streams[name][:remaining])
        remaining -= len(data)
        result[name] = data.decode("utf-8", errors="replace")
    result["seconds"] = time.monotonic() - started
    return result


config = json.loads(pathlib.Path("/work/_aotg_selftest.json").read_text())
assert os.environ.get("DOTNET_GCHeapHardLimit") == "0x20000000"
if config["runtimeconfig"] is not None:
    pathlib.Path("/tmp/public-test.runtimeconfig.json").write_text(json.dumps(config["runtimeconfig"]))
compilation = run(config["compile_argv"], config["compile_timeout"], config["dotnet"])
execution = None
if compilation["status"] != "ok":
    status = "compile-" + compilation["status"]
elif compilation["exit_code"] != 0 or not pathlib.Path(config["output"]).is_file():
    status = "compile-error"
else:
    execution = run(config["run_argv"], config["run_timeout"], config["dotnet"])
    status = "run-" + execution["status"] if execution["status"] != "ok" else "pass" if execution["exit_code"] == 0 else "test-failed"
print(json.dumps({"status": status, "compile": compilation, "execution": execution}, ensure_ascii=True))
raise SystemExit(0 if status == "pass" else 1)
'''


def _require(condition, message):
    if not condition:
        raise ArtifactError(message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _regular(path, *, max_bytes=64 * 1024 * 1024, executable=False):
    path = Path(path)
    _require(path.is_absolute() and ".." not in path.parts
             and all(not item.is_symlink() for item in [path, *path.parents]),
             "Supply an absolute existing path without symlinks or traversal")
    with path.open("rb") as stream:
        details = os.fstat(stream.fileno())
        _require(stat.S_ISREG(details.st_mode) and details.st_nlink == 1,
                 "Public self-test inputs must be regular, non-hardlinked files")
        if max_bytes is not None:
            _require(details.st_size <= max_bytes, "Public self-test source exceeds size limit")
            data = stream.read(max_bytes + 1)
            _require(len(data) <= max_bytes, "Public self-test source grew beyond size limit")
        else:
            data = stream.read()
    if executable:
        _require(os.access(path, os.X_OK), "Compiler is not executable")
    return path, data


def _bound(value, label, maximum):
    _require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= maximum,
             f"Invalid {label}")


def _toolchain(compiler, compiler_kind, source_name, test_name, csc_dll, reference_dir,
               runtime_version, main_type):
    _require(compiler_kind in ("g++", "dotnet-csc"), "Only existing g++ or .NET 8 direct csc is supported")
    # System compiler aliases are resolved explicitly; task inputs are never
    # allowed to use symlinks. The resulting path remains inside read-only /usr.
    _require(Path(compiler).is_absolute() and ".." not in Path(compiler).parts, "Compiler path must be absolute")
    executable, data = _regular(Path(compiler).resolve(strict=True), executable=True)
    receipt = {"kind": compiler_kind, "compiler_sha256": _sha(data), "os_libraries_pinned": False}
    if compiler_kind == "g++":
        _require(executable.is_relative_to("/usr"), "The C++ compiler must be an existing /usr tool")
        _require(csc_dll is None and reference_dir is None and runtime_version is None,
                 "Do not mix .NET inputs with the C++ compiler")
        output = "/tmp/public-test"
        return {"compile_argv": [str(executable), "-std=c++17", "-O2", "-I/work",
                                  "/work/" + test_name, "-o", output],
                "run_argv": [output], "output": output, "runtimeconfig": None,
                "dotnet": False}, {}, receipt
    _require(isinstance(runtime_version, str) and re.fullmatch(r"8\.0\.[0-9]+", runtime_version),
             "Pin an existing stable .NET 8 runtime version")
    _require(isinstance(main_type, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", main_type),
             "Invalid public C# test entry point")
    _require(csc_dll is not None and reference_dir is not None, "Direct csc requires existing compiler and reference paths")
    root = executable.parent
    roslyn, roslyn_bytes = _regular(csc_dll)
    references = Path(reference_dir)
    _require(references.is_absolute() and references.is_dir()
             and all(not path.is_symlink() for path in [references, *references.parents]),
             "Reference directory must exist without symlinks")
    _require(roslyn.is_relative_to(root) and references.is_relative_to(root),
             "Roslyn and reference assemblies must be inside the explicit dotnet tool tree")
    assemblies = sorted(references.glob("*.dll"))
    _require(1 <= len(assemblies) <= 512, "Missing or excessive .NET reference assemblies")
    reference_hashes = []
    for path in assemblies:
        _, content = _regular(path)
        reference_hashes.append({"name": path.name, "sha256": _sha(content)})
    _require((root / "shared/Microsoft.NETCore.App" / runtime_version).is_dir()
             and (root / "host/fxr" / runtime_version).is_dir(), "Pinned .NET runtime/hostfxr is not installed")
    dotnet = "/tools/dotnet/" + executable.name
    prefix = [dotnet, "exec", "--fx-version", runtime_version]
    output = "/tmp/public-test.dll"
    compiler_argv = [*prefix, "/tools/roslyn/" + roslyn.name,
                     "/nologo", "/nostdlib+", "/target:exe", "/main:" + main_type,
                     "/out:" + output, *("/reference:/tools/references/" + p.name for p in assemblies),
                     "/work/" + source_name, "/work/" + test_name]
    receipt.update({"csc_sha256": _sha(roslyn_bytes), "reference_inputs_sha256": digest(reference_hashes),
                    "runtime_version": runtime_version, "runtime_tree_fully_hashed": False})
    runtimeconfig = {"runtimeOptions": {"tfm": "net8.0", "framework": {
        "name": "Microsoft.NETCore.App", "version": runtime_version}, "rollForward": "Disable"}}
    bindings = {"/tools/roslyn": roslyn.parent, "/tools/references": references,
                "/tools/runtime": root / "shared/Microsoft.NETCore.App" / runtime_version,
                "/tools/hostfxr": root / "host/fxr" / runtime_version,
                "/tools/dotnet-host-input": executable}
    return {"compile_argv": compiler_argv, "run_argv": [*prefix, output], "output": output,
            "runtimeconfig": runtimeconfig, "dotnet": True}, bindings, receipt


def run_public_selftest(source, public_test, *, compiler, compiler_kind="g++", csc_dll=None,
                        reference_dir=None, runtime_version=None, main_type="PublicTests",
                        execution_authorized=False, compile_timeout_seconds=30, timeout_seconds=10):
    """Compile/run the explicit public test, returning bounded output and status.

    The C++ public test includes the source by basename (e.g. intervals.cpp),
    avoiding duplicate compilation. C# compiles both files with PublicTests as
    the default entry point. Caller pins the public test path; this function
    does not trust self-tests as independent correctness or source review.
    """
    _require(execution_authorized is True, "Explicit execution_authorized=True is required")
    _require(sys.platform == "linux", "Public native self-tests require Linux namespace containment")
    _bound(compile_timeout_seconds, "compile timeout", 120)
    _bound(timeout_seconds, "execution timeout", 30)
    source, source_bytes = _regular(source, max_bytes=MAX_SOURCE_BYTES)
    public_test, test_bytes = _regular(public_test, max_bytes=MAX_SOURCE_BYTES)
    suffix = ".cpp" if compiler_kind == "g++" else ".cs"
    for path, data in ((source, source_bytes), (public_test, test_bytes)):
        _require(path.suffix == suffix and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", path.name),
                 "Unexpected public source filename")
        data.decode("utf-8")
    _require(source.name != public_test.name, "Source and public test must have distinct filenames")
    configuration, bindings, toolchain = _toolchain(
        compiler, compiler_kind, source.name, public_test.name, csc_dll, reference_dir, runtime_version, main_type)
    configuration.update({"compile_timeout": compile_timeout_seconds, "run_timeout": timeout_seconds})
    report = {"artifact": "aotg-public-selftest", "version": 1, "status": "not-run",
              "independent": False, "quality_accepted": False, "source_sha256": _sha(source_bytes),
              "public_test_sha256": _sha(test_bytes), "driver_sha256": _sha(_DRIVER.encode()),
              "toolchain": toolchain, "compile": None, "execution": None, "stdout": "", "stderr": "",
              "limits": {"address_space_bytes": AS_BYTES, "file_bytes": FILE_BYTES, "dotnet_gc_heap_bytes": GC_BYTES,
                         "phase_output_bytes": PHASE_OUTPUT_BYTES}, "isolation": None}
    with tempfile.TemporaryDirectory(prefix="aotg-public-selftest-") as temporary:
        work = Path(temporary) / "work"
        work.mkdir(mode=0o700)
        if configuration["dotnet"]:
            # Do not expose all of ~/.dotnet: it may also contain developer
            # certificates or unrelated caches. Build only the host's required
            # directory layout, with links to individually audited RO tool trees.
            tool_root = Path(temporary) / "dotnet-layout"
            tool_root.mkdir(mode=0o700)
            _, host_bytes = _regular(bindings.pop("/tools/dotnet-host-input"))
            _require(_sha(host_bytes) == toolchain["compiler_sha256"], "Dotnet host changed during staging")
            (tool_root / "dotnet").write_bytes(host_bytes)
            (tool_root / "dotnet").chmod(0o500)
            for relative, destination in (("host/fxr/" + runtime_version, "/tools/hostfxr"),
                                           ("shared/Microsoft.NETCore.App/" + runtime_version, "/tools/runtime")):
                link = tool_root / relative
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(destination, target_is_directory=True)
            bindings["/tools/dotnet"] = tool_root
        for name, content in ((source.name, source_bytes), (public_test.name, test_bytes),
                              ("_aotg_driver.py", _DRIVER.encode()),
                              ("_aotg_selftest.json", json.dumps(configuration).encode())):
            (work / name).write_bytes(content)
            (work / name).chmod(0o400)
        isolated = run_isolated(["/usr/bin/python3", "-I", "-B", "/work/_aotg_driver.py"], work,
                                readonly_bindings=bindings, timeout_seconds=compile_timeout_seconds + timeout_seconds + 12,
                                execution_authorized=True, memory_limit_bytes=AS_BYTES, file_limit_bytes=FILE_BYTES,
                                readonly_workspace=True)
    report["isolation"] = {key: isolated.get(key) for key in (
        "status", "isolation_verified", "readonly_workspace", "seconds", "limits", "dotnet_gc_heap_limit_bytes")}
    if (isolated.get("isolation_verified") is not True or isolated.get("readonly_workspace") is not True
            or isolated.get("dotnet_gc_heap_limit_bytes") != GC_BYTES
            or isolated.get("limits", {}).get("memory_bytes") != AS_BYTES
            or isolated.get("limits", {}).get("file_bytes") != FILE_BYTES):
        report["status"] = "isolation-unverified"
        return report
    if isolated["status"] not in ("ok", "nonzero-exit"):
        report["status"] = "isolation-" + isolated["status"]
        return report
    try:
        outcome = json.loads(isolated["stdout"])
        _require(isinstance(outcome, dict) and set(outcome) == {"status", "compile", "execution"}, "Invalid driver report")
        _require(outcome["status"] in ("pass", "compile-error", "test-failed", "compile-timeout", "run-timeout",
                                        "compile-output-limit", "run-output-limit", "compile-launch-error", "run-launch-error"),
                 "Unknown driver status")
        _require(isolated["exit_code"] == (0 if outcome["status"] == "pass" else 1), "Driver status/exit mismatch")
        _require(type(isolated["exit_code"]) is int and isinstance(outcome["compile"], dict), "Invalid driver completion")
        for phase in (outcome["compile"], outcome["execution"]):
            if phase is not None:
                _require(isinstance(phase, dict) and set(phase) == {"status", "exit_code", "seconds", "stdout", "stderr", "output_truncated"},
                         "Invalid phase report")
                _require(isinstance(phase["stdout"], str) and isinstance(phase["stderr"], str)
                         and len(phase["stdout"]) + len(phase["stderr"]) <= PHASE_OUTPUT_BYTES,
                         "Invalid bounded output")
                _require(phase["status"] in ("ok", "timeout", "output-limit", "launch-error")
                         and (type(phase["exit_code"]) is int or phase["exit_code"] is None)
                         and type(phase["seconds"]) in (int, float) and math.isfinite(phase["seconds"])
                         and phase["seconds"] >= 0 and type(phase["output_truncated"]) is bool,
                         "Invalid phase metadata")
        if outcome["status"] == "pass":
            _require(all(isinstance(phase, dict) and phase["status"] == "ok" and phase["exit_code"] == 0 and not phase["output_truncated"]
                         for phase in (outcome["compile"], outcome["execution"])), "Incomplete successful phases")
    except (ValueError, TypeError, KeyError):
        report["status"] = "invalid-driver-output"
        return report
    report.update(outcome)
    last = report["execution"] or report["compile"]
    if last is not None:
        report["stdout"], report["stderr"] = last["stdout"], last["stderr"]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--public-test", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--compiler-kind", choices=("g++", "dotnet-csc"), default="g++")
    parser.add_argument("--csc-dll", type=Path)
    parser.add_argument("--reference-dir", type=Path)
    parser.add_argument("--runtime-version")
    parser.add_argument("--main-type", default="PublicTests")
    parser.add_argument("--compile-timeout", type=float, default=30)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--allow-execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run_public_selftest(args.source, args.public_test, compiler=args.compiler,
                                    compiler_kind=args.compiler_kind, csc_dll=args.csc_dll,
                                    reference_dir=args.reference_dir, runtime_version=args.runtime_version,
                                    main_type=args.main_type, execution_authorized=args.allow_execute,
                                    compile_timeout_seconds=args.compile_timeout, timeout_seconds=args.timeout)
    except (OSError, ValueError) as error:
        print(f"field-selftest: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, allow_nan=False, ensure_ascii=True, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
