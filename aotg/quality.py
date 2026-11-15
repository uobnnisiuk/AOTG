"""Independent compile-and-run grading for the two fixed coding benchmarks.

This module is NOT an OS sandbox. Candidate programs and compilers must run in
an externally isolated, disposable environment without network or credentials.
Execution requires explicit opt-in; a quality pass does not certify isolation.
Only the submitted source is copied from the candidate workspace. The harness
and expectations come from the evaluator's catalog, outside that workspace.
Candidate native code can forge stdout, so matching observations alone NEVER
accept quality. Acceptance also requires an independently supplied source-review
receipt binding the exact source, grader and catalog hashes. The caller must
obtain that receipt from a trusted reviewer, never from candidate-generated
files. This grader checks hash binding, not reviewer identity or review honesty.
"""

import argparse
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .artifacts import ArtifactError, digest, publish_artifact, read_artifact

CATALOG = Path(__file__).resolve().parents[1] / "tests/fixtures/benchmark/catalog.json"
MAX_SOURCE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
CASES = ("cpp-half-open-interval", "csharp-atomic-batch")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_number(value, name, maximum):
    if (type(value) not in (int, float) or not math.isfinite(value)
            or not 0 < value <= maximum):
        raise ArtifactError(f"{name} must be finite and between 0 and {maximum}")


def _executable(value):
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise ArtifactError("Supply an absolute path to an existing executable")
    return path.resolve()


def _tree_inputs(directory):
    """Pin existing .NET toolchain component bytes, with no user path in output."""
    if not directory.is_dir():
        raise ArtifactError("Required installed .NET component directory is missing")
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            if not path.resolve().is_relative_to(directory.resolve()):
                raise ArtifactError(".NET component links outside its recorded directory")
            files[path.relative_to(directory).as_posix()] = _file_sha(path)
        if len(files) > 2048:
            raise ArtifactError("Too many .NET component files")
    if not files:
        raise ArtifactError("The installed .NET component directory is empty")
    return {"files": files, "sha256": digest(files)}


def _catalog_case(case_id, catalog_path):
    catalog = read_artifact(catalog_path)
    matches = [item for item in catalog.get("cases", [])
               if isinstance(item, dict) and item.get("id") == case_id]
    if case_id not in CASES or len(matches) != 1:
        raise ArtifactError("Expected one supported coding case in the catalog")
    return matches[0]


def _harness(case):
    expected = []
    if case["id"] == CASES[0]:
        lines = ["#include <iostream>", "bool overlaps(int, int, int, int);", "int main() {"]
        assertions = case.get("assertions")
        if not isinstance(assertions, list) or not assertions:
            raise ArtifactError("C++ assertions are missing")
        for index, assertion in enumerate(assertions):
            arguments = assertion.get("arguments")
            result = assertion.get("result")
            if (not isinstance(arguments, list) or len(arguments) != 4
                    or any(type(a) is not int or not -(2**31) <= a < 2**31 for a in arguments)
                    or type(result) is not bool):
                raise ArtifactError("Invalid C++ assertion")
            args = ", ".join(str(a) for a in arguments)
            lines.append(f'  std::cout << "AOTG:{index}:" << (overlaps({args}) ? "true" : "false") << "\\n";')
            expected.append(result)
        lines.extend(["  return 0;", "}"])
        return "\n".join(lines) + "\n", expected, ".cpp"
    lines = ["using System;", "public static class AotgTrustedHarness {",
             "  public static int Main() {"]
    sequences = case.get("assertion_sequences")
    if not isinstance(sequences, list) or not sequences:
        raise ArtifactError("C# assertion sequences are missing")
    for sequence in sequences:
        operations = sequence.get("operations")
        if not isinstance(operations, list) or not operations:
            raise ArtifactError("C# operations are missing")
        lines.extend(["    {", "      var registry = new BatchRegistry();"])
        for operation in operations:
            result = operation.get("result")
            if type(result) is not bool:
                raise ArtifactError("Invalid C# assertion result")
            if set(operation) == {"try_register", "result"}:
                values = operation["try_register"]
                if not isinstance(values, list) or any(type(v) is not str for v in values):
                    raise ArtifactError("Invalid C# batch")
                literals = ", ".join(json.dumps(v, ensure_ascii=True) for v in values)
                call = "registry.TryRegister(new string[] {" + literals + "})"
            elif set(operation) == {"contains", "result"} and type(operation["contains"]) is str:
                call = "registry.Contains(" + json.dumps(operation["contains"], ensure_ascii=True) + ")"
            else:
                raise ArtifactError("Invalid C# operation")
            lines.append(f'      Console.WriteLine("AOTG:{len(expected)}:" + ({call} ? "true" : "false"));')
            expected.append(result)
        lines.append("    }")
    lines.extend(["    return 0;", "  }", "}"])
    return "\n".join(lines) + "\n", expected, ".cs"


def grade_observations(output, expected):
    """Compare untrusted observations; a match alone is NOT quality acceptance."""
    lines = output.splitlines()
    observations = []
    for index, line in enumerate(lines):
        if line not in (f"AOTG:{index}:true", f"AOTG:{index}:false"):
            return {"status": "invalid-observations", "observed": len(observations),
                    "expected": len(expected), "mismatches": []}
        observations.append(line.endswith(":true"))
    if len(observations) != len(expected):
        return {"status": "missing-observations" if len(observations) < len(expected)
                else "invalid-observations", "observed": len(observations),
                "expected": len(expected), "mismatches": []}
    mismatches = [i for i, (actual, wanted) in enumerate(zip(observations, expected))
                  if actual is not wanted]
    return {"status": "assertion-mismatch" if mismatches else "pass",
            "observed": len(observations), "expected": len(expected), "mismatches": mismatches}


def _review_gate(receipt, report):
    gate = {"status": "missing", "receipt": None, "receipt_sha256": None,
            "reviewer_identity_verified_by_grader": False}
    if receipt is None:
        return gate
    fields = {"artifact", "version", "source_sha256", "grader_sha256", "catalog_sha256",
              "independent", "reviewer", "verdict", "evidence_reference"}
    if (not isinstance(receipt, dict) or set(receipt) != fields
            or receipt["artifact"] != "aotg-source-review" or type(receipt["version"]) is not int
            or receipt["version"] != 1 or type(receipt["independent"]) is not bool
            or receipt["verdict"] not in ("accepted", "rejected")):
        raise ArtifactError("Invalid independent source-review receipt")
    for key in ("reviewer", "evidence_reference"):
        if not isinstance(receipt[key], str) or not receipt[key].strip() or len(receipt[key]) > 512:
            raise ArtifactError("Source review requires reviewer and evidence references")
    for key in ("source_sha256", "grader_sha256", "catalog_sha256"):
        if not isinstance(receipt[key], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt[key]):
            raise ArtifactError("Source review requires exact SHA-256 bindings")
    gate["receipt"] = dict(receipt)
    gate["receipt_sha256"] = digest(receipt)
    if any(receipt[key] != report[key] for key in ("source_sha256", "grader_sha256", "catalog_sha256")):
        gate["status"] = "hash-mismatch"
    elif not receipt["independent"]:
        gate["status"] = "not-independent"
    else:
        gate["status"] = receipt["verdict"]
    return gate


def _environment(directory, tool_directories=()):
    # Do not inherit API tokens, HOME, compiler injection variables or proxy settings.
    search_path = os.pathsep.join([*(str(p) for p in tool_directories), os.defpath])
    result = {"PATH": search_path, "LANG": "C", "LC_ALL": "C",
              "TMP": str(directory), "TEMP": str(directory), "TMPDIR": str(directory),
              "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
              "DOTNET_MULTILEVEL_LOOKUP": "0", "DOTNET_CLI_HOME": str(directory)}
    if os.name == "nt":
        for key in ("SystemRoot", "WINDIR"):
            if key in os.environ:
                result[key] = os.environ[key]
    return result


def _stop(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        # Windows tree cleanup is best effort; external isolation remains required.
        taskkill = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/taskkill.exe"
        try:
            subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _run(argv, directory, timeout_seconds, phase, tool_directories=()):
    started = time.monotonic()
    stdout_path, stderr_path = directory / (phase + ".stdout"), directory / (phase + ".stderr")
    result = {"status": "ok", "exit_code": None, "seconds": 0.0,
              "stdout": "", "stderr": "", "output_truncated": False}
    with stdout_path.open("w+b") as stdout, stderr_path.open("w+b") as stderr:
        try:
            process = subprocess.Popen(argv, cwd=directory,
                                       env=_environment(directory, tool_directories),
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       start_new_session=os.name == "posix")
        except OSError:
            result["status"] = "launch-error"
            result["seconds"] = time.monotonic() - started
            return result
        try:
            while True:
                size = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
                if size > MAX_OUTPUT_BYTES:
                    result["status"] = "output-limit"
                    result["output_truncated"] = True
                    break
                if process.poll() is not None:
                    break
                if time.monotonic() - started >= timeout_seconds:
                    result["status"] = "timeout"
                    break
                time.sleep(0.01)
        finally:
            # Also reap children left behind after a normal POSIX parent exit.
            _stop(process)
        result["exit_code"] = process.returncode
        # Read the original open handles: a candidate cannot redirect diagnostics
        # to another file by replacing a log pathname with a symlink.
        total = os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
        if total > MAX_OUTPUT_BYTES:
            result["status"] = "output-limit"
            result["output_truncated"] = True
        remaining = MAX_OUTPUT_BYTES
        for key, stream in (("stdout", stdout), ("stderr", stderr)):
            stream.seek(0)
            data = stream.read(remaining)
            remaining -= len(data)
            result[key] = data.decode("utf-8", errors="replace").replace(str(directory), "<evaluation>")
    result["seconds"] = time.monotonic() - started
    return result


def grade_source(case_id, source_path, *, compiler, compiler_kind, runtime_argv=(),
                 execution_authorized=False, isolation_evidence=None,
                 compile_timeout_seconds=30, timeout_seconds=10, catalog_path=CATALOG,
                 csc_dll=None, reference_dir=None, dotnet_runtime_version=None,
                 source_review=None):
    """Compile a copied submission and evaluate it against a separate trusted harness.

    Call inside an external OS sandbox. The opt-in acknowledges native-code
    execution, not proof of sandboxing. ``isolation_evidence`` is an operator's
    reference to separately verified isolation; it is not independently attested.
    Absolute compiler/runtime paths must already exist. No download is performed.
    ``source_review`` must be supplied by a separate trusted source reviewer. A
    candidate's self-authored receipt is not acceptable evidence. Without a
    matching accepted review, even matching native output remains unaccepted.
    """
    if execution_authorized is not True:
        raise ArtifactError("Native execution requires explicit execution_authorized=True")
    if not isinstance(isolation_evidence, str) or not isolation_evidence.strip():
        raise ArtifactError("Record an external isolation evidence reference before execution")
    _bounded_number(compile_timeout_seconds, "compile_timeout_seconds", 120)
    _bounded_number(timeout_seconds, "timeout_seconds", 60)
    if compiler_kind not in ("g++", "csc", "mcs", "dotnet-csc"):
        raise ArtifactError("Unsupported compiler kind")
    if (case_id == CASES[0]) != (compiler_kind == "g++"):
        raise ArtifactError("Compiler kind does not match the coding case")
    executable = _executable(compiler)
    if not isinstance(runtime_argv, (list, tuple)) or any(type(a) is not str for a in runtime_argv):
        raise ArtifactError("runtime_argv must be a list of strings")
    runtime = list(runtime_argv)
    if runtime:
        runtime[0] = str(_executable(runtime[0]))
    dotnet_inputs = None
    references = []
    if compiler_kind == "dotnet-csc":
        if runtime or csc_dll is None or reference_dir is None:
            raise ArtifactError("dotnet-csc requires csc_dll/reference_dir and manages its own runtime")
        if not isinstance(dotnet_runtime_version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", dotnet_runtime_version):
            raise ArtifactError("Pin an installed stable .NET runtime version")
        csc_dll = _executable(csc_dll)
        reference_dir = Path(reference_dir)
        if not reference_dir.is_absolute():
            raise ArtifactError("Supply an absolute existing .NET reference directory")
        reference_dir = reference_dir.resolve()
        references = sorted(reference_dir.glob("*.dll"))
        if not references:
            raise ArtifactError("No installed .NET reference assemblies were found")
        dotnet_inputs = {
            "roslyn": _tree_inputs(csc_dll.parent),
            "references": _tree_inputs(reference_dir),
            "runtime": _tree_inputs(executable.parent / "shared/Microsoft.NETCore.App" / dotnet_runtime_version),
            "hostfxr": _tree_inputs(executable.parent / "host/fxr" / dotnet_runtime_version),
            "runtime_version": dotnet_runtime_version,
        }
    tool_directories = [executable.parent]
    if runtime:
        tool_directories.append(Path(runtime[0]).parent)
    with Path(source_path).open("rb") as stream:
        source = stream.read(MAX_SOURCE_BYTES + 1)
    if len(source) > MAX_SOURCE_BYTES:
        raise ArtifactError("Candidate source exceeds 1 MiB")
    source.decode("utf-8")
    case = _catalog_case(case_id, catalog_path)
    harness_text, expected, suffix = _harness(case)
    harness_bytes = harness_text.encode("utf-8")
    report = {
        "artifact": "aotg-independent-quality", "version": 2, "case_id": case_id,
        "status": "not-run", "source_sha256": _sha(source),
        "behavioral_status": "not-run", "quality_accepted": False,
        "grader_sha256": _file_sha(Path(__file__)), "python_version": sys.version.split()[0],
        "catalog_sha256": _file_sha(catalog_path), "harness_sha256": _sha(harness_bytes),
        "toolchain": {"compiler_kind": compiler_kind, "compiler_sha256": _file_sha(executable),
                      "runtime_sha256": _file_sha(runtime[0]) if runtime else None,
                      "runtime_arguments": runtime[1:], "dotnet_inputs": dotnet_inputs,
                      "os_shared_libraries_pinned": False},
        "isolation": {"provided_by": "external", "verified_by_this_grader": False,
                      "evidence_reference": isolation_evidence},
        "limits": {"compile_seconds": compile_timeout_seconds, "run_seconds": timeout_seconds,
                   "captured_output_bytes": MAX_OUTPUT_BYTES},
        "compile": None, "execution": None, "grading": None,
    }
    report["source_review"] = _review_gate(source_review, report)
    with tempfile.TemporaryDirectory(prefix="aotg-quality-") as temporary:
        directory = Path(temporary)
        candidate = directory / ("candidate" + suffix)
        harness = directory / ("trusted_harness" + suffix)
        output = directory / ("candidate.exe" if suffix == ".cs" or os.name == "nt" else "candidate")
        if compiler_kind == "dotnet-csc":
            output = directory / "candidate.dll"
            runtime_config = {"runtimeOptions": {"framework": {"name": "Microsoft.NETCore.App",
                              "version": dotnet_runtime_version}, "rollForward": "Disable"}}
            runtime_config_bytes = json.dumps(runtime_config, sort_keys=True).encode("utf-8")
            (directory / "candidate.runtimeconfig.json").write_bytes(runtime_config_bytes)
            report["runtimeconfig_sha256"] = _sha(runtime_config_bytes)
        candidate.write_bytes(source)
        harness.write_bytes(harness_bytes)
        version_flag = "--version" if compiler_kind in ("g++", "mcs") else "/help"
        dotnet_prefix = [str(executable), "exec", "--fx-version", dotnet_runtime_version] if dotnet_inputs else []
        version_argv = [*dotnet_prefix, str(csc_dll), "/version"] if dotnet_inputs else [str(executable), version_flag]
        version = _run(version_argv, directory, 5, "version", tool_directories)
        report["toolchain"]["version_probe"] = version
        if compiler_kind == "g++":
            argv = [str(executable), "-std=c++17", "-O2", str(candidate), str(harness), "-o", str(output)]
        elif compiler_kind in ("csc", "dotnet-csc"):
            prefix = [*dotnet_prefix, str(csc_dll)] if dotnet_inputs else [str(executable)]
            refs = ["/nostdlib+", *("/reference:" + str(p) for p in references)] if dotnet_inputs else []
            argv = [*prefix, *refs, "/nologo", "/target:exe", "/main:AotgTrustedHarness",
                    "/out:" + str(output), str(candidate), str(harness)]
        else:
            argv = [str(executable), "-target:exe", "-main:AotgTrustedHarness",
                    "-out:" + str(output), str(candidate), str(harness)]
        compilation = _run(argv, directory, compile_timeout_seconds, "compile", tool_directories)
        report["compile"] = compilation

        def intact():
            try:
                valid = (_file_sha(candidate) == report["source_sha256"]
                         and _file_sha(harness) == report["harness_sha256"])
                if dotnet_inputs:
                    valid = valid and _file_sha(directory / "candidate.runtimeconfig.json") == report["runtimeconfig_sha256"]
                return valid
            except OSError:
                return False

        if not intact():
            report["status"] = "harness-tampering"
        elif compilation["status"] != "ok":
            report["status"] = "compile-" + compilation["status"]
        elif compilation["exit_code"] != 0 or not output.is_file():
            report["status"] = "compile-error"
        else:
            report["executable_sha256"] = _file_sha(output)
            run_argv = [*dotnet_prefix, str(output)] if dotnet_inputs else [*runtime, str(output)]
            execution = _run(run_argv, directory, timeout_seconds, "run", tool_directories)
            report["execution"] = execution
            if not intact():
                report["status"] = "harness-tampering"
            elif execution["status"] != "ok":
                report["status"] = "run-" + execution["status"]
            elif execution["exit_code"] != 0:
                report["status"] = "runtime-error"
            else:
                report["grading"] = grade_observations(execution["stdout"], expected)
                report["status"] = report["grading"]["status"]
    report["behavioral_status"] = report["status"]
    if report["behavioral_status"] == "pass":
        review_status = report["source_review"]["status"]
        if review_status == "accepted":
            report["quality_accepted"] = True
        else:
            report["status"] = ("source-review-required" if review_status == "missing"
                                else "source-review-" + review_status)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--compiler-kind", choices=("g++", "csc", "mcs", "dotnet-csc"), required=True)
    parser.add_argument("--csc-dll", type=Path, help="Existing Roslyn csc.dll for dotnet-csc")
    parser.add_argument("--reference-dir", type=Path, help="Existing Microsoft.NETCore.App.Ref netX.Y directory")
    parser.add_argument("--dotnet-runtime-version", help="Exact installed stable runtime, e.g. 8.0.30")
    parser.add_argument("--runtime", help="Absolute existing runtime executable (e.g. mono)")
    parser.add_argument("--allow-execute", action="store_true")
    parser.add_argument("--isolation-evidence", required=True)
    parser.add_argument("--source-review", type=Path,
                        help="Trusted independent review receipt; never candidate-authored output")
    parser.add_argument("--compile-timeout", type=float, default=30)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.exit(2, "quality: output already exists; preserve prior evidence\n")
    try:
        report = grade_source(args.case, args.source, compiler=args.compiler,
                              compiler_kind=args.compiler_kind,
                              runtime_argv=[args.runtime] if args.runtime else [],
                              execution_authorized=args.allow_execute,
                              isolation_evidence=args.isolation_evidence,
                              compile_timeout_seconds=args.compile_timeout,
                              timeout_seconds=args.timeout, csc_dll=args.csc_dll,
                              reference_dir=args.reference_dir,
                              dotnet_runtime_version=args.dotnet_runtime_version,
                              source_review=read_artifact(args.source_review) if args.source_review else None)
        publish_artifact(args.output, report)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"quality: {exc}\n")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
