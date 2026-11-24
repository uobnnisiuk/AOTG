"""PR31 offline ADV-12 bridge. Only trusted synthetic C++ is executed."""
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
import zlib
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "docs/field-notes/comparison-v2-runtime/assessment-component"
PINS = {
    "aotg/__init__.py": "c4328d19744befda05683d5d703db8f15979394a",
    "aotg/artifacts.py": "84676ce8435b28b7ff52c835815bfecd8d0bbf4d",
    "aotg/field_evidence.py": "1d547a18c5ec45080c2a1bb4d2b835d295792b37",
    "aotg/field_client.py": "d8b0c176225425b60b439812a60c47f2c0ebb378",
    "aotg/quality.py": "dd71740f9a9d454142a532e9fea6c3da7354f240",
    "aotg/field_sandbox.py": "1f61ce684e19c3051c3f4b18e2a3d0b70cf3c170",
    "aotg/field_selftest.py": "183b33aee2c4d0048a1447ced352bd187a9dc940",
    "aotg/field_proxy.py": "b0ccb8bcee3ae6ac2e731aed40db78f7249962de",
    "tools/assemble_field_evidence.py": "dab6787e24e0014fb1cc3a886eb62a3a67b8b676",
    "tools/io_capture_diagnostics.py": "777957dc9c3c3968517cd1dd315ba074d1048be5",
    "tools/tool_roundtrip_diagnostics.py": "713a9622f9363d518bdd53a07417bd302ff7a30b",
    "tests/test_field_assessment_assemble.py": "31f7c7f39ee5392bf5c8a99a8a64dc591f6b13ec",
    "tests/fixtures/assessment/native-driver.md": "bae1ae76cadfe42761ab0445fcb0a976e834ce99",
    "tests/fixtures/benchmark/catalog.json": "3ae824fbc1b6da454c4e8ff9d17c9b7ee37c88f2",
}
MAIN_INPUTS = {
    "aotg/quality.py": "482e042ee7ca5612d7b9279e9def668758926f74",
    "tests/fixtures/benchmark/catalog.json": "323d66218056ae5a79b94e6f019a4f26b05a0054",
    "aotg/artifacts.py": PINS["aotg/artifacts.py"],
}


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


@unittest.skipUnless(
    sys.platform == "linux" and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd,
    "The archived assessment reader requires POSIX directory descriptors",
)
class ArchiveQualityBridgeTests(unittest.TestCase):
    def test_independent_cpp_reports_and_rejections(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "Existing Linux g++ required; no download")
        with tempfile.TemporaryDirectory(prefix="aotg-adv12-bridge-") as tmp:
            scratch = Path(tmp)
            staged = scratch / "candidate"
            # Copy only a finite, explicitly pinned inventory; never alter the archive.
            for relative, pin in PINS.items():
                raw = (ARCHIVE / relative).read_bytes()
                self.assertEqual(git_blob(raw), pin, relative)
                target = staged / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            for relative, pin in MAIN_INPUTS.items():
                raw = (ROOT / relative).read_bytes()
                self.assertEqual(git_blob(raw), pin, relative)
                (staged / relative).write_bytes(raw)

            old_modules = dict(sys.modules)
            try:
                spec = importlib.util.spec_from_file_location(
                    "_aotg_adv12_bridge_fixture", staged / "tests/test_field_assessment_assemble.py"
                )
                fixture = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(fixture)
                a = fixture.a
                evidence = scratch / "synthetic-evidence"
                evidence.mkdir()
                f = fixture.Fixture(evidence)
                self.assertEqual(len(f.field["schedule"]), 32)
                reports = []
                phases = set()

                def bind_report(index, report, *, update_outer=True):
                    arm = f.authority["arms"][str(index)]
                    arm["quality"] = f.trusted(f"arm-{index}/quality.json", report)
                    if update_outer:
                        isolated = json.loads(Path(arm["isolation"]["path"]).read_text())
                        isolated["stdout"] = base64.b64encode(zlib.compress(a.canonical(report))).decode()
                        arm["isolation"] = f.trusted(f"arm-{index}/isolation.json", isolated)

                for row in f.field["schedule"]:
                    index = row["index"]
                    arm = f.authority["arms"][str(index)]
                    source = Path(arm["replay"]["staged_files"][0]["path"])
                    receipt = json.loads(Path(arm["source_review"]["path"]).read_text())
                    # This is a checked-in reference solution from the synthetic fixture,
                    # not model code. All authority/isolation receipts are test-only.
                    self.assertEqual(source.read_bytes(), f.source)
                    report = f.api.quality.grade_source(
                        fixture.CASE, source, compiler=Path(compiler).resolve(),
                        compiler_kind="g++", execution_authorized=True,
                        isolation_evidence=arm["isolation_reference"],
                        catalog_path=Path(f.catalog_d["path"]), source_review=receipt,
                    )
                    self.assertEqual(report["status"], "pass", report)
                    self.assertTrue(report["quality_accepted"])
                    self.assertEqual(report["grading"]["observed"], 15)
                    self.assertEqual(report["toolchain"]["overflow_detection"]["mode"], "ubsan")
                    phase = report["overflow_preflight"]["attempts"]["ubsan"]["compile"]
                    phases.add(phase["seconds"])
                    identity = {k: v for k, v in report["toolchain"].items() if k != "version_probe"}
                    if not reports:
                        f.authority["toolchains"][fixture.CASE] = deepcopy(identity)
                    self.assertEqual(identity, f.authority["toolchains"][fixture.CASE])
                    reports.append(report)
                    bind_report(index, report)

                self.assertGreater(len(phases), 1, "Distinct native probe timings required")
                result = f.run()
                self.assertEqual(result["global_errors"], [])
                self.assertTrue(all(not row["missing_or_conflicting"] for row in result["ledger"]),
                                result["ledger"])
                self.assertEqual(result["decision"]["status"], "adopt")
                self.assertEqual(len(result["run"]["trials"]), 32)
                self.assertFalse(result["goal_complete"])

                # Keep independent authority fixed. Rebind the raw report and its
                # synthetic outer stdout together so the identity gate itself is tested.
                arm = f.authority["arms"]["0"]
                expected = {"driver": f.driver, "source_name": "intervals.cpp",
                            "modules": f.identity["aotg_modules"]}

                def gate(authority=None):
                    # Every independent control has its own immutable-read history.
                    # Only the explicit mutation control below shares a Reader.
                    if authority is None:
                        authority = a.Authority(a.Reader(), f.authority, f.t, [f.k, f.e])
                    return a.quality_gate(
                        f.api, authority, arm, a.sha(f.source), fixture.CASE,
                        f.field["verifier_sha256"], f.catalog_d["sha256"], f.catalog, expected,
                    )

                self.assertTrue(gate()[0])
                for key in ("compiler_sha256", "compiler_flags", "mode", "overflow_probe_sha256"):
                    with self.subTest(identity_key=key):
                        changed = deepcopy(reports[0])
                        tc = changed["toolchain"]
                        if key == "compiler_sha256":
                            tc[key] = "0" * 64
                        elif key == "compiler_flags":
                            tc[key] = tc[key] + ["-DUNEXPECTED"]
                        elif key == "mode":
                            tc["overflow_detection"][key] = "signed-overflow-trap"
                        else:
                            tc["overflow_detection"][key] = "0" * 64
                        bind_report(0, changed)
                        with self.assertRaisesRegex(a.EvidenceError, "native_toolchain_drift"):
                            gate()
                changed = deepcopy(reports[0])
                changed["grader_sha256"] = a.sha((ARCHIVE / "aotg/quality.py").read_bytes())
                bind_report(0, changed)
                with self.assertRaisesRegex(a.EvidenceError, "native_grade_binding_mismatch"):
                    gate()
                bind_report(0, reports[0])
                changed = deepcopy(reports[0])
                changed["overflow_preflight"]["attempts"]["ubsan"]["compile"]["seconds"] += 1
                bind_report(0, changed, update_outer=False)
                with self.assertRaisesRegex(a.EvidenceError, "outer_stdout_quality_mismatch"):
                    gate()
                bind_report(0, reports[0])
                self.assertTrue(gate()[0])

                # Preserve the separate read-history guard: the very same Reader
                # must reject a changed file, even with an updated descriptor.
                authority = a.Authority(a.Reader(), f.authority, f.t, [f.k, f.e])
                self.assertTrue(gate(authority)[0])
                changed = deepcopy(reports[0])
                changed["overflow_preflight"]["attempts"]["ubsan"]["compile"]["seconds"] += 1
                bind_report(0, changed)
                with self.assertRaisesRegex(a.EvidenceError, "input_changed_between_reads"):
                    gate(authority)
                bind_report(0, reports[0])
                self.assertTrue(gate()[0])

                # Separate C# adapter control: the native report, toolchain and
                # outer receipt below are synthetic, not a .NET execution.
                self.check_synthetic_csharp_gate(f, a)
                self.check_mixed_synthetic_assembly(fixture, scratch / "mixed-evidence")
            finally:
                # The archive loader uses its own module namespace. Restore only
                # modules it added/replaced so other test suites cannot see it.
                for name in list(sys.modules):
                    if name.startswith("_aotg_private_assessment"):
                        if name in old_modules:
                            sys.modules[name] = old_modules[name]
                        else:
                            del sys.modules[name]


    def check_synthetic_csharp_gate(self, f, a):
        """Bind C# report bytes to the fixed grader/driver and reject bad observations."""
        case = "csharp-atomic-batch"
        source_name = "BatchRegistry.cs"
        source = b"// SYNTHETIC C# fixture; never compiled or executed\n"
        source_sha = a.sha(source)
        verifier = f.field["verifier_sha256"]
        catalog_sha = f.catalog_d["sha256"]
        prefix = "csharp-adapter-only"
        arm = deepcopy(f.authority["arms"]["0"])
        old_review = arm["source_review"]
        old_source = arm["replay"]["staged_files"][0]
        receipt = json.loads(Path(old_review["path"]).read_text())
        receipt["source_sha256"] = source_sha
        arm["source_review"] = f.trusted(f"{prefix}/source-review.json", receipt)
        arm["review_record"] = f.trusted(f"{prefix}/review.txt", b"SYNTHETIC C# review; no native run")
        source_d = f.trusted(f"{prefix}/{source_name}", source)
        replay = arm["replay"]
        replay.update(source_sha256=source_sha, source_review_sha256=arm["source_review"]["sha256"],
                      argv=["/usr/bin/python3", "-I", "-S", "-B", "-c", f.driver,
                            case, source_name, arm["isolation_reference"]])
        replay["staged_files"] = [
            source_d if item == old_source else arm["source_review"] if item == old_review else item
            for item in replay["staged_files"]
        ]
        replay["execution_record"] = f.trusted(f"{prefix}/replay.txt", b"SYNTHETIC C#; no native execution")
        report = json.loads(Path(arm["quality"]["path"]).read_text())
        # The C++ report was genuinely graded in this test, but none of its
        # native timings, toolchain or execution output are C# evidence.
        phase = {"status": "ok", "exit_code": 0, "seconds": .01,
                 "stdout": "", "stderr": "", "output_truncated": False}
        toolchain = {"compiler_kind": "dotnet-csc", "compiler_sha256": a.sha(b"synthetic dotnet"),
                     "runtime_sha256": None, "runtime_arguments": [],
                     "dotnet_inputs": {"roslyn": a.sha(b"synthetic roslyn"),
                                       "references": a.sha(b"synthetic references"),
                                       "runtime": a.sha(b"synthetic runtime"),
                                       "hostfxr": a.sha(b"synthetic hostfxr"),
                                       "runtime_version": "8.0.30"},
                     "os_shared_libraries_pinned": False}
        f.authority["toolchains"][case] = deepcopy(toolchain)
        harness, expected, suffix = f.api.quality._harness(
            next(item for item in f.catalog["cases"] if item["id"] == case)
        )
        self.assertEqual(suffix, ".cs")
        self.assertEqual(len(expected), 16)
        lines = [f"AOTG:{i}:{str(value).lower()}" for i, value in enumerate(expected)]
        stdout = "\n".join(lines) + "\n"
        report = {"artifact": report["artifact"], "version": report["version"],
                  "case_id": case, "source_sha256": source_sha, "grader_sha256": verifier,
                  "catalog_sha256": catalog_sha, "harness_sha256": a.sha(harness.encode()),
                  "status": "pass", "behavioral_status": "pass", "quality_accepted": True,
                  "source_review": {"status": "accepted", "receipt": receipt,
                                    "receipt_sha256": a.digest(receipt)},
                  "toolchain": toolchain, "compile": phase, "execution": {**phase, "stdout": stdout},
                  "grading": f.api.quality.grade_observations(stdout, expected),
                  "isolation": {"evidence_reference": arm["isolation_reference"]}}
        self.assertEqual(report["grading"]["status"], "pass")
        outer = json.loads(Path(arm["isolation"]["path"]).read_text())
        outer["command_sha256"] = a.digest(replay["argv"])
        expected_replay = {"driver": f.driver, "source_name": source_name,
                           "modules": f.identity["aotg_modules"]}

        def bind(value):
            arm["quality"] = f.trusted(f"{prefix}/quality.json", value)
            isolated = {**outer, "stdout": base64.b64encode(zlib.compress(a.canonical(value))).decode()}
            arm["isolation"] = f.trusted(f"{prefix}/isolation.json", isolated)

        def gate():
            authority = a.Authority(a.Reader(), f.authority, f.t, [f.k, f.e])
            return a.quality_gate(f.api, authority, arm, source_sha, case, verifier,
                                  catalog_sha, f.catalog, expected_replay)

        bind(report)
        self.assertTrue(gate()[0])
        # Keep the claimed grading/pass intact: the assembler must recompute
        # every observation, including the rollback and ordinal cases.
        for i, value in enumerate(expected):
            with self.subTest(csharp_observation=i):
                changed = deepcopy(report)
                wrong = list(lines)
                wrong[i] = f"AOTG:{i}:{str(not value).lower()}"
                changed["execution"]["stdout"] = "\n".join(wrong) + "\n"
                self.assertEqual(f.api.quality.grade_observations(changed["execution"]["stdout"], expected)
                                 ["mismatches"], [i])
                bind(changed)
                self.assertFalse(gate()[0])
        for key in ("roslyn", "references", "runtime", "hostfxr", "runtime_version"):
            with self.subTest(csharp_toolchain=key):
                changed = deepcopy(report)
                changed["toolchain"]["dotnet_inputs"][key] = "9.0.0" if key == "runtime_version" else "0" * 64
                bind(changed)
                with self.assertRaisesRegex(a.EvidenceError, "native_toolchain_drift"):
                    gate()
        changed = deepcopy(report)
        changed["case_id"] = "cpp-half-open-interval"
        bind(changed)
        with self.assertRaisesRegex(a.EvidenceError, "native_grade_binding_mismatch"):
            gate()
        bind(report)
        original_argv = replay["argv"]
        replay["argv"] = [*original_argv[:-2], "intervals.cpp", original_argv[-1]]
        with self.assertRaisesRegex(a.EvidenceError, "native_replay_argv_mismatch"):
            gate()
        replay["argv"] = original_argv
        self.assertTrue(gate()[0])


    def check_mixed_synthetic_assembly(self, fixture, root):
        """Generate 64 complete synthetic arms with case-specific evidence.

        Only the fixture producer is extended; the archived assembler, reader,
        grader and evaluator are used without patching. No C# native execution.
        """
        a = fixture.a
        csharp = "csharp-atomic-batch"
        source_name = "BatchRegistry.cs"
        source = b"// SYNTHETIC C# source; no native execution\n"
        public = {"PublicTests.cs": b"SYNTHETIC C# public test", "verify.sh": b"SYNTHETIC verify"}

        class MixedFixture(fixture.Fixture):
            def write(self, name, value):
                if name == "field.json":
                    # This runs before any worker/client/authority digest is made.
                    self.cs_workload = {
                        "id": csharp,
                        "source": {"name": source_name, "path": "/fixture/input/" + source_name,
                                   "sha256": a.sha(b"starter")},
                        "prompt": {"path": "/fixture/input/csharp-prompt.txt",
                                   "sha256": a.sha(b"synthetic C# contract")},
                        "public_files": [
                            {"name": n, "path": "/fixture/input/" + n, "sha256": a.sha(v)}
                            for n, v in public.items()
                        ],
                    }
                    workloads = [*value["workloads"], {
                        "id": csharp, "input_sha256": a.digest(self.cs_workload),
                        "tests_sha256": self.catalog_d["sha256"],
                        "cache_cohort": "fresh-engine-fixed-short-primer",
                    }]
                    frozen = self.api.evidence.freeze_plan(
                        identity_sha256=value["identity_sha256"], verifier_sha256=value["verifier_sha256"],
                        candidates=value["candidates"], workloads=workloads,
                        baseline_id=value["baseline_id"], blocks=value["blocks"],
                        limits=value["limits"], metric_gates=value["metric_gates"],
                        minimum_improvement=value["minimum_improvement"],
                        required_metrics=value["required_metrics"],
                    )
                    value.update(frozen)
                elif name == "client.json":
                    value["workloads"][csharp] = self.cs_workload
                return super().write(name, value)

            def arm(self, row):
                super().arm(row)
                if row["workload_id"] != csharp:
                    return
                i = row["index"]
                ka, ea = self.k / ("arm-%02d" % i), self.e / ("arm-%03d" % i)
                arm = self.authority["arms"][str(i)]
                source_sha = a.sha(source)
                old_source, old_review = arm["replay"]["staged_files"][:2]
                receipt = json.loads(Path(old_review["path"]).read_text())
                receipt["source_sha256"] = source_sha
                arm["source_review"] = self.trusted(f"arm-{i}/source-review.json", receipt)
                source_d = self.trusted(f"arm-{i}/{source_name}", source)
                replay = arm["replay"]
                replay.update(source_sha256=source_sha, source_review_sha256=arm["source_review"]["sha256"],
                              argv=["/usr/bin/python3", "-I", "-S", "-B", "-c", self.driver,
                                    csharp, source_name, arm["isolation_reference"]])
                replay["staged_files"][:2] = [source_d, arm["source_review"]]
                # Old synthetic trusted source is not referenced by the new receipt.
                self_test.assertEqual(old_source["sha256"], a.sha(self.source))
                report = json.loads(Path(arm["quality"]["path"]).read_text())
                toolchain = {
                    "compiler_kind": "dotnet-csc", "compiler_sha256": a.sha(b"synthetic dotnet"),
                    "runtime_sha256": None, "runtime_arguments": [],
                    "dotnet_inputs": {"roslyn": a.sha(b"synthetic roslyn"),
                                      "references": a.sha(b"synthetic references"),
                                      "runtime": a.sha(b"synthetic runtime"),
                                      "hostfxr": a.sha(b"synthetic hostfxr"),
                                      "runtime_version": "8.0.30"},
                    "os_shared_libraries_pinned": False,
                }
                self.authority["toolchains"][csharp] = toolchain
                harness, expected, _ = self.api.quality._harness(
                    next(c for c in self.catalog["cases"] if c["id"] == csharp))
                self_test.assertEqual(len(expected), 16)
                stdout = "".join(f"AOTG:{j}:{str(v).lower()}\n" for j, v in enumerate(expected))
                report.update(case_id=csharp, source_sha256=source_sha,
                              harness_sha256=a.sha(harness.encode()), toolchain=toolchain,
                              source_review={"status": "accepted", "receipt": receipt,
                                             "receipt_sha256": a.digest(receipt)},
                              grading=self.api.quality.grade_observations(stdout, expected))
                report["execution"]["stdout"] = stdout
                arm["quality"] = self.trusted(f"arm-{i}/quality.json", report)
                isolated = json.loads(Path(arm["isolation"]["path"]).read_text())
                isolated.update(command_sha256=a.digest(replay["argv"]),
                                stdout=base64.b64encode(zlib.compress(a.canonical(report))).decode())
                arm["isolation"] = self.trusted(f"arm-{i}/isolation.json", isolated)

                events = [json.loads(line) for line in (ka / "coding/private/events.jsonl").read_text().splitlines()]
                events[0]["part"]["state"]["input"]["filePath"] = source_name
                public_state = events[1]["part"]["state"]
                public_report = json.loads(public_state["output"])
                public_report.update(source_sha256=source_sha,
                                     public_test_sha256=a.sha(public["PublicTests.cs"]))
                public_state["output"] = a.canonical(public_report).decode()
                arm["public_selftest"]["output_sha256"] = a.sha(public_state["output"].encode())
                raw_events = b"".join(a.canonical(event) + b"\n" for event in events)
                self.put(ka / "coding/private/events.jsonl", raw_events)
                (ka / "coding/work/intervals.cpp").unlink()
                (ka / "coding/work/PublicTests.cpp").unlink()
                self.put(ka / "coding/work" / source_name, source)
                for name, raw in public.items():
                    self.put(ka / "coding/work" / name, raw)
                coding = json.loads((ka / "coding/result.json").read_text())
                coding.update(workload_id=csharp, source_name=source_name,
                              source_sha256_after=source_sha,
                              prompt_sha256=self.cs_workload["prompt"]["sha256"],
                              public_selftest_sha256={n: a.sha(v) for n, v in public.items()},
                              private_events_sha256=a.sha(raw_events))
                coding.update(self.api.client.summarize_events(
                    raw_events, ka / "coding/work", source_name, [source_name, *public]))
                self.put(ka / "coding/result.json", coding)
                kr, er = self.kr[i], self.er[i]
                kr["client_result_sha256"] = a.digest(coding)
                self.put(ka / "result.json", kr)
                er["k8_evidence_sha256"] = a.digest(kr)
                self.put(ea / "result.json", er)
                done_path = self.e / ("done-%d.json" % i)
                done = json.loads(done_path.read_text())
                done["evidence_sha256"] = a.digest(kr)
                self.put(done_path, done)

        self_test = self
        root.mkdir()
        f = MixedFixture(root)
        schedule = f.field["schedule"]
        self.assertEqual(len(schedule), 64)
        self.assertEqual(sum(row["workload_id"] == csharp for row in schedule), 32)
        self.assertEqual(sum(row["workload_id"] == fixture.CASE for row in schedule), 32)

        def assert_positive(result):
            self.assertEqual(result["global_errors"], [])
            self.assertEqual(len(result["run"]["trials"]), 64)
            self.assertEqual(result["observation_counts"]["verified_trial"], 64)
            self.assertTrue(all(t["status"] == "passed" for t in result["run"]["trials"]))
            self.assertEqual(result["decision"]["status"], "adopt")
            self.assertFalse(result["measurement_generated"])
            self.assertFalse(result["goal_complete"])

        assert_positive(f.run())
        # A bad baseline in either workload invalidates adoption across both candidates.
        cs_index = next(row["index"] for row in schedule
                        if row["workload_id"] == csharp and row["candidate_id"] == "baseline")
        cpp_index = next(row["index"] for row in schedule if row["workload_id"] == fixture.CASE)
        key = str(cs_index)
        original = deepcopy(f.authority["arms"][key])
        f.authority["arms"][key] = deepcopy(f.authority["arms"][str(cpp_index)])
        rejected = f.run()
        self.assertEqual(rejected["global_errors"], [])
        self.assertIn("external_source_review_binding_mismatch",
                      [e["reason"] for e in rejected["ledger"][cs_index]["missing_or_conflicting"]])
        self.assertEqual(rejected["decision"]["status"], "incomplete")
        self.assertFalse(rejected["goal_complete"])
        f.authority["arms"][key] = original

        # Rebind a mutated C# report and its outer stdout, but retain its false
        # claim of passing all observations. The full assembly must reject it.
        report = json.loads(Path(original["quality"]["path"]).read_text())
        isolated = json.loads(Path(original["isolation"]["path"]).read_text())
        changed = deepcopy(report)
        lines = changed["execution"]["stdout"].splitlines()
        prefix, value = lines[-1].rsplit(":", 1)
        lines[-1] = prefix + (":false" if value == "true" else ":true")
        changed["execution"]["stdout"] = "\n".join(lines) + "\n"
        arm = deepcopy(original)
        arm["quality"] = f.trusted("mixed-negative/quality.json", changed)
        arm["isolation"] = f.trusted("mixed-negative/isolation.json", {
            **isolated, "stdout": base64.b64encode(zlib.compress(a.canonical(changed))).decode(),
        })
        f.authority["arms"][key] = arm
        rejected = f.run()
        self.assertEqual(rejected["global_errors"], [])
        trial = next(t for t in rejected["run"]["trials"] if t["index"] == cs_index)
        self.assertEqual(trial["status"], "failed")
        self.assertEqual(trial["reason"], "independent_quality_failed")
        self.assertEqual(rejected["decision"]["status"], "incomplete")
        self.assertFalse(rejected["goal_complete"])
        f.authority["arms"][key] = original
        assert_positive(f.run())


if __name__ == "__main__":
    unittest.main()
