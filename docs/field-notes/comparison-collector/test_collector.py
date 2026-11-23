"""Synthetic files/streams/Job receipts only: no SSH, inference or service actions."""
import base64
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import collect_comparison as L
R = L.protocol


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="collection-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.nonce = "0123456789abcdef"
        self.work = self.root / ("evo-comparison-" + self.nonce)
        self.work.mkdir(mode=0o700)
        self.request = {"artifact": "aotg-comparison-collection-request", "version": 1,
                        "run_id": self.work.name, "nonce": self.nonce, "owner_uid": os.geteuid(), "owner_gid": os.getegid(),
                        "work_root": str(self.work), "work_identity": {"device": self.work.stat().st_dev, "inode": self.work.stat().st_ino},
                        "authorization_sha256": "1" * 64, "client_plan_sha256": "2" * 64, "worker_plan_sha256": "3" * 64,
                        "owner_result_sha256": "4" * 64,
                        "schedule": [{"index": i, "candidate_id": "baseline", "comparison_id": "candidate-a",
                                      "workload_id": "cpp-test", "block": i // 16, "profile_sha256": "5" * 64} for i in range(64)]}
        self.owner = {"artifact": "aotg-owner-entry-result", "version": 1, "nonce": self.nonce,
                      "authorization_sha256": self.request["authorization_sha256"], "status": "maintenance-returned",
                      "unit_restore_verified": True}
        self.owner_raw = R.canon(self.owner)
        self.request["owner_result_sha256"] = R.sha(self.owner_raw)
        self.summary = {"artifact": "aotg-evo-worker-result", "version": 1, "run_id": self.work.name,
                        "plan_sha256": self.request["worker_plan_sha256"], "status": "completed-awaiting-independent-quality",
                        "arms": copy.deepcopy(self.request["schedule"])}
        for label, _, _ in R.inventory():
            file = self.path(label); file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            file.write_bytes(b"{}\n" if not label.endswith(".log") else b"synthetic log\n"); file.chmod(0o600)
        self.path("work/owner-entry-result.json").write_bytes(self.owner_raw)
        self.path("task/summary.json").write_bytes(R.canon(self.summary))
        self.seed = {"ssh": ["/synthetic/ssh.exe", "-T", "-o", "BatchMode=yes", "-o", "ForwardAgent=no", "synthetic-host"], "windows_transport": {
            "wrapper": {"sha256": "6"*64}, "helper": {"windows_path": "C:\\synthetic\\helper.cs", "sha256": "7"*64},
            "ssh": {"path": "/synthetic/ssh.exe", "windows_path": "C:\\synthetic\\ssh.exe", "sha256": "8"*64}, "windows_root": "C:\\synthetic\\jobs"}}
        self.source = Path(R.__file__).read_bytes()

    def path(self, label):
        group, name = label.split("/", 1)
        return self.work / ("work/" + name if group == "task" else name)

    def capture(self, hook=None):
        rows = []
        def emit(row):
            rows.append(copy.deepcopy(row))
            if hook: hook(row)
        result = R.collect(self.request, emit)
        return rows, result

    def wire(self, rows):
        return b"".join(R.canon(x)+b"\n" for x in rows)

    def decode(self, rows):
        d = L.create_output(self.root / "decoded")
        try: return L.decode_wire(io.BytesIO(self.wire(rows)), self.request, d, deadline=float("inf"))
        finally: os.close(d)

    def callback(self, rows, mutate=None, after=None):
        def run(**kw):
            self.assertEqual((kw["remote_seconds"], kw["wall_seconds"], kw["cleanup_seconds"]), (60,70,20))
            raw = self.wire(rows)
            for offset in range(0, len(raw), 65536): kw["stdout"].write(raw[offset:offset+65536])
            t=self.seed["windows_transport"]; stem="a"*24
            job = {"artifact":"aotg-windows-ssh-job","version":1,"wrapper_sha256":t["wrapper"]["sha256"],
                   "helper":{"path":t["helper"]["windows_path"],"sha256":t["helper"]["sha256"]},
                   "executable":{"path":t["ssh"]["windows_path"],"sha256":t["ssh"]["sha256"]},
                   "argv":self.seed["ssh"][1:]+["/usr/bin/python3.14","-I","-S","-B","-"],
                   "cwd":t["windows_root"],"wall_seconds":70,
                   "cancel_path":t["windows_root"]+"\\"+stem+".cancel","result_path":t["windows_root"]+"\\"+stem+".result.json"}
            exit_code=0 if rows[-1].get("status")=="complete" else 2
            receipt={"artifact":"aotg-windows-ssh-job-result","version":1,"plan_sha256":R.sha(R.canon(job)),
                     "helper_sha256":t["helper"]["sha256"],"wrapper_sha256":t["wrapper"]["sha256"],"result":{
                         "ProcessId":1234,"ExitCode":exit_code,"TimedOut":False,"Cancelled":False,"JobEmpty":True,"Seconds":1.5,
                         "ExecutableSha256":t["ssh"]["sha256"],"CleanupScope":"windows-job-object"}}
            response={"job_plan_bytes":R.canon(job),"receipt_bytes":R.canon(receipt),"wrapper_returncode":exit_code,
                      "stdout_sha256":R.sha(raw),"stderr_sha256":R.sha(b""),"payload_sha256":R.sha(kw["payload"]),"callback_error":None}
            if mutate: mutate(response,job,receipt)
            if after: after()
            return response
        return run

    def run_local(self, rows, mutate=None, after=None, clock=None):
        return L.run_collection(self.request,self.seed,self.owner_raw,self.root/"output",self.callback(rows,mutate,after),
                                remote_source=self.source,remote_source_sha256=R.sha(self.source),
                                **({"clock":clock} if clock else {}))


class RemoteTests(Fixture):
    def test_complete_fixed_inventory_and_rereads_accounted(self):
        rows, final=self.capture()
        self.assertEqual(final["status"],"complete"); self.assertEqual(final["complete_files"],517)
        self.assertEqual(final["total_read_bytes"],final["raw_bytes"]+2*(len(self.owner_raw)+len(R.canon(self.summary))))
        self.assertFalse(final["independent_restoration_verified"])
        self.assertEqual(self.decode(rows)["final"],final)

    def test_missing_is_explicit_incomplete_no_truncated_success(self):
        self.path("task/arm-063/server-ready.json").unlink()
        rows, final=self.capture(); self.assertEqual(final["status"],"incomplete")
        failed=[x for x in rows if x.get("status")=="incomplete" and x.get("artifact")=="aotg-comparison-file-close"]
        self.assertEqual(len(failed),1); self.assertEqual(failed[0]["reason"],"FileNotFoundError")
        self.assertEqual(self.decode(rows)["final"]["complete_files"],516)

    def test_symlink_and_hardlink_refused(self):
        for name in ("config.json","settings.json"):
            self.path("task/arm-000/"+name).unlink()
        self.path("task/arm-000/config.json").symlink_to(self.path("task/arm-001/config.json"))
        os.link(self.path("task/arm-001/settings.json"),self.path("task/arm-000/settings.json"))
        rows, final=self.capture(); self.assertEqual(final["status"],"incomplete")
        self.assertGreaterEqual(sum(x.get("reason")=="nonregular_or_linked_file" for x in rows),2)

    def test_fifo_is_nonblocking_refusal(self):
        p=self.path("task/arm-000/config.json");p.unlink();os.mkfifo(p,0o600)
        rows, final=self.capture();self.assertEqual(final["status"],"incomplete")
        self.assertTrue(any(x.get("reason")=="nonregular_or_linked_file" for x in rows))

    def test_unsafe_mode_and_directory_owner_guard(self):
        self.path("task/arm-000/config.json").chmod(0o666)
        _, final=self.capture();self.assertEqual(final["status"],"incomplete")
        self.request["owner_uid"]+=1
        with self.assertRaises(R.CollectionError): self.capture()

    def test_wrong_owner_or_summary_before_capture(self):
        self.summary["arms"][0]["profile_sha256"]="f"*64
        self.path("task/summary.json").write_bytes(R.canon(self.summary))
        _, final=self.capture();self.assertEqual(final["attempted_files"],0)
        self.assertIn("summary_arm_binding",final["errors"])

    def test_duplicate_summary_row_refused(self):
        self.summary["arms"][1]=self.summary["arms"][0]
        self.path("task/summary.json").write_bytes(R.canon(self.summary))
        _,final=self.capture();self.assertIn("summary_arm_index",final["errors"])

    def test_changed_file_after_read_refused(self):
        def change(row):
            if row.get("artifact")=="aotg-comparison-file-chunk" and row["index"]==5:
                self.path("task/arm-000/result.json").write_bytes(b'{"changed":1}')
        rows,final=self.capture(change);self.assertEqual(final["status"],"incomplete")
        self.assertTrue(any(x.get("reason")=="file_changed_during_collection" for x in rows))

    def test_root_replaced_detected_without_following(self):
        def change(row):
            if row.get("artifact")=="aotg-comparison-file-close" and row["index"]==516:
                self.work.rename(self.root/"old");self.work.mkdir(mode=0o700)
        _,final=self.capture(change);self.assertIn("work_root_changed",final["errors"])

    def test_symlink_ancestor_refused(self):
        self.work.rename(self.root/"actual");self.work.symlink_to(self.root/"actual",target_is_directory=True)
        _,final=self.capture();self.assertFalse(final["preconditions_verified"])

    def test_jsonl_tail_and_record_limit_refused(self):
        self.path("task/resources.jsonl").write_bytes(b"{}")
        self.path("task/resource-observations.jsonl").write_bytes(b"{}\n"*60002)
        rows,final=self.capture();self.assertEqual(final["status"],"incomplete")
        self.assertTrue(any(x.get("reason")=="partial_jsonl_tail" for x in rows))
        self.assertTrue(any(x.get("reason")=="jsonl_record_or_line_limit" for x in rows))
        # The rejected chunk was read but not emitted; partial hash matches transferred bytes.
        close=next(x for x in rows if x.get("artifact")=="aotg-comparison-file-close" and x["index"]==4)
        chunks=[x for x in rows if x.get("artifact")=="aotg-comparison-file-chunk" and x["index"]==4]
        raw=b"".join(base64.b64decode(x["base64"]) for x in chunks)
        self.assertEqual(close["bytes"],len(raw));self.assertEqual(close["partial_sha256"],R.sha(raw))
        self.assertGreater(close["read_bytes"],close["bytes"])

    def test_metadata_counts_towards_aggregate_cap(self):
        with patch.dict(R.LIMITS,{"total_raw_bytes":len(self.owner_raw)+10}):
            _,final=self.capture()
        self.assertEqual(final["status"],"incomplete")
        self.assertEqual(final["total_read_bytes"],len(self.owner_raw)+10)

    def test_sparse_large_file_is_not_read(self):
        p=self.path("task/arm-000/logs/engine-private.log")
        with p.open("wb") as stream:stream.truncate(262145)
        rows,_=self.capture()
        row=next(x for x in rows if x.get("label")=="task/arm-000/logs/engine-private.log" and x.get("status"))
        self.assertEqual(row["reason"],"file_byte_limit");self.assertEqual(row["read_bytes"],0)

    def test_alarm_clock_expiration_stays_incomplete(self):
        values=iter([0,0,61,61])
        rows=[];final=R.collect(self.request,rows.append,clock=lambda:next(values,61))
        self.assertEqual(final["status"],"incomplete");self.assertIn("remote_collection_deadline",final["errors"])


class ReceiverTests(Fixture):
    def test_full_callback_complete_has_no_quality_or_remote_exit_claim(self):
        rows,_=self.capture();result=self.run_local(rows)
        self.assertEqual(result["status"],"complete",result["errors"])
        self.assertTrue(result["transport"]["owned_windows_job_empty"])
        self.assertFalse(result["remote_process_exit_verified"])
        self.assertFalse(result["quality_accepted"])
        self.assertEqual(len(list((self.root/"output").glob("*.raw"))),517)

    def test_missing_remote_file_retains_evidence_and_incomplete(self):
        self.path("task/arm-003/ready.json").unlink()
        rows,_=self.capture();result=self.run_local(rows)
        self.assertEqual(result["status"],"incomplete");self.assertEqual(result["capture"]["final"]["complete_files"],516)

    def test_bad_chunk_offset_refused(self):
        rows,_=self.capture();next(x for x in rows if x["artifact"]=="aotg-comparison-file-chunk")["offset"]=1
        with self.assertRaisesRegex(R.CollectionError,"chunk_order"): self.decode(rows)

    def test_bad_hash_or_truncated_terminal_refused(self):
        rows,_=self.capture();rows.pop()
        with self.assertRaisesRegex(R.CollectionError,"missing_terminal"): self.decode(rows)

    def test_extra_after_final_refused(self):
        rows,_=self.capture();rows.append(rows[-1])
        with self.assertRaisesRegex(R.CollectionError,"after_final"): self.decode(rows)

    def test_forged_complete_count_refused(self):
        rows,_=self.capture();rows[-1]["complete_files"]=516
        with self.assertRaisesRegex(R.CollectionError,"final_counts"): self.decode(rows)

    def test_malformed_jsonl_not_accepted_as_evidence(self):
        self.path("task/resources.jsonl").write_bytes(b"not-json\n")
        rows,final=self.capture();self.assertEqual(final["status"],"complete")
        result=self.run_local(rows);self.assertEqual(result["status"],"incomplete")

    def test_jobempty_false_cannot_complete(self):
        def mutate(response,job,receipt):
            receipt["result"]["JobEmpty"]=False;response["receipt_bytes"]=R.canon(receipt)
        rows,_=self.capture();result=self.run_local(rows,mutate)
        self.assertEqual(result["status"],"incomplete");self.assertIn("transport_or_cleanup_incomplete",result["errors"])

    def test_forged_route_cannot_complete(self):
        def mutate(response,job,receipt):
            job["argv"][1]="different-host";response["job_plan_bytes"]=R.canon(job)
            receipt["plan_sha256"]=R.sha(response["job_plan_bytes"]);response["receipt_bytes"]=R.canon(receipt)
        rows,_=self.capture();result=self.run_local(rows,mutate)
        self.assertEqual(result["status"],"incomplete");self.assertIn("job_route_or_pin",result["errors"])

    def test_wrong_payload_or_stdout_hash_refused(self):
        rows,_=self.capture()
        result=self.run_local(rows,lambda r,*_:r.update(payload_sha256="f"*64))
        self.assertIn("transport_stream_hash",result["errors"])

    def test_local_deadline_no_late_complete(self):
        seconds=[0.0];rows,_=self.capture()
        result=self.run_local(rows,after=lambda:seconds.__setitem__(0,91),clock=lambda:seconds[0])
        self.assertEqual(result["status"],"incomplete");self.assertIn("local_collection_deadline",result["errors"])

    def test_callback_raises_once_persists_failure(self):
        calls=[]
        def callback(**kw):calls.append(1);kw["stdout"].write(b"partial");raise RuntimeError("synthetic secret not logged")
        result=L.run_collection(self.request,self.seed,self.owner_raw,self.root/"output",callback,
            remote_source=self.source,remote_source_sha256=R.sha(self.source))
        self.assertEqual(calls,[1]);self.assertEqual(result["errors"],["RuntimeError"])
        self.assertTrue((self.root/"output/collection-result.json").is_file())

    def test_output_exclusive_and_does_not_follow_link(self):
        output=self.root/"output";output.symlink_to(self.work,target_is_directory=True)
        with self.assertRaises(FileExistsError):L.create_output(output)

    def test_false_owner_restore_never_invokes_callback(self):
        self.owner["unit_restore_verified"]=False;raw=R.canon(self.owner);self.request["owner_result_sha256"]=R.sha(raw)
        with self.assertRaisesRegex(R.CollectionError,"restoration"):
            L.run_collection(self.request,self.seed,raw,self.root/"output",lambda **_:self.fail("callback called"),
                remote_source=self.source,remote_source_sha256=R.sha(self.source))
        self.assertFalse((self.root/"output").exists())

    def test_sink_cap_and_sticky_failure(self):
        sink=L.Sink(io.BytesIO(),3,10,lambda:0)
        sink.write(b"abc")
        with self.assertRaisesRegex(R.CollectionError,"output_limit"):sink.write(b"d")
        self.assertTrue(sink.failed);self.assertEqual(sink.count,3)

    def test_duplicate_json_key_refused(self):
        with self.assertRaisesRegex(R.CollectionError,"duplicate_json_key"):R.parse(b'{"a":1,"a":2}')

    def test_seed_noninteractive_guard_before_any_callback(self):
        self.seed["ssh"].remove("BatchMode=yes")
        with self.assertRaisesRegex(R.CollectionError,"noninteractive"):
            L.run_collection(self.request,self.seed,self.owner_raw,self.root/"output",lambda **_:self.fail("callback called"),
                remote_source=self.source,remote_source_sha256=R.sha(self.source))
        self.assertFalse((self.root/"output").exists())

    def test_changed_protected_after_refused(self):
        rows,_=self.capture();rows[-1]["protected_after"]["owner_result_sha256"]="f"*64
        with self.assertRaisesRegex(R.CollectionError,"protected_before_after"):self.decode(rows)


if __name__ == "__main__":unittest.main()
