"""Phase contracts with synthetic handoff verifier/runner; no real transport."""
import base64
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parent))
from test_collector import Fixture,L,R
import collection_phase as P

FAKE_HANDOFF=b'''import hashlib,json
def validate_plan(value):
 assert value['artifact']=='synthetic-handoff-plan';return value
def validate_auth(auth,watch,expected):
 assert hashlib.sha256(json.dumps(auth,sort_keys=True,separators=(',',':')).encode()).hexdigest()==expected
 assert auth['nonce']==watch['nonce']
def verify_runtime(watch,seed):
 assert seed['run_id']==watch['run_id']
'''


class PhaseTests(Fixture):
    def setUp(self):
        super().setUp()
        self.handoff_source=self.root/"synthetic-handoff.py";self.handoff_source.write_bytes(FAKE_HANDOFF)
        self.addCleanup(patch.stopall)
        patch.object(P,"HANDOFF_SHA256",R.sha(FAKE_HANDOFF)).start()
        self.auth={"nonce":self.nonce};self.auth_raw=R.canon(self.auth);self.auth_sha=R.sha(self.auth_raw)
        self.owner["authorization_sha256"]=self.auth_sha;self.owner_raw=R.canon(self.owner)
        self.profiles=[{"id":"baseline","profile_sha256":"5"*64},{"id":"candidate-a","profile_sha256":"6"*64},{"id":"candidate-b","profile_sha256":"7"*64}]
        schedule=[{k:v for k,v in row.items() if k!="profile_sha256"} for row in self.request["schedule"]]
        field={"schedule":schedule,"candidates":copy.deepcopy(self.profiles)}
        self.field=self.root/"field.json";self.field.write_bytes(R.canon(field))
        self.seed.update(run_id=self.work.name,maintenance_nonce=self.nonce,schedule=schedule,
                         remote_task_root=str(self.work/"work"),field_plan=str(self.field),field_plan_sha256=R.sha(self.field.read_bytes()),
                         output_root=str(self.root/"client"))
        self.seed["windows_transport"]["linux_root"]=str(self.root/"client-jobs")
        seed_path=self.root/"seed.json";seed_path.write_bytes(R.canon(self.seed))
        auth_path=self.root/"authorization.json";auth_path.write_bytes(self.auth_raw)
        self.handoff_root=self.root/"handoff-results"
        self.watch={"artifact":"synthetic-handoff-plan","run_id":self.work.name,"nonce":self.nonce,
                    "controller":self.desc(self.handoff_source),"transport_seed":self.desc(seed_path),
                    "owner_uid":os.getuid(),"owner_gid":os.getgid(),"remote_work_dir":str(self.work),
                    "client_plan_sha256":R.sha(R.canon(self.seed)),"output_root":str(self.handoff_root),
                    "runtime_root":str(self.root/"runtime"),"jobs_root":str(self.root/"handoff-jobs")}
        watch_path=self.root/"watch.json";watch_path.write_bytes(R.canon(self.watch))
        worker={"artifact":"aotg-evo-worker-plan","version":2,"run_id":self.work.name,"schedule":schedule,
                "task_root":str(self.work/"work"),"profiles":self.profiles,"field_plan":{"sha256":R.sha(self.field.read_bytes())}}
        worker_path=self.root/"worker.json";worker_path.write_bytes(R.canon(worker))
        self.seed["worker_plan_sha256"]=R.sha(worker_path.read_bytes());seed_path.write_bytes(R.canon(self.seed))
        self.watch["transport_seed"]=self.desc(seed_path);self.watch["client_plan_sha256"]=R.sha(R.canon(self.seed))
        io_path=self.root/"io.json"
        io_path.write_bytes(R.canon({"authorization_sha256":self.auth_sha,"client_plan_sha256":self.watch["client_plan_sha256"],
            "worker_plan_sha256":self.seed["worker_plan_sha256"],"run_id":self.work.name,"nonce":self.nonce,"output_root":str(self.root/"io-output")}))
        self.watch["io_plan"]=self.desc(io_path);watch_path.write_bytes(R.canon(self.watch))
        self.plan={"artifact":"aotg-comparison-collection-plan","version":1,"driver":self.desc(Path(P.__file__)),
                   "handoff_source":self.desc(self.handoff_source),"handoff_plan":self.desc(watch_path),
                   "authorization":self.desc(auth_path),"worker_plan":self.desc(worker_path),"client_plan":self.desc(seed_path),
                   "sources":{role:self.desc(Path(P.__file__).parent/name) for role,(name,_) in P.SOURCE_PINS.items()},
                   "run_id":self.work.name,"nonce":self.nonce,"owner_uid":os.getuid(),"owner_gid":os.getgid(),
                   "remote_work_root":str(self.work),"authorization_sha256":self.auth_sha,"client_plan_sha256":R.sha(R.canon(self.seed)),
                   "output_root":str(self.root/"phase"),"jobs_root":"/mnt/c/aotg-synthetic-collector-never-created","local_seconds":90}
        self.plan_path=self.root/"collection.json";self.save_plan()
        original=P.directory
        def directory(path):
            if str(path)=="/mnt/c":return original(self.root)
            return original(path)
        patch.object(P,"directory",directory).start()

    def desc(self,path):return {"path":str(path),"sha256":R.sha(path.read_bytes())}
    def save_plan(self):self.plan_path.write_bytes(R.canon(self.plan))
    def prepared(self):return P.prepare(str(self.plan_path),R.sha(self.plan_path.read_bytes()))

    def results(self):
        self.handoff_root.mkdir(mode=0o700)
        (self.handoff_root/"input-bindings.json").write_bytes(R.canon({"plan_raw_sha256":self.plan["handoff_plan"]["sha256"],
            "authorization_raw_sha256":self.plan["authorization"]["sha256"],"watch_plan_sha256":P.digest(self.watch),
            "authorization_sha256":self.auth_sha,"controller_sha256":P.HANDOFF_SHA256}))
        folder=self.handoff_root/"control-001";folder.mkdir(mode=0o700)
        response={"artifact":"aotg-comparison-handoff-control","version":2,"operation":"read-result",
                  "work_identity":self.request["work_identity"],"result_raw_b64":base64.b64encode(self.owner_raw).decode()}
        association={"artifact":"aotg-comparison-handoff-control-association","version":2,"run_id":self.work.name,
                     "watch_plan_sha256":P.digest(self.watch),"authorization_sha256":self.auth_sha,"operation":"read-result",
                     "cleanup_verified":True,"index":1,"payload_sha256":"a"*64,"job_plan_sha256":"b"*64,"receipt_sha256":"c"*64}
        (folder/"stdout.json").write_bytes(R.canon(response));(folder/"association.json").write_bytes(R.canon(association))
        self.summary={"artifact":"aotg-k8-comparison-handoff-result","version":2,"run_id":self.work.name,
                     "watch_plan_sha256":P.digest(self.watch),"authorization_sha256":self.auth_sha,
                     "client_plan_sha256":self.plan["client_plan_sha256"],"owner_reported_unit_restore_verified":True,
                     "owner_result_raw_sha256":R.sha(self.owner_raw),"work_identity":self.request["work_identity"],
                     "owner_control_capture":{"response":self.desc(folder/"stdout.json"),"association":self.desc(folder/"association.json")},
                     "status":"incomplete-or-failed","comparison_complete":False}
        (self.handoff_root/"owner-entry-result.json").write_bytes(self.owner_raw)
        self.save_summary()

    def save_summary(self):(self.handoff_root/"summary.json").write_bytes(R.canon(self.summary))

    def test_prepare_is_readonly_and_future_owner_not_required(self):
        result=self.prepared()
        self.assertEqual(result["canonical_sha256"],P.digest(self.plan))
        self.assertFalse(self.handoff_root.exists());self.assertFalse((self.root/"phase").exists())

    def test_default_cli_preview_does_not_collect(self):
        output=io.StringIO()
        with patch.object(sys,"argv",[P.__file__,"--plan",str(self.plan_path)]),redirect_stdout(output):
            self.assertEqual(P.main(),0)
        self.assertTrue(json.loads(output.getvalue())["dry_run"]);self.assertFalse((self.root/"phase").exists())

    def test_wrong_external_raw_hash_refused_before_helper(self):
        with patch.object(P,"module_from",side_effect=AssertionError("not reached")):
            with self.assertRaisesRegex(ValueError,"raw_hash"):P.prepare(str(self.plan_path),"f"*64)

    def test_wrong_handoff_source_pin_refused(self):
        with patch.object(P,"HANDOFF_SHA256","0"*64):
            with self.assertRaisesRegex(ValueError,"unreviewed_handoff"):self.prepared()

    def test_profile_or_schedule_mismatch_refused(self):
        file=Path(self.plan["worker_plan"]["path"]);worker=json.loads(file.read_text());worker["profiles"][0]["profile_sha256"]="f"*64
        file.write_bytes(R.canon(worker));self.plan["worker_plan"]=self.desc(file);self.save_plan()
        with self.assertRaisesRegex(ValueError,"worker_raw_client_binding"):self.prepared()

    def test_future_client_job_root_collision_refused_before_output_exists(self):
        self.plan["output_root"]=self.seed["windows_transport"]["linux_root"];self.save_plan()
        with self.assertRaisesRegex(ValueError,"paths_overlap"):self.prepared()

    def test_future_io_output_root_collision_refused_before_output_exists(self):
        self.plan["output_root"]=str(self.root/"io-output");self.save_plan()
        with self.assertRaisesRegex(ValueError,"paths_overlap"):self.prepared()

    def test_parent_deadline_cannot_extend_local_ninety(self):
        self.results();prepared=self.prepared();seen=[];original=P.module_from
        def module(raw,path,name):
            if name=="_collection_transport":
                def collect(receiver,**kw):seen.append(kw["deadline"]);return {"status":"complete"}
                return types.SimpleNamespace(collect_after_owner_result=collect)
            return original(raw,path,name)
        with patch.object(P,"module_from",module),patch.object(P,"load_runner",return_value=object()),patch.object(P,"create_job_root"):
            P.collect_once(prepared,plan_sha256=P.digest(self.plan),clock=lambda:10,deadline=500)
        self.assertEqual(seen,[100])

    def test_expired_parent_deadline_refuses_before_prepare_or_job(self):
        prepared=self.prepared()
        with patch.object(P,"prepare",side_effect=AssertionError("not called")):
            with self.assertRaisesRegex(ValueError,"parent_deadline"):
                P.collect_once(prepared,plan_sha256=P.digest(self.plan),clock=lambda:10,deadline=10)

    def test_parent_deadline_shortens_remaining_phase(self):
        self.results();prepared=self.prepared();seen=[];original=P.module_from
        def module(raw,path,name):
            if name=="_collection_transport":
                def collect(receiver,**kw):seen.append(kw["deadline"]);return {"status":"complete"}
                return types.SimpleNamespace(collect_after_owner_result=collect)
            return original(raw,path,name)
        with patch.object(P,"module_from",module),patch.object(P,"load_runner",return_value=object()),patch.object(P,"create_job_root"):
            P.collect_once(prepared,plan_sha256=P.digest(self.plan),clock=lambda:10,deadline=60)
        self.assertEqual(seen,[60])

    def test_owner_and_control_raw_join(self):
        self.results();raw,identity,bindings=P.restored_inputs(self.prepared())
        self.assertEqual(raw,self.owner_raw);self.assertEqual(identity,self.request["work_identity"])
        self.assertEqual(bindings["handoff_summary_sha256"],R.sha((self.handoff_root/"summary.json").read_bytes()))

    def test_false_restore_or_missing_report_refuses_before_job(self):
        prepared=self.prepared()
        with patch.object(P,"load_runner",side_effect=AssertionError("job not reached")):
            with self.assertRaises(FileNotFoundError):P.collect_once(prepared,plan_sha256=P.digest(self.plan))
        self.results();self.summary["owner_reported_unit_restore_verified"]=False;self.save_summary()
        with self.assertRaisesRegex(ValueError,"restore_binding"):P.restored_inputs(self.prepared())

    def test_foreign_or_symlink_control_capture_refused(self):
        self.results();p=self.handoff_root/"control-001/stdout.json"
        copy_path=self.root/"foreign.json";copy_path.write_bytes(p.read_bytes())
        self.summary["owner_control_capture"]["response"]=self.desc(copy_path);self.save_summary()
        with self.assertRaisesRegex(ValueError,"capture_location"):P.restored_inputs(self.prepared())

    def test_changed_control_response_and_fake_local_capture_refused(self):
        self.results();p=self.handoff_root/"control-001/stdout.json";value=json.loads(p.read_text());value["local_capture"]={}
        p.write_bytes(R.canon(value));self.summary["owner_control_capture"]["response"]=self.desc(p);self.save_summary()
        with self.assertRaisesRegex(ValueError,"raw_control_identity"):P.restored_inputs(self.prepared())

    def test_control_cleanup_false_refused(self):
        self.results();p=self.handoff_root/"control-001/association.json";value=json.loads(p.read_text());value["cleanup_verified"]=False
        p.write_bytes(R.canon(value));self.summary["owner_control_capture"]["association"]=self.desc(p);self.save_summary()
        with self.assertRaisesRegex(ValueError,"association_identity"):P.restored_inputs(self.prepared())

    def test_owner_raw_mismatch_refused(self):
        self.results();(self.handoff_root/"owner-entry-result.json").write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError,"owner_raw_binding"):P.restored_inputs(self.prepared())

    def test_old_handoff_source_binding_refused(self):
        self.results();p=self.handoff_root/"input-bindings.json";value=json.loads(p.read_text());value["controller_sha256"]="f"*64
        p.write_bytes(R.canon(value))
        with self.assertRaisesRegex(ValueError,"handoff_input_bindings"):P.restored_inputs(self.prepared())

    def test_consumed_phase_refuses(self):
        (self.root/"phase").mkdir()
        with self.assertRaisesRegex(ValueError,"output_consumed"):self.prepared()

    def test_failed_comparison_with_restored_owner_can_collect_once(self):
        self.results();prepared=self.prepared();calls=[]
        original=P.module_from
        def module(raw,path,name):
            if name=="_collection_transport":
                def collect(receiver,**kw):
                    calls.append(kw);self.assertEqual(kw["request"]["work_identity"],self.request["work_identity"])
                    return {"status":"complete","synthetic_adapter":True}
                return types.SimpleNamespace(collect_after_owner_result=collect)
            return original(raw,path,name)
        with patch.object(P,"module_from",module),patch.object(P,"load_runner",return_value=object()),patch.object(P,"create_job_root"):
            result=P.collect_once(prepared,plan_sha256=P.digest(self.plan))
        self.assertEqual(result["status"],"complete");self.assertEqual(len(calls),1)
        self.assertFalse(result["independent_restoration_verified"])
        with self.assertRaisesRegex(ValueError,"one_use"):P.collect_once(prepared,plan_sha256=P.digest(self.plan))

    def test_late_preparation_does_not_create_any_job(self):
        self.results();prepared=self.prepared();seconds=[0]
        def runner(_):seconds[0]=71;return object()
        with patch.object(P,"load_runner",runner),patch.object(P,"create_job_root",side_effect=AssertionError("not called")):
            with self.assertRaisesRegex(ValueError,"preparation_deadline"):
                P.collect_once(prepared,plan_sha256=P.digest(self.plan),clock=lambda:seconds[0])
        self.assertFalse((self.root/"phase").exists())


if __name__=="__main__":unittest.main()
