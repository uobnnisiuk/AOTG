"""Real local pipe pumping with fake OwnedSSH/Job metadata; never SSH/native jobs."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import select
import sys
import threading
import time
import types
import unittest

sys.path.insert(0,str(Path(__file__).parent))
from test_collector import Fixture, L, R
import collector_transport as T


class FakeProcess:
    def __init__(self,stdout,stderr):
        self.stdout,self.stderr=stdout,stderr;self.returncode=None
    def poll(self):return self.returncode


class FakeJob:
    def __init__(self,seed,argv,seconds,stdout,stderr,*,raw=b"",err=b"",close_error=False,hold=False):
        self.seed,self.argv=seed,argv;self.cancelled=threading.Event();self.done=threading.Event()
        self.close_count=self.cancel_count=0;self.received=b"";self.close_error=close_error
        r0,w0=os.pipe();r1,w1=os.pipe();r2,w2=os.pipe()
        self.stdin=os.fdopen(w0,"wb",buffering=0)
        self.process=FakeProcess(os.fdopen(r1,"rb",buffering=0),os.fdopen(r2,"rb",buffering=0))
        t=seed["windows_transport"];root=Path(t["linux_root"]);stem="a"*24
        self.result=root/(stem+".result.json")
        job={"artifact":"aotg-windows-ssh-job","version":1,"wrapper_sha256":t["wrapper"]["sha256"],
             "helper":{"path":t["helper"]["windows_path"],"sha256":t["helper"]["sha256"]},
             "executable":{"path":t["ssh"]["windows_path"],"sha256":t["ssh"]["sha256"]},
             "argv":argv[1:],"cwd":t["windows_root"],"wall_seconds":seconds,
             "cancel_path":t["windows_root"]+"\\"+stem+".cancel","result_path":t["windows_root"]+"\\"+stem+".result.json"}
        plan_raw=R.canon(job);(root/(stem+".plan.json")).write_bytes(plan_raw);self.plan_sha256=R.sha(plan_raw)
        def produce():
            try:
                os.set_blocking(r0,False)
                while not self.cancelled.is_set():
                    if not select.select([r0],[],[],.01)[0]:continue
                    chunk=os.read(r0,65536)
                    if not chunk:break
                    self.received+=chunk
                for fd,data in ((w1,raw),(w2,err)):
                    os.set_blocking(fd,False);offset=0
                    while offset<len(data) and not self.cancelled.is_set():
                        if select.select([],[fd],[],.01)[1]:
                            try:offset+=os.write(fd,data[offset:offset+65536])
                            except BlockingIOError:pass
                if hold:self.cancelled.wait(2)
            except (OSError,ValueError):pass
            finally:
                for fd in (r0,w1,w2):
                    try:os.close(fd)
                    except OSError:pass
                self.process.returncode=124 if self.cancelled.is_set() else 0
                self.done.set()
        self.thread=threading.Thread(target=produce,daemon=True);self.thread.start()

    def cancel_job(self):self.cancel_count+=1;self.cancelled.set()

    def close(self,*,deadline):
        self.close_count+=1
        if not self.done.is_set():self.cancel_job()
        if not self.done.wait(2):raise RuntimeError("fake thread not ended")
        self.thread.join(timeout=1)
        if self.close_error:raise RuntimeError("synthetic cleanup uncertainty")
        t=self.seed["windows_transport"]
        receipt={"artifact":"aotg-windows-ssh-job-result","version":1,"plan_sha256":self.plan_sha256,
                 "helper_sha256":t["helper"]["sha256"],"wrapper_sha256":t["wrapper"]["sha256"],"result":{
                     "ProcessId":1234,"ExitCode":self.process.returncode,"TimedOut":False,"Cancelled":self.cancelled.is_set(),
                     "JobEmpty":True,"Seconds":.1,"ExecutableSha256":t["ssh"]["sha256"],"CleanupScope":"windows-job-object"}}
        self.result.write_bytes(R.canon(receipt));return receipt


class TransportTests(Fixture):
    def setUp(self):
        super().setUp();self.jobs=self.root/"jobs";self.jobs.mkdir(mode=0o700)
        self.seed["windows_transport"]["linux_root"]=str(self.jobs)
        self.created=[]

    def factory(self,**kwargs):
        def create(*args):
            job=FakeJob(*args,**kwargs);self.created.append(job);return job
        return create

    def invoke(self,callback,*,out=None,clock=time.monotonic):
        out=out if out is not None else io.BytesIO();err=io.BytesIO();payload=b"synthetic input\n"*5000
        result=callback(payload=payload,stdout=out,stderr=err,remote_seconds=60,wall_seconds=70,cleanup_seconds=20,
                        deadline=clock()+90,stdout_limit=384*1024**2,stderr_limit=256*1024)
        return result,out,err,payload

    def test_real_pipes_exact_stdin_stdout_and_stderr_one_job(self):
        out=b"x"*180000;err=b"diagnostic\n"
        callback=T.OwnedSSHCallback(self.seed,self.factory(raw=out,err=err))
        result,stdout,stderr,payload=self.invoke(callback)
        self.assertIsNone(result["callback_error"]);self.assertEqual(stdout.getvalue(),out);self.assertEqual(stderr.getvalue(),err)
        self.assertEqual(self.created[0].received,payload);self.assertEqual(len(self.created),1)
        checked=L.validate_transport(self.seed,result,R.sha(payload),R.sha(out),R.sha(err))
        self.assertTrue(checked["transport_completed"]);self.assertEqual(self.created[0].close_count,1)

    def test_sink_failure_still_cancels_and_closes(self):
        class Broken:
            def write(self,data):raise OSError("synthetic body must not be logged")
        callback=T.OwnedSSHCallback(self.seed,self.factory(raw=b"x"*200000,hold=True))
        result,_,_,_=self.invoke(callback,out=Broken())
        self.assertIn("OSError",result["callback_error"]);self.assertNotIn("synthetic body",result["callback_error"])
        self.assertEqual(self.created[0].close_count,1);self.assertGreaterEqual(self.created[0].cancel_count,1)
        self.assertTrue(self.created[0].done.is_set())

    def test_stderr_bound_refuses_and_cleanup_runs(self):
        callback=T.OwnedSSHCallback(self.seed,self.factory(err=b"x"*(256*1024+1)))
        result,_,stderr,_=self.invoke(callback)
        self.assertIn("transport_output_limit",result["callback_error"])
        self.assertLessEqual(len(stderr.getvalue()),256*1024);self.assertEqual(self.created[0].close_count,1)

    def test_work_deadline_reserves_cleanup_and_never_retries(self):
        seconds=[0.0]
        def selector(*args):seconds[0]=71.0;return [],[],[]
        callback=T.OwnedSSHCallback(self.seed,self.factory(hold=True),clock=lambda:seconds[0],selector=selector)
        result,_,_,_=self.invoke(callback,clock=lambda:seconds[0])
        self.assertIn("transport_work_deadline",result["callback_error"])
        self.assertEqual(self.created[0].close_count,1)
        with self.assertRaisesRegex(ValueError,"one_use"):self.invoke(callback,clock=lambda:seconds[0])
        self.assertEqual(len(self.created),1)

    def test_cleanup_uncertainty_keeps_raw_plan_and_failure(self):
        callback=T.OwnedSSHCallback(self.seed,self.factory(raw=b"data",close_error=True))
        result,_,_,_=self.invoke(callback)
        self.assertIn("cleanup_RuntimeError",result["callback_error"]);self.assertTrue(result["job_plan_bytes"])
        self.assertEqual(result["receipt_bytes"],b"");self.assertEqual(self.created[0].close_count,1)

    def test_adapter_full_fixture_after_hash_bound_restoration(self):
        rows,_=self.capture();runner=types.SimpleNamespace(OwnedSSH=self.factory(raw=self.wire(rows)))
        result=T.collect_after_owner_result(L,request=self.request,seed=self.seed,owner_result_bytes=self.owner_raw,
            output_dir=self.root/"output",verified_runner=runner,remote_source=self.source,remote_source_sha256=R.sha(self.source))
        self.assertEqual(result["status"],"complete",result["errors"]);self.assertEqual(len(self.created),1)
        self.assertFalse(result["independent_restoration_verified"])

    def test_adapter_false_restore_does_not_create_transport(self):
        self.owner["unit_restore_verified"]=False;raw=R.canon(self.owner);self.request["owner_result_sha256"]=R.sha(raw)
        with self.assertRaisesRegex(R.CollectionError,"restoration"):
            T.collect_after_owner_result(L,request=self.request,seed=self.seed,owner_result_bytes=raw,
                output_dir=self.root/"output",verified_runner=types.SimpleNamespace(OwnedSSH=self.factory()),
                remote_source=self.source,remote_source_sha256=R.sha(self.source))
        self.assertEqual(self.created,[])

    def test_new_limits_refused_before_launch(self):
        callback=T.OwnedSSHCallback(self.seed,self.factory())
        with self.assertRaisesRegex(ValueError,"fixed_transport_limits"):
            callback(payload=b"x",stdout=io.BytesIO(),stderr=io.BytesIO(),remote_seconds=61,wall_seconds=70,cleanup_seconds=20,
                     deadline=time.monotonic()+90,stdout_limit=384*1024**2,stderr_limit=256*1024)
        self.assertEqual(self.created,[])

    def test_read_metadata_symlink_or_drift_refused(self):
        p=self.jobs/"actual.json";p.write_bytes(b"{}")
        q=self.jobs/"link.json";q.symlink_to(p)
        with self.assertRaises(OSError):T.read_regular(q)
        with self.assertRaisesRegex(ValueError,"metadata_file"):T.read_regular(p,1)


if __name__=="__main__":unittest.main()
