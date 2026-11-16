"""Offline v2 comparison contracts and fake execute lifecycle; no host/GPU/SSH calls."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
import socket
import time
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
from aotg.field_evidence import freeze_plan

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value);return value
W=module('comparison_worker_test',ROOT/'field-worker-v2.py')
C=module('comparison_client_test',ROOT/'k8-field-runner-v2.py')

def field_for(plan):
    return freeze_plan(identity_sha256='a'*64,verifier_sha256=C.VERIFIER_SHA256,
        candidates=[{'id':p['id'],'profile_sha256':p['profile_sha256']} for p in plan['profiles']],
        workloads=[{'id':name,'input_sha256':'b'*64,'tests_sha256':C.CATALOG_SHA256,'cache_cohort':'synthetic-fixed'}
                   for name in ['cpp-half-open-interval','csharp-atomic-batch']],baseline_id='baseline512',
        blocks=4,limits={'trial_seconds':180,'total_seconds':5340,'max_temperature_c':80,
                         'min_mem_available_bytes':48*1024**3,'max_swapout_bytes':0},metric_gates={})

def plan_for(root):
    protected = root / "inputs"
    run_id = "startup-synthetic"
    desc = lambda name: {"path": str(protected / name), "sha256": "0" * 64}
    plan = {
        "artifact": "aotg-evo-worker-plan", "version": 2,
        "run_id": run_id, "worker_sha256": "0" * 64,
        "maintenance_unit": "aotg-synthetic.service", "task_root": str(root / run_id),
        "control_root": str(protected / "control"),
        "source_roots": [str(protected / "control/serve")],
        "source_files": [desc("control/serve/server.py")], "dependency_packages": [],
        "api_key_file": str(protected / "key"), "path_dirs": [str(protected / "bin")],
        "library_dirs": [str(protected / "lib")], "readonly_roots": [str(protected)],
        "gpu": {"bdf": "0000:01:00.0", "hip_index": 0, "arch": "gfx1151",
                "vendor": "0x1002", "device": "0x1586"},
        "strata_dirs": {k: str(protected / k) for k in ("install", "data", "components")},
        "max_seconds": 5340, "kernel_since": "2026-11-16 00:00:00 UTC",
        "required_alarm_keys": ["synthetic-alarm"],
    }
    for name in ("worker_python", "python", "engine", "telemetry", "hip_probe",
                 "journalctl", "active_config", "expert_profile"):
        plan[name] = desc(name)
    plan["native_argv"] = ["--serve", "--prefill", W.TOKEN, "--expert-profile", W.EXPERT]
    for key, value in (("--max-context", "131072"), ("--kv", "int8"), ("--draft", "dflash2"),
                       ("--spec", "8"), ("--draft-conf", "0.35"), ("--draft-fallback", "none")):
        plan["native_argv"] += [key, value]
    for key in ("--pack", "--native", "--ple-gguf", "--draft-model", "--mtp-draft-vocab"):
        plan["native_argv"] += [key, str(protected / ("model-" + key[2:]))]
    plan["profiles"] = [{"id": "baseline512", "prefill": 512,
                         "profile_sha256": W.profile_identity(plan, 512)}]
    plan['budget_policy_sha256']=W.BUDGET_POLICY_SHA256
    plan['field_plan']=desc('field-plan.json')
    plan['field_validator_modules']={name:{'path':str(protected/(name+'.py')),'sha256':value}
                                     for name,value in W.FIELD_VALIDATOR_SHAS.items()}
    plan['profiles']=[{'id':name,'prefill':prefill,'profile_sha256':W.profile_identity(plan,prefill)}
                      for name,prefill in [('baseline512',512),('prefill256',256),('prefill1024',1024)]]
    field=field_for(plan)
    plan['schedule']=field['schedule']
    return plan

class Scenario:
    def __init__(self, root, failure=None):
        self.plan = plan_for(root)
        self.root, self.failure, self.now = root, failure, 0.0
        self.calls = {"popen": 0, "cleanup": 0, "barrier": 0, "close": 0,
                      "kernel": 0, "hip": 0, "ticks": 0}
        inputs = root / "inputs"; inputs.mkdir()
        for name, data in (("telemetry", b'ERROR_PATTERN = "SYNTHETIC-NO-MATCH"\n'),
                           ("expert_profile", b"synthetic profile"), ("key", b"synthetic-key")):
            path = inputs / name; path.write_bytes(data); path.chmod(0o600)
            if name in self.plan:
                self.plan[name]["sha256"] = hashlib.sha256(data).hexdigest()
        self.base = {"model_name": "synthetic-model", "exe": self.plan["engine"]["path"],
                     "cwd": self.plan["control_root"], "backend": "hip", "drafting": "dflash2",
                     "user_args": ["--prefill", "512", "--max-context", "131072"],
                     "args": ["--expert-profile", self.plan["expert_profile"]["path"]],
                     "args_written": ["--expert-profile", self.plan["expert_profile"]["path"]]}
        self.plan["profiles"][0]["profile_sha256"] = W.profile_identity(self.plan, 512)
        self.proc = None
        self.mon = None

    @property
    def task(self): return Path(self.plan["task_root"])
    @property
    def arm(self): return self.task / ("arm-"+str(max(0,self.calls["popen"]-1)).zfill(3))
    def sleep(self, seconds): self.now += seconds
    def preflight(self, plan):
        W.validate_plan(plan)
        if self.failure == "preflight": raise W.StopTrial("synthetic preflight failure")
        return copy.deepcopy(self.base)
    def hip(self, plan, monitor):
        self.calls["hip"] += 1
        if self.failure == "insufficient-budget": self.now += 100
    def engine(self, plan, owned, profile, arm):
        if self.failure == "readiness-timeout": return None
        if self.failure == "native-replaced" and (arm / "startup-ready.json").exists(): return 8124
        return 8123
    def kernel(self, plan, pattern):
        self.calls["kernel"] += 1
        return {"status": "errors" if self.failure in ("kernel", "all-finalizers") else "clear",
                "since": plan["kernel_since"], "errors": [], "synthetic": True}
    def barrier(self, group, baseline):
        self.calls["barrier"] += 1
        if self.failure in ("barrier", "ownership-constructor", "all-finalizers"):
            raise W.StopTrial("synthetic unresolved cgroup")
    def popen(self, argv, **kwargs):
        self.calls["popen"] += 1
        if self.failure == "launch": raise OSError("synthetic launch failure")
        assert "--offline" in argv and "--parallel" in argv and argv[argv.index("--parallel")+1] == "1"
        assert argv[argv.index("--port")+1] == "19480"
        assert kwargs["start_new_session"] and kwargs["cwd"] == self.arm
        scenario = self
        class Process:
            pid = 7123
            def poll(self):
                if scenario.failure == "exit-load": return 7
                if scenario.failure == "exit-idle" and (scenario.arm / "startup-ready.json").exists(): return 9
                return None
        self.proc = Process()
        if self.failure != "readiness-timeout":
            ready = {"pid": self.proc.pid, "bound_host": "127.0.0.1", "bound_port": 19480,
                     "model_state": "ready", "api_state": "ready", "model_id": self.base["model_name"]}
            if self.failure == "bad-ready": ready["bound_port"] = 19481
            (self.arm / "server-ready.json").write_text(json.dumps(ready))
        return self.proc
    def owned(self, process, group):
        if self.failure == "ownership-constructor":
            raise W.StopTrial("synthetic ownership constructor failure")
        scenario = self
        class Owned:
            def cleanup(self):
                scenario.calls["cleanup"] += 1
                if scenario.failure in ("cleanup", "all-finalizers"): raise W.StopTrial("synthetic cleanup failure")
        return Owned()
    def monitor(self, plan, telemetry, stream, deadline, observation_stream):
        scenario = self
        class FakeMonitor:
            pause_since = None
            def tick(self, owned, native, force=False):
                scenario.calls["ticks"] += 1
                scenario.now += .25
                W.require(scenario.now < deadline, "Total worker time limit")
                ready_path=scenario.task/'ready.json'
                if ready_path.exists():
                    ready=json.loads(ready_path.read_text());done={k:ready[k] for k in W.MARKER_IDENTITY_FIELDS}
                    done.update(artifact='aotg-field-done',version=1,status='completed',evidence_sha256='e'*64)
                    if scenario.failure=='wrong-comparison':done['comparison_id']='wrong-comparison'
                    target=scenario.task/('done-'+str(ready['index'])+'.json')
                    if not target.exists():target.write_text(json.dumps(done))
                if scenario.failure == "guard-prelaunch" and owned is None:
                    raise W.StopTrial("synthetic guard failure")
                if scenario.failure in ("guard-load","guard-and-close") and owned is not None:
                    raise W.StopTrial("synthetic guard failure")
                if scenario.failure == "guard-idle" and (scenario.arm / "startup-ready.json").exists():
                    raise W.StopTrial("synthetic guard failure")
            def finish_scan(self): pass
            def close(self):
                scenario.calls["close"] += 1
                if (scenario.failure in ("monitor-close", "all-finalizers", "guard-and-close")
                        or (scenario.failure == "outer-monitor-close" and scenario.calls["close"] == 2)):
                    raise TimeoutError("synthetic journal close timeout")
        self.mon = FakeMonitor()
        return self.mon
    def run(self):
        original_sha = W.sha_file
        def sha(path):
            if str(path).startswith("/proc/"):
                return "1" * 64 if self.failure == "engine-hash" else self.plan["engine"]["sha256"]
            return original_sha(path)
        fake_subprocess = types.SimpleNamespace(Popen=self.popen, DEVNULL=-3, STDOUT=-2)
        with contextlib.ExitStack() as stack:
            for name, value in {
                "current_unit": lambda p: "synthetic-cgroup", "preflight": self.preflight,
                "verify_file": lambda d: None, "verify_hip": self.hip, "verify_engine": self.engine,
                "Monitor": self.monitor, "OwnedProcesses": self.owned,
                "cgroup_identities": lambda group: {"synthetic-baseline"},
                "require_clean_cgroup": self.barrier, "final_kernel_scan": self.kernel,
                "sha_file": sha, "subprocess": fake_subprocess,
                "time": types.SimpleNamespace(monotonic=lambda: self.now, sleep=self.sleep, time=lambda:1700000000+self.now),
                "bootstrap": lambda *a: "# synthetic never executed",
            }.items(): stack.enter_context(patch.object(W, name, value))
            stack.enter_context(patch.dict(os.environ, {"EVO_GPU_BDF": "synthetic-original"}))
            old_umask = os.umask(0o077); os.umask(old_umask)
            try:
                W.execute(self.plan, "a" * 64)
            finally:
                self.environment_restored = os.environ.get("EVO_GPU_BDF") == "synthetic-original"
                os.umask(old_umask)

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='aotg-v2-contract-fake-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.plan=plan_for(self.root);self.field=field_for(self.plan)
        inputs=self.root/'inputs';inputs.mkdir()
        for name in W.FIELD_VALIDATOR_SHAS:
            (inputs/(name+'.py')).write_bytes((ROOT/'runtime/aotg'/(name+'.py')).read_bytes())
    def test_exact64_balanced_schedule_validates_with_reviewed_real_validator(self):
        self.assertIs(W.validate_plan(self.plan),self.plan)
        self.assertIs(W.validate_field_contract(self.plan,self.field),self.field)
        counts={name:sum(x['candidate_id']==name for x in self.field['schedule']) for name in ['baseline512','prefill256','prefill1024']}
        self.assertEqual(counts,{'baseline512':32,'prefill256':16,'prefill1024':16})
        self.assertFalse(any(x.startswith('_aotg_comparison_v2_verified') for x in sys.modules))
    def test_truncation_shared_baseline_wrong_order_or_block_rejected_even_when_both_plans_agree(self):
        for mode in ['sixteen','shared32','swap-order','three-blocks','different-block','boolean-index','boolean-block']:
            f=copy.deepcopy(self.field);p=copy.deepcopy(self.plan)
            if mode=='sixteen':f['schedule']=f['schedule'][:16]
            elif mode=='shared32':f['schedule']=f['schedule'][:32]
            elif mode=='swap-order':f['schedule'][0]['candidate_id']='prefill256'
            elif mode=='three-blocks':f['blocks']=3
            elif mode=='different-block':f['schedule'][4]['block']=2
            elif mode=='boolean-index':f['schedule'][0]['index']=False
            else:f['schedule'][0]['block']=False
            p['schedule']=copy.deepcopy(f['schedule'])
            with self.subTest(mode=mode),self.assertRaises((W.StopTrial,ValueError)):
                W.validate_field_contract(p,f)
    def test_old_version_budget_quality_pair_and_profile_are_rejected(self):
        for key,value in [('version',1),('max_seconds',2040),('max_seconds',5341),('budget_policy_sha256','0'*64)]:
            p=copy.deepcopy(self.plan);p[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(W.StopTrial):W.validate_plan(p)
        for mutate in [lambda f:f.update(version=1),lambda f:f.update(verifier_sha256='0'*64),
                       lambda f:f['workloads'][0].update(tests_sha256='0'*64),
                       lambda f:f['candidates'][0].update(profile_sha256='1'*64),
                       lambda f:f['limits'].update(total_seconds=2040)]:
            f=copy.deepcopy(self.field);mutate(f)
            with self.assertRaises((W.StopTrial,ValueError)):W.validate_field_contract(self.plan,f)
    def test_validator_drift_rejected_before_module_execution(self):
        p=Path(self.plan['field_validator_modules']['field_evidence']['path'])
        p.write_text("raise AssertionError('must never execute')")
        with self.assertRaisesRegex(W.StopTrial,'before import'):W.validate_field_contract(self.plan,self.field)
    def test_done_marker_requires_every_comparison_binding(self):
        row=self.plan['schedule'][19]
        ready={**row,'run_id':'synthetic','plan_sha256':'a'*64,'field_plan_sha256':'b'*64,
               'schedule_sha256':'c'*64,'profile_sha256':'d'*64}
        done={**ready,'artifact':'aotg-field-done','version':1,'status':'completed','evidence_sha256':'e'*64}
        W.validate_done(done,ready)
        for key in W.MARKER_IDENTITY_FIELDS:
            changed=dict(done);changed[key]=999 if type(changed[key]) is int else 'different'
            with self.subTest(key=key),self.assertRaises(W.StopTrial):W.validate_done(changed,ready)
        old={k:v for k,v in done.items() if k not in ['comparison_id','block','profile_sha256','field_plan_sha256','schedule_sha256']}
        with self.assertRaises(W.StopTrial):W.validate_done(old,ready)
    def test_client_validates_same_full_plan_and_complete_workload_descriptors(self):
        plan={'schedule':self.field['schedule'],'workloads':{w['id']:{'synthetic':w['id']} for w in self.field['workloads']}}
        field=copy.deepcopy(self.field)
        for w in field['workloads']:w['input_sha256']=C.digest(plan['workloads'][w['id']])
        C.validate_comparison_contract(plan,field)
        plan['workloads']['cpp-half-open-interval']['synthetic']='changed'
        with self.assertRaisesRegex(RuntimeError,'descriptor'):C.validate_comparison_contract(plan,field)
    def test_ready_and_done_roundtrip_uses_same_full_identity(self):
        row=self.plan['schedule'][37]
        ready={**row,'run_id':'synthetic','plan_sha256':'a'*64,'field_plan_sha256':'b'*64,
               'schedule_sha256':'c'*64,'profile_sha256':'d'*64}
        captured={}
        def fake_remote(plan,source,timeout,deadline=None):
            tree=ast.parse(source)
            marker=next(n for n in tree.body if isinstance(n,ast.Assign) and any(getattr(x,'id',None)=='MARKER' for x in n.targets))
            captured.update(ast.literal_eval(marker.value));return {'written':True}
        with patch.object(C,'remote',side_effect=fake_remote):C.finish_arm({'remote_task_root':'/synthetic-only'},ready,{'synthetic':True},True,deadline=100)
        W.validate_done(captured,ready)
    def test_lifecycle_capture_refusal_missing_closure_and_sequence_cannot_pass(self):
        opened={'kind':'aotg-proxy-capture-v2','phase':'opened','event_sequence':0}
        closed={'kind':'aotg-proxy-capture-v2','phase':'closed','event_sequence':1,'status':'complete',
                'record_error':False,'active_handlers':0,'rejected_total':0,'rejection_events_dropped':0}
        C.validate_capture([opened,closed])
        for rows in [[opened],[],[opened,{**closed,'rejected_total':1}],[opened,{**closed,'record_error':True}],
                     [opened,{**closed,'event_sequence':3}],[opened,{**closed,'status':'incomplete'}]]:
            with self.assertRaises(RuntimeError):C.validate_capture(rows)

class LifecycleTests(unittest.TestCase):
    def scenario(self,failure=None):
        tmp=tempfile.TemporaryDirectory(prefix='aotg-v2-worker-fake-');self.addCleanup(tmp.cleanup)
        return Scenario(Path(tmp.name),failure)
    def test_all64_fake_arms_handshake_and_cleanup_without_any_native_calls(self):
        s=self.scenario();s.run();result=json.loads((s.task/'summary.json').read_text())
        self.assertEqual(len(result['arms']),64);self.assertEqual(s.calls['popen'],64)
        self.assertEqual(s.calls['cleanup'],64);self.assertEqual(s.calls['barrier'],64)
        self.assertEqual(result['status'],'completed-awaiting-independent-quality')
        self.assertFalse(result['quality_accepted']);self.assertTrue(s.environment_restored)
    def test_wrong_comparison_marker_stops_before_second_arm_and_still_cleans(self):
        s=self.scenario('wrong-comparison')
        with self.assertRaises(W.StopTrial):s.run()
        self.assertEqual(s.calls['popen'],1);self.assertEqual(s.calls['cleanup'],1);self.assertEqual(s.calls['barrier'],1)
        self.assertIn('identity mismatch',json.loads((s.task/'summary.json').read_text())['stop_reason'])
        self.assertTrue(s.environment_restored)
    def test_journal_failure_does_not_skip_other_cleanup_or_kernel_and_summary(self):
        s=self.scenario('all-finalizers')
        with self.assertRaises(W.StopTrial):s.run()
        self.assertEqual(s.calls['cleanup'],1);self.assertEqual(s.calls['barrier'],1);self.assertEqual(s.calls['kernel'],1)
        result=json.loads((s.arm/'result.json').read_text());self.assertEqual(len(result['cleanup_failures']),3)
        self.assertTrue((s.task/'summary.json').is_file());self.assertTrue(s.environment_restored)
    def test_guard_failure_stays_primary_when_journal_close_also_fails(self):
        s=self.scenario('guard-and-close')
        with self.assertRaisesRegex(W.StopTrial,'synthetic guard failure'):s.run()
        result=json.loads((s.task/'summary.json').read_text());self.assertEqual(result['stop_reason'],'synthetic guard failure')
        self.assertEqual(s.calls['cleanup'],1);self.assertEqual(s.calls['barrier'],1);self.assertEqual(s.calls['kernel'],1)
        self.assertTrue(s.environment_restored)
    def test_resource_and_owned_process_guard_algorithms_are_unchanged(self):
        baseline=json.loads((ROOT/'tests/fixtures/guard-baseline-fingerprints.json').read_text())
        self.assertEqual(baseline['baseline_raw_sha256'],
            'cdac8769878976a784bc0008543e376133a86914653b4f0594d2338e3aef653e')
        def fingerprint(node):
            # Empty type_params was added to these AST nodes in Python 3.12.
            for child in ast.walk(node):
                if hasattr(child,'type_params') and not child.type_params:
                    child._fields=tuple(field for field in child._fields if field!='type_params')
            return hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()
        after={n.name:fingerprint(n) for n in ast.parse(Path(W.__file__).read_text()).body
               if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for name in ['resource_check','Monitor','OwnedProcesses','require_clean_cgroup','final_kernel_scan']:
            self.assertEqual(baseline['definitions'][name],after[name],name)


class ProxyIntegrationTests(unittest.TestCase):
    """Real MRO and local socket ownership, never an upstream or model call."""
    def proxy(self):
        records=[]
        proxy=C.BoundedProxy(('127.0.0.1',0),upstream='http://127.0.0.1:1/v1',
            api_key='synthetic',model='synthetic',max_requests=9,max_tokens=16,
            total_seconds=10,request_seconds=1,record=records.append)
        self.addCleanup(proxy.server_close)
        return proxy,records
    def socket_pair(self):
        left,right=socket.socketpair();self.addCleanup(left.close);self.addCleanup(right.close)
        return left,right
    def test_closing_concurrency_and_deadline_refusal_cannot_seal_complete(self):
        for reason in ['closing','concurrency','deadline']:
            with self.subTest(reason=reason):
                proxy,records=self.proxy();accepted,peer=self.socket_pair()
                if reason=='closing':proxy.accepting=False
                elif reason=='deadline':proxy.work_deadline=time.monotonic()-1
                else:proxy.active.update(object() for _ in range(8))
                proxy.process_request(accepted,('127.0.0.1',1))
                self.assertEqual(proxy.connection_refusal_counts[reason],1)
                self.assertEqual(proxy.active_handlers,0);self.assertTrue(proxy.audit_failed)
                self.assertEqual(accepted.fileno(),-1)
                proxy.active.clear();proxy.server_close()
                self.assertEqual(records[-1]['status'],'incomplete')
                with self.assertRaises(RuntimeError):C.validate_capture(records)
                self.assertFalse(any(x.get('kind')=='aotg-proxy-rejection-v2' for x in records))
    def test_thread_creation_failure_is_capture_loss_not_a_valid_zero_request_capture(self):
        proxy,records=self.proxy();accepted,peer=self.socket_pair()
        with patch.object(C.MeasurementProxy,'process_request',side_effect=OSError('synthetic thread failure')):
            with self.assertRaises(OSError):proxy.process_request(accepted,('127.0.0.1',1))
        self.assertEqual(proxy.active,set());self.assertEqual(proxy.connection_refusal_counts['thread_start'],1)
        self.assertEqual(accepted.fileno(),-1)
        proxy.server_close()
        with self.assertRaises(RuntimeError):C.validate_capture(records)
    def test_post_close_refusal_raises_and_still_closes_owned_socket(self):
        proxy,records=self.proxy();proxy.server_close();proxy.accepting=False
        accepted,peer=self.socket_pair()
        with self.assertRaises(OSError):proxy.process_request(accepted,('127.0.0.1',1))
        self.assertEqual(accepted.fileno(),-1)

class ClientExecuteTests(unittest.TestCase):
    """Full runner control flow, fake transports/provider/client only."""
    def scenario(self, *, closed_status='complete', relay_failure=False, advance_probe=None, refusal_counts=None):
        tmp=tempfile.TemporaryDirectory(prefix='aotg-v2-client-fake-');self.addCleanup(tmp.cleanup)
        root=Path(tmp.name);key=root/'synthetic-token';key.write_text('synthetic')
        profile=root/'profile.json'
        profile.write_text(json.dumps({'provider':{'evo':{'options':{'apiKey':'{file:'+str(key)+'}'}}}}))
        row={'index':0,'candidate_id':'baseline512','comparison_id':'prefill256',
             'workload_id':'cpp-half-open-interval','block':0}
        plan={'output_root':str(root/'out'),'profile':str(profile),'max_seconds':5400,
              'cleanup_reserve_seconds':60,'task_seconds':130,'schedule':[row],
              'maintenance_nonce':'0123456789abcdef','upstream':'http://127.0.0.1:1/v1',
              'endpoint':'http://127.0.0.1:2/v1','model':'synthetic','max_requests':9,
              'opencode':'/never/run/opencode','workloads':{'cpp-half-open-interval':{}},
              'tool_path':[],'max_steps':8,'namespace_tools':{}}
        clock=types.SimpleNamespace(now=0)
        history=[]
        class Relay:
            def __init__(self,*args,**kwargs):self.limits=kwargs;history.append(('relay',kwargs))
            def serve_forever(self,**kwargs):pass
            def open_admission(self):history.append(('open',None))
            def close_admission(self):pass
            def drain(self,*,deadline):history.append(('relay-drain',deadline))
            def shutdown(self):pass
            def server_close(self):history.append(('relay-close',None))
            def stop_children(self,*,deadline):
                history.append(('stop-children',deadline))
                if relay_failure:raise RuntimeError('synthetic missing JobEmpty receipt')
        class Proxy:
            def __init__(self,*args,**kwargs):
                self.record=kwargs['record'];self.connection_refusal_counts=refusal_counts if refusal_counts is not None else {'closing':0,'concurrency':0,'deadline':0,'thread_start':0}
                history.append(('proxy',kwargs['work_deadline']))
                self.record({'kind':'aotg-proxy-capture-v2','phase':'opened','event_sequence':0})
            def serve_forever(self,**kwargs):pass
            def close_admission(self):pass
            def drain(self,*,deadline):history.append(('proxy-drain',deadline))
            def shutdown(self):pass
            def server_close(self):
                self.record({'kind':'aotg-proxy-capture-v2','phase':'closed','event_sequence':1,
                    'status':closed_status,'record_error':closed_status!='complete','active_handlers':0,
                    'rejected_total':0,'rejection_events_dropped':0})
                history.append(('proxy-close',None))
        def probe(*args,**kwargs):
            if advance_probe is not None:clock.now=advance_probe
            return {'status':'completed','content':'42'}
        with patch.object(C,'preflight',return_value={}),patch.object(C,'Relay',Relay), \
             patch.object(C,'BoundedProxy',Proxy),patch.object(C.time,'monotonic',side_effect=lambda:clock.now), \
             patch.object(C,'await_arm',return_value=row),patch.object(C,'measure_chat',side_effect=probe), \
             patch.object(C,'run_opencode',return_value={'status':'completed-awaiting-independent-quality','seconds':1}) as client, \
             patch.object(C,'finish_arm',return_value={'written':True}) as finish, \
             patch.object(C,'OwnedSSH',side_effect=AssertionError('Actual SSH forbidden')) as owned:
            result=C.execute(plan,C.digest(plan))
        owned.assert_not_called()
        self.assertEqual(json.loads((root/'out/summary.json').read_text()),result)
        self.assertEqual(json.loads((root/'out/arm-00/result.json').read_text()),result['arms'][0])
        return result,client,finish,history
    def test_incomplete_capture_prevents_done_and_persists_result_and_final_summary(self):
        result,client,finish,history=self.scenario(closed_status='incomplete')
        self.assertEqual(result['status'],'stopped-cleanup-unverified')
        self.assertEqual(result['arms'][0]['status'],'stopped-capture-incomplete')
        self.assertFalse(result['arms'][0]['requests_complete']);self.assertFalse(result['quality_accepted'])
        client.assert_called_once();finish.assert_not_called()
        self.assertIn(('relay-close',None),history)
    def test_late_refusal_or_malformed_counts_cannot_hide_behind_sealed_complete_capture(self):
        zero={'closing':0,'concurrency':0,'deadline':0,'thread_start':0}
        cases=[{**zero,reason:1} for reason in zero]
        cases += [{}, {**zero,'unknown':0}, {**zero,'closing':False}, {**zero,'closing':-1}]
        for counts in cases:
            with self.subTest(counts=counts):
                result,client,finish,history=self.scenario(refusal_counts=counts)
                self.assertEqual(result['status'],'stopped-cleanup-unverified')
                self.assertEqual(result['arms'][0]['status'],'stopped-capture-incomplete')
                self.assertFalse(result['arms'][0]['requests_complete'])
                self.assertEqual(result['arms'][0]['requests'][-1]['status'],'complete')
                self.assertEqual(result['arms'][0]['pre_http_connection_refusals'],counts)
                finish.assert_not_called()

    def test_job_receipt_cleanup_failure_still_saves_summary_and_never_marks_done(self):
        result,client,finish,history=self.scenario(relay_failure=True)
        self.assertEqual(result['status'],'stopped-cleanup-unverified')
        self.assertIn('JobEmpty',str(result['cleanup_errors']))
        self.assertFalse(result['arms'][0]['requests_complete']);finish.assert_not_called()
        self.assertIn(('proxy-close',None),history);self.assertIn(('relay-close',None),history)
    def test_probe_cannot_start_client_after_its_own_work_deadline(self):
        result,client,finish,history=self.scenario(advance_probe=5341)
        self.assertEqual(result['status'],'stopped')
        self.assertIn('deadline',result['arms'][0]['error'])
        client.assert_not_called();finish.assert_not_called()
        self.assertTrue(all(value<=5400 for key,value in history if key in ['stop-children','proxy-drain','relay-drain']))
    def test_complete_capture_keeps_v2_budget_but_never_accepts_quality(self):
        result,client,finish,history=self.scenario()
        self.assertEqual(result['status'],'completed-awaiting-independent-quality')
        self.assertFalse(result['quality_accepted'])
        self.assertEqual(client.call_args.kwargs['max_seconds'],130)
        self.assertEqual(finish.call_args.kwargs['deadline'],5340)
        self.assertIn(('relay',{'work_deadline':5340,'cleanup_deadline':5400}),history)

if __name__=='__main__':unittest.main()
