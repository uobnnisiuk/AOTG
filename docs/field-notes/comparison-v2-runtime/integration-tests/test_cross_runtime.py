"""Synthetic cross-runtime protocol check: no engine, service, SSH or model.

The worker's actual execute emits each ready marker. Real client await_arm and
finish_arm execute their generated remote snippets against temporary local files;
the only remote adapter is an in-memory code transport. Real worker validation
consumes done. Host/process/resource boundaries are fakes, explicitly not evidence.
"""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
PINS=json.loads((HERE/'source-pins.json').read_text())['files']

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def verify_test_import_closure(pins):
    """Test harness gate only; not the future production launcher's implementation."""
    runtime={str(p.relative_to(ROOT)) for p in (ROOT/'runtime/aotg').glob('*.py')}
    if {p for p in pins if p.startswith('runtime/aotg/')}!=runtime:
        raise RuntimeError('Incomplete or extra runtime import inventory')
    for name,expected in pins.items():
        path=ROOT/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or sha(path)!=expected:
            raise RuntimeError('Source pin differs before test import: '+name)

def load_checked_fixture(pins):
    verify_test_import_closure(pins)
    path=ROOT/'tests/test_comparison_runtime.py'
    spec=importlib.util.spec_from_file_location('integration_boundary_fakes',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

# Checks all bytes before the existing fixture loads runner/runtime modules.
BASE=load_checked_fixture(PINS)
W,C=BASE.W,BASE.C

class JoinedScenario(BASE.Scenario):
    def __init__(self, root, ready_mutation=None, done_mutation=None):
        super().__init__(root)
        self.ready_mutation=ready_mutation;self.done_mutation=done_mutation
        self.exchanges=[];self.seen=set();self.remote_calls=0
        inputs=root/'inputs'
        for name in W.FIELD_VALIDATOR_SHAS:
            (inputs/(name+'.py')).write_bytes((ROOT/'runtime/aotg'/(name+'.py')).read_bytes())
        self.workloads={}
        for identity,source in [('cpp-half-open-interval','intervals.cpp'),('csharp-atomic-batch','Submission.cs')]:
            folder=inputs/identity;folder.mkdir()
            for name,data in [(source,b'// SYNTHETIC SOURCE; NEVER COMPILED\n'),('verify.sh',b'# SYNTHETIC; NEVER EXECUTED\n'),('prompt.txt',b'Synthetic transport contract, no coding task.')]:
                p=folder/name;p.write_bytes(data);p.chmod(0o600)
            desc=lambda name:{'path':str(folder/name),'sha256':sha(folder/name)}
            self.workloads[identity]={'id':identity,'source':{'name':source,**desc(source)},
                'public_files':[{'name':'verify.sh',**desc('verify.sh')}],'prompt':desc('prompt.txt')}
        self.field=BASE.field_for(self.plan)
        for workload in self.field['workloads']:workload['input_sha256']=C.digest(self.workloads[workload['id']])
        self.plan['schedule']=copy.deepcopy(self.field['schedule'])
        f=inputs/'field-plan.json';f.write_text(json.dumps(self.field,indent=2)+'\n')
        self.plan['field_plan']={'path':str(f),'sha256':sha(f)}
        self.plan['worker_sha256']=sha(ROOT/'field-worker-v2.py')
        self.plan_file=inputs/'worker-plan.json';self.plan_file.write_text(json.dumps(self.plan,indent=2)+'\n')
        self.raw_worker_sha=sha(self.plan_file)
        model='qwen3.8-flash-next-iq3_s';endpoint='http://127.0.0.1:19482/v1'
        profile=inputs/'client-profile.json'
        profile.write_text(json.dumps({'$schema':'https://opencode.ai/config.json','autoupdate':False,'share':'disabled',
            'provider':{'evo':{'npm':'@ai-sdk/openai-compatible','options':{'baseURL':endpoint,'apiKey':'{file:'+str(inputs/'key')+'}'},
            'models':{model:{'limit':{'context':131072,'output':1024},'tool_call':True}}}}}))
        profile.chmod(0o600)
        # These executable-named bytes are never run; preflight only reads their hashes.
        transport={}
        for name,relative in [('wrapper','transport/wrapper.ps1'),('helper','transport/helper.exe'),
                              ('ssh','Windows/System32/OpenSSH/ssh.exe'),('powershell','transport/powershell.exe')]:
            p=inputs/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('SYNTHETIC '+name)
            transport[name]={'path':str(p),'sha256':sha(p)}
        jobs=root/'jobs';jobs.mkdir();transport['linux_root']=str(jobs)
        relay=inputs/'relay.py';relay.write_text('# SYNTHETIC NEVER EXECUTED\n')
        self.client={'artifact':'aotg-k8-field-plan','version':2,'runner_sha256':sha(ROOT/'k8-field-runner-v2.py'),
            'run_id':self.plan['run_id'],'maintenance_nonce':'0000000000000001','max_seconds':5400,
            'task_seconds':130,'cleanup_reserve_seconds':60,'budget_policy_sha256':C.BUDGET_POLICY_SHA256,
            'proxy_capture_version':2,'max_steps':8,'max_requests':9,'endpoint':endpoint,
            'upstream':'http://127.0.0.1:19481/v1','remote_endpoint':'http://127.0.0.1:19480/v1',
            'model':model,'relay_source':{'path':str(relay),'sha256':sha(relay)},
            'ssh':[transport['ssh']['path'],'-F','none','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','synthetic.invalid'],
            'runtime_modules':{str(p.relative_to(ROOT/'runtime')):sha(p) for p in (ROOT/'runtime/aotg').glob('*.py')},
            'quality_catalog':{'path':str(ROOT/'runtime/tests/fixtures/benchmark/catalog.json'),'sha256':C.CATALOG_SHA256},
            'inputs':[{'path':str(self.plan_file),'sha256':self.raw_worker_sha}],
            'windows_transport':transport,'profile':str(profile),'field_plan':str(f),'field_plan_sha256':sha(f),
            'worker_plan_sha256':self.raw_worker_sha,'schedule':copy.deepcopy(self.field['schedule']),
            'workloads':self.workloads,'output_root':str(root/'unused-client-output'),'remote_task_root':str(self.task)}
        # Actual read-only client checks, plus actual full worker plan/field checks.
        self.preview=C.preflight(self.client)
        W.validate_plan(self.plan);W.validate_field_contract(self.plan,self.field)

    def transport(self,plan,source,timeout,*,deadline=None):
        """Run only trusted generated snippets, synchronously against this fake task."""
        self.remote_calls+=1
        tree=ast.parse(source)
        literal={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body
                 if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ['TASK','INDEX','SECONDS','MARKER']}
        assert literal['TASK']==str(self.task)
        assert 'subprocess' not in source and 'systemctl' not in source
        if 'INDEX' in literal:
            # Existing matching row is guaranteed, so generated wait never sleeps.
            current=json.loads((self.task/'ready.json').read_text())
            assert current['index']==literal['INDEX']
        stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout):exec(compile(source,'<synthetic-local-remote-transport>','exec'),{})
        return json.loads(stdout.getvalue())

    def monitor(self,plan,telemetry,stream,deadline,observation_stream):
        scenario=self
        class Monitor:
            pause_since=None
            def tick(self,owned,native,force=False):
                scenario.calls['ticks']+=1;scenario.now+=.25
                W.require(scenario.now<deadline,'Synthetic monotonic total cutoff')
                path=scenario.task/'ready.json'
                if not path.exists():return
                ready=json.loads(path.read_text());index=ready['index']
                if index in scenario.seen:return
                scenario.seen.add(index)
                if scenario.ready_mutation:
                    key,value=scenario.ready_mutation;ready[key]=value;path.write_text(json.dumps(ready))
                peer_ready=C.await_arm(scenario.client,scenario.field['schedule'][index],deadline=1000000000000)
                outcome={'synthetic_only':True,'index':index,'quality_accepted':False}
                receipt=C.finish_arm(scenario.client,peer_ready,outcome,True,deadline=1000000000000)
                done_path=scenario.task/f'done-{index}.json'
                done=json.loads(done_path.read_text())
                if scenario.done_mutation:
                    key,value=scenario.done_mutation;done[key]=value;done_path.write_text(json.dumps(done))
                scenario.exchanges.append({'ready':peer_ready,'done':done,'receipt':receipt,'outcome':outcome})
            def finish_scan(self):pass
            def close(self):scenario.calls['close']+=1
        return Monitor()

    def run(self):
        original_sha=W.sha_file
        def fake_sha(path):return self.plan['engine']['sha256'] if str(path).startswith('/proc/') else original_sha(path)
        fake_process=types.SimpleNamespace(Popen=self.popen,DEVNULL=-3,STDOUT=-2)
        with contextlib.ExitStack() as stack:
            for name,value in {'current_unit':lambda p:'synthetic-cgroup','preflight':self.preflight,
                'verify_file':lambda d:None,'verify_hip':self.hip,'verify_engine':self.engine,
                'Monitor':self.monitor,'OwnedProcesses':self.owned,'cgroup_identities':lambda g:{'synthetic-baseline'},
                'require_clean_cgroup':self.barrier,'final_kernel_scan':self.kernel,'sha_file':fake_sha,
                'subprocess':fake_process,'time':types.SimpleNamespace(monotonic=lambda:self.now,sleep=self.sleep,time=lambda:1700000000+self.now),
                'bootstrap':lambda *a:'# SYNTHETIC NEVER EXECUTED'}.items():stack.enter_context(patch.object(W,name,value))
            stack.enter_context(patch.object(C,'remote',side_effect=self.transport))
            stack.enter_context(patch.object(C,'OwnedSSH',side_effect=AssertionError('Actual SSH forbidden')))
            old_umask=os.umask(0o077);os.umask(old_umask)
            try:W.execute(self.plan,self.raw_worker_sha)
            finally:os.umask(old_umask)

class CrossRuntimeTests(unittest.TestCase):
    def scenario(self,**kwargs):
        temp=tempfile.TemporaryDirectory(prefix='aotg-v2-joined-synthetic-');self.addCleanup(temp.cleanup)
        return JoinedScenario(Path(temp.name),**kwargs)
    def test_import_inventory_gate_rejects_wrong_missing_or_extra_module_before_loading(self):
        for mode in ['wrong','missing','extra']:
            pins=dict(PINS)
            if mode=='wrong':pins['runtime/aotg/field_proxy.py']='0'*64
            elif mode=='missing':del pins['runtime/aotg/field_proxy.py']
            else:pins['runtime/aotg/injected.py']='0'*64
            with self.subTest(mode=mode),patch.object(importlib.util,'spec_from_file_location') as load:
                with self.assertRaises(RuntimeError):load_checked_fixture(pins)
                load.assert_not_called()
    def test_full_readonly_client_preflight_has_exact_closure_and_raw_identity(self):
        s=self.scenario();self.assertTrue(s.preview['dry_run']);self.assertEqual(s.preview['trials'],64)
        self.assertEqual(s.preview['plan_sha256'],C.digest(s.client))
        self.assertNotEqual(s.raw_worker_sha,C.digest(s.plan))
        self.assertNotEqual(s.client['field_plan_sha256'],C.digest(s.field))
        self.assertFalse(Path(s.client['output_root']).exists())
        self.assertFalse(s.task.exists());self.assertEqual(s.remote_calls,0)
    def test_all64_worker_ready_client_done_real_producers_roundtrip(self):
        s=self.scenario();s.run();summary=json.loads((s.task/'summary.json').read_text())
        self.assertEqual(len(s.exchanges),64);self.assertEqual(s.remote_calls,128)
        self.assertEqual(len(summary['arms']),64);self.assertEqual(s.calls['cleanup'],64)
        self.assertEqual(s.calls['barrier'],64);self.assertEqual(s.calls['kernel'],1)
        self.assertFalse(summary['quality_accepted'])
        self.assertEqual(summary['status'],'completed-awaiting-independent-quality')
        for row,x in zip(s.field['schedule'],s.exchanges,strict=True):
            for key in row:self.assertEqual(x['ready'][key],row[key])
            self.assertEqual(x['ready']['plan_sha256'],s.raw_worker_sha)
            self.assertEqual(x['ready']['field_plan_sha256'],s.client['field_plan_sha256'])
            self.assertEqual(x['ready']['schedule_sha256'],C.digest(s.field['schedule']))
            for key in W.MARKER_IDENTITY_FIELDS:self.assertEqual(x['ready'][key],x['done'][key])
            self.assertEqual(x['done']['evidence_sha256'],C.digest(x['outcome']))
            self.assertTrue(x['receipt']['written'])
    def test_changed_ready_identity_cannot_get_done_and_cleans_first_arm(self):
        cases=[('candidate_id','prefill256'),('comparison_id','prefill1024'),('workload_id','csharp-atomic-batch'),
               ('block',False),('profile_sha256','0'*64),('plan_sha256','0'*64),
               ('field_plan_sha256','0'*64),('schedule_sha256','0'*64)]
        for mutation in cases:
            with self.subTest(mutation=mutation):
                s=self.scenario(ready_mutation=mutation)
                with self.assertRaises(RuntimeError):s.run()
                self.assertEqual(s.calls['popen'],1);self.assertEqual(s.calls['cleanup'],1)
                self.assertEqual(s.calls['barrier'],1);self.assertFalse((s.task/'done-0.json').exists())
                self.assertEqual(json.loads((s.task/'summary.json').read_text())['status'],'stopped')
    def test_changed_done_identity_is_rejected_by_worker_before_next_start(self):
        for mutation in [('comparison_id','prefill1024'),('block',True),('profile_sha256','0'*64),('field_plan_sha256','0'*64)]:
            with self.subTest(mutation=mutation):
                s=self.scenario(done_mutation=mutation)
                with self.assertRaises(W.StopTrial):s.run()
                self.assertEqual(s.calls['popen'],1);self.assertEqual(s.calls['cleanup'],1)
                self.assertEqual(len(s.exchanges),1)
                self.assertEqual(json.loads((s.task/'summary.json').read_text())['status'],'stopped')
    def test_client_preflight_rejects_missing_or_wrong_actual_runtime_pin(self):
        s=self.scenario()
        for mode in ['missing','wrong','extra']:
            p=copy.deepcopy(s.client)
            if mode=='missing':del p['runtime_modules']['aotg/quality.py']
            elif mode=='wrong':p['runtime_modules']['aotg/quality.py']='0'*64
            else:p['runtime_modules']['aotg/injected.py']='0'*64
            with self.subTest(mode=mode),self.assertRaises(RuntimeError):C.preflight(p)
        self.assertFalse(s.task.exists())
    def test_same_canonical_field_with_changed_raw_serialization_is_rejected(self):
        s=self.scenario();path=Path(s.client['field_plan'])
        path.write_text(json.dumps(s.field,separators=(',',':')))
        self.assertEqual(C.digest(json.loads(path.read_text())),C.digest(s.field))
        self.assertNotEqual(sha(path),s.client['field_plan_sha256'])
        with self.assertRaisesRegex(RuntimeError,'raw bytes'):C.preflight(s.client)

if __name__=='__main__':unittest.main()
