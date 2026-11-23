"""Explicit private-source regression; fake files/clocks/children only.
Requires trusted private base/candidate/core-test paths. Never starts a real child.
"""
import argparse
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import test_resource_context as H

BASE_SHA='692904c3d1c394fe617a2a16a76284925c2823f2cc52a3e26d3376b7119538f9'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod);return mod

class IntegrationTests(unittest.TestCase):
    def test_original_functions_and_cleanup_unchanged(self):
        before={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(BASE.read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        after={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(CANDIDATE.read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for name,value in before.items():
            if name!='Monitor':self.assertEqual(after[name],value,name)
        for name in ('start_kernel','finish_scan','close'):
            def method(path):
                m=next(n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.ClassDef) and n.name=='Monitor')
                return ast.dump(next(n for n in m.body if getattr(n,'name',None)==name),include_attributes=False)
            self.assertEqual(method(BASE),method(CANDIDATE))
        # Entire original guard/thermal try-body remains byte-independent AST equal.
        def guard(path):
            tree=ast.parse(path.read_bytes());m=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Monitor')
            tick=next(n for n in m.body if getattr(n,'name',None)=='tick')
            return next(n for n in ast.walk(tick) if isinstance(n,ast.Try) and any(isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id=='resource_check' for x in ast.walk(n)))
        self.assertEqual([ast.dump(x,include_attributes=False) for x in guard(BASE).body],[ast.dump(x,include_attributes=False) for x in guard(CANDIDATE).body])
    def monitor(self):
        m=REAL_MONITOR.__new__(REAL_MONITOR);trace=[]
        class Stream(io.StringIO):
            def __init__(self,kind):super().__init__();self.kind=kind
            def write(self,s):trace.append(self.kind+'-write');return super().write(s)
            def flush(self):trace.append(self.kind+'-flush')
        m.plan={'run_id':'synthetic','maintenance_unit':H.CG.rsplit('/',1)[-1],'gpu':{'bdf':'synthetic'},'required_alarm_keys':['alarm'],'task_root':'/synthetic'}
        data={'selected_gpu_bdf':'synthetic','temperatures_c':{'amdgpu:edge':20,'nvme:Composite':20,'nvme:Sensor 2':20},'per_gpu_temperatures_c':{'synthetic':{'edge':20}},'alarms':{'alarm':0},'host_mem_available_bytes':64*2**30,'gpu':{'mem_info_vram_total':64*2**30,'mem_info_vram_used':16*2**30,'mem_info_gtt_used':0},'swap_bytes':{'SwapTotal':2**30,'SwapFree':2**30},'utc':'synthetic'}
        m.telemetry=types.SimpleNamespace(sample=lambda *_:dict(data));m.stream=Stream('resource');m.observation_stream=Stream('observation')
        m.deadline=5340;m.started=0;m.pswpout=115;m.gtt=0;m.last_sample=0;m.observation_sequence=0;m.anchor={'pswpout':115};m.journal=None;m.last_kernel=100;m.pause_since=None
        m.observation_budget=W.ObservationJournal(m.observation_stream,origin=0,deadline=5340,run_id='synthetic')
        m.observation_budget.start({'phase':'startup-anchor'},0)
        owner=types.SimpleNamespace(process=types.SimpleNamespace(pid=201),records={201:H.ROOT,202:H.NATIVE},refresh=lambda:trace.append('guard-owner-refresh'))
        return m,owner,trace
    def tick(self,m,owner,pswpout):
        with patch.object(W.time,'monotonic',return_value=100),patch.object(W,'read_pswpout',return_value=pswpout),patch.object(W.shutil,'disk_usage',return_value=types.SimpleNamespace(free=2**40)):
            m.tick(owner,202,force=True)
    def test_context_after_pass_and_primary_flush_bound_to_owned_roles(self):
        m,o,trace=self.monitor()
        def helper(*a,**kw):
            trace.append('context-read');self.assertEqual(kw['root_identity'],H.ROOT);self.assertEqual(kw['native_identity'],H.NATIVE)
            self.assertEqual(a,('/system.slice/'+m.plan['maintenance_unit'],));kw['_clock']()
            return {'status':'incomplete','value':None}
        with patch.object(W,'collect_resource_context',side_effect=helper):self.tick(m,o,115)
        self.assertLess(trace.index('observation-flush'),trace.index('guard-owner-refresh'))
        self.assertLess(trace.index('guard-owner-refresh'),trace.index('resource-flush'))
        self.assertLess(trace.index('resource-flush'),trace.index('context-read'))
        rows=[json.loads(x) for x in m.observation_stream.getvalue().splitlines()]
        self.assertEqual(rows[2]['primary_sha256'],rows[3]['primary_sha256']);self.assertEqual(rows[2]['guard_verdict'],'passed')
    def test_guard_reject_zero_optional_reads_and_original_error(self):
        m,o,trace=self.monitor()
        with patch.object(W,'collect_resource_context') as helper:
            with self.assertRaisesRegex(W.StopTrial,'New swapout or counter reset'):self.tick(m,o,158)
            helper.assert_not_called()
        self.assertEqual(m.stream.getvalue(),'');self.assertEqual(m.observation_budget.stopped_reason,'guard-rejected')
    def test_reject_write_failure_preserves_guard_error_and_no_context(self):
        m,o,trace=self.monitor();original=m.record_observation
        def broken(record,**kw):
            if record['phase']=='guard-result':raise OSError('synthetic write failure')
            return original(record,**kw)
        m.record_observation=broken
        with patch.object(W,'collect_resource_context') as helper:
            with self.assertRaisesRegex(W.StopTrial,'New swapout or counter reset') as caught:self.tick(m,o,158)
            self.assertTrue(caught.exception.__notes__);helper.assert_not_called()
    def test_original_execute_cleans_after_real_context_or_write_failure(self):
        for failure in ('context','write'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as td:
                scenario=CORE.Scenario(Path(td));real_factory=scenario.monitor
                def factory(plan,telemetry,stream,deadline,observation_stream):
                    fake=real_factory(plan,telemetry,stream,deadline,observation_stream);oldtick=fake.tick
                    def tick(owned,native,force=False):
                        if owned is None:return oldtick(owned,native,force)
                        m,o,_=self.monitor()
                        if failure=='write':
                            def badwrite(_):raise OSError('synthetic observation write')
                            m.observation_stream.write=badwrite
                        with patch.object(W,'collect_resource_context',side_effect=RuntimeError('synthetic sampler fault')):
                            self.tick(m,o,115)
                    fake.tick=tick;return fake
                scenario.monitor=factory
                with self.assertRaises(W.StopTrial):scenario.run()
                self.assertEqual(scenario.calls['popen'],1);self.assertEqual(scenario.calls['cleanup'],1)
                self.assertEqual(scenario.calls['barrier'],1);self.assertEqual(scenario.calls['kernel'],1)
                result=json.loads((scenario.task/'summary.json').read_text())
                self.assertEqual(result['status'],'stopped');self.assertFalse(result['quality_accepted']);self.assertTrue(scenario.environment_restored)
    def test_embedded_helpers_identical_to_public_sources(self):
        after={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(CANDIDATE.read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for filename in ('resource_context.py','serialized_budget.py','observation_journal.py'):
            for node in ast.parse((HERE/filename).read_bytes()).body:
                if getattr(node,'name',None)=='Tests':break
                if isinstance(node,(ast.FunctionDef,ast.ClassDef)):self.assertEqual(after[node.name],ast.dump(node,include_attributes=False),node.name)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--base-worker',required=True,type=Path);parser.add_argument('--candidate-worker',required=True,type=Path);parser.add_argument('--core-tests',required=True,type=Path)
    args=parser.parse_args();BASE=args.base_worker;CANDIDATE=args.candidate_worker
    if hashlib.sha256(BASE.read_bytes()).hexdigest()!=BASE_SHA:raise SystemExit('Unexpected private base')
    W=load('synthetic_integrated_worker',CANDIDATE);REAL_MONITOR=W.Monitor
    CORE=load('synthetic_core_tests',args.core_tests);CORE.W=W
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IntegrationTests))
    if result.skipped:raise SystemExit('Unexpected skipped tests')
    raise SystemExit(not result.wasSuccessful())
