"""Synthetic files/clock only; optional private-worker integration uses no live IO."""
import argparse
import ast
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('resource_context_candidate',HERE/'resource_context.py')
H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
CG='/system.slice/aotg-0000000000000000-worker.service'
ROOT={'pid':201,'start_ticks':1001};NATIVE={'pid':202,'start_ticks':1002}
BASE=None;CANDIDATE=None

def proc_stat(pid,ticks):return str(pid)+' (synthetic name) '+' '.join(['S']+['0']*18+[str(ticks)])+'\n'
def pressure():return 'some avg10=0.00 avg60=1.25 avg300=2.50 total=12\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n'
class Files:
    def __init__(self):
        self.values={};self.calls=[];self.group_calls=0;self.after_read=None;self.after_group=None
        for pid,ticks in ((200,1000),(201,1001),(202,1002)):
            self.values['proc',str(pid)+'/stat']=proc_stat(pid,ticks)
            self.values['proc',str(pid)+'/cgroup']='0::'+CG+'\n'
        for name,keys in H.CONTEXT_KEYS.items():
            self.values['proc' if name=='vmstat' else 'cgroup',name]=''.join(k+' '+('115' if k=='pswpout' else '0')+'\n' for k in keys)
        self.values['cgroup','memory.current']='1048576\n';self.values['cgroup','memory.swap.current']='0\n'
        self.values['cgroup','memory.pressure']=pressure();self.values['proc','pressure/memory']=pressure()
    def read(self,domain,name,cap):
        self.calls.append((domain,name,cap));v=self.values[domain,name]
        if isinstance(v,Exception):raise v
        if self.after_read:self.after_read(domain,name)
        return v
    def group_identity(self):
        self.group_calls+=1
        return self.after_group(self.group_calls) if self.after_group else {'device':1,'inode':2}
    def close(self):raise AssertionError('Injected reader must remain caller-owned')

def collect(files,clock=lambda:0.0,**kw):
    return H.collect_resource_context(CG,root_identity=ROOT,native_identity=NATIVE,_files=files,_clock=clock,_worker_pid=200,**kw)

class ContextTests(unittest.TestCase):
    def test_exact_fixed_reads_and_identity_binding(self):
        f=Files();r=collect(f)
        self.assertEqual(r['status'],'observed-bindings-verified');self.assertEqual(r['read_calls'],20)
        self.assertTrue(all(x['verified'] for x in r['bindings'].values()))
        self.assertEqual(r['metrics']['global-vmstat']['value']['values']['pswpout'],115)
        self.assertIsNone(r['guard_accepted']);self.assertFalse(r['atomic_snapshot']);self.assertFalse(r['cause_attribution_proven'])
        self.assertEqual(set((d,n) for d,n,_ in f.calls),set(f.values));self.assertLess(r['read_bytes'],H.CONTEXT_BYTES)
    def test_missing_file_is_null_and_not_zero(self):
        f=Files();f.values['cgroup','memory.swap.current']=FileNotFoundError()
        r=collect(f);self.assertEqual(r['status'],'incomplete')
        self.assertEqual(r['metrics']['cgroup-swap-current'],{'status':'missing','value':None,'reason':'FileNotFoundError'})
    def test_unsupported_counter_is_null_and_partial(self):
        f=Files();f.values['proc','vmstat']='pswpout 115\n'
        r=collect(f);v=r['metrics']['global-vmstat'];self.assertEqual(v['status'],'partial')
        self.assertEqual(v['value']['values']['pswpout'],115);self.assertIsNone(v['value']['values']['pgscan_direct'])
    def test_invalid_or_duplicate_counters_not_accepted(self):
        for text in ('pswpout -1\n','pswpout NaN\n','pswpout 1\npswpout 2\n','pswpout 18446744073709551616\n'):
            with self.subTest(text=text):
                f=Files();f.values['proc','vmstat']=text;r=collect(f)
                self.assertEqual(r['status'],'incomplete');self.assertIsNone(r['metrics']['global-vmstat']['value'])
    def test_nan_pressure_not_accepted(self):
        f=Files();f.values['proc','pressure/memory']=pressure().replace('1.25','NaN');r=collect(f)
        self.assertIsNone(r['metrics']['global-memory-pressure']['value']);self.assertEqual(r['status'],'incomplete')
    def test_stale_owned_native_start_tick_stays_unverified(self):
        f=Files();f.values['proc','202/stat']=proc_stat(202,9000);r=collect(f)
        self.assertFalse(r['bindings']['native']['verified']);self.assertEqual(r['status'],'incomplete')
    def test_pid_changes_during_read_invalidates_binding(self):
        f=Files()
        def after(domain,name):
            if name=='memory.current':f.values['proc','201/stat']=proc_stat(201,1009)
        f.after_read=after;r=collect(f)
        self.assertFalse(r['bindings']['root']['verified']);self.assertEqual(r['status'],'incomplete')
    def test_wrong_worker_cgroup_prevents_metric_reads(self):
        f=Files();f.values['proc','200/cgroup']='0::/unrelated\n';r=collect(f)
        self.assertEqual(r['metrics'],{});self.assertTrue(all(name.endswith(('stat','cgroup')) for _,name,_ in f.calls))
        self.assertEqual(r['status'],'incomplete')
    def test_cgroup_inode_change_is_not_a_complete_snapshot(self):
        f=Files();f.after_group=lambda n:{'device':1,'inode':n};r=collect(f)
        self.assertIn('cgroup-identity-changed',r['errors']);self.assertEqual(r['status'],'incomplete')
    def test_late_read_stops_further_io_without_accepting_ack(self):
        f=Files();clock=[0.0];f.after_read=lambda *_:clock.__setitem__(0,.051)
        r=collect(f,lambda:clock[0]);self.assertEqual(len(f.calls),1);self.assertEqual(r['status'],'incomplete')
        self.assertIn('deadline',r['errors'])
    def test_per_read_and_total_call_limits_enforced(self):
        f=Files();f.values['proc','200/stat']='x'*4097;r=collect(f)
        self.assertIn('total-byte-limit',r['errors'][0]);self.assertEqual(r['status'],'incomplete')
        with patch.object(H,'CONTEXT_READS',1):
            f=Files();r=collect(f);self.assertEqual(len(f.calls),1);self.assertEqual(r['status'],'incomplete')
    def test_no_root_native_or_scope_expansion(self):
        for group in ('/system.slice/../other','/user.slice/aotg-0000000000000000-worker.service',CG+'/child'):
            with self.assertRaises(H.ContextUnavailable):H.collect_resource_context(group,_files=Files(),_clock=lambda:0,_worker_pid=200)
        with self.assertRaises(H.ContextUnavailable):H.collect_resource_context(CG,native_identity=NATIVE,_files=Files())
        with self.assertRaises(H.ContextUnavailable):H.collect_resource_context(CG,root_identity={'pid':True,'start_ticks':1},_files=Files())
    def test_known_pre_engine_state_has_explicit_nonrequested_identities(self):
        r=H.collect_resource_context(CG,_files=Files(),_clock=lambda:0,_worker_pid=200)
        self.assertEqual(r['status'],'observed-bindings-verified')
        self.assertIsNone(r['bindings']['native']['verified']);self.assertIsNone(r['bindings']['root']['requested'])

@unittest.skipUnless(os.name=='posix','POSIX no-follow behavior')
class ReadOnlyFileTests(unittest.TestCase):
    def test_regular_symlink_parent_fifo_and_cap(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'good').write_text('123\n');(root/'link').symlink_to(root/'good')
            (root/'other').mkdir();(root/'other'/'value').write_text('x');(root/'parent-link').symlink_to(root/'other',target_is_directory=True)
            os.mkfifo(root/'fifo');(root/'big').write_bytes(b'x'*65)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                self.assertEqual(H._context_read_at(fd,'good',64),'123\n')
                for name in ('link','parent-link/value','fifo','big','../good'):
                    with self.subTest(name=name),self.assertRaises((OSError,H.ContextUnavailable)):H._context_read_at(fd,name,64)
            finally:os.close(fd)

if __name__=='__main__':
    unittest.main(verbosity=2)
