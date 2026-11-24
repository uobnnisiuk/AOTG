"""Portable synthetic journal tests. No live /proc, network, process or model use.
Run from any directory: python3 -I -S -B /path/test_observation_journal.py
"""
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from dataclasses import replace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # Explicit trusted sibling sources, works under -I.
import capacity_envelope as E
import diagnostic_triage as D
import observation_journal as J
import serialized_budget as B
import test_resource_context as H
from test_observation_reconciliation import ReconciliationTests
from test_observation_evidence_join import EvidenceJoinTests

class JournalTests(unittest.TestCase):
    def make(self, deadline=5340):
        stream=io.StringIO();j=J.ObservationJournal(stream,origin=0,deadline=deadline,run_id='synthetic')
        j.start({'phase':'startup-anchor'},0)
        return j,stream
    def primary(self,j,now,*,force=False,verdict='passed',end=None):
        n=j.primary_ticks
        raw=j.observed({'phase':'observed','sequence':n,'sample':{'pswpout':115}},now,force=force)
        j.verdict({'phase':'guard-result','sequence':n,'guard_verdict':verdict,'sample':{'pswpout':115}},now if end is None else end)
        return raw
    def test_exact_two_phase_flush_and_hash_reference(self):
        j,s=self.make();raw=j.observed({'phase':'observed','sequence':0,'sample':{'x':1}},0,force=True)
        self.assertEqual(len(s.getvalue().splitlines()),2)
        j.verdict({'phase':'guard-result','sequence':0,'guard_verdict':'passed','sample':{'x':1},'anchor':{}},.01)
        calls=[]
        out=j.context_after_primary_flush(lambda c:(calls.append(c()),{'status':'incomplete','value':None})[1],clock=lambda:.02)
        records=[json.loads(x) for x in s.getvalue().splitlines()]
        digest=hashlib.sha256(raw).hexdigest()
        self.assertEqual(records[2]['primary_sha256'],digest);self.assertNotIn('sample',records[2]);self.assertNotIn('anchor',records[2])
        self.assertEqual(json.loads(out)['primary_sha256'],digest);self.assertEqual(calls,[.02])
    def test_rejection_zero_sampler_calls_and_stop_latched(self):
        j,s=self.make();self.primary(j,0,force=True,verdict='rejected')
        calls=[];self.assertIsNone(j.context_after_primary_flush(lambda c:calls.append(1)))
        self.assertEqual(calls,[]);self.assertEqual(j.stopped_reason,'guard-rejected')
        self.assertEqual(json.loads(s.getvalue().splitlines()[-1])['context_schedule']['reason'],'guard-rejected-no-context')
        with self.assertRaises(B.BudgetStop):self.primary(j,3)
    def test_force_budget_does_not_skip_required_samples_or_reset_context(self):
        j,_=self.make();calls=[]
        for _ in range(65):
            self.primary(j,0,force=True)
            j.context_after_primary_flush(lambda c:(calls.append(0),{})[1],clock=lambda:0)
        self.assertEqual(j.primary_ticks,65);self.assertEqual(calls,[0]);self.assertEqual(j._attempts,1)
        with self.assertRaisesRegex(B.BudgetStop,'forced-sample-quota'):self.primary(j,0,force=True)
    def test_actual_start_spacing_not_tick_time(self):
        j,_=self.make();starts=[]
        self.primary(j,0,force=True,end=1.4)
        j.context_after_primary_flush(lambda c:(starts.append(c()),{})[1],clock=lambda:1.5)
        self.primary(j,2,end=2)
        self.assertIsNone(j.context_after_primary_flush(lambda c:self.fail('early read'),clock=lambda:2))
        self.primary(j,3.5)
        j.context_after_primary_flush(lambda c:(starts.append(c()),{})[1],clock=lambda:3.5)
        self.assertEqual(starts,[1.5,3.5])
    def test_returned_missing_preserved_and_not_stop(self):
        j,s=self.make();self.primary(j,0,force=True)
        j.context_after_primary_flush(lambda c:{'status':'incomplete','metrics':{'swap':{'value':None,'reason':'FileNotFoundError'}}},clock=lambda:0)
        self.assertIsNone(j.stopped_reason);self.primary(j,2)
        self.assertEqual(json.loads(s.getvalue().splitlines()[3])['context']['metrics']['swap']['value'],None)
    def test_unexpected_exception_witness_and_no_retry(self):
        j,s=self.make();self.primary(j,0,force=True)
        def broken(c):raise RuntimeError('private detail not serialized')
        with self.assertRaisesRegex(B.BudgetStop,'unexpected-context-exception'):j.context_after_primary_flush(broken,clock=lambda:0)
        self.assertEqual(j._attempts,1);self.assertEqual(j.context_ticks,1)
        self.assertNotIn('private detail',s.getvalue());self.assertIsNone(j.context_after_primary_flush(lambda c:self.fail('retry')))
        with self.assertRaises(B.BudgetStop):self.primary(j,2)
    def test_post_sampler_deadline_rejected_and_latched(self):
        for late in (.051,5340):
            j,s=self.make();self.primary(j,0,force=True);clock=[0]
            def slow(c):clock[0]=late;return {'status':'observed-bindings-verified'}
            with self.assertRaises(B.BudgetStop):j.context_after_primary_flush(slow,clock=lambda:clock[0])
            self.assertEqual(j.context_ticks,1);self.assertEqual(json.loads(s.getvalue().splitlines()[-1])['context']['status'],'incomplete')
    def test_clock_discontinuity_fails_before_optional_io(self):
        for bad in (-1,float('nan'),float('inf')):
            j,_=self.make();self.primary(j,0,force=True)
            with self.assertRaises(B.BudgetStop):j.context_after_primary_flush(lambda c:self.fail('read'),clock=lambda:bad)
            self.assertIsNotNone(j.stopped_reason)
    def test_selected_then_deadline_expires_has_no_read(self):
        j,_=self.make(deadline=1);self.primary(j,0,force=True)
        with self.assertRaises(B.BudgetStop):j.context_after_primary_flush(lambda c:self.fail('read'),clock=lambda:.99)
        self.assertEqual(j._attempts,1)
    def test_no_headroom_skip_stored_without_extra_row(self):
        j,s=self.make(deadline=1);self.primary(j,.96,force=True)
        self.assertIsNone(j.context_after_primary_flush(lambda c:self.fail('read'),clock=lambda:.96))
        self.assertEqual(j.rows,3);self.assertEqual(json.loads(s.getvalue().splitlines()[-1])['context_schedule']['reason'],'deadline-headroom-skipped-no-context')
    def test_headroom_skip_checks_deadline_after_resource_flush(self):
        for end in (.99, 1.0, 1.01):
            with self.subTest(end=end):
                j,s=self.make(deadline=1);self.primary(j,.96,force=True)
                no_read=lambda c:self.fail('read on headroom skip')
                if end<1:
                    self.assertIsNone(j.context_after_primary_flush(no_read,clock=lambda:end))
                    self.assertIsNone(j.stopped_reason)
                else:
                    with self.assertRaisesRegex(B.BudgetStop,'worker-deadline'):
                        j.context_after_primary_flush(no_read,clock=lambda:end)
                    self.assertEqual(j.stopped_reason,'worker-deadline')
                self.assertEqual(j.rows,3)
    def test_interval_skip_checks_deadline_after_resource_flush(self):
        j,s=self.make(deadline=1);self.primary(j,0,force=True)
        j.context_after_primary_flush(lambda c:{},clock=lambda:0)
        self.primary(j,.96,force=True)
        with self.assertRaisesRegex(B.BudgetStop,'worker-deadline'):
            j.context_after_primary_flush(lambda c:self.fail('read on interval skip'),clock=lambda:1)
        self.assertEqual(j._attempts,1)
        self.assertEqual(j.stopped_reason,'worker-deadline')
    def test_selected_context_flush_checks_worker_deadline(self):
        for end in (.99, 1.0, 1.01):
            with self.subTest(end=end):
                j,s=self.make(deadline=1);self.primary(j,.9,force=True)
                now=[.9]
                def sample(clock):
                    now[0]=.92
                    return {'status':'incomplete'}
                with patch.object(s,'flush',side_effect=lambda:now.__setitem__(0,end)):
                    if end<1:
                        self.assertIsNotNone(j.context_after_primary_flush(sample,clock=lambda:now[0]))
                        self.assertIsNone(j.stopped_reason)
                    else:
                        with self.assertRaisesRegex(B.BudgetStop,'worker-deadline'):
                            j.context_after_primary_flush(sample,clock=lambda:now[0])
                        self.assertEqual(j.stopped_reason,'worker-deadline')
                self.assertEqual(j.context_ticks,1)
                self.assertEqual(j.rows,4)
                self.assertEqual(json.loads(s.getvalue().splitlines()[-1])['context']['status'],'incomplete')
    def test_reserves_full_context_before_sampler(self):
        j,s=self.make();j.bytes=j.limits.max_bytes-(2048+1024+16384)+1
        j.observed({'phase':'observed','sequence':0},0,force=True)
        # Use remaining bytes smaller than full context plus outstanding guard.
        j.bytes=j.limits.max_bytes-16384-1024+1
        with self.assertRaisesRegex(B.BudgetStop,'aggregate-byte-cap'):
            j.verdict({'phase':'guard-result','sequence':0,'guard_verdict':'passed'},0)
        self.assertIsNone(j.context_after_primary_flush(lambda c:self.fail('read')))
        self.assertIn('context-capacity-refused',s.getvalue())
    def test_hard_sample_and_context_quota_fail_closed(self):
        j,_=self.make();j.primary_ticks=J.MAX_PRIMARY_SAMPLES
        with self.assertRaisesRegex(B.BudgetStop,'primary-sample-quota'):self.primary(j,0,force=True)
        j,_=self.make();j._attempts=J.MAX_CONTEXT_ATTEMPTS
        with self.assertRaisesRegex(B.BudgetStop,'context-attempt-quota'):self.primary(j,0,force=True)
    def test_sequence_duplicate_and_unfinished_record_rejected(self):
        for index in (1,True,-1):
            j,_=self.make()
            with self.assertRaises(B.BudgetStop):j.observed({'phase':'observed','sequence':index},0,force=True)
        j,_=self.make();j.observed({'phase':'observed','sequence':0},0,force=True)
        with self.assertRaises(B.BudgetStop):j.observed({'phase':'observed','sequence':1},0,force=True)
    def test_exact_utf8_escape_newline_and_line_limit(self):
        j,_=self.make();base={'a':'\u3042'}
        raw=B._line(base,100);self.assertEqual(raw,b'{"a":"\\u3042"}\n')
        for cap in (1024,2048,16384):
            row={'pad':''};row['pad']='x'*(cap-len(B._line(row,cap)))
            self.assertEqual(len(B._line(row,cap)),cap)
            with self.assertRaises(B.BudgetStop):B._line({**row,'pad':row['pad']+'x'},cap)
        with self.assertRaises(B.BudgetStop):j.bounded_resource_line({'pad':'x'*2048})
    def test_oversize_context_stops_without_truncation_or_retry(self):
        j,s=self.make();self.primary(j,0,force=True)
        before=s.getvalue()
        with self.assertRaisesRegex(B.BudgetStop,'serialized-line-cap'):
            j.context_after_primary_flush(lambda c:{'raw':'x'*16384},clock=lambda:0)
        self.assertEqual(s.getvalue(),before);self.assertEqual(j._attempts,1);self.assertIsNone(j.context_after_primary_flush(lambda c:self.fail('retry')))
    def test_partial_write_and_flush_failure_latch(self):
        class Broken(io.StringIO):
            def write(self,s):return len(s)-1
        j=J.ObservationJournal(Broken(),origin=0,deadline=1,run_id='synthetic')
        with self.assertRaises(B.BudgetStop):j.start({'phase':'startup-anchor'},0)
        self.assertIsNotNone(j.stopped_reason)
    def test_flush_confirmed_accounting_on_complete_records(self):
        j,s=self.make();self.primary(j,0,force=True)
        j.context_after_primary_flush(lambda c:{},clock=lambda:0)
        summary=j.summary()
        self.assertEqual(summary['admitted_rows'],4)
        self.assertEqual(summary['admitted_bytes'],len(s.getvalue().encode('ascii')))
        self.assertEqual(summary['flush_confirmed_rows'],summary['admitted_rows'])
        self.assertEqual(summary['flush_confirmed_bytes'],summary['admitted_bytes'])
        self.assertEqual((summary['unconfirmed_admitted_rows'],summary['unconfirmed_admitted_bytes']),(0,0))
    def test_short_or_failed_write_keeps_admission_not_confirmation(self):
        for mode in ('short','raise'):
            with self.subTest(mode=mode):
                j,s=self.make();before=j.summary()
                effect=(lambda value:len(value)-1) if mode=='short' else OSError('synthetic write failure')
                with patch.object(s,'write',side_effect=effect):
                    with self.assertRaises((B.BudgetStop,OSError)):
                        j.observed({'phase':'observed','sequence':0},0,force=True)
                summary=j.summary()
                self.assertEqual(summary['admitted_rows'],before['admitted_rows']+1)
                self.assertEqual(summary['flush_confirmed_rows'],before['flush_confirmed_rows'])
                self.assertEqual(summary['flush_confirmed_bytes'],before['flush_confirmed_bytes'])
                self.assertEqual(summary['unconfirmed_admitted_rows'],1)
                self.assertGreater(summary['unconfirmed_admitted_bytes'],0)
                self.assertEqual(summary['rows'],summary['admitted_rows'])
                self.assertEqual(summary['bytes'],summary['admitted_bytes'])
                with self.assertRaises(B.BudgetStop):
                    j.observed({'phase':'observed','sequence':0},0,force=True)
    def test_failed_context_flush_is_unconfirmed_even_if_bytes_visible(self):
        j,s=self.make();self.primary(j,0,force=True);before=j.summary()
        with patch.object(s,'flush',side_effect=OSError('synthetic flush failure')):
            with self.assertRaises(OSError):
                j.context_after_primary_flush(lambda c:{},clock=lambda:0)
        summary=j.summary()
        self.assertEqual(summary['admitted_rows'],4)
        self.assertEqual(summary['flush_confirmed_rows'],3)
        self.assertEqual(summary['flush_confirmed_bytes'],before['flush_confirmed_bytes'])
        self.assertEqual(summary['unconfirmed_admitted_rows'],1)
        self.assertEqual(summary['admitted_bytes'],len(s.getvalue().encode('ascii')))
        self.assertEqual(summary['unconfirmed_admitted_bytes'],summary['admitted_bytes']-before['flush_confirmed_bytes'])
        self.assertEqual(summary['status'],'incomplete-stopped')
        self.assertIsNone(j.context_after_primary_flush(lambda c:self.fail('retry')))
    def test_complete_window_and_64_forced_arm_checks(self):
        j,_=self.make();count=0;last=None
        microseconds=0;forced=0;step=0
        while microseconds<5_340_000_000:
            at=microseconds/1_000_000
            self.primary(j,at,force=(step==0))
            forced+=int(step==0)
            raw=j.context_after_primary_flush(lambda c:{},clock=lambda:at)
            if raw:
                if last is not None:self.assertGreaterEqual(at-last,2)
                count+=1;last=at
            if step>0 and step%435==0 and forced<65:
                self.primary(j,at,force=True);forced+=1
                self.assertIsNone(j.context_after_primary_flush(lambda c:self.fail('force reset context'),clock=lambda:at))
            microseconds+=190001;step+=1
        self.assertGreater(j._last_sample,5339.8)
        self.assertEqual(j._forced,65);self.assertLessEqual(j.primary_ticks,28200)
        self.assertLessEqual(count,2671);self.assertLessEqual(j.rows,59072);self.assertIsNone(j.stopped_reason)
    def test_actual_serialized_worst_case_budget_arithmetic(self):
        e=replace(E.Envelope(),primary_forced_ticks=65,primary_hard_tick_quota=28200,primary_guard_max_line_bytes=1024,context_max_line_bytes=16384)
        r=E.calculate(e);self.assertEqual(r['observations_rows'],59072);self.assertEqual(r['observations_bytes'],130394112)
        raws=[]
        for cap in (2048,1024,16384):
            row={'p':''};row['p']='x'*(cap-len(B._line(row,cap)));raws.append(B._line(row,cap))
        self.assertEqual(2048+28200*(len(raws[0])+len(raws[1]))+2671*len(raws[2]),r['observations_bytes'])
        self.assertLess(r['total_raw_bytes'],256*1024**2);self.assertFalse(r['breaches']);self.assertFalse(r['runtime_qualified'])
        self.assertEqual(28200*2048,57753600)
    def test_maximal_helper_shapes_fit_16k_without_compaction(self):
        f=H.Files();mx=str(2**64-1)
        for (domain,name),value in list(f.values.items()):
            if name in H.H.CONTEXT_KEYS:f.values[domain,name]=''.join(k+' '+mx+'\n' for k in H.H.CONTEXT_KEYS[name])
            elif name.endswith('pressure') or name=='pressure/memory':f.values[domain,name]=''.join(k+' avg10=100.000000 avg60=100.000000 avg300=100.000000 total='+mx+'\n' for k in ('some','full'))
            elif name in ('memory.current','memory.swap.current'):f.values[domain,name]=mx+'\n'
        identities=[{'pid':2**31-3+i,'start_ticks':2**64-1} for i in range(3)]
        for identity in identities:
            f.values['proc',str(identity['pid'])+'/stat']=H.proc_stat(identity['pid'],identity['start_ticks'])
            f.values['proc',str(identity['pid'])+'/cgroup']='0::'+H.CG+'\n'
        f.after_group=lambda n:{'device':2**64-1,'inode':2**64-1}
        def collect_max():return H.H.collect_resource_context(H.CG,root_identity=identities[1],native_identity=identities[2],_worker_pid=identities[0]['pid'],_files=f,_clock=lambda:0)
        r=collect_max()
        row={'artifact':'aotg-memory-context-link','version':1,'run_id':'x'*64,'sequence':28200,'primary_sha256':'f'*64,'context':r}
        self.assertLessEqual(len(B._line(row,16384)),16384)
        f.values['proc',str(identities[2]['pid'])+'/stat']=H.proc_stat(identities[2]['pid'],9999)
        r=collect_max();self.assertEqual(r['status'],'incomplete')
        self.assertLessEqual(len(B._line({**row,'context':r},16384)),16384)
    def test_cadence_bound_includes_force_and_refuses_undersized_quota(self):
        with self.assertRaisesRegex(ValueError,'hard-quota'):
            E.calculate(replace(E.Envelope(),primary_forced_ticks=65,primary_hard_tick_quota=28107))
        r=E.calculate(replace(E.Envelope(),primary_forced_ticks=65))
        self.assertEqual(r['primary_ticks'],28172)

def suite():
    out=unittest.TestSuite();loader=unittest.defaultTestLoader
    for cls in (JournalTests,E.EnvelopeTests,B.Tests,D.Tests,H.ContextTests,H.ReadOnlyFileTests,ReconciliationTests,EvidenceJoinTests):
        out.addTests(loader.loadTestsFromTestCase(cls))
    return out

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(suite())
    if result.skipped:raise SystemExit('Unexpected skipped tests')
    raise SystemExit(not result.wasSuccessful())
