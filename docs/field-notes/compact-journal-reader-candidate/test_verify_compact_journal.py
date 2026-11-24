"""Adversarial synthetic-byte tests; no private records or live operations."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import verify_compact_journal as V
RAW=(HERE/'synthetic-writer-fixture.jsonl').read_bytes()
ROWS=[json.loads(x) for x in RAW.splitlines()]

def pack(rows):return b''.join(V.canonical(x) for x in rows)
def mutable():return copy.deepcopy(ROWS)
def stoprows():
    rows=mutable()[:3];g=rows[2];g['guard_verdict']='rejected';g['reason']='New swapout or counter reset';g['error_type']='StopTrial';g['context_schedule']['reason']='guard-rejected-no-context';return rows

class ReaderTests(unittest.TestCase):
    def refused(self,raw,reason=None,**kw):
        r=V.verify_journal(raw,**kw);self.assertEqual(r['status'],'refused',r)
        if reason:self.assertEqual(r['reason'],reason,r)
        self.assertFalse(r['record_chain_consistent']);return r
    def test_reviewed_writer_fixture_consistent_but_never_runtime_success(self):
        meta=json.loads((HERE/'fixture-provenance.json').read_text());self.assertTrue(meta['synthetic']);self.assertEqual(hashlib.sha256(RAW).hexdigest(),meta['fixture_sha256'])
        r=V.verify_journal(RAW,expected_run_id='synthetic-fixture',expected_sha256=meta['fixture_sha256'])
        self.assertEqual(r['status'],'incomplete');self.assertEqual(r['reason'],'runtime-completion-not-proven');self.assertTrue(r['record_chain_consistent']);self.assertTrue(r['input_exhausted'])
        self.assertEqual((r['observed_samples'],r['guard_results'],r['context_records']),(1,1,1))
        for k in ('quality_accepted','runtime_completion_proven','cause_attribution_proven','trusted_custody_verified','same_window_for_triage','authorizes_retry'):self.assertIs(r[k],False)
    def test_chunk_boundaries_preserve_exact_raw_hash(self):
        expected=V.verify_journal(RAW)
        for width in (1,2,17,4096,65536):
            self.assertEqual(V.verify_journal(iter(RAW[n:n+width] for n in range(0,len(RAW),width))),expected)
    def test_empty_anchor_only_and_unterminated_eof_are_distinct(self):
        for raw,reason in ((b'','empty-journal'),(pack(ROWS[:1]),'anchor-only'),(RAW[:-1],'unterminated-final-line')):
            r=V.verify_journal(raw);self.assertEqual(r['status'],'incomplete');self.assertEqual(r['reason'],reason);self.assertFalse(r['record_chain_consistent'])
    def test_duplicate_json_keys_nested_and_top_refused(self):
        for raw in (b'{"phase":1,"phase":2}\n',b'{"x":{"a":1,"a":2}}\n'):
            self.refused(raw,'json-duplicate-key')
    def test_nonfinite_constants_and_float_overflow_refused(self):
        for value in (b'NaN',b'Infinity',b'-Infinity',b'1e9999'):
            self.refused(b'{"x":'+value+b'}\n','json-nonfinite')
    def test_noncanonical_space_crlf_and_utf8_refused(self):
        for raw in (b'{ "a": 1}\n',V.canonical(ROWS[0]).replace(b'\n',b'\r\n'),b'{"x":"\xc3\xa9"}\n'):
            self.refused(raw,'noncanonical-jsonl')
    def test_wrong_run_version_or_artifact_refused(self):
        for key,value,reason in (('run_id','different','run-id-mismatch'),('version',True,'record-version'),('artifact','other','record-artifact')):
            rows=mutable();rows[1][key]=value;self.refused(pack(rows),reason)
        self.refused(RAW,'expected-run-id-mismatch',expected_run_id='other')
    def test_anchor_repetition_and_changed_anchor_refused(self):
        self.refused(pack([ROWS[0],ROWS[0]]),'duplicate-anchor')
        rows=mutable();rows[1]['anchor']['pswpout']=0;self.refused(pack(rows),'anchor-changed')
    def test_missing_anchor_refused(self):self.refused(pack(ROWS[1:]),'observed-before-anchor')
    def test_duplicate_gap_bool_sequence_refused(self):
        self.refused(pack(ROWS+[ROWS[1]]),'duplicate-observation')
        rows=mutable();rows[1]['sequence']=1;self.refused(pack(rows),'observation-sequence-gap')
        rows=mutable();rows[1]['sequence']=True;self.refused(pack(rows),'sequence-shape')
    def test_guard_or_context_hash_tamper_refused(self):
        for index,reason in ((2,'guard-primary-hash-mismatch'),(3,'context-primary-hash-mismatch')):
            rows=mutable();rows[index]['primary_sha256']='0'*64;self.refused(pack(rows),reason)
        rows=mutable();rows[1]['sample']['pswpout']=158;self.refused(pack(rows),'guard-primary-hash-mismatch')
    def test_coherent_rewrite_still_needs_external_hash_and_never_authenticates(self):
        rows=mutable();rows[1]['sample']['pswpout']=158;digest=hashlib.sha256(V.canonical(rows[1])).hexdigest();rows[2]['primary_sha256']=rows[3]['primary_sha256']=digest
        r=V.verify_journal(pack(rows));self.assertTrue(r['record_chain_consistent']);self.assertFalse(r['trusted_custody_verified'])
        self.refused(pack(rows),'input-sha256-mismatch',expected_sha256=hashlib.sha256(RAW).hexdigest())
    def test_guard_sequence_and_timestamp_binding_refused(self):
        rows=mutable();rows[2]['sequence']=1;self.refused(pack(rows),'guard-sequence-mismatch')
        rows=mutable();rows[2]['sample_utc']='different';self.refused(pack(rows),'guard-sample-mismatch')
    def test_missing_guard_eof_and_midstream_distinguished(self):
        r=V.verify_journal(pack(ROWS[:2]));self.assertEqual(r['reason'],'missing-final-guard');self.assertEqual(r['status'],'incomplete')
        self.refused(pack(ROWS[:2]+[ROWS[1]]),'missing-guard-before-next-record')
    def test_missing_selected_context_eof_and_midstream_distinguished(self):
        r=V.verify_journal(pack(ROWS[:3]));self.assertEqual(r['reason'],'missing-selected-context-at-eof');self.assertFalse(r['record_chain_consistent'])
        row=copy.deepcopy(ROWS[1]);row['sequence']=1
        self.refused(pack(ROWS[:3]+[row]),'missing-selected-context-before-next-record')
    def test_rejected_guard_terminal_incomplete_and_context_forbidden(self):
        rows=stoprows();r=V.verify_journal(pack(rows));self.assertEqual(r['reason'],'guard-rejected');self.assertEqual(r['status'],'incomplete');self.assertTrue(r['record_chain_consistent'])
        self.refused(pack(rows+[ROWS[3]]),'context-after-guard-rejection')
    def test_duplicate_guard_context_and_unselected_context_refused(self):
        self.refused(pack(ROWS+[ROWS[2]]),'duplicate-guard')
        self.refused(pack(ROWS+[ROWS[3]]),'duplicate-or-unselected-context')
        rows=mutable();rows[2]['context_schedule']['reason']='interval-skipped-no-context';rows[2]['context_schedule']['interval_skips']=1
        self.refused(pack(rows),'duplicate-or-unselected-context')
    def test_schedule_counter_and_verdict_contradictions_refused(self):
        for key,value,reason in (('attempts_before',1,'context-attempt-count-mismatch'),('interval_skips',1,'context-skip-count-mismatch'),('reason','unlisted','context-schedule-reason')):
            rows=mutable();rows[2]['context_schedule'][key]=value;self.refused(pack(rows),reason)
        rows=stoprows();rows[2]['context_schedule']['reason']='context-selected';self.refused(pack(rows),'reject-selected-context')
    def test_context_failure_witness_is_terminal_and_not_success(self):
        rows=mutable();rows[3]['context']={'status':'incomplete','reason':'context-read-deadline','guard_accepted':None,'cause_attribution_proven':False}
        r=V.verify_journal(pack(rows));self.assertEqual(r['reason'],'context-failure-witness');self.assertEqual(r['status'],'incomplete')
        self.refused(pack(rows+[ROWS[1]]),'record-after-terminal')
    def test_expected_helper_missing_is_diagnostic_incomplete(self):
        rows=mutable();rows[3]['context']['status']='incomplete';rows[3]['context']['errors']=['synthetic-missing'];rows[3]['context']['metrics']['cgroup-swap-current']={'status':'missing','reason':'FileNotFoundError','value':None}
        r=V.verify_journal(pack(rows));self.assertEqual(r['reason'],'diagnostic-context-missing');self.assertTrue(r['record_chain_consistent']);self.assertEqual(r['incomplete_context_records'],1)
    def test_context_authority_claims_and_scope_expansion_refused(self):
        for key,value in (('guard_accepted',True),('cause_attribution_proven',True),('diagnostic_only',False),('atomic_snapshot',True)):
            rows=mutable();rows[3]['context'][key]=value;self.refused(pack(rows),'context-authority-claim')
        rows=mutable();rows[3]['context']['quality_accepted']=True;self.refused(pack(rows),'context-schema')
        rows=mutable();rows[3]['context']['expected_cgroup']='/unrelated';self.refused(pack(rows),'context-cgroup-shape')
    def test_line_caps_before_processing_and_oversized_context(self):
        rows=mutable();rows[1]['sample']['pad']='x'*2048;self.refused(pack(rows),'observed-line-cap')
        rows=stoprows();rows[2]['reason']='x'*1024;self.refused(pack(rows),'guard-line-cap')
        rows=mutable();rows[3]['context']['errors']=['x'*16384];self.refused(pack(rows),'line-byte-cap')
        self.refused(b'x'*16384,'unterminated-line-cap')
    def test_total_bytes_rows_chunk_types_and_depth_are_bounded(self):
        self.assertEqual((V.MAX_BYTES,V.MAX_ROWS,V.MAX_LINE,V.MAX_CHUNK),(134217728,60001,16384,65536))
        with patch.object(V,'MAX_BYTES',len(RAW)-1):self.refused(RAW,'input-byte-cap')
        with patch.object(V,'MAX_ROWS',2):self.refused(RAW,'row-count-cap')
        self.refused([b'x'*65537],'input-chunk-size');self.refused([b''],'input-chunk-size');self.refused(['text'],'input-chunk-type')
        self.refused(b'{"x":'+b'['*65+b'0'+b']'*65+b'}\n','json-depth-cap')
    def test_stream_exception_is_incomplete_without_payload_disclosure(self):
        def broken():
            yield V.canonical(ROWS[0])
            raise OSError('private path must not leak')
        r=V.verify_journal(broken());self.assertEqual(r['reason'],'input-stream-error');self.assertEqual(r['status'],'incomplete');self.assertFalse(r['input_exhausted']);self.assertIsNone(r['input_sha256']);self.assertNotIn('private',str(r))
    def test_context_sequence_and_schema_refused(self):
        rows=mutable();rows[3]['sequence']=1;self.refused(pack(rows),'context-sequence-mismatch')
        rows=mutable();rows[3]['extra']='x';self.refused(pack(rows),'context-link-schema')
    def test_multiple_primary_sequences_and_skip_counts_then_selected(self):
        rows=mutable()
        for sequence,selected in ((1,False),(2,True)):
            observed=copy.deepcopy(ROWS[1]);observed['sequence']=sequence
            guard=copy.deepcopy(ROWS[2]);guard['sequence']=sequence;guard['primary_sha256']=hashlib.sha256(V.canonical(observed)).hexdigest()
            guard['context_schedule']={'reason':'context-selected' if selected else 'interval-skipped-no-context','attempts_before':1,'interval_skips':1}
            rows.extend((observed,guard))
            if selected:
                c=copy.deepcopy(ROWS[3]);c['sequence']=sequence;c['primary_sha256']=guard['primary_sha256'];rows.append(c)
        r=V.verify_journal(pack(rows));self.assertTrue(r['record_chain_consistent']);self.assertEqual((r['observed_samples'],r['guard_results'],r['context_records']),(3,3,2));self.assertFalse(r['same_window_for_triage'])
        with patch.object(V,'MAX_CONTEXT',1):self.refused(pack(rows),'context-attempt-cap')
    def test_missing_initial_gtt_before_guard_rejection_remains_evidence(self):
        for value in (None,-1,True,'invalid',10**400):
            rows=stoprows();rows[0]['anchor']['initial_gtt_bytes']=value;rows[1]['anchor']['initial_gtt_bytes']=value
            rows[2]['primary_sha256']=hashlib.sha256(V.canonical(rows[1])).hexdigest()
            r=V.verify_journal(pack(rows));self.assertEqual(r['status'],'incomplete');self.assertEqual(r['reason'],'guard-rejected');self.assertTrue(r['record_chain_consistent']);self.assertEqual(r['anchor_measurement_issues'],['initial_gtt_bytes']);self.assertFalse(r['quality_accepted'])
    def test_startup_opaque_fields_cannot_forge_timed_join(self):
        rows=mutable();rows[1]['sample']['utc']='different';self.refused(pack(rows),'sample-utc-mismatch')
        rows=mutable();del rows[0]['anchor']['pswpout'];self.refused(pack(rows),'anchor-schema')

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReaderTests))
    if result.skipped:raise SystemExit('Unexpected skipped tests')
    raise SystemExit(not result.wasSuccessful())
