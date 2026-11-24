"""Bounded read-only verification of the reviewed compact observation JSONL.

Pure bytes/iterator API. No file, proc, process, network or model operations.
A consistent journal never proves successful execution, custody, quality or cause.
"""
import hashlib
import json
import math
import re

MAX_BYTES=128*1024*1024
MAX_ROWS=60001
MAX_LINE=16384
MAX_CHUNK=65536
MAX_PRIMARY=28200
MAX_CONTEXT=2671
OBS_CAP=2048
GUARD_CAP=1024
SHA=re.compile(r'[0-9a-f]{64}')
BASE={'artifact','version','run_id','phase','guard_verdict'}
TIMED={'sequence','observed_at_utc','sample_utc'}
CONTEXT_REQUIRED={'artifact','version','status','diagnostic_only','utc_read_start','expected_cgroup','bindings','metrics','errors','limits','atomic_snapshot','guard_accepted','cause_attribution_proven','utc_read_end','seconds','read_calls','read_bytes'}
CONTEXT_OPTIONAL={'cgroup_identity_before','cgroup_identity_after'}
REASONS={'guard-rejected-no-context','interval-skipped-no-context','deadline-headroom-skipped-no-context','context-attempt-quota','context-capacity-refused','context-selected'}

class Refused(ValueError):
    pass

def need(value,reason):
    if not value:raise Refused(reason)

def exact_int(value,low,high):return type(value) is int and low<=value<=high

def pairs(items):
    out={}
    for key,value in items:
        need(key not in out,'json-duplicate-key');out[key]=value
    return out

def finite_float(text):
    value=float(text);need(math.isfinite(value),'json-nonfinite');return value

def nonfinite(_):raise Refused('json-nonfinite')

def canonical(record):
    return (json.dumps(record,ensure_ascii=True,sort_keys=True,allow_nan=False,separators=(',',':'))+'\n').encode('ascii')

def parse(raw):
    try:
        record=json.loads(raw,object_pairs_hook=pairs,parse_float=finite_float,parse_constant=nonfinite)
        need(type(record) is dict,'json-not-object')
        stack=[(record,0)]
        while stack:
            value,depth=stack.pop();need(depth<=64,'json-depth-cap')
            if isinstance(value,dict):stack.extend((x,depth+1) for x in value.values())
            elif isinstance(value,list):stack.extend((x,depth+1) for x in value)
        need(canonical(record)==raw,'noncanonical-jsonl')
        return record
    except Refused:raise
    except (UnicodeError,ValueError,TypeError,OverflowError,RecursionError):raise Refused('invalid-json') from None

def anchor(value):
    need(type(value) is dict and set(value)=={'utc_read_start','utc_read_end','pswpout','initial_gtt_bytes'},'anchor-schema')
    need(all(type(value[x]) is str and 1<=len(value[x])<=64 for x in ('utc_read_start','utc_read_end')),'anchor-time-shape')
    # The writer records a missing/invalid initial GTT before its unchanged
    # guard rejects it. Preserve that evidence instead of treating it as zero.
    return [name for name in ('pswpout','initial_gtt_bytes')
            if not ((type(value[name]) is int and 0<=value[name]<=2**64-1)
                    or (type(value[name]) is float and math.isfinite(value[name]) and 0<=value[name]<=2**64-1))]

def context(value):
    need(type(value) is dict,'context-schema')
    witness={'status','reason','guard_accepted','cause_attribution_proven'}
    if set(value)==witness:
        need(value['status']=='incomplete' and type(value['reason']) is str and 1<=len(value['reason'])<=128,'context-failure-witness')
        need(value['guard_accepted'] is None and value['cause_attribution_proven'] is False,'context-authority-claim')
        return 'failure-witness'
    need(CONTEXT_REQUIRED<=set(value)<=CONTEXT_REQUIRED|CONTEXT_OPTIONAL,'context-schema')
    need(value['artifact']=='aotg-memory-context' and type(value['version']) is int and value['version']==1,'context-version')
    need(value['status'] in ('incomplete','observed-bindings-verified'),'context-status')
    need(value['diagnostic_only'] is True and value['atomic_snapshot'] is False and value['guard_accepted'] is None and value['cause_attribution_proven'] is False,'context-authority-claim')
    need(type(value['bindings']) is dict and type(value['metrics']) is dict and type(value['errors']) is list,'context-container-shape')
    need(all(type(x) is str and len(x)<=256 for x in value['errors']),'context-error-shape')
    need(type(value['expected_cgroup']) is str and re.fullmatch(r'/system\.slice/aotg-[0-9a-f]{16}-worker\.service',value['expected_cgroup']) is not None,'context-cgroup-shape')
    need(type(value['limits']) is dict and value['limits']=={'seconds':.05,'reads':24,'bytes':262144} and type(value['limits']['reads']) is int and type(value['limits']['bytes']) is int and type(value['limits']['seconds']) is float,'context-limits')
    need(type(value['seconds']) in (int,float) and math.isfinite(value['seconds']) and value['seconds']>=0,'context-duration-shape')
    need(exact_int(value['read_calls'],0,24) and exact_int(value['read_bytes'],0,262144),'context-read-bounds')
    need(all(type(value[k]) is str and 1<=len(value[k])<=64 for k in ('utc_read_start','utc_read_end')),'context-time-shape')
    return value['status']

class Chain:
    def __init__(self,expected_run_id):
        self.expected=expected_run_id;self.run_id=None;self.state='anchor';self.anchor=None;self.anchor_issues=[];self.next_sequence=0
        self.observed=0;self.guards=0;self.contexts=0;self.attempts=0;self.interval_skips=0
        self.current=None;self.context_missing=0;self.terminal_reason=None
    def common(self,r):
        need(type(r.get('version')) is int and r['version']==1,'record-version')
        need(type(r.get('run_id')) is str and 1<=len(r['run_id'])<=64,'run-id-shape')
        if self.run_id is None:
            self.run_id=r['run_id'];need(self.expected is None or self.run_id==self.expected,'expected-run-id-mismatch')
        else:need(r['run_id']==self.run_id,'run-id-mismatch')
    def timed(self,r):
        need(exact_int(r.get('sequence'),0,MAX_PRIMARY-1),'sequence-shape')
        need(all(type(r.get(k)) is str and 1<=len(r[k])<=64 for k in ('observed_at_utc','sample_utc')),'sample-time-shape')
    def take(self,r,raw):
        self.common(r)
        if self.state=='terminal':
            if r.get('artifact')=='aotg-memory-context-link' and self.terminal_reason=='guard-rejected':raise Refused('context-after-guard-rejection')
            raise Refused('record-after-terminal')
        if r.get('artifact')=='aotg-memory-context-link':
            need(len(raw)<=MAX_LINE,'context-line-cap')
            need(set(r)=={'artifact','version','run_id','sequence','primary_sha256','context'},'context-link-schema')
            if self.state!='context':
                if exact_int(r.get('sequence'),0,self.next_sequence-1):raise Refused('duplicate-or-unselected-context')
                raise Refused('unexpected-context')
            need(type(r['sequence']) is int and r['sequence']==self.current['sequence'],'context-sequence-mismatch')
            need(r['primary_sha256']==self.current['sha256'],'context-primary-hash-mismatch')
            kind=context(r['context']);self.contexts+=1
            if kind=='failure-witness':self.state='terminal';self.terminal_reason='context-failure-witness'
            else:
                if kind=='incomplete':self.context_missing+=1
                self.state='observed';self.current=None
            return
        need(r.get('artifact')=='aotg-resource-observation','record-artifact')
        phase=r.get('phase')
        if phase=='startup-anchor':
            need(self.state=='anchor','duplicate-anchor')
            need(len(raw)<=OBS_CAP,'anchor-line-cap')
            need(set(r)==BASE|{'anchor'} and r['guard_verdict']=='not-evaluated','anchor-record-schema')
            self.anchor_issues=anchor(r['anchor']);self.anchor=r['anchor'];self.state='observed';return
        if phase=='observed':
            need(len(raw)<=OBS_CAP,'observed-line-cap');self.timed(r)
            if r['sequence']<self.next_sequence:raise Refused('duplicate-observation')
            if r['sequence']>self.next_sequence:raise Refused('observation-sequence-gap')
            if self.state=='context':raise Refused('missing-selected-context-before-next-record')
            if self.state=='guard':raise Refused('missing-guard-before-next-record')
            need(self.state=='observed','observed-before-anchor')
            need(set(r)==BASE|TIMED|{'anchor','sample'} and r['guard_verdict']=='not-evaluated','observed-schema')
            need(r['anchor']==self.anchor,'anchor-changed')
            need(type(r['sample']) is dict and r['sample'].get('utc')==r['sample_utc'],'sample-utc-mismatch')
            need(self.observed<MAX_PRIMARY,'primary-count-cap')
            self.current={'sequence':r['sequence'],'sha256':hashlib.sha256(raw).hexdigest(),'observed_at_utc':r['observed_at_utc'],'sample_utc':r['sample_utc']}
            self.observed+=1;self.state='guard';return
        if phase=='guard-result':
            need(len(raw)<=GUARD_CAP,'guard-line-cap');self.timed(r)
            if r['sequence']<self.next_sequence:raise Refused('duplicate-guard')
            need(self.state=='guard','unexpected-guard')
            need(r['sequence']==self.current['sequence'],'guard-sequence-mismatch')
            extra={'reason','error_type'} if r.get('guard_verdict')=='rejected' else set()
            need(set(r)==BASE|TIMED|{'primary_sha256','context_schedule'}|extra,'guard-schema')
            need(r['guard_verdict'] in ('passed','rejected'),'guard-verdict')
            need(r['primary_sha256']==self.current['sha256'],'guard-primary-hash-mismatch')
            need(all(r[k]==self.current[k] for k in ('observed_at_utc','sample_utc')),'guard-sample-mismatch')
            if extra:need(all(type(r[k]) is str and r[k] for k in extra),'guard-error-shape')
            schedule=r['context_schedule'];need(type(schedule) is dict and set(schedule)=={'reason','attempts_before','interval_skips'},'context-schedule-schema')
            why=schedule['reason'];need(why in REASONS,'context-schedule-reason')
            need(type(schedule['attempts_before']) is int and schedule['attempts_before']==self.attempts,'context-attempt-count-mismatch')
            want_skips=self.interval_skips+int(why=='interval-skipped-no-context')
            need(type(schedule['interval_skips']) is int and schedule['interval_skips']==want_skips,'context-skip-count-mismatch')
            self.interval_skips=want_skips;self.guards+=1;self.next_sequence+=1
            if r['guard_verdict']=='rejected':
                need(why=='guard-rejected-no-context','reject-selected-context');self.state='terminal';self.terminal_reason='guard-rejected';return
            need(why!='guard-rejected-no-context','passed-with-reject-schedule')
            if why=='context-selected':
                need(self.attempts<MAX_CONTEXT,'context-attempt-cap');self.attempts+=1;self.state='context';return
            if why in ('context-attempt-quota','context-capacity-refused'):
                if why=='context-attempt-quota':need(self.attempts==MAX_CONTEXT,'false-context-quota')
                self.state='terminal';self.terminal_reason=why;return
            self.state='observed';self.current=None;return
        raise Refused('unknown-phase')
    def ending(self):
        if self.state=='anchor':return 'empty-journal',False
        if self.state=='guard':return 'missing-final-guard',False
        if self.state=='context':return 'missing-selected-context-at-eof',False
        if self.state=='terminal':return self.terminal_reason,True
        if not self.observed:return 'anchor-only',False
        if self.anchor_issues:return 'anchor-measurement-invalid',True
        return ('diagnostic-context-missing' if self.context_missing else 'runtime-completion-not-proven'),True

def verify_journal(chunks,*,expected_run_id=None,expected_sha256=None):
    """Verify bounded canonical JSONL from bytes or an iterator of <=64 KiB chunks.

    Never reads files itself. Output contains counts/reasons, no raw payloads.
    `incomplete` is deliberate even for a consistent EOF: no completion or custody
    marker exists in this journal. External plans/results remain separate gates.
    """
    if expected_run_id is not None and (type(expected_run_id) is not str or not 1<=len(expected_run_id)<=64):raise ValueError('expected-run-id')
    if expected_sha256 is not None and (type(expected_sha256) is not str or SHA.fullmatch(expected_sha256) is None):raise ValueError('expected-sha256')
    if isinstance(chunks,bytes):
        data=chunks;chunks=(data[n:n+MAX_CHUNK] for n in range(0,len(data),MAX_CHUNK))
    chain=Chain(expected_run_id);digest=hashlib.sha256();buffer=bytearray();rows=0;size=0;complete=False;consistent=False;status='incomplete';reason=None
    try:
        iterator=iter(chunks)
        while True:
            try:part=next(iterator)
            except StopIteration:complete=True;break
            except Exception:reason='input-stream-error';break
            need(type(part) is bytes,'input-chunk-type');need(0<len(part)<=MAX_CHUNK,'input-chunk-size')
            need(size+len(part)<=MAX_BYTES,'input-byte-cap');size+=len(part);digest.update(part)
            buffer.extend(part)
            while True:
                end=buffer.find(b'\n')
                if end<0:
                    need(len(buffer)<MAX_LINE,'unterminated-line-cap');break
                need(end+1<=MAX_LINE,'line-byte-cap');need(rows<MAX_ROWS,'row-count-cap')
                raw=bytes(buffer[:end+1]);del buffer[:end+1];rows+=1
                chain.take(parse(raw),raw)
        if reason is None:
            if buffer:reason='unterminated-final-line'
            else:reason,consistent=chain.ending()
            if expected_sha256 is not None:need(digest.hexdigest()==expected_sha256,'input-sha256-mismatch')
    except Refused as exc:status='refused';reason=str(exc);consistent=False
    except (TypeError,ValueError,RecursionError,OverflowError):status='refused';reason='invalid-stream-or-record';consistent=False
    return {'artifact':'aotg-compact-journal-verification','version':1,'status':status,'reason':reason,'record_chain_consistent':consistent,'input_exhausted':complete,'admitted_bytes':size,'admitted_lines':rows,'admitted_prefix_sha256':digest.hexdigest(),'input_sha256':digest.hexdigest() if complete else None,'expected_run_id_supplied':expected_run_id is not None,'expected_sha256_supplied':expected_sha256 is not None,'observed_samples':chain.observed,'guard_results':chain.guards,'context_attempts':chain.attempts,'context_records':chain.contexts,'incomplete_context_records':chain.context_missing,'anchor_measurement_issues':chain.anchor_issues,'limits':{'bytes':MAX_BYTES,'rows':MAX_ROWS,'line_bytes':MAX_LINE,'chunk_bytes':MAX_CHUNK},'diagnostic_only':True,'runtime_completion_proven':False,'quality_accepted':False,'cause_attribution_proven':False,'trusted_custody_verified':False,'same_window_for_triage':False,'authorizes_retry':False}
