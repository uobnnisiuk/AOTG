"""Two-phase adapter of the reviewed pure SerializedBudget for a private worker.

No live reader or CLI. Guard evaluation is external and remains unchanged.
Every admitted JSONL byte includes escaping and its newline. Context is optional
only after a flushed passed verdict and primary resource line; rejection never
invokes a sampler. Clocks/readers in tests are synthetic.
"""
import hashlib
import math
import time

# The reviewed sibling is explicit even when Python removes the script directory
# under -I. Deployment embeds these definitions and pins their source closure.
if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from serialized_budget import BudgetStop, Limits, SerializedBudget, _line

MAX_PRIMARY_SAMPLES = 28_200
MAX_FORCED_SAMPLES = 65
MAX_CONTEXT_ATTEMPTS = 2_671
CONTEXT_INTERVAL_SECONDS = 2.0
CONTEXT_CALL_SECONDS = 0.05
RESOURCE_LINE_BYTES = 2_048
GUARD_LINE_BYTES = 1_024
CONTEXT_LINE_BYTES = 16_384


class ObservationJournal(SerializedBudget):
    def __init__(self, stream, *, origin, deadline, run_id):
        super().__init__(Limits(context_line_bytes=CONTEXT_LINE_BYTES))
        if (type(origin) not in (int,float) or not math.isfinite(origin)
                or type(deadline) not in (int,float) or not math.isfinite(deadline)
                or not origin < deadline <= origin + self.limits.window_ms/1000
                or not isinstance(run_id,str) or not 1 <= len(run_id) <= 64):
            raise BudgetStop('invalid-observation-origin')
        self.stream=stream;self.origin=origin;self.deadline=deadline;self.run_id=run_id
        self._last_clock=origin;self._last_sample=None;self._pending=None
        self._forced=0;self._selected=None;self._last_started=None
        self._attempts=0;self._reserved_rows=0;self._reserved_bytes=0
        self._flush_confirmed_rows=0;self._flush_confirmed_bytes=0

    def clock(self, now, *, io=False):
        if type(now) not in (int,float) or not math.isfinite(now):self._stop('nonfinite-clock')
        if now < self._last_clock:self._stop('clock-rollback')
        self._last_clock=now
        if now < self.origin or now >= self.deadline:self._stop('worker-deadline')
        self._time(int((now-self.origin)*1000))
        return now

    def _capacity(self, rows, size):
        if self.rows+self._reserved_rows+rows>self.limits.max_rows:self._stop('aggregate-row-cap')
        if self.bytes+self._reserved_bytes+size>self.limits.max_bytes:self._stop('aggregate-byte-cap')

    def _persist(self, record, cap):
        # Upstream commit performs exact serialization and aggregate admission.
        raw=self._commit((record,),cap)[0]
        try:
            written=self.stream.write(raw.decode('ascii'))
            if written!=len(raw):self._stop('short-observation-write')
            self.stream.flush()
        except BaseException:
            if self.stopped_reason is None:self.stopped_reason='observation-write-failed'
            raise
        # Admission remains charged even if write/flush failed. Only a full
        # write followed by successful flush is confirmed, not fsync durability.
        self._flush_confirmed_rows+=1;self._flush_confirmed_bytes+=len(raw)
        return raw

    def start(self, record, now):
        self.clock(now)
        if self.initial_written:self._stop('duplicate-initial')
        if record.get('phase')!='startup-anchor':self._stop('initial-phase')
        self._capacity(1,self.limits.primary_line_bytes)
        raw=self._persist({**record,'run_id':self.run_id},self.limits.primary_line_bytes);self.initial_written=True;return raw

    def observed(self, record, now, *, force=False):
        self.clock(now)
        if not self.initial_written or self._pending is not None or self._selected is not None:self._stop('primary-phase-order')
        if type(force) is not bool:self._stop('force-type')
        if self.primary_ticks>=MAX_PRIMARY_SAMPLES:self._stop('primary-sample-quota')
        if record.get('phase')!='observed' or type(record.get('sequence')) is not int or record['sequence']!=self.primary_ticks:self._stop('primary-sequence')
        if force:
            if self._forced>=MAX_FORCED_SAMPLES:self._stop('forced-sample-quota')
        elif self._last_sample is not None and now-self._last_sample<.19:
            self._stop('primary-period')
        # Reserve the guard's full permitted line before committing pre-guard
        # evidence. This does not require or delay the real guard verdict.
        self._capacity(2,self.limits.primary_line_bytes+GUARD_LINE_BYTES)
        raw=self._persist({**record,'run_id':self.run_id},self.limits.primary_line_bytes)
        self._reserved_rows=1;self._reserved_bytes=GUARD_LINE_BYTES
        self._pending={'sequence':record['sequence'],'primary_sha256':hashlib.sha256(raw).hexdigest(),'at':now}
        self.primary_ticks+=1;self._last_sample=now;self._forced+=int(force)
        self.last_primary_ms=int((now-self.origin)*1000)
        return raw

    def verdict(self, record, now):
        self.clock(now)
        if self._pending is None or record.get('phase')!='guard-result' or record.get('sequence')!=self._pending['sequence']:self._stop('guard-phase-order')
        verdict=record.get('guard_verdict')
        if verdict not in ('passed','rejected'):self._stop('guard-verdict')
        selected=False;stop_after=None
        if verdict=='rejected':
            reason='guard-rejected-no-context';self.context_skipped_guard+=1
        elif self._last_started is not None and now-self._last_started<CONTEXT_INTERVAL_SECONDS:
            reason='interval-skipped-no-context';self.context_skipped_interval+=1
        elif now+CONTEXT_CALL_SECONDS>=self.deadline:
            reason='deadline-headroom-skipped-no-context'
        elif self._attempts>=MAX_CONTEXT_ATTEMPTS:
            reason='context-attempt-quota';stop_after=reason
        else:
            # Guard line is already reserved. Reserve the FULL context cap,
            # not merely the smallest valid JSON, before any optional read.
            try:self._capacity(1,self.limits.context_line_bytes)
            except BudgetStop:
                reason='context-capacity-refused';stop_after=self.stopped_reason
            else:reason='context-selected';selected=True
        enriched={**{k:v for k,v in record.items() if k not in ('sample','anchor')},
                  'run_id':self.run_id,'primary_sha256':self._pending['primary_sha256'],'context_schedule':{'reason':reason,'attempts_before':self._attempts,
                   'interval_skips':self.context_skipped_interval}}
        self._reserved_rows=0;self._reserved_bytes=0
        raw=self._persist(enriched,GUARD_LINE_BYTES)
        pending=self._pending;self._pending=None
        if selected:
            self._attempts+=1
            self._selected={**pending,'attempt':self._attempts}
            self._reserved_rows=1;self._reserved_bytes=self.limits.context_line_bytes
        if verdict=='rejected':self.stopped_reason='guard-rejected'
        if stop_after is not None:self._stop(stop_after)
        return raw

    def context_after_primary_flush(self, sample, *, clock=time.monotonic):
        selected=self._selected
        if selected is None:
            # A passed tick still needs the shared deadline checked after
            # accepted-resource flush, even without a scheduled context read.
            if self.stopped_reason is None:
                self.clock(clock(),io=True)
            return None
        # Consume the selection before calling any external reader. Failure,
        # disappearance, or writer error can never be retried at this tick.
        self._selected=None
        fault=None
        try:
            began=self.clock(clock(),io=True)
            if began+CONTEXT_CALL_SECONDS>=self.deadline:self._stop('context-deadline-headroom')
            if self._last_started is not None and began-self._last_started<CONTEXT_INTERVAL_SECONDS:
                self._stop('context-start-period')
            self._last_started=began
            call_deadline=min(self.deadline,began+CONTEXT_CALL_SECONDS)
            def read_clock():
                now=self.clock(clock(),io=True)
                if now>=call_deadline:self._stop('context-read-deadline')
                return now
            context=sample(read_clock)
            read_clock()
        except BudgetStop as exc:
            fault=exc;context={'status':'incomplete','reason':str(exc),'guard_accepted':None,'cause_attribution_proven':False}
        except Exception as exc:
            self.stopped_reason='unexpected-context-exception'
            fault=BudgetStop(self.stopped_reason)
            context={'status':'incomplete','reason':type(exc).__name__,'guard_accepted':None,'cause_attribution_proven':False}
        record={'artifact':'aotg-memory-context-link','version':1,'run_id':self.run_id,
                'sequence':selected['sequence'],'primary_sha256':selected['primary_sha256'],'context':context}
        self._reserved_rows=0;self._reserved_bytes=0
        try:raw=self._persist(record,self.limits.context_line_bytes)
        except BudgetStop:
            # Oversized context is not truncated, replaced with zeros or silently
            # dropped. The worker fails closed, retaining the selected verdict.
            raise
        self.context_ticks+=1
        if fault is not None:raise fault
        # The reader's 50 ms budget is separate from the worker deadline.
        # Serialization and write/flush must not permit a late successful tick.
        self.clock(clock(),io=True)
        return raw

    def bounded_resource_line(self, sample):
        try:return _line(sample,RESOURCE_LINE_BYTES).decode('ascii')
        except BudgetStop as exc:self._stop('accepted-resource:'+str(exc))

    def summary(self):
        return {**super().summary(),'adapter_version':1,'primary_hard_quota':MAX_PRIMARY_SAMPLES,
                'admitted_rows':self.rows,'admitted_bytes':self.bytes,
                'flush_confirmed_rows':self._flush_confirmed_rows,
                'flush_confirmed_bytes':self._flush_confirmed_bytes,
                'unconfirmed_admitted_rows':self.rows-self._flush_confirmed_rows,
                'unconfirmed_admitted_bytes':self.bytes-self._flush_confirmed_bytes,
                'forced_samples':self._forced,'forced_hard_quota':MAX_FORCED_SAMPLES,
                'context_attempts':self._attempts,'context_hard_quota':MAX_CONTEXT_ATTEMPTS,
                'reserved_rows':self._reserved_rows,'reserved_bytes':self._reserved_bytes,
                'runtime_qualified':False}
