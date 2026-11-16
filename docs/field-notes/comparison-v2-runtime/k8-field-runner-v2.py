#!/usr/bin/python3
"""Private first-machine client orchestrator. Default validates files only.

It never controls the production service. Execution requires a frozen plan hash,
the separate approved maintenance window, and an exactly matching remote arm.
Existing Windows SSH -W routing is reused; credentials remain file references.
The proposed v2 5400-second total includes a final 60-second cleanup reserve. All
timed waits share monotonic cutoffs; failed cleanup is evidence, never success.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import re
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import sys
import threading
import time
import tempfile

REPO = Path(__file__).resolve().parent / 'runtime'
sys.path.insert(0, str(REPO))
from aotg.artifacts import digest
from aotg.field_bench import measure_chat
from aotg.field_client import run_opencode, client_command, validate_profile, _workload
from aotg.field_proxy import MeasurementProxy
from aotg.field_evidence import validate_field_plan

BUDGET_POLICY_SHA256 = "96f81bfa1ea1c90e4988a0a25560156ea402493b9549ac7f17d408c53f3bf277"
VERIFIER_SHA256 = "f8797a3a6ab7bad05995572e7bed306f372eb5cd8a356396bc8f0f4ac8f42e9c"
CATALOG_SHA256 = "277abb01f995890be289b2c3d2e679f8a3283a12040b54218991fc005c19c268"
MARKER_IDENTITY_FIELDS = ("run_id", "plan_sha256", "field_plan_sha256", "schedule_sha256",
                          "index", "candidate_id", "comparison_id", "workload_id", "block", "profile_sha256")

SSH_CLOSE_SECONDS = 20
CLIENT_OVERHEAD_SECONDS = 24  # version namespace (10 s) + two bounded group teardowns
ARM_CLEANUP_SECONDS = 60
MARKER_SECONDS = 15 + SSH_CLOSE_SECONDS
WAIT_SECONDS = 150 + 10 + SSH_CLOSE_SECONDS


class CleanupUnverified(RuntimeError):
    pass


def remaining(deadline):
    return max(0.0, deadline - time.monotonic())


def budget(deadline, maximum, label):
    value = min(maximum, remaining(deadline))
    require(value > 0, label + ' deadline exhausted')
    return value


def describe(error):
    return type(error).__name__ + ': ' + str(error)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path = Path(path)
    with path.open('x', encoding='utf-8') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def signal_client_ready(plan, root):
    # The owner orchestrator separately verifies this PID/start identity and
    # listener ownership before copying the marker to the approved EVO task.
    require(isinstance(plan.get('maintenance_nonce'),str)
            and re.fullmatch('[0-9a-f]{16}',plan['maintenance_nonce']), 'Frozen maintenance nonce required')
    stat_text=Path('/proc/self/stat').read_text()
    fields=stat_text[stat_text.rindex(')')+2:].split()
    boot_seconds=int(next(line.split()[1] for line in Path('/proc/stat').read_text().splitlines()
                          if line.startswith('btime ')))
    started_at=datetime.fromtimestamp(boot_seconds+int(fields[19])/os.sysconf('SC_CLK_TCK'),timezone.utc)
    marker={'artifact':'aotg-k8-client-ready','version':1,'client_plan_sha256':digest(plan),
            'nonce':plan['maintenance_nonce'],'pid':os.getpid(),'pid_start_ticks':fields[19],
            'started_at_utc':started_at.isoformat()}
    save(Path(root)/'client-ready.json',marker)
    return marker


class OwnedSSH:
    """An exact SSH invocation whose Windows descendants belong to one job."""
    def __init__(self,plan,argv,seconds,stdout,stderr):
        require(math.isfinite(seconds) and 1 <= seconds <= 2100, 'Finite owned SSH budget required')
        self.close_lock = threading.Lock()
        self.receipt = None
        transport=plan['windows_transport']
        root=Path(transport['linux_root'])
        identifier=secrets.token_hex(12)
        self.cancel=root/(identifier+'.cancel')
        self.result=root/(identifier+'.result.json')
        input_path=root/(identifier+'.plan.json')
        winroot=transport['windows_root'].rstrip('\\/')
        job={'artifact':'aotg-windows-ssh-job','version':1,
             'wrapper_sha256':transport['wrapper']['sha256'],
             'helper':{'path':transport['helper']['windows_path'],'sha256':transport['helper']['sha256']},
             'executable':{'path':transport['ssh']['windows_path'],'sha256':transport['ssh']['sha256']},
             'argv':argv[1:],'cwd':winroot,'wall_seconds':seconds,
             'cancel_path':winroot+'\\'+self.cancel.name,'result_path':winroot+'\\'+self.result.name}
        save(input_path,job)
        self.plan_sha256=sha(input_path)
        self.process=subprocess.Popen([transport['powershell']['path'],'-NoLogo','-NoProfile','-NonInteractive',
            '-File',transport['wrapper']['windows_path'],'-Plan',winroot+'\\'+input_path.name],
            stdin=subprocess.PIPE,stdout=stdout,stderr=stderr,bufsize=0)
        self.stdin,self.stdout=self.process.stdin,self.process.stdout
    def poll(self):
        return self.process.poll()
    def cancel_job(self):
        try:self.cancel.touch(exist_ok=False)
        except FileExistsError:pass
    def close(self,seconds=SSH_CLOSE_SECONDS,*,deadline=None):
        limit = time.monotonic() + seconds
        if deadline is not None: limit = min(limit, deadline)
        if self.process.poll() is None:self.cancel_job()
        require(self.close_lock.acquire(timeout=remaining(limit)), 'Owned SSH cleanup lock deadline')
        try:
            if self.receipt is not None:return self.receipt
            self.process.wait(timeout=remaining(limit))
            require(self.result.is_file(),'Missing Windows job cleanup receipt; no next arm')
            receipt=json.loads(self.result.read_text())
            require(receipt.get('artifact')=='aotg-windows-ssh-job-result' and receipt.get('version')==1
                    and receipt.get('plan_sha256')==self.plan_sha256
                    and receipt.get('result',{}).get('JobEmpty') is True,
                    'Windows SSH job cleanup not proven; no next arm')
            self.receipt=receipt
            return receipt
        finally:
            self.close_lock.release()


def validate_comparison_contract(plan, field):
    validate_field_plan(field)
    require({w['id'] for w in field['workloads']} == {'cpp-half-open-interval','csharp-atomic-batch'},
            'Require reviewed C++ and C# workload identities')
    require(len(field['workloads']) == 2 and len(field['candidates']) == 3
            and len(field['schedule']) == 64, 'Require exact64 balanced comparison plan')
    require(all(type(r['index']) is int and type(r['block']) is int for r in field['schedule'])
            and all(type(r['index']) is int and type(r['block']) is int for r in plan['schedule']),
            'Schedule index/block must be integers, not booleans')
    require(field['schedule'] == plan['schedule'], 'Schedule differs from full validated v2 field plan')
    require(field['limits'] == {'trial_seconds':180,'total_seconds':5340,
            'max_temperature_c':80,'min_mem_available_bytes':48*1024**3,'max_swapout_bytes':0},
            'Field limits differ from fixed resource/time policy')
    require(field['verifier_sha256'] == VERIFIER_SHA256
            and all(w['tests_sha256'] == CATALOG_SHA256 for w in field['workloads']),
            'Require paired revised independent grader/catalog; legacy receipts are ineligible')
    require(set(plan['workloads']) == {w['id'] for w in field['workloads']}, 'Workload inventory mismatch')
    for workload in field['workloads']:
        require(digest(plan['workloads'][workload['id']]) == workload['input_sha256'],
                'Complete frozen workload descriptor hash differs')
    return field


def validate_connection_refusals(counts):
    reasons = {'closing', 'concurrency', 'deadline', 'thread_start'}
    require(isinstance(counts, dict) and set(counts) == reasons,
            'Pre-HTTP refusal evidence missing or has unknown reasons')
    require(all(type(value) is int and value >= 0 for value in counts.values()),
            'Pre-HTTP refusal counts must be nonnegative integers')
    require(all(value == 0 for value in counts.values()),
            'Pre-HTTP connection refused; no completion marker')


def validate_capture(records):
    require(records and records[0].get('kind') == 'aotg-proxy-capture-v2'
            and records[0].get('phase') == 'opened', 'Missing v2 proxy capture opening')
    require([r.get('event_sequence') for r in records] == list(range(len(records))),
            'Proxy capture sequence missing or reordered')
    closed = records[-1]
    require(closed.get('kind') == 'aotg-proxy-capture-v2' and closed.get('phase') == 'closed'
            and closed.get('status') == 'complete' and closed.get('record_error') is False
            and closed.get('active_handlers') == 0 and closed.get('rejected_total') == 0
            and closed.get('rejection_events_dropped') == 0,
            'Proxy capture incomplete or refused requests; no completion marker')


def preflight(plan):
    require(plan['artifact'] == 'aotg-k8-field-plan' and type(plan['version']) is int and plan['version'] == 2, 'Wrong v2 client plan')
    require(plan['runner_sha256'] == sha(__file__), 'Runner hash changed')
    require(type(plan['max_seconds']) is int and plan['max_seconds'] == 5400
            and plan['task_seconds'] == 130 and plan.get('budget_policy_sha256') == BUDGET_POLICY_SHA256,
            'Separately approved v2 budget required; old windows are ineligible')
    require(plan.get('proxy_capture_version') == 2 and callable(getattr(MeasurementProxy,'mark_capture_incomplete',None)),
            'Require reviewed v2 proxy with pre-HTTP loss reporting')
    require(type(plan.get('cleanup_reserve_seconds')) is int and plan['cleanup_reserve_seconds'] == 60,
            'Require frozen60-second cleanup reserve within proposed5400-second total budget')
    require(isinstance(plan.get('maintenance_nonce'),str)
            and re.fullmatch('[0-9a-f]{16}',plan['maintenance_nonce']), 'Frozen maintenance nonce required')
    require(plan['max_steps'] == 8 and plan['max_requests'] == 9, 'Unreviewed request limits')
    require(plan['endpoint'] == 'http://127.0.0.1:19482/v1', 'Unexpected local measurement endpoint')
    require(plan['upstream'] == 'http://127.0.0.1:19481/v1', 'Unexpected temporary relay endpoint')
    require(plan['remote_endpoint'] == 'http://127.0.0.1:19480/v1', 'Unexpected isolated EVO endpoint')
    require(plan['model'] == 'qwen3.8-flash-next-iq3_s', 'Unexpected model')
    require(plan['relay_source']['sha256'] == sha(plan['relay_source']['path']), 'Existing relay source changed')
    require(plan['ssh'][0].endswith('/Windows/System32/OpenSSH/ssh.exe'), 'Use existing Windows SSH')
    require('-W' not in plan['ssh'] and all(isinstance(x, str) for x in plan['ssh']), 'Invalid base SSH command')
    require(plan['ssh'].count('-F') == 1 and plan['ssh'][plan['ssh'].index('-F') + 1] == 'none', 'Explicit SSH settings required')
    for option in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes'):
        require(option in plan['ssh'], 'Missing pinned SSH policy')
    runtime = plan['runtime_modules']
    actual = {str(p.relative_to(REPO)):p for p in (REPO/'aotg').glob('*.py')}
    require(set(runtime) == set(actual), 'Exact candidate runtime source inventory required')
    for name,path in actual.items():
        require(sha(path) == runtime[name], 'Runtime module changed: '+name)
    require(runtime['aotg/field_evidence.py'] == '3965ae8ead3e8c11fa513ba84a83105e1f5811d8a51b65c046b75b0ed6a888ac',
            'Reviewed field validator differs')
    require(sha(plan['quality_catalog']['path']) == plan['quality_catalog']['sha256'] == CATALOG_SHA256
            and runtime['aotg/quality.py'] == VERIFIER_SHA256, 'Paired independent grader/catalog differs')
    for item in plan['inputs']:
        require(sha(item['path']) == item['sha256'], 'Frozen input changed: ' + item['path'])
    transport=plan['windows_transport']
    for name in ('wrapper','helper','ssh','powershell'):
        require(sha(transport[name]['path'])==transport[name]['sha256'],'Windows transport input changed')
    require(Path(transport['linux_root']).is_dir(),'Owned Windows job evidence directory missing')
    profile = validate_profile(plan['profile'], plan['endpoint'], plan['model'])
    require(profile['model_limits'] == {'context': 131072, 'output': 1024}, 'Model limits changed')
    field = json.loads(Path(plan['field_plan']).read_text())
    require(sha(plan['field_plan']) == plan['field_plan_sha256'], 'Field plan raw bytes changed')
    validate_comparison_contract(plan, field)
    for workload in plan['workloads'].values():
        _workload(workload)
    root = Path(plan['output_root'])
    require(root.is_absolute() and root.parent.is_dir() and not root.exists(), 'Require new private results path')
    require(Path(plan['remote_task_root']).is_absolute() and '..' not in Path(plan['remote_task_root']).parts, 'Unsafe remote path')
    return {'dry_run': True, 'plan_sha256': digest(plan), 'trials': len(plan['schedule']),
            'production_changed': False, 'inference_invoked': False, 'quality_accepted': False}


def remote(plan, code, timeout, *, deadline=None):
    # The only remote interpreter used here reads arm state or writes the one
    # owned done marker. No shell interpolation of user/model text occurs.
    deadline = deadline if deadline is not None else time.monotonic()+timeout+SSH_CLOSE_SECONDS
    operation_deadline = min(time.monotonic()+timeout, deadline-SSH_CLOSE_SECONDS)
    seconds = budget(operation_deadline, 180, 'Remote state')
    require(seconds >= 1, 'Remote state budget lacks SSH startup reserve')
    with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
        process=OwnedSSH(plan,[*plan['ssh'],'python3 -B -'],seconds,stdout,stderr)
        try:
            process.stdin.write(code.encode());process.stdin.close()
            while process.poll() is None:
                require(time.monotonic()<operation_deadline,'Remote state deadline')
                require(os.fstat(stdout.fileno()).st_size<=262144 and os.fstat(stderr.fileno()).st_size<=65536,
                        'Remote state output exceeded limit')
                time.sleep(min(.02,remaining(operation_deadline)))
            require(process.process.returncode == 0,'Owned remote state operation failed')
            require(os.fstat(stdout.fileno()).st_size<=262144 and os.fstat(stderr.fileno()).st_size<=65536,
                    'Remote state output exceeded limit')
            stdout.seek(0)
            return json.loads(stdout.read(262144))
        finally:
            try:process.close(deadline=deadline)
            except Exception as error:
                raise CleanupUnverified('Owned remote cleanup unverified: '+describe(error)) from error


def await_arm(plan, row, *, deadline):
    code = '''import json,time,pathlib
task=pathlib.Path(TASK)
deadline=time.monotonic()+SECONDS
while time.monotonic()<deadline:
 p=task/'ready.json'
 if p.exists():
  r=json.loads(p.read_text())
  if r['index']>INDEX: raise RuntimeError('Skipped arm; no retry')
  if r['index']==INDEX:
   print(json.dumps(r));break
 s=task/'summary.json'
 if s.exists() and json.loads(s.read_text()).get('status') not in ('running',):
  raise RuntimeError('Worker ended before requested arm')
 time.sleep(.2)
else: raise RuntimeError('Arm wait deadline')
'''
    seconds = budget(deadline-10-SSH_CLOSE_SECONDS, 150, 'Arm wait')
    code = 'TASK=' + repr(plan['remote_task_root']) + '\nINDEX=' + str(row['index']) + '\nSECONDS=' + str(seconds) + '\n' + code
    ready = remote(plan, code, seconds + 10, deadline=deadline)
    for key in ('index', 'candidate_id', 'comparison_id', 'workload_id', 'block'):
        require(type(ready[key]) is type(row[key]) and ready[key] == row[key], 'Remote arm identity mismatch')
    require(ready['run_id'] == plan['run_id'] and ready['plan_sha256'] == plan['worker_plan_sha256'], 'Remote plan identity mismatch')
    require(ready.get('artifact') == 'aotg-field-ready' and type(ready.get('version')) is int and ready.get('version') == 1, 'Remote marker schema mismatch')
    require(ready['field_plan_sha256'] == plan['field_plan_sha256']
            and ready['schedule_sha256'] == digest(plan['schedule']), 'Remote full schedule/field plan differs')
    require(ready['endpoint'] == plan['remote_endpoint'], 'Remote port mismatch')
    profile = next(x for x in json.loads(Path(plan['field_plan']).read_text())['candidates'] if x['id'] == row['candidate_id'])
    require(ready['profile_sha256'] == profile['profile_sha256'], 'Remote profile mismatch')
    # Remote deadline is informative only; local clocks may differ. Worker has
    # its own independent monotonic timer; 130 s client + short probe fit 180 s.
    return ready


def finish_arm(plan, ready, result, succeeded, *, deadline=None):
    marker = {key: ready[key] for key in MARKER_IDENTITY_FIELDS}
    marker.update(artifact='aotg-field-done', version=1,
                  status='completed' if succeeded else 'failed', evidence_sha256=digest(result))
    code = '''import json,os,pathlib
task=pathlib.Path(TASK)
current=json.loads((task/'ready.json').read_text())
for k in ('run_id','plan_sha256','field_plan_sha256','schedule_sha256','index','candidate_id','comparison_id','workload_id','block','profile_sha256'):
 if current[k]!=MARKER[k]: raise RuntimeError('Remote arm changed')
p=task/('done-'+str(MARKER['index'])+'.json')
tmp=p.with_name(p.name+'.k8.tmp')
if p.exists(): raise RuntimeError('No completion replay')
with tmp.open('x') as f:
 os.chmod(tmp,0o600);json.dump(MARKER,f);f.flush();os.fsync(f.fileno())
tmp.replace(p)
print(json.dumps({'written':True}))
'''
    return remote(plan, 'TASK=' + repr(plan['remote_task_root']) + '\nMARKER=' + repr(marker) + '\n' + code, 15, deadline=deadline)


class ScopedConnections:
    """Track accepted sockets before their handler thread can start."""
    def initialize_scope(self):
        self.condition=threading.Condition()
        self.accepting=True
        self.active=set()
        self.connection_refusal_counts={'closing':0,'concurrency':0,'deadline':0,'thread_start':0}
    def process_request(self, request, client_address):
        with self.condition:
            if (not self.accepting or len(self.active)>=8
                    or time.monotonic() >= getattr(self, 'work_deadline', float('inf'))):
                reason='closing' if not self.accepting else 'concurrency' if len(self.active)>=8 else 'deadline'
                self.connection_refusal_counts[reason]+=1
                marker=getattr(self,'mark_capture_incomplete',None)
                try:
                    if marker is not None:marker()
                finally:
                    self.shutdown_request(request)
                return
            self.active.add(request)
        try:
            super().process_request(request,client_address)
        except BaseException:
            with self.condition:
                self.connection_refusal_counts['thread_start']+=1
                self.active.discard(request);self.condition.notify_all()
            marker=getattr(self,'mark_capture_incomplete',None)
            try:
                if marker is not None:marker()
            finally:
                self.shutdown_request(request)
            raise
    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(5)
            super().process_request_thread(request,client_address)
        finally:
            with self.condition:
                self.active.discard(request);self.condition.notify_all()
    def close_admission(self):
        with self.condition:
            self.accepting=False
            for connection in list(self.active):
                try:connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
    def drain(self, seconds=None, *, deadline=None):
        if deadline is None: deadline=time.monotonic()+seconds
        elif seconds is not None: deadline=min(deadline,time.monotonic()+seconds)
        with self.condition:
            while self.active and time.monotonic()<deadline:
                self.condition.wait(min(.1,max(0,deadline-time.monotonic())))
            require(not self.active,'Connection handlers did not drain; evidence cannot be frozen')


class BoundedProxy(ScopedConnections,MeasurementProxy):
    # Rebind our fixed loopback port after a drained arm's TIME_WAIT sockets.
    # SO_REUSEPORT is never enabled; another active listener still prevents bind.
    allow_reuse_address=True
    def __init__(self,*args,**kwargs):
        self.work_deadline=kwargs.pop('work_deadline',float('inf'))
        self.initialize_scope()
        super().__init__(*args,**kwargs)
        self.deadline=min(self.deadline,self.work_deadline)


class Relay(ScopedConnections,socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    def __init__(self, plan, errors, *, work_deadline, cleanup_deadline, remote_port=19480):
        self.initialize_scope()
        require(type(remote_port) is int and remote_port in (19480,18080), 'Unreviewed relay port')
        self.remote_port=remote_port
        self.accepting=False
        self.work_deadline,self.cleanup_deadline=work_deadline,cleanup_deadline
        self.plan, self.errors = plan, errors
        self.lock, self.children, self.connections = threading.Lock(), set(), set()
        self.cleanup_errors=[]
        super().__init__(('127.0.0.1', 19481), RelayHandler)
    def cancel_children(self):
        self.close_admission()
        with self.lock:
            children, connections = list(self.children), list(self.connections)
        for connection in connections:
            try: connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        for child in children:
            try: child.stdin.close()
            except (OSError, ValueError): pass
            try:child.cancel_job()
            except Exception as error:
                with self.lock:self.cleanup_errors.append('Cancel owned job: '+describe(error))
        return children
    def stop_children(self, *, deadline):
        errors=[]
        children=self.cancel_children()
        for child in children:
            try:child.close(deadline=deadline)
            except Exception as error:errors.append(describe(error))
        try:self.drain(deadline=deadline)
        except Exception as error:errors.append(describe(error))
        with self.lock:
            errors.extend(self.cleanup_errors)
        require(not errors,'Relay cleanup unverified: '+ '; '.join(errors))
    def open_admission(self):
        with self.condition:
            require(not self.active,'Prior relay handlers remain')
            require(time.monotonic()<self.work_deadline,'Relay work deadline exhausted')
            self.accepting=True


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        command = [*server.plan['ssh'][:-1], '-W', '127.0.0.1:'+str(server.remote_port), server.plan['ssh'][-1]]
        with server.condition:
            seconds=min(40,remaining(server.work_deadline))
            if not server.accepting or seconds<1:return
            process = OwnedSSH(server.plan,command,seconds,subprocess.PIPE,server.errors)
            with server.lock:
                server.children.add(process); server.connections.add(self.request)
        self.request.settimeout(budget(server.work_deadline,35,'Relay request'))
        def upload():
            try:
                while True:
                    if time.monotonic()>=server.work_deadline:break
                    block = self.request.recv(65536)
                    if not block: break
                    process.stdin.write(block)
            except (OSError, ValueError): pass
            finally:
                try: process.stdin.close()
                except (OSError, ValueError): pass
        upstream = threading.Thread(target=upload, daemon=True)
        upstream.start()
        try:
            while True:
                block = process.stdout.read(65536)
                if not block: break
                self.request.sendall(block)
        except (OSError, ValueError): pass
        finally:
            try: self.request.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try:
                process.close(deadline=server.cleanup_deadline)
                upstream.join(timeout=min(3,remaining(server.cleanup_deadline)))
                require(not upstream.is_alive(),'Relay upload handler cleanup deadline')
            except Exception as error:
                with server.lock:server.cleanup_errors.append(describe(error))
            finally:
                process.stdout.close()
                with server.lock:
                    if process.receipt is not None:server.children.discard(process)
                    server.connections.discard(self.request)


def cleanup_server(server, serving_thread, *, deadline, errors):
    """No sequential relative waits can extend the common cleanup deadline."""
    if server is None:return
    def attempt(label, action):
        try:action()
        except Exception as error:errors.append(label+': '+describe(error))
    attempt('close admission',server.close_admission)
    # BaseServer.shutdown itself has no timeout. Keep its join explicitly bounded.
    shutdown=threading.Thread(target=server.shutdown,daemon=True)
    shutdown.start()
    shutdown.join(timeout=remaining(deadline))
    if shutdown.is_alive():errors.append('Server shutdown deadline; listener cleanup unverified')
    attempt('handler drain',lambda:server.drain(deadline=deadline))
    attempt('listener close',server.server_close)
    if serving_thread is not None:
        serving_thread.join(timeout=remaining(deadline))
        if serving_thread.is_alive():errors.append('Serving thread cleanup deadline')


def cleanup_arm(proxy, proxy_thread, relay, *, deadline):
    errors=[]
    # Cancel upstream jobs first so proxy callbacks can finish before freezing.
    if proxy is not None:
        try:proxy.close_admission()
        except Exception as error:errors.append('Proxy admission: '+describe(error))
    if relay is not None:
        try:relay.stop_children(deadline=deadline)
        except Exception as error:errors.append('Relay children: '+describe(error))
    cleanup_server(proxy,proxy_thread,deadline=deadline,errors=errors)
    return errors


def execute(plan, approval):
    preflight(plan)
    require(approval == digest(plan), 'Execution must match explicitly approved client plan')
    root = Path(plan['output_root']); root.mkdir(mode=0o700)
    save(root/'plan.json', plan)
    started = time.monotonic()
    final_deadline=started+plan['max_seconds']
    work_deadline=final_deadline-plan['cleanup_reserve_seconds']
    arm_budget=20+plan['task_seconds']+CLIENT_OVERHEAD_SECONDS+ARM_CLEANUP_SECONDS+MARKER_SECONDS
    summary = {'artifact': 'aotg-k8-field-run', 'version': 1, 'plan_sha256': digest(plan),
               'quality_accepted': False, 'status': 'running', 'arms': [], 'cleanup_errors': [],
               'limits':{'total_seconds':plan['max_seconds'],
                         'cleanup_reserve_seconds':plan['cleanup_reserve_seconds'],
                         'active_work_seconds':plan['max_seconds']-plan['cleanup_reserve_seconds']}}
    relay = relay_thread = errors = None
    try:
        profile = json.loads(Path(plan['profile']).read_text())
        key_ref = profile['provider']['evo']['options']['apiKey']
        key = Path(key_ref[6:-1]).read_text().strip()
        errors=(root/'ssh-private.log').open('xb')
        relay = Relay(plan, errors, work_deadline=work_deadline, cleanup_deadline=final_deadline)
        relay_thread = threading.Thread(target=relay.serve_forever, kwargs={'poll_interval':.05}, daemon=True)
        relay_thread.start()
        signal_client_ready(plan,root)
        for row in plan['schedule']:
            require(remaining(work_deadline) > WAIT_SECONDS+arm_budget,
                    'Global client budget lacks wait/work/cleanup reserve')
            ready = await_arm(plan, row, deadline=work_deadline-arm_budget)
            require(remaining(work_deadline)>arm_budget,'Global client budget exhausted before inference')
            relay.open_admission()
            arm = root/('arm-%02d' % row['index']); arm.mkdir(mode=0o700)
            save(arm/'ready.json', ready)
            measurements=[]
            record_lock=threading.Lock()
            record_state={'accepting':True,'error':None}
            def record(value,records=measurements,output=arm,lock=record_lock,state=record_state):
                with lock:
                    if not state['accepting']:return
                    records.append(value)
                    try:
                        with (output/'requests.jsonl').open('a') as stream:
                            stream.write(json.dumps(value, sort_keys=True)+'\n')
                    except Exception as error:
                        state['error']=describe(error)
                        raise
            proxy=proxy_thread=None
            outcome = {**row, 'status':'failed', 'quality_accepted':False}
            succeeded = False
            arm_cleanup=[]
            try:
                proxy_seconds=budget(work_deadline-ARM_CLEANUP_SECONDS-MARKER_SECONDS,170,'Proxy work')
                proxy = BoundedProxy(('127.0.0.1',19482), upstream=plan['upstream'], api_key=key,
                    model=plan['model'], max_requests=plan['max_requests'], max_tokens=1024,
                    total_seconds=proxy_seconds, request_seconds=min(35,proxy_seconds), record=record,
                    work_deadline=work_deadline-ARM_CLEANUP_SECONDS-MARKER_SECONDS)
                proxy_thread = threading.Thread(target=proxy.serve_forever,kwargs={'poll_interval':.05},daemon=True)
                proxy_thread.start()
                short = measure_chat(plan['endpoint'], {'model':plan['model'],'messages':[
                    {'role':'user','content':'Return only the integer answer to 6 multiplied by 7.'}],
                    'max_tokens':16}, api_key=key,
                    timeout_seconds=budget(work_deadline-ARM_CLEANUP_SECONDS-MARKER_SECONDS,20,'Short probe'))
                save(arm/'short-answer.json',short)
                require(short['status']=='completed' and short['content'].strip()=='42', 'Short-answer contract failed')
                client_seconds=budget(work_deadline-ARM_CLEANUP_SECONDS-MARKER_SECONDS-CLIENT_OVERHEAD_SECONDS,
                                      plan['task_seconds'],'OpenCode work')
                require(client_seconds==plan['task_seconds'],'Global client budget lacks full frozen task duration')
                result = run_opencode(executable=plan['opencode'],profile=plan['profile'],
                    command=client_command(plan['opencode'],plan['model']),workload=plan['workloads'][row['workload_id']],
                    endpoint=plan['endpoint'],model=plan['model'],output_dir=arm/'coding',
                    tool_path=plan['tool_path'],max_seconds=client_seconds,max_steps=plan['max_steps'],
                    max_output_bytes=2*1024*1024,namespace_tools=plan['namespace_tools'],execution_authorized=True)
                # Behavioral failure is evidence, not an automatic retry.
                outcome.update(client_result_sha256=digest(result),client_status=result['status'],
                               seconds=result['seconds'],short_result_sha256=digest(short))
                succeeded = result['status']=='completed-awaiting-independent-quality'
                outcome['status']='completed-awaiting-independent-quality' if succeeded else 'client-failed'
            except Exception as error:
                outcome['error'] = describe(error)
            finally:
                arm_cleanup_deadline=min(final_deadline,time.monotonic()+ARM_CLEANUP_SECONDS)
                try:
                    arm_cleanup=cleanup_arm(proxy,proxy_thread,relay,
                        deadline=arm_cleanup_deadline)
                except Exception as error:
                    arm_cleanup.append('Unexpected arm cleanup: '+describe(error))
                if arm_cleanup:
                    succeeded=False
                    outcome['status']='stopped-cleanup-unverified'
                    summary['cleanup_errors'].extend(arm_cleanup)
                outcome['cleanup_errors']=arm_cleanup
                outcome['requests_complete']=not arm_cleanup
                # Never wait forever on a callback during evidence failure.
                locked=record_lock.acquire(timeout=remaining(arm_cleanup_deadline))
                if locked:
                    try:
                        record_state['accepting']=False
                        outcome['requests']=list(measurements)
                        outcome['pre_http_connection_refusals']=None
                        try:
                            counts=getattr(proxy,'connection_refusal_counts',None)
                            outcome['pre_http_connection_refusals']=dict(counts) if isinstance(counts,dict) else None
                            validate_connection_refusals(outcome['pre_http_connection_refusals'])
                            validate_capture(outcome['requests'])
                        except Exception as error:
                            succeeded=False
                            outcome.update(status='stopped-capture-incomplete',requests_complete=False)
                            detail='Proxy capture: '+describe(error)
                            outcome['cleanup_errors'].append(detail)
                            summary['cleanup_errors'].append(detail)
                        if record_state['error']:
                            succeeded=False
                            outcome.update(status='stopped-cleanup-unverified',requests_complete=False)
                            detail='Request evidence callback failed: '+record_state['error']
                            outcome['cleanup_errors'].append(detail)
                            summary['cleanup_errors'].append(detail)
                    finally:record_lock.release()
                else:
                    succeeded=False
                    outcome.update(status='stopped-cleanup-unverified',requests_complete=False,requests=[])
                    outcome['cleanup_errors'].append('Request evidence callback did not release lock')
                    summary['cleanup_errors'].append('Request evidence callback did not release lock')
                save(arm/'result.json',outcome)
                summary['arms'].append(outcome)
            require(not outcome['cleanup_errors'],'Arm cleanup unverified; no marker or next arm')
            require(remaining(work_deadline)>MARKER_SECONDS,'Global client budget exhausted before completion marker')
            marker=finish_arm(plan,ready,outcome,succeeded,deadline=work_deadline)
            save(arm/'done-receipt.json',marker)
            require(succeeded, 'Arm failed; remaining schedule stopped without retry')
        summary['status']='completed-awaiting-independent-quality'
    except Exception as error:
        summary.update(status='stopped',error=describe(error))
        if isinstance(error,CleanupUnverified):summary['cleanup_errors'].append(describe(error))
    finally:
        try:
            if relay:
                try:relay.stop_children(deadline=final_deadline)
                except Exception as error:summary['cleanup_errors'].append('Final relay children: '+describe(error))
                cleanup_server(relay,relay_thread,deadline=final_deadline,errors=summary['cleanup_errors'])
        except Exception as error:
            summary['cleanup_errors'].append('Final cleanup: '+describe(error))
        finally:
            if errors is not None:
                try:errors.close()
                except Exception as error:summary['cleanup_errors'].append('Private log close: '+describe(error))
            if summary['cleanup_errors']:summary['status']='stopped-cleanup-unverified'
            summary['seconds']=time.monotonic()-started
            summary['total_deadline_exceeded']=time.monotonic()>final_deadline
            if summary['total_deadline_exceeded'] and not summary['cleanup_errors']:
                summary['status']='stopped-deadline-exceeded'
            save(root/'summary.json',summary)
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',required=True)
    parser.add_argument('--execute-approved-plan-sha256')
    args=parser.parse_args()
    plan=json.loads(Path(args.plan).read_text())
    result=execute(plan,args.execute_approved_plan_sha256) if args.execute_approved_plan_sha256 else preflight(plan)
    print(json.dumps(result,sort_keys=True))
