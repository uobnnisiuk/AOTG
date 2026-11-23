"""One bounded existing-OwnedSSH callback. No CLI execution or runtime imports.

The controller supplies runner.OwnedSSH only AFTER its established full closure
verification and in-memory import. This component does not accept source paths,
discover hosts, authenticate, stage a run, or call the small control exchange.
"""
import hashlib
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time


def required(value, reason):
    if not value: raise ValueError(reason)


def read_regular(path, limit=65536):
    path = Path(path)
    required(path.is_absolute() and ".." not in path.parts, "metadata_path")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            required(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, "metadata_file")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno()); entry = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            signature = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_nlink)
            required(len(raw) <= limit and signature(before) == signature(after) == signature(entry), "metadata_changed")
            return raw
    finally:
        os.close(directory)


class OwnedSSHCallback:
    """Supply only the already-verified runner.OwnedSSH class; never a runtime path."""
    def __init__(self, seed, owned_ssh_factory, *, clock=time.monotonic, selector=select.select):
        self.seed, self.factory, self.clock, self.selector = seed, owned_ssh_factory, clock, selector
        self.used = False

    def __call__(self, *, payload, stdout, stderr, remote_seconds, wall_seconds, cleanup_seconds,
                 deadline, stdout_limit, stderr_limit):
        required(not self.used, "collector_transport_one_use")
        required(type(payload) is bytes and len(payload) <= 256*1024, "payload_limit")
        required((remote_seconds,wall_seconds,cleanup_seconds,stdout_limit,stderr_limit)
                 == (60,70,20,384*1024**2,256*1024), "fixed_transport_limits")
        started = self.clock()
        required(type(deadline) in (int,float) and started < deadline <= started+90, "fixed_total_deadline")
        work_deadline = min(started+70, deadline-20)
        required(work_deadline > started, "missing_cleanup_reserve")
        self.used = True
        argv = self.seed["ssh"] + ["/usr/bin/python3.14","-I","-S","-B","-"]
        job = None; readers = {}; input_stream = None; sent = 0; error = None
        digests = {"stdout":hashlib.sha256(), "stderr":hashlib.sha256()}
        totals = {"stdout":0,"stderr":0}; caps={"stdout":stdout_limit,"stderr":stderr_limit}
        sinks = {"stdout":stdout,"stderr":stderr}; plan_raw = receipt_raw = b""
        wrapper_returncode = None; pipes=[]
        try:
            required(self.clock() < work_deadline, "transport_launch_deadline")
            job = self.factory(self.seed, argv, 70, subprocess.PIPE, subprocess.PIPE)
            process = job.process
            input_stream = job.stdin
            pipes = [input_stream, process.stdout, process.stderr]
            required(all(p is not None for p in pipes), "transport_pipes_required")
            for stream in pipes: os.set_blocking(stream.fileno(),False)
            readers = {process.stdout.fileno():(process.stdout,"stdout"), process.stderr.fileno():(process.stderr,"stderr")}
            while readers or process.poll() is None:
                now = self.clock(); required(now < work_deadline,"transport_work_deadline")
                if process.poll() is not None and input_stream is not None:
                    required(sent == len(payload), "remote_exited_before_payload_complete")
                    input_stream.close(); input_stream = None
                writers = [input_stream.fileno()] if input_stream is not None else []
                readable, writable, _ = self.selector(list(readers), writers, [], min(.05, work_deadline-now))
                if writable:
                    required(self.clock() < work_deadline,"transport_input_deadline")
                    try: count = os.write(writable[0], payload[sent:sent+65536])
                    except BlockingIOError: count = 0
                    sent += count
                    if sent == len(payload): input_stream.close(); input_stream = None
                for fd in readable:
                    required(self.clock() < work_deadline,"transport_output_deadline")
                    try: data = os.read(fd,65536)
                    except BlockingIOError: continue
                    stream, role = readers[fd]
                    if not data:
                        stream.close(); del readers[fd]; continue
                    required(totals[role]+len(data) <= caps[role],"transport_output_limit")
                    sinks[role].write(data)
                    digests[role].update(data); totals[role]+=len(data)
            required(sent == len(payload),"payload_incomplete")
        except Exception as exc:
            error = str(exc) if type(exc) is ValueError and re.fullmatch(r"[a-z_]{1,80}",str(exc)) else type(exc).__name__
        finally:
            # Never retry. Even sink rejection, EPIPE, timeout or an uncertain exit
            # must reach the existing Job cancellation/receipt path once.
            if input_stream is not None:
                try: input_stream.close()
                except OSError: pass
            if job is not None:
                try:
                    if error is not None and job.process.poll() is None: job.cancel_job()
                    job.close(deadline=deadline)
                except Exception as exc:
                    error = (error+";" if error else "") + "cleanup_" + type(exc).__name__
                wrapper_returncode = job.process.returncode
                try:
                    root = Path(self.seed["windows_transport"]["linux_root"])
                    result = Path(job.result)
                    required(result.parent == root and re.fullmatch(r"[a-f0-9]{24}\.result\.json",result.name),"job_result_path")
                    stem = result.name[:-len(".result.json")]
                    plan_raw = read_regular(root/(stem+".plan.json"))
                    required(hashlib.sha256(plan_raw).hexdigest() == job.plan_sha256,"job_plan_changed")
                    receipt_raw = read_regular(result)
                except Exception as exc:
                    error = (error+";" if error else "") + "metadata_" + type(exc).__name__
            for stream in pipes:
                try: stream.close()
                except OSError: pass
        if self.clock() >= deadline: error = (error+";" if error else "") + "transport_total_deadline"
        return {"job_plan_bytes":plan_raw,"receipt_bytes":receipt_raw,"wrapper_returncode":wrapper_returncode,
                "stdout_sha256":digests["stdout"].hexdigest(),"stderr_sha256":digests["stderr"].hexdigest(),
                "payload_sha256":hashlib.sha256(payload).hexdigest(),"callback_error":error[:128] if error else None}


def collect_after_owner_result(receiver, *, request, seed, owner_result_bytes, output_dir,
                               verified_runner, remote_source, remote_source_sha256, clock=time.monotonic, deadline=None):
    """Controller adapter for a separately budgeted 90-second read-only phase.

    `receiver` and `verified_runner` are supplied by the controller after verifying
    their exact source closure; this function performs no import or approval step.
    run_collection checks the hash-bound owner result before constructing a job.
    Its summary is evidence collection only, never an independent restoration test.
    """
    receiver.validate_seed(seed)
    return receiver.run_collection(request,seed,owner_result_bytes,output_dir,
        OwnedSSHCallback(seed,verified_runner.OwnedSSH,clock=clock),
        remote_source=remote_source,remote_source_sha256=remote_source_sha256,clock=clock,deadline=deadline)
