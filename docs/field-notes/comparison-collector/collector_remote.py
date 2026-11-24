"""Fixed-file, unprivileged post-restoration collector; no remote writes.

Without an injected CONFIG, direct execution only prints limits. The caller
must pin these bytes and the generated stdin payload before its existing SSH job.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import select
import signal
import stat
import sys
import time

MIB=1024*1024
LIMITS={"remote_seconds":60,"local_seconds":90,"transport_seconds":70,"cleanup_seconds":20,
        "total_raw_bytes":256*MIB,"wire_bytes":384*MIB,"wire_records":6200,"planned_files":520,
        "chunk_bytes":65536,"wire_line_bytes":100000,"stderr_bytes":262144,
        "resources_bytes":64*MIB,"resources_records":30000,
        "observations_bytes":128*MIB,"observations_records":60001,"jsonl_line_bytes":16384}
REQUEST_FIELDS={"artifact","version","run_id","nonce","owner_uid","owner_gid","work_root","work_identity",
                "authorization_sha256","client_plan_sha256","worker_plan_sha256","owner_result_sha256","schedule"}
ROW_FIELDS={"index","candidate_id","comparison_id","workload_id","block","profile_sha256"}

def need(value,reason):
    if not value:raise CollectionError(reason)

class CollectionError(ValueError):pass

def sha(value):return hashlib.sha256(value).hexdigest()
def canon(value):return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
def utc():return datetime.now(timezone.utc).isoformat()
def integer(value,minimum=0):return type(value) is int and value>=minimum

def parse(raw):
    def pairs(items):
        value={}
        for key,item in items:
            need(key not in value,"duplicate_json_key");value[key]=item
        return value
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,"nonfinite_json"))
    need(isinstance(value,dict),"json_object_required")
    return value

def validate(request):
    need(isinstance(request,dict) and set(request)==REQUEST_FIELDS,"request_fields")
    need(request["artifact"]=="aotg-comparison-collection-request" and type(request["version"]) is int and request["version"]==1,"request_version")
    need(integer(request["owner_uid"],1) and integer(request["owner_gid"]),"nonroot_owner_required")
    for key in ("authorization_sha256","client_plan_sha256","worker_plan_sha256","owner_result_sha256"):
        need(isinstance(request[key],str) and re.fullmatch(r"[0-9a-f]{64}",request[key]),"request_hash")
    need(isinstance(request["nonce"],str) and re.fullmatch(r"[0-9a-f]{16}",request["nonce"])
         and isinstance(request["run_id"],str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,95}",request["run_id"])
         and request["run_id"].endswith("-"+request["nonce"]),"request_run")
    path=request["work_root"]
    need(isinstance(path,str) and path.startswith("/") and str(PurePosixPath(path))==path
         and ".." not in PurePosixPath(path).parts and "\0" not in path
         and PurePosixPath(path).name==request["run_id"],"fixed_work_root")
    identity=request["work_identity"]
    need(isinstance(identity,dict) and set(identity)=={"device","inode"}
         and integer(identity["device"]) and integer(identity["inode"],1),"work_identity")
    need(isinstance(request["schedule"],list) and len(request["schedule"])==64,"full_schedule_required")
    for index,row in enumerate(request["schedule"]):
        need(isinstance(row,dict) and set(row)==ROW_FIELDS and type(row["index"]) is int and row["index"]==index
             and integer(row["block"]) and row["block"]<4,"schedule_identity")
        need(all(isinstance(row[k],str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,95}",row[k])
                 for k in ("candidate_id","comparison_id","workload_id"))
             and isinstance(row["profile_sha256"],str) and re.fullmatch(r"[0-9a-f]{64}",row["profile_sha256"]),"schedule_binding")
    return request

def inventory():
    files=[("work/owner-entry-result.json",262144,None), ("task/summary.json",MIB,None),
           ("task/kernel-final.json",131072,None), ("task/resources.jsonl",LIMITS["resources_bytes"],LIMITS["resources_records"]),
           ("task/resource-observations.jsonl",LIMITS["observations_bytes"],LIMITS["observations_records"])]
    for index in range(64):
        arm="task/arm-"+str(index).zfill(3)+"/"
        for name,cap in (("result.json",65536),("config.json",131072),("settings.json",65536),
                         ("ready.json",65536),("server-ready.json",65536),
                         ("logs/server-private.log",262144),("logs/engine-private.log",262144)):
            files.append((arm+name,cap,None))
        files.append(("task/done-"+str(index)+".json",65536,None))
    need(len(files)<=LIMITS["planned_files"],"inventory_limit")
    return files

def signature(info):
    return {"device":info.st_dev,"inode":info.st_ino,"bytes":info.st_size,"mtime_ns":info.st_mtime_ns,
            "ctime_ns":info.st_ctime_ns,"mode":info.st_mode,"uid":info.st_uid,"gid":info.st_gid,"links":info.st_nlink}

def open_directory(path):
    value=PurePosixPath(path)
    need(value.is_absolute() and ".." not in value.parts,"nontraversing_directory")
    current=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in value.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
            os.close(current);current=child
        return current
    except BaseException:os.close(current);raise

def owned_directory(info,request):
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==request["owner_uid"] and info.st_gid==request["owner_gid"]
         and not info.st_mode&0o022,"unsafe_directory_owner_or_mode")

def open_file(root,label,request):
    group,relative=label.split("/",1)
    parts=(["work"] if group=="task" else [])+relative.split("/")
    directory=os.dup(root)
    try:
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            try:owned_directory(os.fstat(child),request)
            except BaseException:os.close(child);raise
            os.close(directory);directory=child
        fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        return directory,parts[-1],fd
    except BaseException:os.close(directory);raise

def check_file(info,request,cap):
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1,"nonregular_or_linked_file")
    need(info.st_uid==request["owner_uid"] and info.st_gid==request["owner_gid"]
         and not info.st_mode&0o022,"unsafe_file_owner_or_mode")
    need(info.st_size<=cap,"file_byte_limit")

def metadata(root,label,request,cap,reader=os.read):
    directory,name,fd=open_file(root,label,request)
    try:
        before=os.fstat(fd);check_file(before,request,cap);parts=[];size=0
        while True:
            data=reader(fd,min(LIMITS["chunk_bytes"],cap+1-size))
            if not data:break
            parts.append(data);size+=len(data)
            need(size<=cap,"metadata_size_mismatch")
        raw=b"".join(parts)
        need(len(raw)<=cap and len(raw)==before.st_size,"metadata_size_mismatch")
        after=os.fstat(fd);entry=os.stat(name,dir_fd=directory,follow_symlinks=False)
        need(signature(before)==signature(after)==signature(entry),"metadata_changed")
        return raw,signature(after)
    finally:os.close(fd);os.close(directory)

def owner_gate(raw,request):
    need(sha(raw)==request["owner_result_sha256"],"owner_result_changed")
    value=parse(raw)
    need(value.get("artifact")=="aotg-owner-entry-result" and type(value.get("version")) is int and value["version"]==1
         and value.get("authorization_sha256")==request["authorization_sha256"]
         and value.get("nonce")==request["nonce"] and value.get("unit_restore_verified") is True
         and value.get("status") in ("maintenance-returned","maintenance-error"),"owner_restoration_not_reported")
    return value

def summary_gate(raw,request):
    value=parse(raw)
    need(value.get("artifact")=="aotg-evo-worker-result" and type(value.get("version")) is int and value["version"]==1
         and value.get("run_id")==request["run_id"] and value.get("plan_sha256")==request["worker_plan_sha256"]
         and value.get("status") in ("stopped","completed-awaiting-independent-quality"),"worker_summary_identity_or_terminal")
    arms=value.get("arms");need(isinstance(arms,list) and len(arms)<=64,"summary_arms")
    seen=set()
    for row in arms:
        need(isinstance(row,dict) and integer(row.get("index")) and row["index"]<64 and row["index"] not in seen,"summary_arm_index")
        expected=request["schedule"][row["index"]]
        need(all(type(row.get(k)) is type(v) and row.get(k)==v for k,v in expected.items()),"summary_arm_binding")
        seen.add(row["index"])
    return value

def collect(request,emit,*,clock=time.monotonic):
    validate(request);need(os.geteuid()==request["owner_uid"] and os.getegid()==request["owner_gid"],"existing_unprivileged_identity")
    started=clock();deadline=started+LIMITS["remote_seconds"];files=inventory();root=None
    result={"artifact":"aotg-comparison-collection-final","version":1,"request_sha256":sha(canon(request)),
            "status":"incomplete","attempted_files":0,"complete_files":0,"raw_bytes":0,"total_read_bytes":0,"unattempted_indices":list(range(len(files))),
            "preconditions_verified":False,"protected_unchanged":False,"owner_reported_restoration":False,
            "independent_restoration_verified":False,"remote_written":False,"inference_invoked":False,"service_control_invoked":False,
            "errors":[],"started_utc":utc()}
    def check_time():need(clock()<deadline,"remote_collection_deadline")
    def read(fd,size):
        check_time();remaining=LIMITS["total_raw_bytes"]-result["total_read_bytes"]
        need(remaining>0,"aggregate_byte_limit")
        data=os.read(fd,min(size,remaining));result["total_read_bytes"]+=len(data)
        return data
    emit({"artifact":"aotg-comparison-collection-open","version":1,"request_sha256":result["request_sha256"],
          "run_id":request["run_id"],"nonce":request["nonce"],"worker_plan_sha256":request["worker_plan_sha256"],
          "owner_result_sha256":request["owner_result_sha256"],"planned_files":len(files),"limits":LIMITS,"started_utc":result["started_utc"]})
    try:
        check_time();root=open_directory(request["work_root"]);before_root=os.fstat(root);owned_directory(before_root,request)
        need({k:signature(before_root)[k] for k in ("device","inode")}==request["work_identity"],"work_root_replaced")
        owner_raw,owner_stat=metadata(root,"work/owner-entry-result.json",request,262144,read);owner_gate(owner_raw,request)
        summary_raw,summary_stat=metadata(root,"task/summary.json",request,MIB,read);summary_gate(summary_raw,request)
        task=os.open("work",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
        try:task_stat=signature(os.fstat(task));owned_directory(os.fstat(task),request)
        finally:os.close(task)
        result.update(preconditions_verified=True,owner_reported_restoration=True,
                      protected_before={"work":signature(before_root),"task":task_stat,"owner_result":owner_stat,
                                        "owner_result_sha256":sha(owner_raw),"worker_summary":summary_stat,"worker_summary_sha256":sha(summary_raw)})
        for index,(label,cap,record_cap) in enumerate(files):
            check_time();result["attempted_files"]+=1;result["unattempted_indices"]=list(range(index+1,len(files)))
            directory=fd=None;count=read_count=rows=partial_line=0;digest=hashlib.sha256();before=None;status="incomplete";reason=None
            emit({"artifact":"aotg-comparison-file-open","version":1,"index":index,"label":label,"byte_cap":cap,"record_cap":record_cap})
            try:
                directory,name,fd=open_file(root,label,request);before=os.fstat(fd);check_file(before,request,cap)
                need(result["total_read_bytes"]+before.st_size<=LIMITS["total_raw_bytes"],"aggregate_byte_limit")
                while True:
                    check_time();data=read(fd,min(LIMITS["chunk_bytes"],cap+1-read_count))
                    if not data:break
                    read_count+=len(data)
                    need(read_count<=cap,"growing_file_or_aggregate_limit")
                    if record_cap is not None:
                        pieces=data.split(b"\n");rows+=len(pieces)-1
                        lengths=[partial_line+len(pieces[0])]+[len(x) for x in pieces[1:]]
                        need(rows<=record_cap and max(lengths)<=LIMITS["jsonl_line_bytes"],"jsonl_record_or_line_limit")
                        partial_line=lengths[-1] if len(pieces)>1 else lengths[0]
                    emit({"artifact":"aotg-comparison-file-chunk","version":1,"index":index,"offset":count,
                          "bytes":len(data),"base64":base64.b64encode(data).decode("ascii")})
                    count+=len(data);result["raw_bytes"]+=len(data);digest.update(data)
                after=os.fstat(fd);entry=os.stat(name,dir_fd=directory,follow_symlinks=False)
                need(signature(before)==signature(after)==signature(entry) and count==before.st_size,"file_changed_during_collection")
                need(record_cap is None or partial_line==0,"partial_jsonl_tail")
                status="captured";result["complete_files"]+=1
            except (OSError,ValueError) as error:
                reason=str(error) if isinstance(error,CollectionError) else type(error).__name__
            finally:
                if fd is not None:os.close(fd)
                if directory is not None:os.close(directory)
            emit({"artifact":"aotg-comparison-file-close","version":1,"index":index,"label":label,"status":status,
                  "reason":reason,"bytes":count,"read_bytes":read_count,"sha256":digest.hexdigest() if status=="captured" else None,
                  "partial_sha256":digest.hexdigest(),"records":rows if record_cap is not None else None,
                  "stat_before":signature(before) if before is not None else None,
                  "stat_after":signature(after) if status=="captured" else None})
        check_time()
        fresh=open_directory(request["work_root"])
        try:root_after=signature(os.fstat(fresh));need(root_after==signature(before_root),"work_root_changed")
        finally:os.close(fresh)
        task=os.open("work",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
        try:task_after=signature(os.fstat(task));need(task_after==task_stat,"task_root_changed")
        finally:os.close(task)
        owner_after,owner_stat_after=metadata(root,"work/owner-entry-result.json",request,262144,read)
        summary_after,summary_stat_after=metadata(root,"task/summary.json",request,MIB,read)
        need(owner_stat_after==owner_stat and sha(owner_after)==sha(owner_raw)
             and summary_stat_after==summary_stat and sha(summary_after)==sha(summary_raw),"protected_record_changed")
        result["protected_after"]={"work":root_after,"task":task_after,"owner_result":owner_stat_after,
                                   "owner_result_sha256":sha(owner_after),"worker_summary":summary_stat_after,
                                   "worker_summary_sha256":sha(summary_after)}
        result["protected_unchanged"]=True
        if result["complete_files"]==len(files):result["status"]="complete"
    except (OSError,ValueError) as error:
        result["errors"].append(str(error) if isinstance(error,CollectionError) else type(error).__name__)
    finally:
        if root is not None:os.close(root)
    result.update(finished_utc=utc(),seconds=clock()-started)
    if result["seconds"]>=LIMITS["remote_seconds"]:result["status"]="incomplete";result["errors"].append("remote_collection_deadline")
    emit(result)
    return result

def main():
    if "CONFIG" not in globals():
        print(json.dumps({"artifact":"aotg-comparison-collection-preview","version":1,"limits":LIMITS,
                          "planned_files":len(inventory()),"remote_actions":False},sort_keys=True));return 0
    signal.signal(signal.SIGALRM,lambda *_:need(False,"remote_alarm_deadline"));signal.alarm(LIMITS["remote_seconds"])
    started=time.monotonic();written=records=0;fd=sys.stdout.fileno();os.set_blocking(fd,False)
    def emit(value):
        nonlocal written,records
        raw=canon(value)+b"\n";records+=1
        need(len(raw)<=LIMITS["wire_line_bytes"] and records<=LIMITS["wire_records"]
             and written+len(raw)<=LIMITS["wire_bytes"],"wire_budget")
        view=memoryview(raw)
        while view:
            left=started+LIMITS["remote_seconds"]-time.monotonic();need(left>0,"wire_deadline")
            if not select.select([],[fd],[],min(.05,left))[1]:continue
            try:n=os.write(fd,view)
            except BlockingIOError:continue
            need(n>0,"wire_closed");written+=n;view=view[n:]
    result=collect(CONFIG,emit)
    signal.alarm(0)
    return 0 if result["status"]=="complete" else 2

if __name__=="__main__":raise SystemExit(main())
