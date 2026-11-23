"""Separate 90-second post-restoration collection phase; default LOCAL preview.

The new launch canonical hash and GUI pins must include this helper and its plan.
Neither a collection plan nor an old maintenance approval creates start authority.
"""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

# Filled only from the separately reviewed additive handoff provenance revision.
HANDOFF_SHA256 = "5a9dfc0d14f265566d2aeda277bff9ca477183b5fa234ce4dce047cc79336276"
SOURCE_PINS = {
    "remote": ("collector_remote.py", "22a8667bd5f935403e85ebbce6a6f8dbfaeddd00137e6241448df87d074ddf5d"),
    "receiver": ("collect_comparison.py", "010fcad5605885ac040ca2219b9b9db41247dec64eef79c76f593cb060bc1390"),
    "transport": ("collector_transport.py", "32952000f3eb6fc84257313fddda8d25ea88b988887d9d62cddeb3b5b0258e22"),
}
FIELDS = {"artifact","version","driver","handoff_source","handoff_plan","authorization","worker_plan","client_plan",
          "sources","run_id","nonce","owner_uid","owner_gid","remote_work_root","authorization_sha256",
          "client_plan_sha256","output_root","jobs_root","local_seconds"}


def need(value, reason):
    if not value: raise ValueError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",",":"), allow_nan=False).encode("ascii")
def digest(value): return sha(canonical(value))


def parse(raw):
    def pairs(items):
        value={}
        for key,item in items: need(key not in value,"duplicate_json_field");value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,"nonfinite_json"))


def absolute(value):
    need(type(value) is str and value.startswith("/") and "\0" not in value,"absolute_path_required")
    path=Path(value);need(str(path)==value and ".." not in path.parts,"canonical_path_required")
    return path


def directory(path):
    path=absolute(str(path));fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        return fd
    except BaseException:os.close(fd);raise


def read(path,maximum=1024*1024,*,private=True):
    path=absolute(str(path));parent=directory(path.parent)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=parent)
        with os.fdopen(fd,"rb") as stream:
            a=os.fstat(stream.fileno())
            need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=maximum
                 and a.st_uid==os.geteuid() and (not private or not a.st_mode&0o022),"unsafe_local_file")
            raw=stream.read(maximum+1);b=os.fstat(stream.fileno());entry=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            sig=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_nlink)
            need(len(raw)<=maximum and sig(a)==sig(b)==sig(entry),"local_input_changed")
            return raw
    finally:os.close(parent)


def descriptor(value):
    need(isinstance(value,dict) and set(value)=={"path","sha256"},"descriptor_fields")
    absolute(value["path"])
    need(type(value["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}",value["sha256"]),"descriptor_hash")
    return value


def verified(value,maximum=1024*1024,*,private=False):
    descriptor(value);raw=read(value["path"],maximum,private=private)
    need(sha(raw)==value["sha256"],"source_or_plan_drift")
    return raw


def module_from(raw,path,name):
    result=types.ModuleType(name);result.__file__=path
    exec(compile(raw,path,"exec",dont_inherit=True),result.__dict__)
    return result


def prepare(plan_path,expected_raw_sha256=None):
    """Verify local frozen inputs, without creating directories or reading future results."""
    raw=read(plan_path,private=False);plan=parse(raw)
    if expected_raw_sha256 is not None:need(sha(raw)==expected_raw_sha256,"collection_raw_hash")
    need(isinstance(plan,dict) and set(plan)==FIELDS,"collection_plan_fields")
    need(plan["artifact"]=="aotg-comparison-collection-plan" and type(plan["version"]) is int
         and plan["version"]==1 and type(plan["local_seconds"]) is int and plan["local_seconds"]==90,"collection_plan_version_or_budget")
    need(Path(plan["driver"]["path"])==Path(__file__).absolute(),"wrong_phase_driver")
    verified(plan["driver"])
    need(plan["handoff_source"]["sha256"]==HANDOFF_SHA256 and HANDOFF_SHA256!="0"*64,"unreviewed_handoff_source")
    handoff_raw=verified(plan["handoff_source"])
    need(set(plan["sources"])==set(SOURCE_PINS),"collection_source_closure")
    sources={}
    for role,(name,expected) in SOURCE_PINS.items():
        item=plan["sources"][role]
        need(item["path"]==str(Path(__file__).absolute().parent/name) and item["sha256"]==expected,"collection_source_pin")
        sources[role]=verified(item)
    # Only reviewed, hash-bound helpers execute; their imports do not launch work.
    handoff=module_from(handoff_raw,plan["handoff_source"]["path"],"_collection_verified_handoff")
    watch_raw=verified(plan["handoff_plan"]);watch=handoff.validate_plan(parse(watch_raw))
    auth_raw=verified(plan["authorization"]);auth=parse(auth_raw)
    handoff.validate_auth(auth,watch,plan["authorization_sha256"])
    seed_raw=verified(plan["client_plan"]);seed=parse(seed_raw)
    need(watch["controller"]==plan["handoff_source"] and watch["transport_seed"]==plan["client_plan"],"handoff_source_or_seed_binding")
    handoff.verify_runtime(watch,seed)
    worker_raw=verified(plan["worker_plan"]);worker=parse(worker_raw)
    need(sha(worker_raw)==seed["worker_plan_sha256"],"worker_raw_client_binding")
    need(worker.get("artifact")=="aotg-evo-worker-plan" and type(worker.get("version")) is int and worker["version"]==2
         and worker.get("run_id")==plan["run_id"],"worker_plan_identity")
    need(plan["run_id"]==watch["run_id"]==seed["run_id"] and plan["nonce"]==watch["nonce"]==seed["maintenance_nonce"]
         and plan["client_plan_sha256"]==watch["client_plan_sha256"]==digest(seed)
         and plan["owner_uid"]==watch["owner_uid"] and plan["owner_gid"]==watch["owner_gid"]
         and plan["remote_work_root"]==watch["remote_work_dir"]
         and worker["task_root"]==seed["remote_task_root"]==str(Path(plan["remote_work_root"])/"work"),"collection_run_binding")
    need(worker["schedule"]==seed["schedule"] and len(worker["schedule"])==64,"collection_schedule_binding")
    profiles={p["id"]:p for p in worker["profiles"]}
    need(len(profiles)==len(worker["profiles"])==3,"worker_profiles")
    schedule=[dict(row,profile_sha256=profiles[row["candidate_id"]]["profile_sha256"]) for row in worker["schedule"]]
    field_raw=read(seed["field_plan"],private=False)
    need(sha(field_raw)==seed["field_plan_sha256"]==worker["field_plan"]["sha256"],"field_plan_binding")
    field=parse(field_raw)
    need(field["schedule"]==worker["schedule"]
         and field["candidates"]==[{"id":p["id"],"profile_sha256":p["profile_sha256"]} for p in worker["profiles"]],"field_profiles_binding")
    output=absolute(plan["output_root"]);jobs=absolute(plan["jobs_root"])
    need(str(jobs).startswith("/mnt/c/") and str(jobs)!="/mnt/c/","dedicated_windows_job_root")
    need(not output.exists() and not output.is_symlink() and not jobs.exists() and not jobs.is_symlink(),"collection_output_consumed")
    for path in (output,jobs):
        fd=directory(path.parent)
        try:need(os.fstat(fd).st_uid==plan["owner_uid"],"collection_parent_owner")
        finally:os.close(fd)
    protected=[Path(item["path"]) for item in [plan[k] for k in ("driver","handoff_source","handoff_plan","authorization","worker_plan","client_plan")]+list(plan["sources"].values())]
    io_plan=parse(verified(watch["io_plan"]))
    need(io_plan["authorization_sha256"]==plan["authorization_sha256"]
         and io_plan["client_plan_sha256"]==plan["client_plan_sha256"]
         and io_plan["worker_plan_sha256"]==plan["worker_plan"]["sha256"]
         and io_plan["run_id"]==plan["run_id"] and io_plan["nonce"]==plan["nonce"],"io_authorization_binding")
    protected += [Path(watch["output_root"]),Path(seed["output_root"]),Path(watch["runtime_root"]),Path(watch["jobs_root"]),
                  absolute(seed["windows_transport"]["linux_root"]),absolute(io_plan["output_root"])]
    for a in (output,jobs):
        for b in protected+[jobs if a==output else output]:
            need(not a.is_relative_to(b) and not b.is_relative_to(a),"collection_paths_overlap")
    return {"context":{"plan_path":str(plan_path)},"plan":plan,"plan_sha256":digest(plan),"canonical_sha256":digest(plan),"plan_raw_sha256":sha(raw),
            "handoff":handoff,"watch":watch,"seed":seed,"worker":worker,"schedule":schedule,"field":field,
            "source_bytes":sources,"used":False}


def restored_inputs(prepared):
    plan,watch=prepared["plan"],prepared["watch"]
    base=Path(watch["output_root"])
    input_raw=read(base/"input-bindings.json",65536);inputs=parse(input_raw)
    need(inputs.get("plan_raw_sha256")==plan["handoff_plan"]["sha256"]
         and inputs.get("authorization_raw_sha256")==plan["authorization"]["sha256"]
         and inputs.get("watch_plan_sha256")==digest(watch)
         and inputs.get("authorization_sha256")==plan["authorization_sha256"]
         and inputs.get("controller_sha256")==HANDOFF_SHA256,"handoff_input_bindings")
    summary_raw=read(base/"summary.json");summary=parse(summary_raw)
    need(summary.get("artifact")=="aotg-k8-comparison-handoff-result" and type(summary.get("version")) is int and summary["version"]==2
         and summary.get("run_id")==plan["run_id"] and summary.get("watch_plan_sha256")==digest(watch)
         and summary.get("authorization_sha256")==plan["authorization_sha256"]
         and summary.get("client_plan_sha256")==plan["client_plan_sha256"]
         and summary.get("owner_reported_unit_restore_verified") is True,"handoff_restore_binding")
    identity=summary.get("work_identity")
    need(isinstance(identity,dict) and set(identity)=={"device","inode"}
         and all(type(v) is int and v>=0 for v in identity.values()) and identity["inode"]>0,"handoff_work_identity")
    capture=summary.get("owner_control_capture")
    need(isinstance(capture,dict) and set(capture)=={"response","association"},"owner_control_capture")
    paths={role:Path(descriptor(item)["path"]) for role,item in capture.items()}
    need(paths["response"].parent==paths["association"].parent and paths["response"].parent.parent==base
         and re.fullmatch(r"control-[0-9]{3}",paths["response"].parent.name)
         and paths["response"].name=="stdout.json" and paths["association"].name=="association.json","control_capture_location")
    response_raw=verified(capture["response"],512*1024,private=True);response=parse(response_raw)
    association_raw=verified(capture["association"],65536,private=True);association=parse(association_raw)
    need(response.get("artifact")=="aotg-comparison-handoff-control" and type(response.get("version")) is int and response["version"]==2
         and response.get("operation")=="read-result" and response.get("work_identity")==identity
         and "local_capture" not in response,"raw_control_identity")
    need(association.get("artifact")=="aotg-comparison-handoff-control-association" and type(association.get("version")) is int and association["version"]==2
         and association.get("run_id")==plan["run_id"] and association.get("watch_plan_sha256")==digest(watch)
         and association.get("authorization_sha256")==plan["authorization_sha256"]
         and association.get("operation")=="read-result" and association.get("cleanup_verified") is True
         and type(association.get("index")) is int and 1<=association["index"]<=500
         and paths["response"].parent.name=="control-"+str(association["index"]).zfill(3),"control_association_identity")
    for key in ("payload_sha256","job_plan_sha256","receipt_sha256"):
        need(type(association.get(key)) is str and re.fullmatch(r"[a-f0-9]{64}",association[key]),"control_association_hash")
    owner_raw=read(base/"owner-entry-result.json",262144)
    need(sha(owner_raw)==summary.get("owner_result_raw_sha256")
         and base64.b64decode(response["result_raw_b64"],validate=True)==owner_raw,"owner_raw_binding")
    return owner_raw,identity,{"handoff_input_bindings_sha256":sha(input_raw),"handoff_summary_sha256":sha(summary_raw),"owner_control_response_sha256":sha(response_raw),
                               "owner_control_association_sha256":sha(association_raw)}


def load_runner(prepared):
    watch,seed=prepared["watch"],prepared["seed"];handoff=prepared["handoff"]
    handoff.verify_runtime(watch,seed)
    need(not any(n=="aotg" or n.startswith("aotg.") for n in sys.modules),"runtime_already_imported")
    need(sys.dont_write_bytecode,"no_bytecode_required")
    raw=verified(watch["transport_runner"])
    prior=sys.pycache_prefix
    try:
        sys.pycache_prefix=str(Path(prepared["plan"]["output_root"])/"unused-bytecode-cache")
        module=module_from(raw,watch["transport_runner"]["path"],"_collection_verified_runner")
    finally:sys.pycache_prefix=prior
    module.validate_comparison_contract(seed,prepared["field"])
    return module


def create_job_root(path,uid):
    """Exact new C-drive child; DrvFS mode emulation is not a POSIX ACL claim."""
    p=absolute(path);need(path.startswith("/mnt/c/") and p.name,"windows_job_child")
    parent=directory(p.parent)
    try:
        need(os.fstat(parent).st_uid==uid,"windows_job_parent_owner")
        os.mkdir(p.name,0o700,dir_fd=parent)
        fd=os.open(p.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:need(os.fstat(fd).st_uid==uid and not os.listdir(fd),"new_job_root_identity")
        finally:os.close(fd)
        os.fsync(parent)
    finally:os.close(parent)


def collect_once(prepared, *, plan_sha256, clock=time.monotonic, deadline=None):
    started=clock()
    if deadline is not None:need(type(deadline) in (int,float) and math.isfinite(deadline) and deadline>started,"parent_deadline_expired_or_invalid")
    deadline=started+90 if deadline is None else min(started+90,deadline)
    need(not prepared["used"] and plan_sha256==prepared["plan_sha256"],"explicit_collection_hash_or_one_use")
    prepared["used"]=True
    current=prepare(prepared["context"]["plan_path"],prepared["plan_raw_sha256"])
    need(current["plan_raw_sha256"]==prepared["plan_raw_sha256"],"collection_plan_bytes_changed")
    plan=current["plan"]
    need(os.geteuid()==plan["owner_uid"] and os.getegid()==plan["owner_gid"] and os.geteuid()!=0,"unprivileged_owner_required")
    owner_raw,identity,bindings=restored_inputs(current)
    receiver=module_from(current["source_bytes"]["receiver"],plan["sources"]["receiver"]["path"],"_collection_receiver")
    transport=module_from(current["source_bytes"]["transport"],plan["sources"]["transport"]["path"],"_collection_transport")
    request={"artifact":"aotg-comparison-collection-request","version":1,"run_id":plan["run_id"],"nonce":plan["nonce"],
             "owner_uid":plan["owner_uid"],"owner_gid":plan["owner_gid"],"work_root":plan["remote_work_root"],"work_identity":identity,
             "authorization_sha256":plan["authorization_sha256"],"client_plan_sha256":plan["client_plan_sha256"],
             "worker_plan_sha256":plan["worker_plan"]["sha256"],"owner_result_sha256":sha(owner_raw),"schedule":current["schedule"]}
    receiver.protocol.validate(request);receiver.protocol.owner_gate(owner_raw,request)
    runner=load_runner(current)
    need(clock()<deadline-20,"collection_preparation_deadline")
    root=receiver.create_output(plan["output_root"])
    result={"artifact":"aotg-comparison-collection-phase-result","version":1,"status":"incomplete",
            "collection_plan_sha256":plan_sha256,"plan_raw_sha256":current["plan_raw_sha256"],"bindings":bindings,
            "collection_seconds_budget":90,"separate_from_controller_budget":True,"independent_restoration_verified":False,"errors":[]}
    try:
        receiver.persist(root,"claim.json",canonical({"collection_plan_sha256":plan_sha256,"bindings":bindings})+b"\n")
        create_job_root(plan["jobs_root"],plan["owner_uid"])
        seed=json.loads(json.dumps(current["seed"]))
        seed["windows_transport"]["linux_root"]=plan["jobs_root"]
        seed["windows_transport"]["windows_root"]="C:"+plan["jobs_root"][len("/mnt/c"):].replace("/","\\")
        result["collection"]=transport.collect_after_owner_result(receiver,request=request,seed=seed,owner_result_bytes=owner_raw,
            output_dir=str(Path(plan["output_root"])/"capture"),verified_runner=runner,
            remote_source=current["source_bytes"]["remote"],remote_source_sha256=plan["sources"]["remote"]["sha256"],
            clock=clock,deadline=deadline)
        if result["collection"]["status"]=="complete" and clock()<deadline:result["status"]="complete"
    except Exception as error:result["errors"].append(type(error).__name__)
    finally:
        result["seconds"]=clock()-started
        if clock()>=deadline:result["status"]="incomplete";result["errors"].append("collection_phase_deadline")
        try:receiver.persist(root,"phase-result.json",canonical(result)+b"\n")
        finally:os.close(root)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan",required=True)
    parser.add_argument("--plan-raw-sha256")
    parser.add_argument("--execute-approved-plan-sha256")
    parser.add_argument("--parent-deadline-monotonic",type=float)
    args=parser.parse_args()
    need(sys.platform=="linux" and os.geteuid()!=0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         "use_unprivileged_isolated_python")
    prepared=prepare(args.plan,args.plan_raw_sha256)
    if args.execute_approved_plan_sha256 is None:
        print(canonical({"artifact":"aotg-comparison-collection-phase-preview","version":1,"dry_run":True,
                         "collection_plan_sha256":prepared["plan_sha256"],"local_seconds":90,"remote_actions":False,
                         "owner_result_required_only_on_collect":True}).decode());return 0
    result=collect_once(prepared,plan_sha256=args.execute_approved_plan_sha256,deadline=args.parent_deadline_monotonic)
    print(canonical({k:v for k,v in result.items() if k!="collection"}).decode())
    return 0 if result["status"]=="complete" else 2


if __name__=="__main__":raise SystemExit(main())
