"""Offline inventory-shaped serialization, using the pinned collector main/emit.

Provide an explicit trusted collector_remote.py path and a NEW JSON output path.
No source edits, SSH, workload, service calls, or actual transport are performed.
Zero-byte file bodies exercise serializer byte volume; they are not valid native
evidence. No decode, completeness, hardware speed, or whole-chain claim follows.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import stat
import types
from unittest.mock import patch

PIN = "22a8667bd5f935403e85ebbce6a6f8dbfaeddd00137e6241448df87d074ddf5d"


def load(path):
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("collector source hash mismatch")
    module=types.ModuleType("_collector_serialization_audit")
    module.__file__=str(path)
    exec(compile(raw,str(path),"exec"),module.__dict__)
    return module


def signature(size,directory=False):
    return {"device":2**64-1,"inode":2**64-1,"bytes":size,
            "mtime_ns":2**63-1,"ctime_ns":2**63-1,
            "mode":stat.S_IFDIR|0o700 if directory else stat.S_IFREG|0o600,
            "uid":2**32-2,"gid":2**32-2,"links":2**64-1 if directory else 1}


def case(module,observation_bytes):
    original=module.inventory()
    sizes=[observation_bytes if label=="task/resource-observations.jsonl" else cap
           for label,cap,_ in original]
    transferred=sum(sizes);rereads=2*(sizes[0]+sizes[1])
    stats={"records":0,"wire_bytes":0,"maximum_line_bytes":0,
           "maximum_non_base64_overhead_bytes":0,"maximum_metadata_line_bytes":0}
    wire_hash=hashlib.sha256();chunks={}
    maximum_by_kind={}

    def produce(config,emit):
        def output(value):
            encoded=module.canon(value)+b"\n"
            overhead=len(encoded)-(len(value["base64"]) if "base64" in value else 0)
            kind=value["artifact"]
            maximum_by_kind[kind]=max(maximum_by_kind.get(kind,0),len(encoded))
            stats["records"]+=1
            stats["maximum_line_bytes"]=max(stats["maximum_line_bytes"],len(encoded))
            stats["maximum_non_base64_overhead_bytes"]=max(stats["maximum_non_base64_overhead_bytes"],overhead)
            if "base64" not in value:
                stats["maximum_metadata_line_bytes"]=max(stats["maximum_metadata_line_bytes"],len(encoded))
            emit(value)
        output({"artifact":"aotg-comparison-collection-open","version":1,"request_sha256":"f"*64,
                "run_id":"a"*79+"-"+"f"*16,"nonce":"f"*16,"worker_plan_sha256":"f"*64,
                "owner_result_sha256":"f"*64,"planned_files":len(original),"limits":module.LIMITS,
                "started_utc":"2026-11-23T12:34:56.123456+00:00"})
        for index,((label,cap,record_cap),size) in enumerate(zip(original,sizes)):
            output({"artifact":"aotg-comparison-file-open","version":1,"index":index,
                    "label":label,"byte_cap":cap,"record_cap":record_cap})
            for offset in range(0,size,module.LIMITS["chunk_bytes"]):
                length=min(module.LIMITS["chunk_bytes"],size-offset)
                if length not in chunks:
                    chunks[length]=base64.b64encode(bytes(length)).decode("ascii")
                output({"artifact":"aotg-comparison-file-chunk","version":1,"index":index,
                        "offset":offset,"bytes":length,"base64":chunks[length]})
            output({"artifact":"aotg-comparison-file-close","version":1,"index":index,"label":label,
                    "status":"captured","reason":None,"bytes":size,"read_bytes":size,
                    "sha256":"f"*64,"partial_sha256":"f"*64,"records":record_cap,
                    "stat_before":signature(size),"stat_after":signature(size)})
        protected={"work":signature(2**63-1,True),"task":signature(2**63-1,True),
                   "owner_result":signature(sizes[0]),"owner_result_sha256":"f"*64,
                   "worker_summary":signature(sizes[1]),"worker_summary_sha256":"f"*64}
        result={"artifact":"aotg-comparison-collection-final","version":1,"request_sha256":"f"*64,
                "status":"complete","attempted_files":len(original),"complete_files":len(original),
                "raw_bytes":transferred,"total_read_bytes":transferred+rereads,"unattempted_indices":[],
                "preconditions_verified":True,"protected_unchanged":True,"owner_reported_restoration":True,
                "independent_restoration_verified":False,"remote_written":False,"inference_invoked":False,
                "service_control_invoked":False,"errors":[],"started_utc":"2026-11-23T12:34:56.123456+00:00",
                "finished_utc":"2026-11-23T12:35:55.123456+00:00","seconds":59.0,
                "protected_before":protected,"protected_after":protected}
        output(result);return result

    def write(fd,data):
        assert fd==123
        stats["wire_bytes"]+=len(data);wire_hash.update(data)
        return len(data)

    with patch.object(module,"CONFIG",{},create=True),patch.object(module,"collect",produce), \
         patch.object(module.sys,"stdout",types.SimpleNamespace(fileno=lambda:123)), \
         patch.object(module.signal,"signal"),patch.object(module.signal,"alarm"), \
         patch.object(module.os,"set_blocking"),patch.object(module.os,"write",write), \
         patch.object(module.select,"select",lambda *args:([],[123],[])), \
         patch.object(module.time,"monotonic",lambda:0):
        result=module.main()
    assert result==0 and stats["wire_bytes"]<module.LIMITS["wire_bytes"]
    assert stats["records"]<module.LIMITS["wire_records"]
    assert stats["maximum_non_base64_overhead_bytes"]<=4096
    assert transferred+rereads<module.LIMITS["total_raw_bytes"]
    return {"inventory_files":len(original),"observations_bytes":observation_bytes,
            "raw_bytes":transferred,"metadata_reread_bytes":rereads,"total_read_bytes":transferred+rereads,
            "raw_budget_margin":module.LIMITS["total_raw_bytes"]-transferred-rereads,
            "wire_budget_margin":module.LIMITS["wire_bytes"]-stats["wire_bytes"],
            "record_budget_margin":module.LIMITS["wire_records"]-stats["records"],
            "maximum_serialized_bytes_by_kind":maximum_by_kind,
            "wire_sha256":wire_hash.hexdigest(),"serialization":stats,
            "emitter_finished":True,"valid_evidence_body_claimed":False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collector-source",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists():raise ValueError("output already exists")
    module=load(args.collector_source)
    result={"artifact":"aotg-synthetic-collector-inventory-serialization","version":1,"source_sha256":PIN,
            "actual_remote_actions":False,"actual_transport_or_storage_speed_tested":False,
            "whole_chain_qualified":False,"formal_platform_metadata_bound_proved":False,
            "stat_model":"64-bit positive stat fields and 32-bit uid/gid, fixed reviewed schema",
            "cases":{}}
    for name,size in (("existing_inventory_all_caps",128*1024**2),
                      ("published_conditional_2s_context",126068736),
                      ("proposed_separate_primary_guard_caps",130393088),
                      ("final_runtime_anchor_2k",130394112)):
        result["cases"][name]=case(module,size)
    with args.output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,sort_keys=True,indent=2);stream.write("\n")
    print(json.dumps({"synthetic_cases":4,"passed":True,"whole_chain_qualified":False}))


if __name__=="__main__":main()
