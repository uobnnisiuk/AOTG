# Synthetic native replay driver fixture

This is trusted driver text for synthetic adapter tests only. It is not an
execution record, review receipt, source submission, or measured result. The
adapter tests parse and hash this text; they never execute it or native code.

```python
# Inside run_isolated, using only trusted driver text supplied by the operator:
import base64, json, sys, zlib
from pathlib import Path
sys.path.insert(0, "/tools/grader")
from aotg.quality import grade_source
case_id, source_name, isolation_reference = sys.argv[1:4]
options = dict(compiler="/usr/bin/g++", compiler_kind="g++")
if case_id == "csharp-atomic-batch":
    options = dict(compiler="/tools/dotnet/dotnet", compiler_kind="dotnet-csc",
                   csc_dll="/tools/roslyn/csc.dll", reference_dir="/tools/references",
                   dotnet_runtime_version="8.0.30")
report = grade_source(
    case_id, "/work/" + source_name, **options,
    catalog_path=Path("/tools/grader/tests/fixtures/benchmark/catalog.json"),
    execution_authorized=True, isolation_evidence=isolation_reference,
    compile_timeout_seconds=30, timeout_seconds=10,
    source_review=json.loads(Path("/work/source-review.json").read_text()))
print(base64.b64encode(zlib.compress(json.dumps(report, sort_keys=True).encode())).decode())
```
