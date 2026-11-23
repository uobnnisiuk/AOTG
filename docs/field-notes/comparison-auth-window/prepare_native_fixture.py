"""Create synthetic local preview inputs; never executes a subprocess or SSH."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
s = importlib.util.spec_from_file_location("gui_fixtures", HERE / "test_render_comparison_window.py")
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
root = HERE / "native-proof"
root.mkdir(mode=0o700)
spec, old_raw = m.fixture()
spec["launcher"] = str(root / "synthetic_launcher.py")
spec["launch_plan"] = str(root / "synthetic_launch.json")
spec["python"] = "/usr/bin/python3.12"
reply = {"artifact": "synthetic-local-preview-only", "execute": False,
         "process_started": False, "remote_actions_executed": False, "status": "UNAPPROVED",
         "launch_plan_sha256": spec["launch_plan_canonical_sha256"],
         "release_plan_sha256": spec["release_plan_canonical_sha256"]}
(root / "synthetic_launcher.py").write_text(
    'import json,sys\n'
    'assert sys.argv[1:]==["--plan",'+repr(spec["launch_plan"])+']\n'
    'print('+repr(json.dumps(reply, sort_keys=True))+')\n', encoding="ascii")
for name in ("synthetic_launch.json", "synthetic_release.json", "synthetic_gate.py"):
    (root / name).write_text("{}\n", encoding="ascii")
ssh_path = Path(spec["client_plan"]["ssh"][0])
spec["client_plan"]["windows_transport"]["ssh"]["sha256"] = hashlib.sha256(ssh_path.read_bytes()).hexdigest()
client_raw = json.dumps(spec["client_plan"], sort_keys=True).encode()
(root / "synthetic_client.json").write_bytes(client_raw)
paths = [root / "synthetic_client.json", Path(spec["launch_plan"]), Path(spec["launcher"]),
         Path(spec["python"]), Path("/mnt/c/Windows/System32/wsl.exe"), ssh_path,
         root / "synthetic_release.json", root / "synthetic_gate.py"]
spec["files"] = [{"path": m.R.to_windows(str(p)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths]
spec["client_plan_file"] = spec["files"][0]
(root / "synthetic_window.ps1").write_bytes(m.R.render(spec, client_raw=client_raw))
(root / "fixture-index.json").write_text(json.dumps({"synthetic_only": True,
    "window_sha256": hashlib.sha256((root / "synthetic_window.ps1").read_bytes()).hexdigest(),
    "ssh_started": False, "authentication_started": False, "production_touched": False}, sort_keys=True)+"\n")
print(json.dumps({"synthetic_fixture_created": True, "process_started": False}))
