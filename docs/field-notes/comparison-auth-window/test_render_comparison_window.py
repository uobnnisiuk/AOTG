"""Synthetic boundary tests; no SSH, auth, WSL launch or production operation."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
loader = importlib.util.spec_from_file_location("gui_renderer", HERE / "render_comparison_window.py")
R = importlib.util.module_from_spec(loader)
loader.loader.exec_module(R)
PIN = "a" * 64


def fixture():
    client = {"artifact": "aotg-k8-field-plan", "version": 2,
              "ssh": ["/mnt/c/Windows/System32/OpenSSH/ssh.exe", "-F", "none", "-T",
                      "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                      "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=C:/fixture/known_hosts",
                      "-i", "C:/fixture/key", "-o", "ConnectTimeout=10",
                      "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
                      "-o", "ForwardAgent=no", "owner@example.invalid"],
              "windows_transport": {"ssh": {"path": "/mnt/c/Windows/System32/OpenSSH/ssh.exe", "sha256": PIN}}}
    raw = json.dumps(client, sort_keys=True).encode()
    cf = {"path": "C:\\fixture\\client.json", "sha256": hashlib.sha256(raw).hexdigest()}
    spec = {"client_plan": client, "client_plan_file": cf,
            "launch_plan": "/mnt/c/fixture/launch.json", "launcher": "/home/fixture/launch.py",
            "python": "/usr/bin/python3.12", "wsl": "C:\\Windows\\System32\\wsl.exe",
            "launch_plan_canonical_sha256": "b"*64, "release_plan_canonical_sha256": "c"*64,
            "gate": {"remote_path": "/home/fixture/.local/state/aotg-field/auth-gate-0000000000000000/auth_gate.py", "sha256": "d"*64},
            "files": [cf] + [{"path": path, "sha256": PIN} for path in [
                "C:\\fixture\\launch.json", "\\\\wsl.localhost\\Ubuntu\\home\\fixture\\launch.py",
                "\\\\wsl.localhost\\Ubuntu\\usr\\bin\\python3.12", "C:\\Windows\\System32\\wsl.exe",
                "C:\\Windows\\System32\\OpenSSH\\ssh.exe", "C:\\fixture\\release.json", "C:\\fixture\\gate.py"]]}
    return spec, raw


class Tests(unittest.TestCase):
    def test_render_preserves_existing_route_except_tty(self):
        spec, raw = fixture()
        result = R.render(spec, client_raw=raw).decode("ascii")
        pinned = json.loads(result.split("$Pinned = ConvertFrom-Json @'\n", 1)[1].split("\n'@", 1)[0])
        expected = spec["client_plan"]["ssh"][1:]
        expected[2] = "-tt"
        self.assertEqual(pinned["ssh_args"], expected)
        self.assertNotIn("__PINNED_JSON__", result)
        self.assertLess(result.index("if(!$ExecuteApprovedWindow)"), result.index("& $Pinned.ssh"))
        self.assertLess(result.index("& $Pinned.ssh"), result.index("$launch=Invoke-LocalLauncher $true"))
        self.assertEqual(result.count("& $Pinned.ssh"), 1)

    def test_numeric_command_reconstructs_exact_compileable_bootstrap(self):
        spec, raw = fixture()
        text = R.render(spec, client_raw=raw).decode()
        pinned = json.loads(text.split("$Pinned = ConvertFrom-Json @'\n", 1)[1].split("\n'@", 1)[0])
        command = pinned["command"]
        m = re.fullmatch(r"sudo /usr/bin/python3\.14 -I -S -B -c exec\\\(\\\(0x([0-9a-f]+)\\\)\.to_bytes\\\(([0-9]+)\\\)\\\)", command)
        self.assertIsNotNone(m)
        decoded = int(m[1], 16).to_bytes(int(m[2]), "big")
        self.assertEqual(decoded, R.bootstrap(spec["gate"]))
        tree = ast.parse(decoded)
        self.assertIn("--enroll", decoded.decode())
        self.assertTrue(tree.body)
        self.assertNotIn("'", command)
        self.assertNotIn('"', command)

    def test_raw_client_must_match_embedded_object(self):
        spec, raw = fixture()
        spec["client_plan"]["ssh"][-1] = "owner@changed.invalid"
        with self.assertRaisesRegex(ValueError, "pinned raw"):
            R.render(spec, client_raw=raw)

    def test_pin_and_input_refusals(self):
        mutations = [lambda x: x.update(extra=True),
                     lambda x: x["files"].append(x["files"][0]),
                     lambda x: x.update(launcher="/home/fixture/../launch.py"),
                     lambda x: x.update(launch_plan_canonical_sha256="A"*64),
                     lambda x: x["gate"].update(remote_path="/home/fixture/evil.py"),
                     lambda x: x["gate"].update(remote_path="/home/fixture/$(whoami)/auth_gate.py"),
                     lambda x: x["files"][5].update(sha256="e"*64),
                     lambda x: x["files"][0].update(path="C:\\fixture\\..\\client.json")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                spec, raw = fixture()
                mutation(spec)
                with self.assertRaises(ValueError):
                    R.render(spec, client_raw=raw)

    def test_connection_scope_cannot_grow(self):
        replacements = [("ForwardAgent=no", "ForwardAgent=yes"),
                        ("StrictHostKeyChecking=yes", "StrictHostKeyChecking=no"),
                        ("ConnectTimeout=10", "ProxyCommand=evil"),
                        ("C:/fixture/key", "C:/fixture/../key"),
                        ("owner@example.invalid", "owner@example.invalid command"),
                        ("-T", "-tt")]
        for old, new in replacements:
            client = fixture()[0]["client_plan"]
            client["ssh"][client["ssh"].index(old)] = new
            with self.subTest(old=old), self.assertRaises(ValueError):
                R.interactive_route(client)
        client = fixture()[0]["client_plan"]
        client["ssh"][-1:-1] = ["-o", "BatchMode=yes"]
        with self.assertRaises(ValueError):
            R.interactive_route(client)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}']:
            with self.assertRaises(ValueError): R.parse(raw)

    def test_template_has_process_only_module_path_and_no_hash_cmdlet(self):
        text = (HERE / "approved-comparison-window.ps1.in").read_text()
        self.assertLess(text.index("$env:PSModulePath="), text.index("ConvertFrom-Json"))
        self.assertIn("[Security.Cryptography.SHA256]::Create()", text)
        self.assertNotIn("Get-FileHash", text)
        self.assertNotIn("SetEnvironmentVariable", text)
        self.assertNotIn("Start-Transcript", text)

    def test_cli_reader_rejects_links_fifo_and_oversize_before_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            p = root / "input.json"
            p.write_bytes(b"{}")
            self.assertEqual(R.read_regular(p, 2), b"{}")
            with self.assertRaises(ValueError): R.read_regular(p, 1)
            link = root / "link.json"
            link.symlink_to(p)
            with self.assertRaises(ValueError): R.read_regular(link, 2)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError): R.read_regular(fifo, 2)

    def test_compiler_plus_allowed_only_as_literal_pinned_file(self):
        spec, raw = fixture()
        spec["files"].append({"path": "\\\\wsl.localhost\\Ubuntu\\usr\\bin\\x86_64-linux-gnu-g++-13", "sha256": PIN})
        self.assertIsInstance(R.render(spec, client_raw=raw), bytes)
        with self.assertRaises(ValueError): R.linux_path("/home/fixture/launch+command.py")


if __name__ == "__main__":
    unittest.main()
