"""Offline worker tests use temporary Git repos and harmless processes."""

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from aotg.autodev.worker import (
    ChangeSet,
    WorkerError,
    _run_in_wsl,
    capture_changes,
    codex_argv,
    prepare_checkout,
)


@unittest.skipUnless(shutil.which("git"), "Git is required for isolated checkout tests")
class WorkerTests(unittest.TestCase):
    def setUp(self):
        folder = TemporaryDirectory(prefix="aotg-worker-test-")
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        self.source = root / "source"
        self.source.mkdir()
        self.git("init", "-b", "main", str(self.source))
        self.write(self.source / "feature.py", b"# Initial version\n")
        self.write(self.source / ".gitignore", b"local-data\n")
        self.git("-C", str(self.source), "-c", "core.autocrlf=false", "add", ".")
        self.git(
            "-C", str(self.source), "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid", "commit", "-m", "Test baseline",
        )
        self.base = self.git("-C", str(self.source), "rev-parse", "HEAD").decode().strip()
        self.checkout = root / "candidate"

    @staticmethod
    def git(*args, input=None):
        return subprocess.run(
            ["git", *args], capture_output=True, check=True, input=input, timeout=15,
        ).stdout

    @staticmethod
    def write(path, data):
        path.write_bytes(data)

    def test_pin_clean_clone_and_extract_patch(self):
        untracked_object = self.git(
            "-C", str(self.source), "hash-object", "-w", "--stdin", input=b"unrelated history"
        ).decode().strip()
        prepared = prepare_checkout(self.source, self.checkout, self.base)
        with self.assertRaises(subprocess.CalledProcessError):
            self.git("-C", str(self.checkout), "cat-file", "-e", untracked_object)
        self.assertEqual(prepared.path, self.checkout.resolve())
        self.assertEqual(prepared.base_sha, self.base)
        self.assertFalse(self.git("-C", str(self.checkout), "remote"))
        self.assertFalse((self.checkout / ".git/objects/info/alternates").exists())
        self.write(self.checkout / "feature.py", b"# Candidate version")
        self.write(self.checkout / "test_feature.py", b"# Regression test\n")
        changes = capture_changes(prepared, ("feature.py", "test_feature.py"))
        self.assertIsInstance(changes, ChangeSet)
        self.assertEqual(changes.paths, ("feature.py", "test_feature.py"))
        self.assertIn(b"\\ No newline at end of file", changes.patch)
        self.git("-C", str(self.source), "apply", "--check", "-", input=changes.patch)
        self.assertEqual((self.source / "feature.py").read_bytes(), b"# Initial version\n")
        self.assertFalse((self.source / "test_feature.py").exists())

    def test_dirty_or_wrong_base_is_rejected(self):
        with self.assertRaises(WorkerError):
            prepare_checkout(self.source, self.checkout, "f" * 40)
        self.write(self.source / "feature.py", b"# Local work\n")
        with self.assertRaises(WorkerError):
            prepare_checkout(self.source, self.checkout, self.base)
        self.assertFalse(self.checkout.exists())

    def test_reject_in_scope_nested_checkout(self):
        with self.assertRaises(WorkerError):
            prepare_checkout(self.source, self.source / "candidate", self.base)

    def test_ignored_and_unapproved_files_are_detected(self):
        prepared = prepare_checkout(self.source, self.checkout, self.base)
        self.write(self.checkout / "feature.py", b"# Approved change\n")
        self.write(self.checkout / "local-data", b"should not enter patch\n")
        with self.assertRaisesRegex(WorkerError, "approved scope"):
            capture_changes(prepared, ("feature.py",))

    def test_candidate_git_configuration_cannot_hide_actual_file_changes(self):
        prepared = prepare_checkout(self.source, self.checkout, self.base)
        self.git("-C", str(self.checkout), "update-index", "--assume-unchanged", "feature.py")
        self.write(self.checkout / "feature.py", b"# Actual change\n")
        self.assertFalse(self.git("-C", str(self.checkout), "status", "--porcelain"))
        changes = capture_changes(prepared, ("feature.py",))
        self.assertIn(b"+# Actual change", changes.patch)

    def test_reject_protected_path_and_binary_files(self):
        prepared = prepare_checkout(self.source, self.checkout, self.base)
        for forbidden in (".github/workflows/ci.yml", ".gitmodules", "AGENTS.md", "a/../feature.py", "a\\b"):
            with self.subTest(forbidden=forbidden), self.assertRaises(WorkerError):
                capture_changes(prepared, (forbidden,))
        self.write(self.checkout / "feature.py", b"binary:\x00")
        with self.assertRaisesRegex(WorkerError, "plain text"):
            capture_changes(prepared, ("feature.py",))

    @unittest.skipUnless(os.name == "posix", "Windows may not permit test symlinks")
    def test_reject_symlinks_without_reading_the_destination(self):
        prepared = prepare_checkout(self.source, self.checkout, self.base)
        (self.checkout / "feature.py").unlink()
        (self.checkout / "feature.py").symlink_to(self.source / "feature.py")
        with self.assertRaisesRegex(WorkerError, "Symlinks"):
            capture_changes(prepared, ("feature.py",))


class CommandTests(unittest.TestCase):
    def test_codex_arguments_are_fixed_and_prompt_comes_from_stdin(self):
        root = Path.cwd()
        executable = root / "trusted tools" / "codex"
        checkout = root / "test checkout"
        argv = codex_argv(executable, checkout)
        self.assertEqual(argv[0:4], (str(executable), "--ask-for-approval", "never", "exec"))
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("workspace-write", argv)
        self.assertIn("sandbox_workspace_write.network_access=false", argv)
        self.assertEqual(argv[argv.index("--cd") + 1], str(checkout))
        self.assertEqual(argv[-1], "-")
        with self.assertRaises(WorkerError):
            codex_argv(Path("codex"), checkout)

    @unittest.skipUnless(os.name == "posix", "Local process runner targets Linux/WSL")
    def test_linux_process_timeout_and_normal_exit(self):
        command = (sys.executable, "-c", "import sys; sys.exit(int(sys.stdin.read()))")
        result = _run_in_wsl(command, Path.cwd(), input_text="3", env={}, timeout_seconds=5)
        self.assertEqual(result.exit_code, 3)
        self.assertFalse(result.timed_out)
        command = (sys.executable, "-c", "import time; time.sleep(20)")
        result = _run_in_wsl(command, Path.cwd(), input_text="", env={}, timeout_seconds=0.1)
        self.assertTrue(result.timed_out)
        self.assertLess(result.exit_code, 0)

    @unittest.skipUnless(os.name == "posix", "Local process runner targets Linux/WSL")
    def test_linux_process_gets_only_explicit_environment_values(self):
        source = "import os, sys; sys.exit(0 if os.environ.get('AOTG_TEST') == 'safe' else 1)"
        result = _run_in_wsl(
            (sys.executable, "-c", source), Path.cwd(),
            input_text="", env={"AOTG_TEST": "safe"},
        )
        self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
