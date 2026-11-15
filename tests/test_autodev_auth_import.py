"""Exercise non-disclosing storage with synthetic, unusable test values."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aotg.autodev.auth_import import _github_hosts, _linear_value, _prompt, _save


class AuthenticationImportTests(unittest.TestCase):
    def test_github_accepts_the_selected_token_type_only(self):
        fake = "github_pat_" + "0" * 25
        self.assertEqual(_github_hosts(fake).count(fake.encode()), 2)
        with self.assertRaises(ValueError):
            _github_hosts("ghp_" + "0" * 40)
        with self.assertRaises(ValueError):
            _github_hosts(fake + "\nuser: another")

    def test_linear_uses_one_ascii_line(self):
        fake = "lin_api_" + "x" * 14
        self.assertEqual(_linear_value(fake), (fake + "\n").encode())
        with self.assertRaises(ValueError):
            _linear_value("Bearer " + fake)

    def test_empty_terminal_input_is_reported_as_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch("getpass.getpass", return_value=""),
                patch("builtins.print") as report,
                patch("aotg.autodev.auth_import._save") as save,
            ):
                self.assertFalse(_prompt("GitHub", Path(temporary) / "hosts.yml", _github_hosts))
            save.assert_not_called()
            self.assertIn("スキップ", report.call_args.args[0])

    @unittest.skipUnless(os.name == "posix", "POSIX storage is required")
    def test_storage_is_private_and_does_not_replace_existing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            item = root / "token"
            _save(item, b"synthetic\n")
            self.assertEqual(item.stat().st_mode & 0o777, 0o600)
            self.assertEqual(item.stat().st_nlink, 1)
            with self.assertRaises(FileExistsError):
                _save(item, b"replacement")
            self.assertEqual(item.read_bytes(), b"synthetic\n")
            self.assertEqual(list(root.iterdir()), [item])

    @unittest.skipUnless(os.name == "posix", "POSIX storage is required")
    def test_storage_refuses_a_linked_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "target"
            target.mkdir(mode=0o700)
            alternate = root / "alternate"
            alternate.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                _save(alternate / "token", b"synthetic\n")
            self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
