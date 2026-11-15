import os
import socket
import subprocess
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from unittest.mock import Mock, patch

from aotg.autodev import chatgpt_signin as signin


class DeviceSignInTests(unittest.TestCase):
    def test_connect_matches_only_the_fixed_authority(self):
        cases = {
            b"CONNECT auth.openai.com:443 HTTP/1.1\r\n\r\n": True,
            b"CONNECT auth.openai.com:443 HTTP/1.1\r\nHost: auth.openai.com:443\r\n\r\n": True,
            b"CONNECT api.openai.com:443 HTTP/1.1\r\n\r\n": False,
            b"CONNECT auth.openai.com:80 HTTP/1.1\r\n\r\n": False,
            b"CONNECT auth.openai.com.example.invalid:443 HTTP/1.1\r\n\r\n": False,
            b"CONNECT auth.openai.com:443 HTTP/1.1\r\nHost: elsewhere.example:443\r\n\r\n": False,
            b"CONNECT auth.openai.com:443 HTTP/1.0\r\nHost: auth.openai.com:443\r\nHost: auth.openai.com:443\r\n\r\n": False,
            b"CONNECT auth.openai.com:443 HTTP/1.1\r\nProxy-Authorization: synthetic\r\n\r\n": False,
            b"CONNECT auth.openai.com:443 HTTP/1.1\r\nContent-Length: 4\r\n\r\n": False,
            b"GET https://auth.openai.com/ HTTP/1.1\r\n\r\n": False,
            b"CONNECT auth.openai.com:443 HTTP/1.1\n\n": False,
            b"CONNECT auth.openai.com:443 HTTP/1.1\r\nX: " + b"a" * signin._HEADER_MAX + b"\r\n\r\n": False,
        }
        for request, expected in cases.items():
            with self.subTest(request=request[:70]):
                client = Mock()
                client.recv.side_effect = [request[:9], request[9:], b""]
                self.assertIs(signin._read_connect(client), expected)

    def test_denial_never_dials(self):
        client = Mock()
        client.recv.return_value = b"CONNECT invalid.example:443 HTTP/1.1\r\n\r\n"
        dial = Mock(side_effect=AssertionError("invalid target"))
        signin._host_connect(client, dial)
        dial.assert_not_called()
        self.assertTrue(client.sendall.call_args.args[0].startswith(b"HTTP/1.1 403"))

    def test_denial_is_sticky_and_stops_the_login_process(self):
        denied = Event()
        invalid = Mock()
        invalid.recv.return_value = b"CONNECT unexpected.invalid:443 HTTP/1.1\r\n\r\n"
        future = Mock()
        future.recv.return_value = b"CONNECT auth.openai.com:443 HTTP/1.1\r\n\r\n"
        dial = Mock()

        def report_during_wait(*args, **kwargs):
            if kwargs:
                signin._host_connect(invalid, dial, denied=denied)
                raise subprocess.TimeoutExpired("synthetic-native", 0.2)

        with patch.object(signin.subprocess, "Popen") as popen:
            child = popen.return_value.__enter__.return_value
            child.wait.side_effect = report_during_wait
            child.poll.return_value = None
            self.assertEqual(signin._device_process(("synthetic-native",), 9, denied), 1)
        child.kill.assert_called_once()
        self.assertTrue(denied.is_set())
        signin._host_connect(future, dial, denied=denied)
        dial.assert_not_called()
        future.recv.assert_not_called()

    def test_host_dial_skips_private_and_loopback_answers(self):
        resolutions = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("224.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
        ]
        with patch.object(signin.socket, "getaddrinfo", return_value=resolutions) as resolve:
            with patch.object(signin.socket, "socket") as connector:
                connection = signin._dial_auth()
        resolve.assert_called_once_with("auth.openai.com", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        connector.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        connection.connect.assert_called_once_with(("93.184.216.34", 443))

    def test_child_environment_and_commands_are_fixed(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic", "HTTP_PROXY": "http://example.invalid",
                                     "HTTPS_PROXY": "http://example.invalid", "HOME": "/ambient"}):
            login, login_env = signin._native_command("device-login", 12345)
            status, status_env = signin._native_command("status")
        self.assertEqual(login[-2:], ("login", "--device-auth"))
        self.assertEqual(status[-2:], ("login", "status"))
        self.assertIn('forced_login_method="chatgpt"', login)
        self.assertIn('cli_auth_credentials_store="file"', status)
        self.assertIn('log_dir="/tmp"', login)
        self.assertEqual(login_env["HTTPS_PROXY"], "http://127.0.0.1:12345")
        self.assertEqual(status_env["CODEX_HOME"], "/state")
        self.assertEqual(status_env["HOME"], "/home")
        self.assertFalse({"HTTPS_PROXY", "HTTP_PROXY", "OPENAI_API_KEY"} & status_env.keys())

    def test_offline_status_requires_the_exact_chatgpt_method(self):
        for message, code, expected in (
            (b"Logged in using ChatGPT\n", 0, True),
            (b"Logged in using ChatGPT\n", 1, False),
            (b"API key configured - synthetic\n", 0, False),
            (b"Logged in using access token\n", 0, False),
        ):
            with self.subTest(code=code, expected=expected):
                with patch.object(signin.subprocess, "Popen") as popen:
                    child = popen.return_value.__enter__.return_value
                    child.stderr.read.return_value = message
                    child.wait.return_value = code
                    self.assertIs(signin._native_status(signin._CHATGPT_STATUS, 0), expected)
                    child.stderr.read.assert_called_once_with(len(signin._CHATGPT_STATUS) + 1)

    def test_auth_home_refuses_an_arbitrary_private_directory(self):
        with self.assertRaises(signin.SignInError):
            signin._auth_home_identity(Path("/private/shared/config/home"), 1000)

    @unittest.skipUnless(os.name == "posix", "POSIX modes and ownership required")
    def test_credential_uses_private_regular_single_link(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            auth = directory / "auth.json"
            auth.write_text("synthetic", encoding="utf-8")
            auth.chmod(0o600)
            self.assertTrue(signin._private_auth_file(auth, os.geteuid()))
            alias = directory / "alias"
            alias.symlink_to(auth)
            self.assertFalse(signin._private_auth_file(alias, os.geteuid()))
            alias.unlink()
            os.link(auth, alias)
            self.assertFalse(signin._private_auth_file(auth, os.geteuid()))
            alias.unlink()
            auth.chmod(0o640)
            self.assertFalse(signin._private_auth_file(auth, os.geteuid()))

    @unittest.skipUnless(os.name == "posix", "POSIX modes and ownership required")
    def test_login_home_accepts_only_an_optional_private_policy_file(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            uid = os.geteuid()
            self.assertTrue(signin._login_home_ready(directory, uid))
            policy = directory / "config.toml"
            policy.write_text('forced_login_method = "chatgpt"\n', encoding="utf-8")
            policy.chmod(0o600)
            self.assertTrue(signin._login_home_ready(directory, uid))
            (directory / "auth.json").touch()
            self.assertFalse(signin._login_home_ready(directory, uid))
            (directory / "auth.json").unlink()
            policy.chmod(0o640)
            self.assertFalse(signin._login_home_ready(directory, uid))

    def test_main_only_emits_constant_failure(self):
        with patch.object(signin, "_outside", side_effect=subprocess.SubprocessError("synthetic-private-output")):
            with patch("builtins.print") as emit:
                result = signin.main(["status", "--native", "/native", "--sha256", "pin", "--auth-home", "/tmp"])
        self.assertEqual(result, 1)
        emit.assert_called_once_with("AOTG ChatGPT authentication check could not be verified")

    def test_argument_error_does_not_echo_invalid_input(self):
        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaisesRegex(SystemExit, "2"):
            signin.main(["synthetic-private-data"])
        self.assertEqual(stderr.getvalue(), "AOTG ChatGPT authentication arguments could not be verified\n")


if __name__ == "__main__":
    unittest.main()
