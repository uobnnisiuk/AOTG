"""Exercise the model broker without credentials or outbound network."""

import ssl
from io import BytesIO
from pathlib import Path
from threading import Event
from time import monotonic
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from aotg.autodev import model_egress
from aotg.autodev.worker import RunResult, WorkerError

_CONNECT = b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n"
_OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"
_SERVER_HELLO_HEADER = b"\x16\x03\x03\x00\x01"


def _tls_hello(hostname):
    outgoing = ssl.MemoryBIO()
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname=hostname)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        return outgoing.read()
    raise AssertionError("Expected a ClientHello before a server reply")


class TestModelEgress(TestCase):
    def _exchange(self, request, hello=None, *, dial=None):
        client = Mock()
        initial_header = BytesIO(request)
        subsequent_bytes = BytesIO(hello or b"")
        client.recv.side_effect = lambda count: initial_header.read(count) or subsequent_bytes.read(count)
        denied, connected = Event(), Event()
        dial = Mock(side_effect=ConnectionRefusedError) if dial is None else dial
        model_egress._handle(client, denied, connected, monotonic() + 3, dial=dial)
        return client, denied.is_set(), connected.is_set(), dial

    def test_disallowed_connect_authority_never_dials(self):
        client, denied, connected, dial = self._exchange(
            _CONNECT.replace(b"chatgpt.com", b"out-of-scope.invalid"),
        )
        self.assertTrue(denied)
        self.assertFalse(connected)
        client.sendall.assert_not_called()
        dial.assert_not_called()

    def test_disallowed_tls_sni_never_dials(self):
        for hostname in ("out-of-scope.invalid", None):
            with self.subTest(hostname=hostname):
                client, denied, connected, dial = self._exchange(_CONNECT, _tls_hello(hostname))
                self.assertTrue(denied)
                self.assertFalse(connected)
                client.sendall.assert_called_once_with(_OK)
                dial.assert_not_called()

    def test_malformed_tls_never_dials(self):
        _, denied, connected, dial = self._exchange(_CONNECT, b"\x16\x03\x01\x00\x10\x01")
        self.assertTrue(denied)
        self.assertFalse(connected)
        dial.assert_not_called()

    def test_connection_failure_stops(self):
        _, denied, connected, dial = self._exchange(_CONNECT, _tls_hello("chatgpt.com"))
        self.assertTrue(denied)
        self.assertFalse(connected)
        dial.assert_called_once_with()

    def test_valid_hello_is_forwarded_to_the_approved_dialer(self):
        hello = _tls_hello("chatgpt.com")
        upstream = MagicMock()
        upstream.__enter__.return_value = upstream
        upstream.recv.side_effect = BytesIO(_SERVER_HELLO_HEADER).read
        with patch.object(model_egress, "_relay") as relay:
            client, denied, connected, dial = self._exchange(_CONNECT, hello, dial=Mock(return_value=upstream))
        self.assertFalse(denied)
        self.assertTrue(connected)
        dial.assert_called_once_with()
        upstream.sendall.assert_called_once_with(hello)
        self.assertEqual([call.args[0] for call in client.sendall.call_args_list], [_OK, _SERVER_HELLO_HEADER])
        relay.assert_called_once()

    def test_filter_setup_failure_does_not_exec_native_client(self):
        with (
            patch.object(model_egress, "apply_model_network_filter", side_effect=RuntimeError),
            patch.object(model_egress.os, "execve") as launch,
            self.assertRaises(SystemExit) as failure,
        ):
            model_egress._entry("client", "/example/codex")
        self.assertEqual(failure.exception.code, 125)
        launch.assert_not_called()

    def test_late_violation_takes_precedence_over_worker_timeout(self):
        folder = MagicMock()
        folder.__enter__.return_value = "/example"
        server = MagicMock()
        runtime = MagicMock()
        runtime.__enter__.return_value = server

        def launch(*args, **kwargs):
            handler = proxy.call_args.args[1]
            self.assertFalse(kwargs["cancelled"]())
            client = Mock()
            client.recv.return_value = b""
            handler(client, dial=Mock())  # An unreadable CONNECT marks the run uncertain.
            self.assertTrue(kwargs["cancelled"]())
            return RunResult(124, True)

        with (
            patch.object(model_egress.sys, "platform", "linux"),
            patch.object(model_egress.os, "geteuid", return_value=1000, create=True),
            patch.object(model_egress.boundary, "_namespace_identity", return_value=("test",)),
            patch.object(model_egress, "TemporaryDirectory", return_value=folder),
            patch.object(model_egress.boundary, "_serve", return_value=runtime),
            patch.object(model_egress.boundary, "_UnixServer") as proxy,
            self.assertRaises(WorkerError),
        ):
            model_egress.run_model_client(
                (str(Path.cwd() / "codex"),), Path.cwd(), input_text="", env={"CODEX_HOME": "/example"},
                timeout_seconds=1, sandbox_bin=Path.cwd(), runner=launch,
            )
