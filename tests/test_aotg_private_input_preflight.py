"""Offline input-gate regressions; fabricated inert source only."""
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_SOURCE = (Path(__file__).resolve().parents[1] / "docs" / "field-notes"
           / "memory-context-candidate" / "test_private_integration.py")
_SPEC = importlib.util.spec_from_file_location("aotg_private_preflight", _SOURCE)
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)


class PrivateInputPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = tuple(Path(self.tmp.name) / name for name in ("base.py", "candidate.py", "core.py"))
        self.sources = (b"base = 1\n", b"candidate = 2\n", b"core = 3\n")
        self.digests = tuple(hashlib.sha256(src).hexdigest() for src in self.sources)
        for path, source in zip(self.paths, self.sources):
            path.write_bytes(source)
        self.pins = patch.multiple(_GATE, BASE_SHA=self.digests[0], CORE_SHA=self.digests[2])
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def test_verified_snapshots_are_used_even_if_path_changes(self):
        snapshots = _GATE.preflight(*self.paths, self.digests[1])
        self.assertEqual(snapshots, self.sources)
        self.paths[1].write_bytes(b"raise AssertionError('unchecked bytes')\n")
        name = "aotg_synthetic_verified_snapshot"
        self.addCleanup(sys.modules.pop, name, None)
        loaded = _GATE.load(name, self.paths[1], snapshots[1])
        self.assertEqual(loaded.candidate, 2)

    def test_all_three_mismatches_and_missing_inputs_fail(self):
        for i, path in enumerate(self.paths):
            with self.subTest(input=i):
                path.write_bytes(b"raise AssertionError('must not import')\n")
                with self.assertRaisesRegex(ValueError, "Unexpected private"):
                    _GATE.preflight(*self.paths, self.digests[1])
                path.unlink()
                with self.assertRaisesRegex(ValueError, "Missing/unreadable private"):
                    _GATE.preflight(*self.paths, self.digests[1])
                path.write_bytes(self.sources[i])

    def test_missing_malformed_and_stale_candidate_digest_fail(self):
        for digest in (None, "", "A" * 64, "0" * 63, _GATE.STALE_CANDIDATE_SHA,
                       self.digests[0], self.digests[2]):
            with self.subTest(digest=digest):
                with self.assertRaisesRegex(ValueError, "Fresh trusted"):
                    _GATE.preflight(*self.paths, digest)


if __name__ == "__main__":
    unittest.main()
