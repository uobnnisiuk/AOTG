"""Offline joins using the real assessment adapter and synthetic producer records."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = load('assessment_io_join', ROOT / 'assessment-component/tools/assemble_field_evidence.py')
F = load('io_fixture_for_join', ROOT / 'metrics-component/tests/test_io_capture_diagnostics.py')


class IOAssemblyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-io-join-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.trusted = self.root / 'trusted'
        self.trusted.mkdir()
        self.fixture = F.Fixture()
        self.descriptors = {}
        for role, raw in self.fixture.raws.items():
            path = self.trusted / role
            path.write_bytes(raw)
            self.descriptors[role] = {'path': str(path), 'sha256': A.sha(raw)}
        record = self.trusted / 'review'
        record.write_bytes(b'SYNTHETIC external inventory attestation; no real run')
        self.item = {'descriptors': self.descriptors,
                     'authorization_sha256': self.fixture.expected['authorization_sha256'],
                     'review_record': {'path': str(record), 'sha256': A.sha(record.read_bytes())}}
        self.reader = A.Reader()
        self.authority = A.Authority(self.reader, {'supplemental_io_captures': [self.item]},
            self.trusted, (self.root / 'k8', self.root / 'evo'))
        self.spec = {'source_root': str(ROOT / 'assessment-component'),
                     'client_plan': self.descriptors['client_plan'],
                     'worker_plan': self.descriptors['worker_plan']}

    def run_join(self):
        return A.io_associations(self.reader, self.spec, self.authority,
                                 self.fixture.client, self.fixture.worker)

    def test_exact_external_copy_join_is_separate_from_coverage(self):
        result, = self.run_join()
        self.assertEqual(result['status'], 'associated_terminal_complete')
        self.assertEqual(result['diagnostic_source_sha256'], A.IO_DIAGNOSTIC_SHA256)
        self.assertTrue(result['producer_association_verified'])
        self.assertTrue(result['owned_windows_job_cleanup_verified'])
        self.assertFalse(result['coverage_evaluated'])
        self.assertFalse(result['remote_process_exit_verified'])
        self.assertFalse(result['quality_accepted'])

    def test_external_authorization_hash_cannot_be_replaced_by_capture_claim(self):
        self.item['authorization_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'external_identity_mismatch'):
            self.run_join()

    def test_expected_client_comes_from_validated_assessment_not_io_record(self):
        self.fixture.client['run_id'] = 'different-synthetic-run'
        with self.assertRaisesRegex(ValueError, 'external_identity_mismatch'):
            self.run_join()

    def test_generated_copy_is_not_an_independent_trusted_copy(self):
        outside = self.root / 'k8'
        outside.mkdir()
        path = outside / 'samples'
        path.write_bytes(self.fixture.raws['samples'])
        self.descriptors['samples']['path'] = str(path)
        with self.assertRaisesRegex(A.EvidenceError, 'io_file_outside_trusted_root'):
            self.run_join()

    def test_helper_hash_is_verified_before_any_module_execution(self):
        original = self.reader.raw
        path = Path(self.spec['source_root']) / 'tools/io_capture_diagnostics.py'
        def read(target, maximum=A.MAX_FILE):
            if Path(target) == path:
                return b"raise AssertionError('must not execute')\n"
            return original(target, maximum)
        with patch.object(self.reader, 'raw', side_effect=read):
            with self.assertRaisesRegex(A.EvidenceError, 'io_diagnostic_source_changed'):
                self.run_join()

    def test_no_independent_authority_never_promotes_raw_coverage(self):
        self.assertEqual(A.io_associations(self.reader, self.spec, None,
                                          self.fixture.client, self.fixture.worker), [])

    def test_one_immutable_snapshot_is_reused_for_all_sixty_four_windows(self):
        descriptor = self.descriptors['samples']
        snapshot = A.io_snapshot(self.reader, descriptor)
        with patch.object(self.reader, 'pinned', side_effect=AssertionError('capture reread')):
            for _ in range(64):
                result = A.io_diagnostics(self.reader, descriptor, 1, 2, 2.5, snapshot=snapshot)
                self.assertFalse(result['producer_identity_verified'])
                self.assertFalse(result['rates_computed'])


if __name__ == '__main__':
    unittest.main()
