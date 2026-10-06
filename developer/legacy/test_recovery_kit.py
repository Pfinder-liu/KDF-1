"""Offline-tool regression tests. No downloads and no real secrets."""
import contextlib
import errno
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_recovery_kit as builder
import recovery_common as common
import verify_recovery_kit as verifier


class RecoveryKitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'kit'
        self.root.mkdir()
        (self.root / 'project').mkdir()
        (self.root / 'project' / 'public.txt').write_text('PUBLIC TEST DATA', encoding='utf-8')
        common.write_manifest(self.root)

    def test_manifest_roundtrip_and_archive(self):
        self.assertEqual(common.verify_manifest(self.root), 1)
        archive = builder.package_kit(self.root)
        with zipfile.ZipFile(archive) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(z.read('kit/project/public.txt'), b'PUBLIC TEST DATA')
            self.assertIn('kit/SHA256SUMS', z.namelist())
        checksum = archive.with_name(archive.name + '.sha256').read_text().split()[0]
        self.assertEqual(checksum, common.sha256_file(archive))

    def test_modified_file_rejected(self):
        (self.root / 'project' / 'public.txt').write_text('MODIFIED')
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            common.verify_manifest(self.root)

    def test_missing_file_rejected(self):
        (self.root / 'project' / 'public.txt').unlink()
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            common.verify_manifest(self.root)

    def test_extra_file_rejected(self):
        (self.root / 'extra.txt').write_text('extra')
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            common.verify_manifest(self.root)

    def test_duplicate_and_empty_manifest_rejected(self):
        path = self.root / common.MANIFEST
        line = path.read_text()
        for value in ['', line + line, 'not-a-hash  project/public.txt\n']:
            path.write_text(value)
            with self.assertRaises(ValueError):
                common.verify_manifest(self.root)

    def test_manifest_cannot_escape_root(self):
        for name in ['../secret', '/etc/passwd', 'C:/file', 'a/../b', '.',
                     'a//b', 'a\\b', 'a\tb', 'SHA256SUMS']:
            with self.subTest(name=name):
                (self.root / common.MANIFEST).write_text('0' * 64 + '  ' + name + '\n')
                with self.assertRaises(ValueError):
                    common.verify_manifest(self.root)

    def test_symlink_rejected(self):
        path = self.root / 'link'
        try:
            path.symlink_to(self.root / 'project' / 'public.txt')
        except OSError:
            self.skipTest('Creating symlinks is not permitted on this OS')
        with self.assertRaisesRegex(ValueError, 'Symlinks'):
            common.verify_manifest(self.root)

    def test_archive_never_overwrites_existing(self):
        archive = builder.package_kit(self.root)
        before = archive.read_bytes()
        with self.assertRaises(ValueError):
            builder.package_kit(self.root)
        self.assertEqual(archive.read_bytes(), before)

    def test_failed_check_cli_returns_one(self):
        (self.root / 'project' / 'public.txt').write_text('broken')
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(verifier.main([str(self.root), '--check-only']), 1)
        self.assertIn('FAIL:', output.getvalue())

    def test_wrong_platform_and_python_rejected(self):
        recorded = {'platform': 'macos-arm64', 'python_minor': '3.13', 'implementation': 'CPython'}
        for name, replacement in [('platform', 'macos-x86_64'), ('python_minor', '3.14'),
                                  ('implementation', 'PyPy')]:
            current = dict(recorded, **{name: replacement})
            with self.assertRaises(ValueError):
                common.check_target(recorded, current)
        common.check_target(recorded, recorded)

    def test_existing_venv_work_directory_rejected(self):
        target = common.current_target()
        (self.root / 'bundle-info.json').write_text(json.dumps({'target': target}))
        common.write_manifest(self.root)
        existing = Path(self.temp.name) / 'existing'
        existing.mkdir()
        for work in [existing, self.root / 'new-inside-kit']:
            with self.assertRaisesRegex(ValueError, 'must be new and outside'):
                verifier.validate(self.root, work)

    def test_probe_requires_permission_denial_not_connection_refusal(self):
        with patch('socket.socket', side_effect=PermissionError(errno.EPERM, 'denied')):
            self.assertIn('denied', verifier.network_denial_probe())
        with patch('socket.socket', side_effect=ConnectionRefusedError(errno.ECONNREFUSED, 'refused')):
            with self.assertRaises(ValueError):
                verifier.network_denial_probe()

    def test_inherited_pip_and_python_paths_removed(self):
        with patch.dict('os.environ', {'PYTHONPATH': '/untrusted', 'PIP_EXTRA_INDEX_URL': 'https://invalid',
                                      'VIRTUAL_ENV': '/old-venv'}):
            env = common.clean_environment()
        self.assertNotIn('PYTHONPATH', env)
        self.assertNotIn('PIP_EXTRA_INDEX_URL', env)
        self.assertNotIn('VIRTUAL_ENV', env)

    def test_pin_file_rejects_urls_options_and_unpinned_versions(self):
        path = Path(self.temp.name) / 'pins'
        for text in ['cffi>=2.0', '--extra-index-url https://invalid', 'cffi @ https://invalid',
                     'cffi==2.0\ncffi==2.0', '']:
            path.write_text(text)
            with self.assertRaises(ValueError):
                builder.read_pins(path)

    def test_mismatched_download_hash_is_deleted(self):
        destination = Path(self.temp.name) / 'public.tar.gz'
        with patch('urllib.request.urlopen', return_value=io.BytesIO(b'corrupt')), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            builder.download_verified('https://files.pythonhosted.org/public.tar.gz', destination, '0' * 64)
        self.assertFalse(destination.exists())

    def test_runtime_download_rejects_untrusted_host(self):
        with self.assertRaises(ValueError):
            builder.download_verified('https://invalid.example/x', self.root / 'x', '0' * 64)

    def test_transient_download_retry_is_bounded(self):
        with patch.object(builder.time, 'sleep'), contextlib.redirect_stdout(io.StringIO()):
            with patch('urllib.request.urlopen', side_effect=[OSError('temporary'),
                                                             io.BytesIO(b'{"ok": true}')]) as request:
                self.assertEqual(builder.release_metadata('public', '1'), {'ok': True})
                self.assertEqual(request.call_count, 2)
            with patch('urllib.request.urlopen', side_effect=OSError('offline')) as request:
                with self.assertRaises(OSError):
                    builder.release_metadata('public', '1')
                self.assertEqual(request.call_count, 3)


if __name__ == '__main__':
    unittest.main()
