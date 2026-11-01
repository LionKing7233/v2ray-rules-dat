import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import patch_release as release
from test_geoip_subtract_hk import category, category_payloads
from geoip_subtract_hk import prefixes


class ReleaseTests(unittest.TestCase):
    def prepare(self, directory):
        original = category('CN', ['8.210.0.0/16', '223.5.5.0/24'])
        original += category('HK', ['8.210.0.0/17'])
        (directory / 'geoip.dat').write_bytes(original)
        (directory / 'geosite.dat').write_bytes(b'unchanged geosite')
        (directory / 'direct-list.txt').write_bytes(b'example.com\n')
        with zipfile.ZipFile(directory / 'rules.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.comment = b'upstream comment'
            for name in ('geoip.dat', 'geosite.dat', 'direct-list.txt'):
                archive.writestr(name, (directory / name).read_bytes())
        for name in ('geoip.dat', 'geosite.dat', 'rules.zip'):
            (directory / (name + '.sha256sum')).write_text(
                f'{release.digest((directory / name).read_bytes())}  {name}\n')
        return {
            'tag_name': '202610312203', 'html_url': 'https://example.test/release',
            'assets': [
                {'name': p.name, 'size': p.stat().st_size,
                 'digest': 'sha256:' + release.digest(p.read_bytes())}
                for p in sorted(directory.iterdir())
            ]
        }

    def test_patches_archive_and_checksums_together(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            metadata = self.prepare(directory)
            before = {p.name: p.read_bytes() for p in directory.iterdir()}
            with patch('builtins.print'):
                release.patch_release(directory, metadata, 'test-commit')
            payloads = category_payloads((directory / 'geoip.dat').read_bytes())
            self.assertEqual({str(p) for p in prefixes(payloads['CN'])},
                             {'8.210.128.0/17', '223.5.5.0/24'})
            with zipfile.ZipFile(directory / 'rules.zip') as archive:
                self.assertEqual(archive.read('geoip.dat'), (directory / 'geoip.dat').read_bytes())
                self.assertEqual(archive.read('geosite.dat'), before['geosite.dat'])
                self.assertEqual(archive.read('direct-list.txt'), before['direct-list.txt'])
                self.assertEqual(archive.comment, b'upstream comment')
            release.verify_checksums(directory)
            for name in ('geosite.dat', 'geosite.dat.sha256sum', 'direct-list.txt'):
                self.assertEqual((directory / name).read_bytes(), before[name])
            info = json.loads((directory / 'patch-info.json').read_text())
            self.assertEqual(info['removed_ipv4_addresses'], 32768)
            self.assertEqual(info['patch_commit'], 'test-commit')

    def test_corrupt_download_fails_before_changing_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            metadata = self.prepare(directory)
            (directory / 'geoip.dat').write_bytes(b'corrupt')
            before = {p.name: p.read_bytes() for p in directory.iterdir()}
            with self.assertRaisesRegex(ValueError, 'size mismatch'):
                release.patch_release(directory, metadata, 'test-commit')
            self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, before)


if __name__ == '__main__':
    unittest.main()
