#!/usr/bin/env python3
"""Verify and patch the downloaded assets of one upstream release."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

from geoip_subtract_hk import postprocess, write_atomic


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_checksums(directory):
    for checksum in directory.glob('*.sha256sum'):
        for line in checksum.read_text().splitlines():
            match = re.fullmatch(r'([a-fA-F0-9]{64}) [ *](.+)', line)
            if not match:
                raise ValueError(f'Invalid checksum line in {checksum.name}')
            expected, name = match.groups()
            if Path(name).name != name or name in ('.', '..'):
                raise ValueError(f'Invalid checksum filename: {name}')
            if digest((directory / name).read_bytes()) != expected.lower():
                raise ValueError(f'SHA256 mismatch: {name}')


def patch_release(directory, metadata, commit):
    required = ('geoip.dat', 'geoip.dat.sha256sum', 'geosite.dat',
                'geosite.dat.sha256sum', 'rules.zip', 'rules.zip.sha256sum')
    for name in required:
        if not (directory / name).is_file():
            raise ValueError(f'Missing upstream asset: {name}')
    for asset in metadata['assets']:
        name = asset['name']
        if Path(name).name != name:
            raise ValueError(f'Invalid upstream asset name: {name}')
        content = (directory / name).read_bytes()
        if len(content) != asset['size']:
            raise ValueError(f'Upstream asset size mismatch: {name}')
        expected = asset.get('digest')
        if expected and expected != 'sha256:' + digest(content):
            raise ValueError(f'Upstream asset digest mismatch: {name}')
    verify_checksums(directory)

    original = (directory / 'geoip.dat').read_bytes()
    patched, removed = postprocess(original)
    old_archive = (directory / 'rules.zip').read_bytes()
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(old_archive)) as source:
        names = source.namelist()
        if names.count('geoip.dat') != 1:
            raise ValueError('rules.zip must contain exactly one geoip.dat')
        with zipfile.ZipFile(output, 'w') as target:
            target.comment = source.comment
            for info in source.infolist():
                if not info.is_dir() and Path(info.filename).name != info.filename:
                    raise ValueError(f'Expected a flat release archive: {info.filename}')
                content = source.read(info)
                if not info.is_dir() and (directory / info.filename).is_file():
                    if content != (directory / info.filename).read_bytes():
                        raise ValueError(f'Archive and standalone asset differ: {info.filename}')
                if info.filename == 'geoip.dat':
                    content = patched
                target.writestr(info, content)
    write_atomic(directory / 'geoip.dat', patched)
    write_atomic(directory / 'rules.zip', output.getvalue())
    for name in ('geoip.dat', 'rules.zip'):
        checksum = f'{digest((directory / name).read_bytes())}  {name}\n'
        (directory / (name + '.sha256sum')).write_text(checksum)
    verify_checksums(directory)
    info = {
        'upstream_repository': 'Loyalsoldier/v2ray-rules-dat',
        'upstream_tag': metadata['tag_name'],
        'upstream_url': metadata['html_url'],
        'patch': 'CN minus HK (IPv4 and IPv6)',
        'patch_commit': commit,
        'upstream_geoip_sha256': digest(original),
        'patched_geoip_sha256': digest(patched),
        'removed_ipv4_addresses': removed[4],
        'removed_ipv6_addresses': removed[6],
    }
    (directory / 'patch-info.json').write_text(json.dumps(info, indent=2) + '\n')
    print(json.dumps(info, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('assets', type=Path)
    parser.add_argument('--metadata', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    patch_release(args.assets, json.loads(args.metadata.read_text()), args.commit)


if __name__ == '__main__':
    main()
