#!/usr/bin/env python3
"""Online preparation, followed by a local-wheel-only recovery rehearsal."""
import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
import json
import http.client
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

sys.dont_write_bytecode = True
from recovery_common import (clean_environment, current_target, inventory, safe_name,
                             sha256_file, verify_manifest, write_manifest)

PROJECT_FILES = (
    'kdf.py', 'SPEC.md', 'README.md', 'VALIDATION.md', 'OFFLINE_RECOVERY.md',
    'test_vectors.json', 'test_kdf.py', 'requirements.txt', 'requirements-offline.txt',
    'build_recovery_kit.py', 'verify_recovery_kit.py', 'recovery_common.py',
    'test_recovery_kit.py', '.gitignore',
)
PIP_VERSION = '25.3'
PYTHON_RELEASE = 'https://www.python.org/downloads/release/python-31312/'
# Checksums published by Python.org, pinned to the CPython version rehearsed here.
PYTHON_MACOS = (
    ('python-3.13.12-macos11.pkg',
     'b8d2eb5b6eabf583dce703027f6d4ed4b71c9bd1b05ad35d1f0c23f78e9aea76'),
    ('Python-3.13.12.tar.xz',
     '2a84cd31dd8d8ea8aaff75de66fc1b4b0127dd5799aa50a64ae9a313885b4593'),
)


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def read_pins(path):
    pins = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9.+-]*)', line)
        if not match:
            raise ValueError('Offline pins must contain exact name==version entries only')
        name, version = normalized(match[1]), match[2]
        if name in pins:
            raise ValueError('Duplicate dependency pin')
        pins[name] = version
    if not pins:
        raise ValueError('No offline dependency pins')
    return pins


def read_wheels(wheelhouse, pins):
    wheels = {}
    for path in sorted(Path(wheelhouse).glob('*.whl')):
        with zipfile.ZipFile(path) as wheel:
            metadata_names = [name for name in wheel.namelist() if name.endswith('.dist-info/METADATA')]
            if len(metadata_names) != 1:
                raise ValueError('Invalid wheel metadata')
            metadata = BytesParser().parsebytes(wheel.read(metadata_names[0]))
        name, version = normalized(metadata['Name']), metadata['Version']
        if name in wheels or pins.get(name) != version:
            raise ValueError('Unexpected wheel or version: ' + path.name)
        wheels[name] = path
    if wheels.keys() != pins.keys():
        raise ValueError('Missing pinned wheels')
    return wheels


def release_metadata(name, version):
    url = f'https://pypi.org/pypi/{name}/{version}/json'
    def fetch():
        request = urllib.request.Request(url, headers={'User-Agent': 'KDF1-RecoveryKit/1'})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    return retry_download(fetch)


def retry_download(action):
    for attempt in range(3):
        try:
            return action()
        except (OSError, http.client.HTTPException) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code not in (408, 429) and error.code < 500:
                raise
            if attempt == 2:
                raise
            print(f'Temporary download failure; retry {attempt + 1}/2', flush=True)
            time.sleep(attempt + 1)


def download_verified(url, destination, expected_hash):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' or parsed.hostname not in ('files.pythonhosted.org', 'www.python.org'):
        raise ValueError('Unexpected artifact download host')
    if not re.fullmatch(r'[0-9a-f]{64}', expected_hash):
        raise ValueError('Missing upstream SHA-256')
    destination = Path(destination)
    safe_name(destination.name)
    print('Downloading:', destination.name, flush=True)
    def fetch():
        request = urllib.request.Request(url, headers={'User-Agent': 'KDF1-RecoveryKit/1'})
        with urllib.request.urlopen(request, timeout=90) as response, destination.open('wb') as handle:
            shutil.copyfileobj(response, handle)
    retry_download(fetch)
    if sha256_file(destination) != expected_hash:
        destination.unlink()
        raise ValueError('Upstream SHA-256 mismatch')


def write_hash_lock(path, pins, wheels):
    lines = ['# Local wheel hashes; generated from exact pinned artifacts.\n']
    lines += [f'{name}=={version} --hash=sha256:{sha256_file(wheels[name])}\n'
              for name, version in sorted(pins.items())]
    Path(path).write_text(''.join(lines), encoding='utf-8')


def package_kit(root):
    root = Path(root)
    verify_manifest(root)
    archive = root.with_name(root.name + '.zip')
    checksum = archive.with_name(archive.name + '.sha256')
    if archive.exists() or checksum.exists():
        raise ValueError('Archive output already exists')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
        for name, path in inventory(root).items():
            bundle.write(path, root.name + '/' + name)
        bundle.write(root / 'SHA256SUMS', root.name + '/SHA256SUMS')
    checksum.write_text(f'{sha256_file(archive)}  {archive.name}\n', encoding='utf-8')
    return archive


def build(output, include_macos_python=False, runtime_files=(), isolation='none'):
    source = Path(__file__).resolve().parent
    output = Path(output).resolve()
    target = current_target()
    if output.exists() or output.with_name(output.name + '.zip').exists():
        raise ValueError('Use a new output path; existing kits are never overwritten')
    if isolation == 'macos-sandbox' and not target['platform'].startswith('macos-'):
        raise ValueError('macos-sandbox requires macOS')
    if include_macos_python and (not target['platform'].startswith('macos-')
                                or target['python_minor'] != '3.13'):
        raise ValueError('Pinned macOS Python installer requires a macOS CPython 3.13 kit')
    pins = read_pins(source / 'requirements-offline.txt')
    if pins.get('argon2-cffi') != read_pins(source / 'requirements.txt').get('argon2-cffi'):
        raise ValueError('Runtime requirements disagree')
    for name in PROJECT_FILES:
        if not (source / name).is_file() or (source / name).is_symlink():
            raise ValueError('Missing/nonregular project file: ' + name)
    output.mkdir(parents=True)
    for folder in ('project', 'wheelhouse', 'sdists', 'runtime'):
        (output / folder).mkdir()
    # Explicit allowlist: never sweep a working tree, venv, secrets, or user dotfiles.
    for name in PROJECT_FILES:
        shutil.copyfile(source / name, output / 'project' / name)
    for name in ('verify_recovery_kit.py', 'recovery_common.py'):
        shutil.copyfile(source / name, output / name)
    all_pins = dict(pins, pip=PIP_VERSION)
    command = [sys.executable, '-I', '-B', '-m', 'pip', '--isolated',
               '--disable-pip-version-check', '--no-cache-dir', 'download',
               '--index-url', 'https://pypi.org/simple', '--only-binary=:all:',
               '--no-deps', '--dest', str(output / 'wheelhouse')]
    command += [f'{name}=={version}' for name, version in all_pins.items()]
    # Host-native tags only. No cross-platform claim or silent source-build fallback.
    subprocess.run(command, check=True, env=clean_environment())
    wheels = read_wheels(output / 'wheelhouse', all_pins)
    provenance = []
    for name, version in all_pins.items():
        metadata = release_metadata(name, version)
        matches = [item for item in metadata['urls'] if item['filename'] == wheels[name].name]
        if len(matches) != 1 or matches[0].get('yanked'):
            raise ValueError('Wheel missing from release or yanked: ' + name)
        record = matches[0]
        if sha256_file(wheels[name]) != record['digests']['sha256']:
            raise ValueError('Wheel disagrees with PyPI SHA-256: ' + name)
        provenance.append({'package': name, 'version': version, 'kind': 'wheel',
                           'filename': record['filename'], 'url': record['url'],
                           'sha256': record['digests']['sha256']})
        sources = [item for item in metadata['urls'] if item['packagetype'] == 'sdist' and not item.get('yanked')]
        if not sources:
            raise ValueError('No source distribution available: ' + name)
        # Archive sources without executing build backends or resolving build dependencies.
        for item in sources:
            safe_name(item['filename'])
            if '/' in item['filename']:
                raise ValueError('Invalid source archive filename')
            download_verified(item['url'], output / 'sdists' / item['filename'], item['digests']['sha256'])
            provenance.append({'package': name, 'version': version, 'kind': 'sdist',
                               'filename': item['filename'], 'url': item['url'],
                               'sha256': item['digests']['sha256']})
    write_hash_lock(output / 'requirements-offline.lock', pins, wheels)
    write_hash_lock(output / 'bootstrap-pip.lock', {'pip': PIP_VERSION}, wheels)
    if include_macos_python:
        for filename, digest in PYTHON_MACOS:
            url = 'https://www.python.org/ftp/python/3.13.12/' + filename
            download_verified(url, output / 'runtime' / filename, digest)
            provenance.append({'kind': 'python-runtime-archive', 'filename': filename,
                               'url': url, 'sha256': digest, 'checksum_source': PYTHON_RELEASE,
                               'installer_execution_tested': False})
    for path in runtime_files:
        path = Path(path)
        safe_name(path.name)
        if not path.is_file() or path.is_symlink() or (output / 'runtime' / path.name).exists():
            raise ValueError('Runtime file must be a regular file with a unique name')
        shutil.copyfile(path, output / 'runtime' / path.name)
        provenance.append({'kind': 'user-supplied-runtime-archive', 'filename': path.name,
                           'sha256': sha256_file(path), 'upstream_authenticity_checked': False,
                           'installer_execution_tested': False})
    (output / 'artifact-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    info = {'scheme': 'KDF-1-v1', 'status': 'candidate / NOT FROZEN', 'target': target,
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'runtime_pins': pins, 'bootstrap_pip': PIP_VERSION,
            'native_build_only': True, 'verification_isolation': isolation,
            'python_runtime_archives_included': bool(include_macos_python or runtime_files),
            'python_runtime_installer_tested': False,
            'source_archives_are_not_a_complete_build_toolchain': True}
    (output / 'bundle-info.json').write_text(json.dumps(info, indent=2) + '\n', encoding='utf-8')
    shutil.copyfile(source / 'OFFLINE_RECOVERY.md', output / 'START_HERE.md')
    write_manifest(output)
    with tempfile.TemporaryDirectory(prefix='kdf1-build-check-') as temp:
        report = Path(temp) / 'offline-validation.json'
        command = [sys.executable, '-B', str(output / 'verify_recovery_kit.py'), str(output), '--report', str(report)]
        if isolation == 'macos-sandbox':
            command += ['--require-network-denied']
            command = ['/usr/bin/sandbox-exec', '-p', '(version 1) (allow default) (deny network*)'] + command
        subprocess.run(command, check=True, env=clean_environment())
        shutil.copyfile(report, output / 'offline-validation.json')
    write_manifest(output)
    archive = package_kit(output)
    print('PASS: built and verified', archive)
    return archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new kit directory; sibling ZIP is also created')
    parser.add_argument('--include-macos-python', action='store_true', help='archive official CPython 3.13.12 installer and source')
    parser.add_argument('--runtime-file', type=Path, action='append', default=[], help='explicit trusted offline installer/archive to preserve')
    parser.add_argument('--verification-isolation', choices=('none', 'macos-sandbox'), default='none')
    args = parser.parse_args(argv)
    try:
        build(args.output, args.include_macos_python, args.runtime_file, args.verification_isolation)
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print('FAIL: build incomplete; do not use a partial directory. ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
