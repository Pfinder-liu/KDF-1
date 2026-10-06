"""Standard-library-only Recovery Kit integrity and environment helpers."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import re
import sys
import sysconfig

MANIFEST = 'SHA256SUMS'


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if (not name or not path.parts or path.is_absolute() or name != path.as_posix()
            or any(part in ('.', '..') for part in path.parts)
            or any(c in name for c in '\\\r\n\t:') or name == MANIFEST):
        raise ValueError('Unsafe or reserved manifest path')
    return path


def inventory(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlinks are not allowed in a Recovery Kit')
        if path.is_file() and path.name != MANIFEST:
            name = path.relative_to(root).as_posix()
            safe_name(name)
            result[name] = path
        elif path.is_file() and path.relative_to(root).as_posix() != MANIFEST:
            raise ValueError('Nested manifest name is reserved')
    return result


def write_manifest(root):
    root = Path(root)
    files = inventory(root)
    if not files:
        raise ValueError('Cannot write an empty manifest')
    text = ''.join(f'{sha256_file(path)}  {name}\n' for name, path in files.items())
    with (root / MANIFEST).open('w', encoding='utf-8', newline='\n') as handle:
        handle.write(text)


def verify_manifest(root):
    root = Path(root)
    manifest = root / MANIFEST
    if manifest.is_symlink():
        raise ValueError('Manifest cannot be a symlink')
    records = {}
    for line in manifest.read_text(encoding='utf-8').splitlines():
        if not re.fullmatch(r'[0-9a-f]{64}  .+', line):
            raise ValueError('Malformed SHA256SUMS record')
        digest, name = line.split('  ', 1)
        safe_name(name)
        if name in records:
            raise ValueError('Duplicate manifest path')
        records[name] = digest
    actual = inventory(root)
    if not records or records.keys() != actual.keys():
        raise ValueError('Manifest file inventory mismatch (missing or extra files)')
    for name, path in actual.items():
        if sha256_file(path) != records[name]:
            raise ValueError('SHA-256 mismatch: ' + name)
    return len(records)


def current_target():
    system, machine = platform.system(), platform.machine().lower()
    arch = {'amd64': 'x86_64', 'aarch64': 'arm64'}.get(machine, machine)
    supported = {('Darwin', 'arm64'): 'macos-arm64',
                 ('Darwin', 'x86_64'): 'macos-x86_64',
                 ('Windows', 'x86_64'): 'windows-x86_64',
                 ('Linux', 'x86_64'): 'linux-x86_64'}
    if (system, arch) not in supported:
        raise ValueError('Build on a documented target platform')
    if platform.python_implementation() != 'CPython' or sys.version_info < (3, 9):
        raise ValueError('Recovery tooling requires CPython 3.9 or later')
    if sys.maxsize <= 2**32:
        raise ValueError('Recovery tooling requires a 64-bit Python interpreter')
    if sysconfig.get_config_var('Py_GIL_DISABLED'):
        raise ValueError('Free-threaded CPython requires a separate kit; not supported here')
    return {'platform': supported[system, arch], 'python_minor': f'{sys.version_info.major}.{sys.version_info.minor}',
            'python_version': platform.python_version(), 'implementation': 'CPython',
            'os_version': platform.platform(), 'libc': list(platform.libc_ver()),
            'soabi': sysconfig.get_config_var('SOABI')}


def check_target(recorded, current):
    for field in ('platform', 'python_minor', 'implementation'):
        if recorded[field] != current[field]:
            raise ValueError('Wrong Recovery Kit target: ' + field)
    # pip also enforces detailed wheel ABI / minimum OS / glibc tags.


def clean_environment():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('PIP_', 'PYTHON')) and k not in ('VIRTUAL_ENV',)}
    env.update(PIP_CONFIG_FILE=os.devnull, PIP_DISABLE_PIP_VERSION_CHECK='1',
               PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
    return env
