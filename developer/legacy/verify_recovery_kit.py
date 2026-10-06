#!/usr/bin/env python3
"""Verify a kit, install only bundled wheels in a NEW venv, run public tests."""
import argparse
import errno
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from recovery_common import check_target, clean_environment, current_target, verify_manifest


def network_denial_probe():
    """A probe, not a firewall: caller must supply OS-level network isolation."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            connection.connect(('127.0.0.1', 9))
    except OSError as error:
        if error.errno in (errno.EPERM, errno.EACCES):
            return 'local socket denied by OS'
        raise ValueError('No OS denial detected; refused/unreachable is not proof of isolation') from error
    raise ValueError('Network probe was allowed')


def validate(kit, work, require_network_denied=False):
    kit, work = Path(kit).resolve(), Path(work).resolve()
    count = verify_manifest(kit)
    info = json.loads((kit / 'bundle-info.json').read_text(encoding='utf-8'))
    check_target(info['target'], current_target())
    if work == kit or kit in work.parents or work.exists():
        raise ValueError('Work directory must be new and outside the kit')
    probe = network_denial_probe() if require_network_denied else 'not checked; disconnect externally'
    work.mkdir(parents=True)
    env = clean_environment()
    # Copy only the manifest-listed source tree; no installed package can mask a missing source file.
    source = work / 'project'
    shutil.copytree(kit / 'project', source)
    venv = work / 'venv'
    logs = []

    def run(command):
        result = subprocess.run(command, cwd=source, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logs.append({'command': [str(c) for c in command], 'exit_code': result.returncode,
                     'output': result.stdout})
        if result.returncode:
            raise RuntimeError('Recovery step failed:\n' + result.stdout)
        print(result.stdout, end='', flush=True)

    run([sys.executable, '-I', '-B', '-m', 'venv', str(venv)])
    python = venv / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
    base = [str(python), '-I', '-B', '-m', 'pip', '--isolated',
            '--disable-pip-version-check', '--no-cache-dir']
    install = ['install', '--no-index', '--find-links', str(kit / 'wheelhouse'),
               '--only-binary=:all:', '--require-hashes', '--no-input']
    run(base + install + ['-r', str(kit / 'bootstrap-pip.lock')])
    run(base + install + ['-r', str(kit / 'requirements-offline.lock')])
    run(base + ['check'])
    run([str(python), '-B', 'kdf.py', '--self-test'])
    run([str(python), '-B', '-m', 'unittest', '-v'])
    # Public data only. Keep an independent hardcoded password check beyond the JSON vector.
    public_check = (
        "from kdf import derive; "
        "result=derive('correct horse battery staple',"
        "'000102030405060708090a0b0c0d0e0f','example.com','test',1,24)[2]; "
        "expected='HtO+f3SK@_5w*VwW6ufM@UzA'; "
        "print('PUBLIC INPUT PASSWORD:',result); "
        "raise SystemExit(0 if result==expected else 1)"
    )
    run([str(python), '-B', '-c', public_check])
    # Reading/running validation must not modify the archived kit.
    verify_manifest(kit)
    return {'status': 'PASS', 'scheme_status': 'KDF-1 v1 candidate / NOT FROZEN',
            'target': current_target(), 'manifest_files_checked': count,
            'network_probe': probe, 'os_isolation_required': require_network_denied,
            'fresh_venv': True, 'no_index': True, 'no_cache': True, 'require_hashes': True,
            'runtime_installer_executed': False, 'steps': logs}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kit', type=Path)
    parser.add_argument('--check-only', action='store_true', help='stdlib-only SHA-256 inventory check')
    parser.add_argument('--work-dir', type=Path, help='new directory OUTSIDE kit; retain venv and project')
    parser.add_argument('--report', type=Path, help='new report path OUTSIDE kit')
    parser.add_argument('--require-network-denied', action='store_true', help='require OS-denied socket probe')
    args = parser.parse_args(argv)
    try:
        if args.check_only:
            print(f'PASS: SHA-256 manifest ({verify_manifest(args.kit)} files)')
            return 0
        if args.report:
            report_path = args.report.resolve()
            kit_path = args.kit.resolve()
            if report_path.exists() or report_path == kit_path or kit_path in report_path.parents:
                raise ValueError('Report must be new and outside kit')
        if args.work_dir:
            report = validate(args.kit, args.work_dir, args.require_network_denied)
        else:
            with tempfile.TemporaryDirectory(prefix='kdf1-offline-') as temp:
                report = validate(args.kit, Path(temp) / 'fresh', args.require_network_denied)
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print('PASS: Recovery Kit installation, tests and public password')
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
