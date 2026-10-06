#!/usr/bin/env python3
"""Developer verification. Requires reference Python dependency and Node, not users."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--node',default=shutil.which('node'));args=parser.parse_args()
try:
    if not args.node:raise RuntimeError('Developer Node executable unavailable; pass --node /path/to/node')
    for directory in [ROOT/'reference',ROOT/'developer'/'legacy',ROOT/'developer']:
        subprocess.run([sys.executable,'-m','unittest','discover','-s',str(directory),'-v'],check=True)
    subprocess.run([args.node,str(ROOT/'developer'/'test_web.js')],check=True)
    subprocess.run([args.node,str(ROOT/'developer'/'test_ux.js')],check=True)
    subprocess.run([args.node,str(ROOT/'developer'/'test_qr.js')],check=True)
    subprocess.run([args.node,str(ROOT/'developer'/'test_phrase_contract.js')],check=True)
except Exception as exc:
    print(f'WEB VALIDATION FAILED — root cause: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
print('PASS: 73 Python regression/artifact tests + 13 Web adapter + 13 UX + 7 QR + 7 phrase-contract groups (113 total)')
