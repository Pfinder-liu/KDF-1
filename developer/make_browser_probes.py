#!/usr/bin/env python3
"""Developer public-only negative test fixtures. Not part of runtime HTML."""
import argparse
import base64
import hashlib
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
def make(destination):
    html=(ROOT/'RECOVER.html').read_text();destination.mkdir(parents=True,exist_ok=True)
    (destination/'damaged-vector.html').write_text(html.replace('HtO+f3SK@_5w*VwW6ufM@UzA','WRONG_PUBLIC',1))
    (destination/'damaged-core.html').write_text(html.replace('let argonCalls = 0;','let argonCalls = 1;',1))
    (destination/'damaged-style.html').write_text(html.replace('max-width:740px','max-width:741px',1))
    (destination/'blocked-wasm.html').write_text(html.replace(" 'wasm-unsafe-eval'",''))
    probe="""window.addEventListener('securitypolicyviolation',event=>{if(event.effectiveDirective==='connect-src')document.getElementById('csp-probe').textContent='PASS: connect-src blocked a public connection probe; no secrets used.';});document.addEventListener('DOMContentLoaded',()=>{fetch('https://example.invalid/kdf-public-csp-probe',{mode:'no-cors'}).then(()=>{document.getElementById('csp-probe').textContent='FAIL: connection unexpectedly allowed';}).catch(()=>{});});"""
    h="'sha256-"+base64.b64encode(hashlib.sha256(probe.encode()).digest()).decode()+"'"
    modified=html.replace('script-src ','script-src '+h+' ',1).replace('</body>','<pre id="csp-probe">WAITING: public connection probe</pre><script>'+probe+'</script></body>')
    (destination/'connection-probe.html').write_text(modified)
    print('PASS: public-only browser probes written to',destination)
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('destination',type=Path);args=parser.parse_args()
    try:make(args.destination)
    except Exception as exc:
        print(f'PROBE BUILD FAILED — root cause: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
