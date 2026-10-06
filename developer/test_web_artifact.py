"""Standalone artifact/source checks; no browser or private data."""
import base64
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
class Page(HTMLParser):
    def __init__(self,html):
        super().__init__();self.scripts={};self.tags=[];self.current=None;self.style='';self.policy='';self.feed(html)
    def handle_starttag(self,tag,attrs):
        d=dict(attrs);self.tags.append((tag,d))
        if tag=='meta' and d.get('http-equiv')=='Content-Security-Policy':self.policy=d['content']
        if tag=='script':self.current=d['id'];self.scripts[self.current]=''
        if tag=='style':self.current='__style'
    def handle_data(self,data):
        if self.current=='__style':self.style+=data
        elif self.current:self.scripts[self.current]+=data
    def handle_endtag(self,tag):
        if tag in ['script','style']:self.current=None
class WebArtifactTests(unittest.TestCase):
    def setUp(self):
        self.html=(ROOT/'RECOVER.html').read_text();self.page=Page(self.html)
    def test_self_contained(self):
        for tag,attrs in self.page.tags:
            self.assertNotIn('src',attrs);self.assertNotIn('href',attrs)
        self.assertEqual(set(self.page.scripts),{'ui-code','vendor-code','core-code','qr-vendor-code','travel-qr-code','public-vector','human-vectors','public-cases','phrase-vectors'})
    def test_hash_csp(self):
        for name in ['ui-code','vendor-code','core-code','qr-vendor-code','travel-qr-code']:
            h=base64.b64encode(hashlib.sha256(self.page.scripts[name].encode()).digest()).decode()
            self.assertIn("'sha256-"+h+"'",self.page.policy)
        h=base64.b64encode(hashlib.sha256(self.page.style.encode()).digest()).decode()
        self.assertIn("'sha256-"+h+"'",self.page.policy)
        self.assertNotIn("'unsafe-inline'",self.page.policy);self.assertNotIn("'unsafe-eval'",self.page.policy)
        self.assertIn("'wasm-unsafe-eval'",self.page.policy)
    def test_no_connections_or_external_resources(self):
        for directive in ['default-src','connect-src','worker-src','frame-src','object-src','font-src','img-src','media-src','form-action','base-uri']:
            self.assertIn(directive+" 'none'",self.page.policy)
        code='\n'.join(self.page.scripts[n] for n in ['ui-code','core-code','vendor-code','qr-vendor-code','travel-qr-code'])
        for forbidden in ['fetch(','XMLHttpRequest','WebSocket','RTCPeerConnection','localStorage','sessionStorage','indexedDB','serviceWorker','sendBeacon','document.cookie']:
            self.assertNotIn(forbidden,code)
    def test_embedded_integrity_checks(self):
        checks=json.loads(re.search(r'const checks=(\{[^;]+\});',self.page.scripts['ui-code']).group(1))
        style_hash=re.search(r"!==\'([0-9a-f]{64})\'",self.page.scripts['ui-code']).group(1)
        self.assertEqual(style_hash,hashlib.sha256(self.page.style.encode()).hexdigest())
        self.assertEqual(set(checks),{'public-vector','human-vectors','public-cases','phrase-vectors','vendor-code','core-code','qr-vendor-code','travel-qr-code'})
        for name,h in checks.items():self.assertEqual(hashlib.sha256(self.page.scripts[name].encode()).hexdigest(),h)
    def test_public_vectors_exact(self):
        for embedded,file in [('public-vector','public-vectors.json'),('human-vectors','human-vectors.json'),('public-cases','developer/public-cases.json'),('phrase-vectors','master-phrase-vectors.json')]:
            self.assertEqual(json.loads(self.page.scripts[embedded]),json.loads((ROOT/file).read_text()))
        v=json.loads(self.page.scripts['public-vector'])
        self.assertEqual(v['expected']['password'],'HtO+f3SK@_5w*VwW6ufM@UzA')
    def test_initial_secrets_disabled(self):
        inputs={attrs['id']:attrs for tag,attrs in self.page.tags if tag in ['input','button']}
        for name in ['code','phrase','label','account','revision','length','recover','public-tests','toggle-phrase','create-code','create-qr','save-qr','print-qr']:
            self.assertIn('disabled',inputs[name])
        self.assertEqual(inputs['phrase']['type'],'password');self.assertEqual(inputs['code']['type'],'text')
        self.assertIn('STOP — 尚未完成自检',self.html)
    def test_vendor_archive_registry_integrity(self):
        data=(ROOT/'developer/vendor/hash-wasm-4.12.0.tgz').read_bytes()
        metadata=json.loads((ROOT/'developer/vendor/hash-wasm-metadata.json').read_text())
        self.assertEqual('sha512-'+base64.b64encode(hashlib.sha512(data).digest()).decode(),metadata['dist']['integrity'])
        self.assertEqual(metadata['version'],'4.12.0')
        self.assertTrue((ROOT/'developer/vendor/LICENSE').is_file())
    def test_embedded_wasm_archived_exactly(self):
        count=0
        for name,b64 in re.findall(r'name:"([^"\n]+)",data:"([A-Za-z0-9+/=]+)"',self.page.scripts['vendor-code']):
            self.assertEqual(base64.b64decode(b64),(ROOT/f'developer/vendor/{name}.wasm').read_bytes());count+=1
        self.assertEqual(count,2)
    def test_reproducible_assembly(self):
        with tempfile.TemporaryDirectory() as temp:
            copy=Path(temp)/'kit';shutil.copytree(ROOT,copy,ignore=shutil.ignore_patterns('__pycache__'))
            spec=importlib.util.spec_from_file_location('test_builder',copy/'developer/build_web.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            module.build();self.assertEqual((copy/'RECOVER.html').read_bytes(),(ROOT/'RECOVER.html').read_bytes())
    def test_primary_kit_has_no_native_launcher(self):
        self.assertFalse(list(ROOT.rglob('*.app')))
        self.assertIn('file:',self.page.scripts['ui-code'])
if __name__=='__main__':unittest.main()
