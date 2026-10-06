"""A1/A2 public regression and fixed official Unicode 13 conformance."""
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch
import kdf
RANGES = kdf.PHRASE_RANGES
ROOT = Path(__file__).resolve().parents[1]

class PhraseContractTests(unittest.TestCase):
    def test_fixed_repertoire_equals_official_unicode_data_and_both_sources(self):
        assigned=set();first=None
        for line in (ROOT/'developer/unicode13/UnicodeData.txt').read_text().splitlines():
            f=line.split(';');cp=int(f[0],16)
            if f[1].endswith(', First>'):first=cp
            elif f[1].endswith(', Last>'):assigned.update(range(first,cp+1));first=None
            else:assigned.add(cp)
        assigned.difference_update(range(0xD800,0xE000));assigned.difference_update([10,13])
        actual={cp for a,b in RANGES for cp in range(a,b+1)}
        self.assertEqual(actual,assigned);self.assertEqual(len(actual),281390)
        table=json.loads((ROOT/'master-phrase-repertoire.json').read_text())['ranges']
        js=json.loads(re.search(r'const phraseRanges = (\[.*?\]);',(ROOT/'developer/core.js').read_text()).group(1))
        self.assertEqual(table,js);self.assertEqual(table,[list(x) for x in RANGES])
        spec=(ROOT/'SPEC.txt').read_text().split('BEGIN MASTER PHRASE REPERTOIRE\n')[1].split('\nEND MASTER PHRASE REPERTOIRE')[0]
        parsed=[]
        for token in spec.split():
            a,b=token.split('-');parsed.append([int(a,16),int(b,16)])
        self.assertEqual(parsed,table)
    def test_public_normalization_and_invalid_vectors(self):
        for row in json.loads((ROOT/'master-phrase-vectors.json').read_text()):
            if row['valid']:self.assertEqual(kdf.norm(row['input']).hex(),row['utf8_hex'])
            else:
                with self.assertRaises(ValueError):kdf.norm(row['input'])
    def test_cr_lf_all_positions_rejected_before_argon(self):
        for separator in ['\n','\r','\r\n']:
            for phrase in [separator+'PUBLIC','PUBLIC'+separator,'PUBLIC'+separator+'phrase']:
                with patch.object(kdf,'hash_secret_raw') as argon:
                    with self.assertRaisesRegex(ValueError,'CR or LF'):kdf.derive(phrase,'000102030405060708090a0b0c0d0e0f','example.com')
                    argon.assert_not_called()
    def test_unicode_audit_counterexample_rejected_before_argon(self):
        with patch.object(kdf,'hash_secret_raw') as argon:
            with self.assertRaisesRegex(ValueError,'repertoire'):kdf.derive('PUBLIC\u0897\u0323','000102030405060708090a0b0c0d0e0f','example.com')
            argon.assert_not_called()
    def test_official_unicode13_normalization_conformance(self):
        count=0
        for line in (ROOT/'developer/unicode13/NormalizationTest.txt').read_text().splitlines():
            text=line.split('#')[0].strip()
            if not text or text.startswith('@'):continue
            columns=[''.join(chr(int(cp,16)) for cp in col.split()) for col in text.split(';')[:5]]
            c1,c2,c3,c4,c5=columns
            for source,target in [(c1,c2),(c2,c2),(c3,c2),(c4,c4),(c5,c4)]:
                self.assertEqual(kdf.norm(source),target.encode('utf8'))
            count+=1
        self.assertEqual(count,18853)
    def test_new_public_phrase_kdf_vectors(self):
        for row in json.loads((ROOT/'master-phrase-vectors.json').read_text()):
            if not row['valid']:continue
            mk,sk,pw=kdf.derive(row['input'],'000102030405060708090a0b0c0d0e0f','example.com','test',1,24)
            self.assertEqual({'master_key_hex':mk.hex(),'site_key_hex':sk.hex(),'password':pw},row['expected'])

if __name__=='__main__':unittest.main()
