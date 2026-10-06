import json
from pathlib import Path
import unittest
from unittest.mock import patch
import human_code as hc
import kdf

ROOT = Path(__file__).resolve().parents[1]
SECRET = bytes(range(16))
CODE = '22222-5R62B-SAJ4K-C8JSR-74S7N-S2FAH-G5'

class HumanCodeTests(unittest.TestCase):
    def test_capacity(self):
        self.assertEqual(len(hc.ALPHABET), 24)
        self.assertEqual(len(set(hc.ALPHABET)), 24)
        self.assertGreater(24**30, 2**128)
        self.assertFalse(set('01ILO') & set(hc.ALPHABET))

    def test_fixed_public_vector(self):
        self.assertEqual(hc.encode(SECRET), CODE)
        self.assertEqual(hc.decode(CODE), SECRET)

    def test_all_public_vectors(self):
        for row in json.loads((ROOT/'human-vectors.json').read_text()):
            secret = bytes.fromhex(row['secret_hex'])
            self.assertEqual(hc.encode(secret),row['code'])
            self.assertEqual(hc.decode(row['code']),secret)

    def test_deterministic_roundtrips(self):
        # Public deterministic coverage; deliberately no real CSPRNG secrets.
        for i in range(256):
            secret = bytes((i+j)%256 for j in range(16))
            self.assertEqual(hc.decode(hc.encode(secret)),secret)

    def test_normalization(self):
        self.assertEqual(hc.decode(' \t'+CODE.lower().replace('-', ' \n-\r\v\f')+' '),SECRET)

    def test_no_fuzzy_or_unicode(self):
        for s in [CODE.replace('2','0',1),CODE.replace('2','O',1),CODE.replace('2','1',1),CODE.replace('2','I',1),CODE.replace('2','L',1),CODE.replace('-','—',1),'\u00a0'+CODE,'\u200b'+CODE,CODE.replace('K','K',1),None,SECRET]:
            with self.subTest(s=repr(s)),self.assertRaises(ValueError): hc.decode(s)

    def test_every_single_symbol_substitution(self):
        for row in json.loads((ROOT/'human-vectors.json').read_text()):
            s=row['code'].replace('-','')
            for i,c in enumerate(s):
                for replacement in hc.ALPHABET:
                    if c == replacement: continue
                    with self.subTest(i=i,c=c,replacement=replacement),self.assertRaises(ValueError):
                        hc.decode(s[:i]+replacement+s[i+1:])

    def test_adjacent_transpositions_public_vectors(self):
        for row in json.loads((ROOT/'human-vectors.json').read_text()):
            s=row['code'].replace('-','')
            for i in range(31):
                if s[i] == s[i+1]: continue
                with self.subTest(i=i),self.assertRaises(ValueError):
                    hc.decode(s[:i]+s[i+1]+s[i]+s[i+2:])

    def test_missing_and_extra_symbols(self):
        s=CODE.replace('-','')
        for i in range(32):
            with self.assertRaises(ValueError): hc.decode(s[:i]+s[i+1:])
            with self.assertRaises(ValueError): hc.decode(s[:i]+'2'+s[i:])

    def test_overflow_with_correct_checksum(self):
        values=[23]*30;c=hc.checksum(values)
        s='S'*30+hc.ALPHABET[c//24]+hc.ALPHABET[c%24]
        with self.assertRaisesRegex(ValueError,'range'): hc.decode(s)

    def test_noncanonical_checksum(self):
        for c in range(571,576):
            with self.assertRaisesRegex(ValueError,'checksum'):
                hc.decode(CODE.replace('-','')[:30]+hc.ALPHABET[c//24]+hc.ALPHABET[c%24])

    def test_unchanged_kdf_outputs(self):
        result=hc.derive('correct horse battery staple',CODE,'example.com','test',1,24)
        self.assertEqual(result,(bytes.fromhex('d926cadd0ae78d32398709deebcb1ba4e74e8991a973f06d5cef6e3a63dde787'),bytes.fromhex('60beb81f4da1e9a96b9f78d26df78ab2203c7a0b702912c22a72268de10a7930'),'HtO+f3SK@_5w*VwW6ufM@UzA'))

    def test_fail_before_argon(self):
        with patch.object(kdf,'hash_secret_raw') as argon:
            with self.assertRaises(ValueError): hc.derive('public phrase',CODE[:-1]+'2','example.com')
            argon.assert_not_called()

    def test_bad_secret(self):
        for s in [b'',b'x'*15,b'x'*17,'00'*16,None]:
            with self.assertRaises(ValueError): hc.encode(s)

if __name__=='__main__': unittest.main()
