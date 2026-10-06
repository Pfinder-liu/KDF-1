"""HRC-1: reversible human representation; no KDF changes."""
ALPHABET = '23456789ABCDEFGHJKMNPQRS'
BASE = len(ALPHABET)
DIGITS = 30
MODULUS = 571
IGNORE = '- \t\r\n\v\f'


def checksum(values):
    return sum((i + 1) * d for i, d in enumerate(values)) % MODULUS


def encode(secret):
    if not isinstance(secret, bytes) or len(secret) != 16:
        raise ValueError('Recovery Secret must be 16 bytes')
    n = int.from_bytes(secret, 'big')
    values = [0] * DIGITS
    for i in range(DIGITS - 1, -1, -1):
        n, values[i] = divmod(n, BASE)
    c = checksum(values)
    text = ''.join(ALPHABET[d] for d in values) + ALPHABET[c // BASE] + ALPHABET[c % BASE]
    return '-'.join([text[i:i+5] for i in range(0, 30, 5)] + [text[30:]])


def decode(text):
    if not isinstance(text, str):
        raise ValueError('Recovery Code must be text')
    # ASCII only; do not uppercase Unicode into a valid ASCII lookalike.
    text = ''.join(chr(ord(c) - 32) if 'a' <= c <= 'z' else c
                   for c in text if c not in IGNORE)
    if len(text) != 32 or any(c not in ALPHABET for c in text):
        raise ValueError('Recovery Code format error. Recheck the paper; no guessing.')
    values = [ALPHABET.index(c) for c in text]
    c = values[30] * BASE + values[31]
    if c != checksum(values[:30]):
        raise ValueError('Recovery Code checksum failed. Recheck the paper.')
    n = 0
    for d in values[:30]:
        n = n * BASE + d
    if n >= 2**128:
        raise ValueError('Recovery Code out of 128-bit range. Recheck the paper.')
    return n.to_bytes(16, 'big')


def derive(master_phrase, code, label, account='', revision=1, length=24):
    import kdf
    secret = decode(code)  # Fail before costly KDF.
    return kdf.derive(master_phrase, secret.hex(), label, account, revision, length)
