from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from ding_codec import parse_envelope, decrypt_envelope, unwrap_cached_key


class DingCodecTests(unittest.TestCase):
    iv = '000102030405060708090a0b0c0d0e0f'
    block = '6bc1bee22e409f96e93d7e117393172a'

    def test_fixed_aes128_cbc_vector(self):
        envelope = '1_7_' + self.iv + '7649abac8119b246cee98e9b12e9197d'
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        self.assertEqual(decrypt_envelope(envelope, key, expected_version=7, padded=False).hex(), self.block)

    def test_fixed_aes256_cbc_vector(self):
        envelope = '2_4_' + self.iv + 'f58c4c04d6e5f1ba779eabfb5f7bfbd6'
        key = bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
        self.assertEqual(decrypt_envelope(envelope, key, expected_version=4, padded=False).hex(), self.block)

    def test_type_version_and_iv_boundaries(self):
        parsed = parse_envelope('2_19_' + self.iv + 'aa' * 16)
        self.assertEqual((parsed.crypto_type, parsed.key_version), (2, 19))
        self.assertEqual(parsed.iv.hex(), self.iv)
        self.assertEqual(parsed.ciphertext, b'\xaa' * 16)

    def test_malformed_envelopes(self):
        for text in ('3_1_' + '00' * 32, '1_-1_' + '00' * 32, '1_2147483648_' + '00' * 32,
                     '1_1_abc', '1_1_' + '00' * 16, '1_1_' + '00' * 33,
                     '1_1_' + '00' * 31 + 'xz', 'prefix1_1_' + '00' * 32):
            with self.subTest(text=text[:20]), self.assertRaises(ValueError):
                parse_envelope(text)

    def test_explicit_version_and_key_length(self):
        envelope = '1_7_' + self.iv + '7649abac8119b246cee98e9b12e9197d'
        for key, version in ((bytes(16), 6), (bytes(32), 7), ('x' * 16, 7)):
            with self.assertRaises(ValueError):
                decrypt_envelope(envelope, key, expected_version=version)

    def test_standard_padding_and_utf8_preserved(self):
        from Crypto.Cipher import AES
        key = bytes(range(16))  # Synthetic test key, never a client credential.
        iv = bytes.fromhex(self.iv)
        text = '测试\n正文，保留末尾空格  '.encode('utf-8')
        count = 16 - len(text) % 16
        ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(text + bytes([count]) * count)
        envelope = '1_1_' + (iv + ciphertext).hex()
        self.assertEqual(decrypt_envelope(envelope, key, expected_version=1), text)

    def test_weak_native_padding_cases_are_rejected(self):
        from Crypto.Cipher import AES
        key, iv = bytes(range(16)), bytes.fromhex(self.iv)
        # Native code may truncate on these trailing bytes; batch code must not.
        for block in (b'A' * 15 + b'\x00', b'A' * 15 + b'\x02', b'A' * 15 + b'\xff'):
            encrypted = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(block)
            with self.assertRaises(ValueError):
                decrypt_envelope('1_1_' + (iv + encrypted).hex(), key, expected_version=1)

    def test_cache_wrapper_fixed_independent_fixtures(self):
        # Generated independently with cryptography's Cipher/encryptor API.
        # All material and keys are public synthetic byte ranges.
        fixtures = {
            1: '6GS0ie5w7/CefgzqMgCGN1/Nci9Ny49ULDvyPnlPvnY=',
            2: '6GS0ie5w7/CefgzqMgCGNwq/w/g0USsA13olakOFgB/dr9Pz6ttMBdJ5wqGsEJvk',
        }
        for kind, fixture in fixtures.items():
            self.assertEqual(unwrap_cached_key(fixture, bytes(range(36)), crypto_type=kind),
                             bytes(range({1: 16, 2: 32}[kind])))

    def test_cache_wrapper_rejects_wrong_key_size_and_material(self):
        fixture = '6GS0ie5w7/CefgzqMgCGN1/Nci9Ny49ULDvyPnlPvnY='
        for material, kind in ((bytes(range(36)), 2), (bytes(36), 1),
                               (bytes(35), 1), (bytes(36), 3)):
            with self.assertRaises(ValueError):
                unwrap_cached_key(fixture, material, crypto_type=kind)

    def test_cache_wrapper_rejects_malformed_outer(self):
        for fixture in ('', '!', 'AA==', '非ASCII', 'A' * 4097,
                        '6GS0ie5w7/CefgzqMgCGN1/Nci9Ny49ULDvyPnlPvnY=\n'):
            with self.assertRaises(ValueError):
                unwrap_cached_key(fixture, bytes(range(36)), crypto_type=1)

    def test_cache_wrapper_rejects_inner_base64_and_padding(self):
        import base64
        import hashlib
        from Crypto.Cipher import AES
        material = bytes(range(36))
        key = hashlib.md5(material).hexdigest()[:16].encode('ascii')
        for padded in (b'!' * 15 + b'\x01', b'A' * 15 + b'\x00',
                       b'A' * 15 + b'\x02'):
            wrapped = base64.b64encode(AES.new(key, AES.MODE_CBC, iv=key).encrypt(padded)).decode('ascii')
            with self.assertRaises(ValueError):
                unwrap_cached_key(wrapped, material, crypto_type=1)


if __name__ == '__main__':
    unittest.main()
