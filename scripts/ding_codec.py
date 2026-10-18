"""DING inner-envelope codec, derived from a verified client build.

Integrated through the version-locked native backend after real-message checks.
Caller supplies a legitimately obtained enterprise/version
key as bytes. No credential discovery, key persistence, network or DLL loading.
"""
from dataclasses import dataclass
import base64
import binascii
import hashlib
import re


@dataclass(frozen=True)
class DingEnvelope:
    crypto_type: int
    key_version: int
    iv: bytes
    ciphertext: bytes


def _unpad_strict(value: bytes) -> bytes:
    if not value:
        raise ValueError('Empty padded payload')
    padding = value[-1]
    if not 1 <= padding <= 16 or value[-padding:] != bytes([padding]) * padding:
        raise ValueError('Invalid PKCS#7 padding; plaintext withheld')
    return value[:-padding]


def unwrap_cached_key(wrapped: str, material: bytes, *, crypto_type: int) -> bytes:
    """Decode the observed cache wrapper with caller-supplied 36-byte material.

    The wrapper uses AES-128 regardless of the body crypto_type. This parameter
    validates the final raw body-key length only. No live keys are discovered,
    logged or persisted. Strict Base64/padding are stronger than native checks.
    This transformation does NOT establish enterprise or version association.
    """
    if crypto_type not in (1, 2):
        raise ValueError('Unsupported body crypto type')
    if not isinstance(material, bytes) or len(material) != 36:
        raise ValueError('Expected 36-byte wrapper material')
    if not isinstance(wrapped, str) or not 1 <= len(wrapped) <= 4096:
        raise ValueError('Invalid cached key wrapper')
    try:
        encrypted = base64.b64decode(wrapped.encode('ascii'), validate=True)
    except (UnicodeEncodeError, binascii.Error) as error:
        raise ValueError('Invalid outer Base64') from error
    if not encrypted or len(encrypted) % 16:
        raise ValueError('Invalid wrapper AES block length')
    # The native path uses ASCII hex characters, NOT the binary MD5 digest.
    wrapping_key = hashlib.md5(material, usedforsecurity=False).hexdigest()[:16].encode('ascii')
    from Crypto.Cipher import AES
    inner = _unpad_strict(AES.new(wrapping_key, AES.MODE_CBC, iv=wrapping_key).decrypt(encrypted))
    try:
        result = base64.b64decode(inner, validate=True)
    except binascii.Error as error:
        raise ValueError('Invalid inner Base64') from error
    if len(result) != {1: 16, 2: 32}[crypto_type]:
        raise ValueError('Unwrapped key length does not match body crypto type')
    return result


def parse_envelope(text: str) -> DingEnvelope:
    if not isinstance(text, str) or len(text) > 16 * 1024 * 1024:
        raise ValueError('Invalid or over-limit DING envelope')
    match = re.fullmatch(r'([12])_([0-9]{1,10})_([0-9a-fA-F]+)', text)
    if not match:
        raise ValueError('Expected type_version_hex DING envelope')
    version = int(match[2])
    if version > 0x7fffffff:
        raise ValueError('Key version exceeds signed 32-bit range')
    if len(match[3]) % 2:
        raise ValueError('Odd-length hexadecimal payload')
    raw = bytes.fromhex(match[3])
    if len(raw) < 32 or len(raw) % 16:
        raise ValueError('Expected 16-byte IV followed by nonempty AES blocks')
    return DingEnvelope(int(match[1]), version, raw[:16], raw[16:])


def decrypt_envelope(text: str, key: bytes, *, expected_version: int,
                     padded: bool = True) -> bytes:
    """Decrypt with an explicit version-bound key; never infer or search for keys.

    Strict PKCS#7 validation intentionally rejects more data than the observed
    native remover, which only tests the final byte. The native encryption path
    emits standard PKCS#7. Padding validity alone does not authenticate content.
    Set padded=False only for a known-answer raw CBC test, not batch messages.
    """
    envelope = parse_envelope(text)
    if envelope.key_version != expected_version:
        raise ValueError('Envelope/key version mismatch')
    required = {1: 16, 2: 32}[envelope.crypto_type]
    if not isinstance(key, bytes) or len(key) != required:
        raise ValueError('Key length does not match crypto type')
    from Crypto.Cipher import AES
    result = AES.new(key, AES.MODE_CBC, iv=envelope.iv).decrypt(envelope.ciphertext)
    if padded:
        result = _unpad_strict(result)
    return result
